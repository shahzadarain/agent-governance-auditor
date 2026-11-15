// SPDX-License-Identifier: Apache-2.0

package storage

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"embed"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"time"

	_ "github.com/jackc/pgx/v5/stdlib" // driver "pgx" (PostgreSQL; experimental, untested)
	_ "modernc.org/sqlite"             // driver "sqlite" (pure Go)
)

//go:embed migrations/*.sql
var migrationFS embed.FS

// Dialect names.
const (
	DialectSQLite   = "sqlite"
	DialectPostgres = "postgres"
)

// SQLStore implements Store over database/sql.
type SQLStore struct {
	db      *sql.DB
	dialect string
}

var _ Store = (*SQLStore)(nil)

// ParseDatabaseURL maps a database URL to a dialect and a driver DSN.
// Accepted forms: "sqlite:///abs/path/agentgov.db", "sqlite://rel/path.db",
// "sqlite:path.db", a bare file path, or "postgres://..." /
// "postgresql://...".
func ParseDatabaseURL(databaseURL string) (dialect, dsn string, err error) {
	u := strings.TrimSpace(databaseURL)
	if u == "" {
		return "", "", errors.New("storage: empty database URL")
	}
	lower := strings.ToLower(u)
	switch {
	case strings.HasPrefix(lower, "postgres://"), strings.HasPrefix(lower, "postgresql://"):
		return DialectPostgres, u, nil
	case strings.HasPrefix(lower, "sqlite:"):
		p := u[len("sqlite:"):]
		p = strings.TrimPrefix(p, "//")
		// "sqlite:///C:/data/x.db" leaves "/C:/data/x.db": drop the slash
		// in front of a Windows drive letter.
		if len(p) >= 3 && p[0] == '/' && p[2] == ':' {
			p = p[1:]
		}
		if p == "" {
			return "", "", errors.New("storage: sqlite URL has no file path")
		}
		return DialectSQLite, p, nil
	case strings.Contains(u, "://"):
		return "", "", errors.New("storage: unsupported database URL scheme (use sqlite or postgres)")
	default:
		return DialectSQLite, u, nil
	}
}

// Open opens the database, applies pending migrations, and returns the
// store. It returns ErrSchemaTooNew when the database was written by a newer
// binary.
func Open(ctx context.Context, databaseURL string) (*SQLStore, error) {
	dialect, dsn, err := ParseDatabaseURL(databaseURL)
	if err != nil {
		return nil, err
	}
	var db *sql.DB
	switch dialect {
	case DialectSQLite:
		if strings.ContainsAny(dsn, "?") {
			return nil, errors.New("storage: sqlite path must not contain '?'")
		}
		if dsn == ":memory:" || strings.HasPrefix(dsn, "file:") {
			return nil, errors.New("storage: use a plain file path for sqlite")
		}
		if dir := filepath.Dir(dsn); dir != "." {
			if err := os.MkdirAll(dir, 0o700); err != nil {
				return nil, fmt.Errorf("storage: create data directory: %w", err)
			}
		}
		// WAL for concurrent readers, foreign keys on, a busy timeout, and
		// IMMEDIATE transactions so writers queue instead of failing when a
		// read transaction upgrades.
		full := dsn + "?_pragma=busy_timeout(10000)&_pragma=journal_mode(WAL)" +
			"&_pragma=foreign_keys(ON)&_pragma=synchronous(NORMAL)&_txlock=immediate"
		db, err = sql.Open("sqlite", full)
		if err != nil {
			return nil, fmt.Errorf("storage: open sqlite: %w", err)
		}
		db.SetMaxOpenConns(8)
	case DialectPostgres:
		// EXPERIMENTAL: not tested against a real PostgreSQL server.
		db, err = sql.Open("pgx", dsn)
		if err != nil {
			return nil, fmt.Errorf("storage: open postgres: %w", err)
		}
		db.SetMaxOpenConns(16)
		db.SetConnMaxIdleTime(5 * time.Minute)
	}
	s := &SQLStore{db: db, dialect: dialect}
	if err := db.PingContext(ctx); err != nil {
		db.Close()
		return nil, fmt.Errorf("storage: connect: %w", err)
	}
	if err := s.migrate(ctx); err != nil {
		db.Close()
		return nil, err
	}
	return s, nil
}

// Dialect returns "sqlite" or "postgres".
func (s *SQLStore) Dialect() string { return s.dialect }

// Close closes the database.
func (s *SQLStore) Close() error { return s.db.Close() }

// Ping checks the database connection.
func (s *SQLStore) Ping(ctx context.Context) error { return s.db.PingContext(ctx) }

// Backup writes a consistent copy of a SQLite database to destPath with
// VACUUM INTO. The destination must not exist. PostgreSQL deployments use
// pg_dump instead.
func (s *SQLStore) Backup(ctx context.Context, destPath string) error {
	if s.dialect != DialectSQLite {
		return errors.New("storage: Backup supports sqlite only; use pg_dump for postgres")
	}
	if _, err := os.Stat(destPath); err == nil {
		return errors.New("storage: backup destination already exists")
	}
	_, err := s.db.ExecContext(ctx, "VACUUM INTO ?", destPath)
	return err
}

// q rewrites '?' placeholders to '$n' for PostgreSQL. Queries in this
// package never contain a literal question mark.
func (s *SQLStore) q(query string) string {
	if s.dialect != DialectPostgres {
		return query
	}
	var b strings.Builder
	n := 0
	for i := 0; i < len(query); i++ {
		if query[i] == '?' {
			n++
			b.WriteByte('$')
			b.WriteString(strconv.Itoa(n))
			continue
		}
		b.WriteByte(query[i])
	}
	return b.String()
}

func (s *SQLStore) inTx(ctx context.Context, fn func(tx *sql.Tx) error) error {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	if err := fn(tx); err != nil {
		_ = tx.Rollback()
		return err
	}
	return tx.Commit()
}

func isUniqueViolation(err error) bool {
	if err == nil {
		return false
	}
	m := err.Error()
	return strings.Contains(m, "UNIQUE constraint failed") ||
		strings.Contains(m, "constraint failed: UNIQUE") ||
		strings.Contains(m, "SQLSTATE 23505")
}

// ---------------------------------------------------------------------------
// Migrations
// ---------------------------------------------------------------------------

type migration struct {
	version int
	name    string
	sql     string
}

func loadMigrations() ([]migration, error) {
	entries, err := fs.ReadDir(migrationFS, "migrations")
	if err != nil {
		return nil, err
	}
	var out []migration
	for _, e := range entries {
		name := e.Name()
		if !strings.HasSuffix(name, ".sql") {
			continue
		}
		under := strings.IndexByte(name, '_')
		if under < 1 {
			return nil, fmt.Errorf("storage: bad migration file name %q", name)
		}
		v, err := strconv.Atoi(name[:under])
		if err != nil || v < 1 {
			return nil, fmt.Errorf("storage: bad migration version in %q", name)
		}
		data, err := fs.ReadFile(migrationFS, "migrations/"+name)
		if err != nil {
			return nil, err
		}
		out = append(out, migration{version: v, name: strings.TrimSuffix(name, ".sql"), sql: string(data)})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].version < out[j].version })
	for i, m := range out {
		if m.version != i+1 {
			return nil, fmt.Errorf("storage: migration versions must be contiguous; found %d at position %d", m.version, i+1)
		}
	}
	return out, nil
}

// splitStatements splits a migration file into statements. A statement ends
// with ';' at the end of a line. Comment lines start with "--".
func splitStatements(text string) []string {
	var out []string
	var cur strings.Builder
	for _, line := range strings.Split(text, "\n") {
		trim := strings.TrimSpace(line)
		if trim == "" || strings.HasPrefix(trim, "--") {
			continue
		}
		cur.WriteString(line)
		cur.WriteByte('\n')
		if strings.HasSuffix(trim, ";") {
			out = append(out, strings.TrimSuffix(strings.TrimSpace(cur.String()), ";"))
			cur.Reset()
		}
	}
	if rest := strings.TrimSpace(cur.String()); rest != "" {
		out = append(out, rest)
	}
	return out
}

func (s *SQLStore) migrate(ctx context.Context) error {
	migs, err := loadMigrations()
	if err != nil {
		return err
	}
	if _, err := s.db.ExecContext(ctx, `CREATE TABLE IF NOT EXISTS schema_migrations (
		version INTEGER PRIMARY KEY, name TEXT NOT NULL, applied_at BIGINT NOT NULL)`); err != nil {
		return fmt.Errorf("storage: create schema_migrations: %w", err)
	}
	applied, err := s.appliedVersion(ctx)
	if err != nil {
		return err
	}
	if applied > len(migs) {
		return fmt.Errorf("%w: database is at migration %d, this binary knows %d", ErrSchemaTooNew, applied, len(migs))
	}
	for _, m := range migs {
		if m.version <= applied {
			continue
		}
		err := s.inTx(ctx, func(tx *sql.Tx) error {
			// Re-check inside the transaction: another process may have
			// applied this migration between the read above and now.
			var n int
			if err := tx.QueryRowContext(ctx, s.q(`SELECT COUNT(*) FROM schema_migrations WHERE version = ?`), m.version).Scan(&n); err != nil {
				return err
			}
			if n > 0 {
				return nil
			}
			for _, stmt := range splitStatements(m.sql) {
				if _, err := tx.ExecContext(ctx, stmt); err != nil {
					return fmt.Errorf("statement failed: %w", err)
				}
			}
			_, err := tx.ExecContext(ctx, s.q(`INSERT INTO schema_migrations (version, name, applied_at) VALUES (?, ?, ?)`),
				m.version, m.name, time.Now().UTC().UnixMicro())
			return err
		})
		if err != nil {
			return fmt.Errorf("storage: migration %s: %w", m.name, err)
		}
	}
	return nil
}

func (s *SQLStore) appliedVersion(ctx context.Context) (int, error) {
	var v sql.NullInt64
	if err := s.db.QueryRowContext(ctx, `SELECT MAX(version) FROM schema_migrations`).Scan(&v); err != nil {
		return 0, fmt.Errorf("storage: read schema_migrations: %w", err)
	}
	return int(v.Int64), nil
}

// MigrationStatus returns the applied and known migration versions.
func (s *SQLStore) MigrationStatus(ctx context.Context) (applied, known int, err error) {
	migs, err := loadMigrations()
	if err != nil {
		return 0, 0, err
	}
	applied, err = s.appliedVersion(ctx)
	return applied, len(migs), err
}

// ---------------------------------------------------------------------------
// Audit hash chain
// ---------------------------------------------------------------------------

// canonicalAudit is the byte string that is hashed for one event: a JSON
// array of [seq, occurred_at_microseconds, actor_type, actor_id, action,
// target, project_id, detail]. encoding/json output for this shape is
// deterministic.
func canonicalAudit(ev AuditEvent) []byte {
	b, _ := json.Marshal([]any{ev.Seq, ev.At.UTC().UnixMicro(), ev.ActorType, ev.ActorID, ev.Action, ev.Target, ev.ProjectID, ev.Detail})
	return b
}

func auditHash(prevHash string, ev AuditEvent) string {
	h := sha256.New()
	h.Write([]byte(prevHash))
	h.Write(canonicalAudit(ev))
	return hex.EncodeToString(h.Sum(nil))
}

// appendAuditTx appends one event inside tx. A nil event is a no-op.
func (s *SQLStore) appendAuditTx(ctx context.Context, tx *sql.Tx, ev *AuditEvent) error {
	if ev == nil {
		return nil
	}
	if s.dialect == DialectPostgres {
		// Serialize appenders so two transactions cannot read the same tail.
		if _, err := tx.ExecContext(ctx, `LOCK TABLE audit_events IN EXCLUSIVE MODE`); err != nil {
			return err
		}
	}
	var seq int64
	var prev string
	err := tx.QueryRowContext(ctx, `SELECT seq, hash FROM audit_events ORDER BY seq DESC LIMIT 1`).Scan(&seq, &prev)
	if err != nil && !errors.Is(err, sql.ErrNoRows) {
		return err
	}
	e := *ev
	e.Seq = seq + 1
	if e.At.IsZero() {
		e.At = time.Now()
	}
	e.At = e.At.UTC().Truncate(time.Microsecond)
	if e.Detail == "" {
		e.Detail = "{}"
	}
	e.PrevHash = prev
	e.Hash = auditHash(prev, e)
	_, err = tx.ExecContext(ctx, s.q(`INSERT INTO audit_events
		(seq, occurred_at, actor_type, actor_id, action, target, project_id, detail, prev_hash, hash)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`),
		e.Seq, e.At.UnixMicro(), e.ActorType, e.ActorID, e.Action, e.Target, e.ProjectID, e.Detail, e.PrevHash, e.Hash)
	return err
}

// AppendAudit appends one event to the chain.
func (s *SQLStore) AppendAudit(ctx context.Context, ev AuditEvent) error {
	return s.inTx(ctx, func(tx *sql.Tx) error { return s.appendAuditTx(ctx, tx, &ev) })
}

// ListAudit returns events newest first.
func (s *SQLStore) ListAudit(ctx context.Context, f AuditFilter) ([]AuditEvent, error) {
	limit := f.Limit
	if limit <= 0 {
		limit = 100
	}
	if limit > 1000 {
		limit = 1000
	}
	before := f.BeforeSeq
	if before <= 0 {
		before = 1<<62 - 1
	}
	const cols = `seq, occurred_at, actor_type, actor_id, action, target, project_id, detail, prev_hash, hash`
	var rows *sql.Rows
	var err error
	if f.ProjectID != "" {
		rows, err = s.db.QueryContext(ctx, s.q(`SELECT `+cols+` FROM audit_events
			WHERE project_id = ? AND seq < ? ORDER BY seq DESC LIMIT ?`), f.ProjectID, before, limit)
	} else {
		rows, err = s.db.QueryContext(ctx, s.q(`SELECT `+cols+` FROM audit_events
			WHERE seq < ? ORDER BY seq DESC LIMIT ?`), before, limit)
	}
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []AuditEvent{}
	for rows.Next() {
		var e AuditEvent
		var at int64
		if err := rows.Scan(&e.Seq, &at, &e.ActorType, &e.ActorID, &e.Action, &e.Target, &e.ProjectID, &e.Detail, &e.PrevHash, &e.Hash); err != nil {
			return nil, err
		}
		e.At = time.UnixMicro(at).UTC()
		out = append(out, e)
	}
	return out, rows.Err()
}

// VerifyAuditChain walks the chain from the first event and recomputes every
// hash. It detects edited rows, removed rows inside the chain, and reordered
// rows. It cannot detect truncation of the newest events; keep an off-host
// copy of the latest hash for that.
func (s *SQLStore) VerifyAuditChain(ctx context.Context) (int, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT seq, occurred_at, actor_type, actor_id, action, target,
		project_id, detail, prev_hash, hash FROM audit_events ORDER BY seq ASC`)
	if err != nil {
		return 0, err
	}
	defer rows.Close()
	n := 0
	prev := ""
	var want int64 = 1
	for rows.Next() {
		var e AuditEvent
		var at int64
		if err := rows.Scan(&e.Seq, &at, &e.ActorType, &e.ActorID, &e.Action, &e.Target, &e.ProjectID, &e.Detail, &e.PrevHash, &e.Hash); err != nil {
			return n, err
		}
		e.At = time.UnixMicro(at).UTC()
		if e.Seq != want {
			return n, fmt.Errorf("storage: audit chain broken: expected event %d, found %d", want, e.Seq)
		}
		if e.PrevHash != prev {
			return n, fmt.Errorf("storage: audit chain broken at event %d: previous hash does not match", e.Seq)
		}
		if auditHash(prev, e) != e.Hash {
			return n, fmt.Errorf("storage: audit chain broken at event %d: content hash does not match", e.Seq)
		}
		prev = e.Hash
		want++
		n++
	}
	return n, rows.Err()
}
