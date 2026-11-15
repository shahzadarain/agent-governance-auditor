// SPDX-License-Identifier: Apache-2.0

package storage

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"strings"
	"time"
)

func us(t time.Time) int64 { return t.UTC().UnixMicro() }

func fromUS(v int64) time.Time { return time.UnixMicro(v).UTC() }

func nullTime(t *time.Time) sql.NullInt64 {
	if t == nil {
		return sql.NullInt64{}
	}
	return sql.NullInt64{Int64: us(*t), Valid: true}
}

func timePtr(v sql.NullInt64) *time.Time {
	if !v.Valid {
		return nil
	}
	t := fromUS(v.Int64)
	return &t
}

func nullInt(p *int) sql.NullInt64 {
	if p == nil {
		return sql.NullInt64{}
	}
	return sql.NullInt64{Int64: int64(*p), Valid: true}
}

func intPtr(v sql.NullInt64) *int {
	if !v.Valid {
		return nil
	}
	i := int(v.Int64)
	return &i
}

func boolInt(b bool) int {
	if b {
		return 1
	}
	return 0
}

func noRows(err error) error {
	if errors.Is(err, sql.ErrNoRows) {
		return ErrNotFound
	}
	return err
}

// ---------------------------------------------------------------------------
// Settings
// ---------------------------------------------------------------------------

// GetSetting returns one settings value.
func (s *SQLStore) GetSetting(ctx context.Context, key string) (string, bool, error) {
	var v string
	err := s.db.QueryRowContext(ctx, s.q(`SELECT value FROM settings WHERE key = ?`), key).Scan(&v)
	if errors.Is(err, sql.ErrNoRows) {
		return "", false, nil
	}
	return v, err == nil, err
}

func (s *SQLStore) setSettingTx(ctx context.Context, tx *sql.Tx, key, value string) error {
	_, err := tx.ExecContext(ctx, s.q(`INSERT INTO settings (key, value) VALUES (?, ?)
		ON CONFLICT (key) DO UPDATE SET value = excluded.value`), key, value)
	return err
}

// SetSettings writes several settings in one transaction.
func (s *SQLStore) SetSettings(ctx context.Context, values map[string]string, ev *AuditEvent) error {
	return s.inTx(ctx, func(tx *sql.Tx) error {
		for k, v := range values {
			if err := s.setSettingTx(ctx, tx, k, v); err != nil {
				return err
			}
		}
		return s.appendAuditTx(ctx, tx, ev)
	})
}

// ---------------------------------------------------------------------------
// Users
// ---------------------------------------------------------------------------

// CountUsers returns the number of accounts.
func (s *SQLStore) CountUsers(ctx context.Context) (int, error) {
	var n int
	err := s.db.QueryRowContext(ctx, `SELECT COUNT(*) FROM users`).Scan(&n)
	return n, err
}

func (s *SQLStore) insertUserTx(ctx context.Context, tx *sql.Tx, u User) error {
	_, err := tx.ExecContext(ctx, s.q(`INSERT INTO users (id, username, password_hash, role, created_at, disabled)
		VALUES (?, ?, ?, ?, ?, ?)`), u.ID, u.Username, u.PasswordHash, u.Role, us(u.CreatedAt), boolInt(u.Disabled))
	if isUniqueViolation(err) {
		return ErrConflict
	}
	return err
}

// CreateFirstUser creates the first account atomically.
func (s *SQLStore) CreateFirstUser(ctx context.Context, u User, requireSetting, requireValue string, clearSettings []string, ev *AuditEvent) error {
	return s.inTx(ctx, func(tx *sql.Tx) error {
		var n int
		if err := tx.QueryRowContext(ctx, `SELECT COUNT(*) FROM users`).Scan(&n); err != nil {
			return err
		}
		if n > 0 {
			return ErrConflict
		}
		if requireSetting != "" {
			var v string
			err := tx.QueryRowContext(ctx, s.q(`SELECT value FROM settings WHERE key = ?`), requireSetting).Scan(&v)
			if errors.Is(err, sql.ErrNoRows) || (err == nil && v != requireValue) {
				return ErrConflict
			}
			if err != nil {
				return err
			}
		}
		if err := s.insertUserTx(ctx, tx, u); err != nil {
			return err
		}
		for _, k := range clearSettings {
			if _, err := tx.ExecContext(ctx, s.q(`DELETE FROM settings WHERE key = ?`), k); err != nil {
				return err
			}
		}
		return s.appendAuditTx(ctx, tx, ev)
	})
}

// CreateUser creates an account. It returns ErrConflict for a taken name.
func (s *SQLStore) CreateUser(ctx context.Context, u User, ev *AuditEvent) error {
	return s.inTx(ctx, func(tx *sql.Tx) error {
		if err := s.insertUserTx(ctx, tx, u); err != nil {
			return err
		}
		return s.appendAuditTx(ctx, tx, ev)
	})
}

const userCols = `id, username, password_hash, role, created_at, disabled`

func scanUser(row interface{ Scan(...any) error }) (User, error) {
	var u User
	var created int64
	var disabled int
	if err := row.Scan(&u.ID, &u.Username, &u.PasswordHash, &u.Role, &created, &disabled); err != nil {
		return User{}, noRows(err)
	}
	u.CreatedAt = fromUS(created)
	u.Disabled = disabled != 0
	return u, nil
}

// GetUserByID returns one account.
func (s *SQLStore) GetUserByID(ctx context.Context, id string) (User, error) {
	return scanUser(s.db.QueryRowContext(ctx, s.q(`SELECT `+userCols+` FROM users WHERE id = ?`), id))
}

// GetUserByUsername returns one account by its (lower-case) name.
func (s *SQLStore) GetUserByUsername(ctx context.Context, username string) (User, error) {
	return scanUser(s.db.QueryRowContext(ctx, s.q(`SELECT `+userCols+` FROM users WHERE username = ?`), username))
}

// ListUsers returns every account ordered by name.
func (s *SQLStore) ListUsers(ctx context.Context) ([]User, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT `+userCols+` FROM users ORDER BY username`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []User{}
	for rows.Next() {
		u, err := scanUser(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, u)
	}
	return out, rows.Err()
}

// ---------------------------------------------------------------------------
// Sessions
// ---------------------------------------------------------------------------

// CreateSession stores a session.
func (s *SQLStore) CreateSession(ctx context.Context, se Session, ev *AuditEvent) error {
	return s.inTx(ctx, func(tx *sql.Tx) error {
		if _, err := tx.ExecContext(ctx, s.q(`INSERT INTO sessions (id_hash, user_id, csrf_token, created_at, expires_at, last_seen)
			VALUES (?, ?, ?, ?, ?, ?)`), se.IDHash, se.UserID, se.CSRFToken, us(se.CreatedAt), us(se.ExpiresAt), us(se.LastSeen)); err != nil {
			return err
		}
		return s.appendAuditTx(ctx, tx, ev)
	})
}

// GetSession returns a session by the hash of its ID.
func (s *SQLStore) GetSession(ctx context.Context, idHash string) (Session, error) {
	var se Session
	var c, e, l int64
	err := s.db.QueryRowContext(ctx, s.q(`SELECT id_hash, user_id, csrf_token, created_at, expires_at, last_seen
		FROM sessions WHERE id_hash = ?`), idHash).Scan(&se.IDHash, &se.UserID, &se.CSRFToken, &c, &e, &l)
	if err != nil {
		return Session{}, noRows(err)
	}
	se.CreatedAt, se.ExpiresAt, se.LastSeen = fromUS(c), fromUS(e), fromUS(l)
	return se, nil
}

// TouchSession records activity on a session.
func (s *SQLStore) TouchSession(ctx context.Context, idHash string, at time.Time) error {
	return s.inTx(ctx, func(tx *sql.Tx) error {
		_, err := tx.ExecContext(ctx, s.q(`UPDATE sessions SET last_seen = ? WHERE id_hash = ?`), us(at), idHash)
		return err
	})
}

// DeleteSession removes a session.
func (s *SQLStore) DeleteSession(ctx context.Context, idHash string, ev *AuditEvent) error {
	return s.inTx(ctx, func(tx *sql.Tx) error {
		if _, err := tx.ExecContext(ctx, s.q(`DELETE FROM sessions WHERE id_hash = ?`), idHash); err != nil {
			return err
		}
		return s.appendAuditTx(ctx, tx, ev)
	})
}

// DeleteExpiredSessions removes sessions past their absolute expiry or idle
// longer than the idle cutoff.
func (s *SQLStore) DeleteExpiredSessions(ctx context.Context, now, idleCutoff time.Time) (int64, error) {
	var n int64
	err := s.inTx(ctx, func(tx *sql.Tx) error {
		res, err := tx.ExecContext(ctx, s.q(`DELETE FROM sessions WHERE expires_at <= ? OR last_seen <= ?`), us(now), us(idleCutoff))
		if err != nil {
			return err
		}
		n, _ = res.RowsAffected()
		return nil
	})
	return n, err
}

// ---------------------------------------------------------------------------
// Projects and members
// ---------------------------------------------------------------------------

// CreateProject creates a project. It returns ErrConflict for a taken slug.
func (s *SQLStore) CreateProject(ctx context.Context, p Project, ev *AuditEvent) error {
	return s.inTx(ctx, func(tx *sql.Tx) error {
		_, err := tx.ExecContext(ctx, s.q(`INSERT INTO projects (id, slug, name, created_by, created_at) VALUES (?, ?, ?, ?, ?)`),
			p.ID, p.Slug, p.Name, p.CreatedBy, us(p.CreatedAt))
		if isUniqueViolation(err) {
			return ErrConflict
		}
		if err != nil {
			return err
		}
		return s.appendAuditTx(ctx, tx, ev)
	})
}

// GetProject returns one project.
func (s *SQLStore) GetProject(ctx context.Context, id string) (Project, error) {
	var p Project
	var c int64
	err := s.db.QueryRowContext(ctx, s.q(`SELECT id, slug, name, created_by, created_at FROM projects WHERE id = ?`), id).
		Scan(&p.ID, &p.Slug, &p.Name, &p.CreatedBy, &c)
	if err != nil {
		return Project{}, noRows(err)
	}
	p.CreatedAt = fromUS(c)
	return p, nil
}

// ListProjects returns every project ordered by slug.
func (s *SQLStore) ListProjects(ctx context.Context) ([]Project, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT id, slug, name, created_by, created_at FROM projects ORDER BY slug`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []Project{}
	for rows.Next() {
		var p Project
		var c int64
		if err := rows.Scan(&p.ID, &p.Slug, &p.Name, &p.CreatedBy, &c); err != nil {
			return nil, err
		}
		p.CreatedAt = fromUS(c)
		out = append(out, p)
	}
	return out, rows.Err()
}

// ListProjectsForUser returns the projects a user is a member of, with the
// user's role in each.
func (s *SQLStore) ListProjectsForUser(ctx context.Context, userID string) ([]Project, error) {
	rows, err := s.db.QueryContext(ctx, s.q(`SELECT p.id, p.slug, p.name, p.created_by, p.created_at, m.role
		FROM projects p JOIN project_members m ON m.project_id = p.id
		WHERE m.user_id = ? ORDER BY p.slug`), userID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []Project{}
	for rows.Next() {
		var p Project
		var c int64
		if err := rows.Scan(&p.ID, &p.Slug, &p.Name, &p.CreatedBy, &c, &p.Role); err != nil {
			return nil, err
		}
		p.CreatedAt = fromUS(c)
		out = append(out, p)
	}
	return out, rows.Err()
}

// DeleteProject deletes a project and everything that belongs to it. Audit
// events are kept.
func (s *SQLStore) DeleteProject(ctx context.Context, id string, ev *AuditEvent) error {
	return s.inTx(ctx, func(tx *sql.Tx) error {
		// agents has no foreign key to scans, so delete it explicitly first.
		if _, err := tx.ExecContext(ctx, s.q(`DELETE FROM agents WHERE project_id = ?`), id); err != nil {
			return err
		}
		res, err := tx.ExecContext(ctx, s.q(`DELETE FROM projects WHERE id = ?`), id)
		if err != nil {
			return err
		}
		if n, _ := res.RowsAffected(); n == 0 {
			return ErrNotFound
		}
		return s.appendAuditTx(ctx, tx, ev)
	})
}

// MemberRole returns the role of a user in a project, or ErrNotFound.
func (s *SQLStore) MemberRole(ctx context.Context, projectID, userID string) (string, error) {
	var role string
	err := s.db.QueryRowContext(ctx, s.q(`SELECT role FROM project_members WHERE project_id = ? AND user_id = ?`), projectID, userID).Scan(&role)
	return role, noRows(err)
}

// ListMembers returns the members of a project.
func (s *SQLStore) ListMembers(ctx context.Context, projectID string) ([]Member, error) {
	rows, err := s.db.QueryContext(ctx, s.q(`SELECT m.project_id, m.user_id, u.username, m.role
		FROM project_members m JOIN users u ON u.id = m.user_id
		WHERE m.project_id = ? ORDER BY u.username`), projectID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []Member{}
	for rows.Next() {
		var m Member
		if err := rows.Scan(&m.ProjectID, &m.UserID, &m.Username, &m.Role); err != nil {
			return nil, err
		}
		out = append(out, m)
	}
	return out, rows.Err()
}

// SetMember adds a member or changes the member's role.
func (s *SQLStore) SetMember(ctx context.Context, m Member, ev *AuditEvent) error {
	return s.inTx(ctx, func(tx *sql.Tx) error {
		_, err := tx.ExecContext(ctx, s.q(`INSERT INTO project_members (project_id, user_id, role) VALUES (?, ?, ?)
			ON CONFLICT (project_id, user_id) DO UPDATE SET role = excluded.role`), m.ProjectID, m.UserID, m.Role)
		if err != nil {
			return err
		}
		return s.appendAuditTx(ctx, tx, ev)
	})
}

// RemoveMember removes a membership. It returns ErrNotFound when absent.
func (s *SQLStore) RemoveMember(ctx context.Context, projectID, userID string, ev *AuditEvent) error {
	return s.inTx(ctx, func(tx *sql.Tx) error {
		res, err := tx.ExecContext(ctx, s.q(`DELETE FROM project_members WHERE project_id = ? AND user_id = ?`), projectID, userID)
		if err != nil {
			return err
		}
		if n, _ := res.RowsAffected(); n == 0 {
			return ErrNotFound
		}
		return s.appendAuditTx(ctx, tx, ev)
	})
}

// ---------------------------------------------------------------------------
// API tokens
// ---------------------------------------------------------------------------

// CreateToken stores a token record (hash only).
func (s *SQLStore) CreateToken(ctx context.Context, t APIToken, ev *AuditEvent) error {
	return s.inTx(ctx, func(tx *sql.Tx) error {
		_, err := tx.ExecContext(ctx, s.q(`INSERT INTO api_tokens
			(id, project_id, name, token_hash, prefix, scopes, created_by, created_at, last_used_at, expires_at, revoked_at)
			VALUES (?, ?, ?, ?, ?, ?, ?, ?, NULL, ?, NULL)`),
			t.ID, t.ProjectID, t.Name, t.TokenHash, t.Prefix, strings.Join(t.Scopes, " "), t.CreatedBy, us(t.CreatedAt), nullTime(t.ExpiresAt))
		if isUniqueViolation(err) {
			return ErrConflict
		}
		if err != nil {
			return err
		}
		return s.appendAuditTx(ctx, tx, ev)
	})
}

const tokenCols = `id, project_id, name, token_hash, prefix, scopes, created_by, created_at, last_used_at, expires_at, revoked_at`

func scanToken(row interface{ Scan(...any) error }) (APIToken, error) {
	var t APIToken
	var scopes string
	var created int64
	var used, exp, rev sql.NullInt64
	if err := row.Scan(&t.ID, &t.ProjectID, &t.Name, &t.TokenHash, &t.Prefix, &scopes, &t.CreatedBy, &created, &used, &exp, &rev); err != nil {
		return APIToken{}, noRows(err)
	}
	t.Scopes = strings.Fields(scopes)
	t.CreatedAt = fromUS(created)
	t.LastUsedAt, t.ExpiresAt, t.RevokedAt = timePtr(used), timePtr(exp), timePtr(rev)
	return t, nil
}

// ListTokens returns the tokens of a project, newest first.
func (s *SQLStore) ListTokens(ctx context.Context, projectID string) ([]APIToken, error) {
	rows, err := s.db.QueryContext(ctx, s.q(`SELECT `+tokenCols+` FROM api_tokens WHERE project_id = ? ORDER BY created_at DESC, id`), projectID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []APIToken{}
	for rows.Next() {
		t, err := scanToken(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, t)
	}
	return out, rows.Err()
}

// GetTokenByHash returns the token with the given hash.
func (s *SQLStore) GetTokenByHash(ctx context.Context, tokenHash string) (APIToken, error) {
	return scanToken(s.db.QueryRowContext(ctx, s.q(`SELECT `+tokenCols+` FROM api_tokens WHERE token_hash = ?`), tokenHash))
}

// RevokeToken marks a token revoked. The project ID scopes the lookup, so a
// token of another project is reported as not found.
func (s *SQLStore) RevokeToken(ctx context.Context, projectID, tokenID string, at time.Time, ev *AuditEvent) error {
	return s.inTx(ctx, func(tx *sql.Tx) error {
		res, err := tx.ExecContext(ctx, s.q(`UPDATE api_tokens SET revoked_at = COALESCE(revoked_at, ?)
			WHERE id = ? AND project_id = ?`), us(at), tokenID, projectID)
		if err != nil {
			return err
		}
		if n, _ := res.RowsAffected(); n == 0 {
			return ErrNotFound
		}
		return s.appendAuditTx(ctx, tx, ev)
	})
}

// TouchToken records the last use of a token.
func (s *SQLStore) TouchToken(ctx context.Context, tokenID string, at time.Time) error {
	return s.inTx(ctx, func(tx *sql.Tx) error {
		_, err := tx.ExecContext(ctx, s.q(`UPDATE api_tokens SET last_used_at = ? WHERE id = ?`), us(at), tokenID)
		return err
	})
}

// ---------------------------------------------------------------------------
// Scans and agents
// ---------------------------------------------------------------------------

const scanCols = `id, project_id, scan_id, target, commit_sha, profile, policy_pack, policy_version, tool_version,
	decision, score, score_label, received_at, uploaded_by_token, payload_bytes, payload_sha256`

func scanScan(row interface{ Scan(...any) error }) (Scan, error) {
	var sc Scan
	var score sql.NullInt64
	var recv int64
	if err := row.Scan(&sc.ID, &sc.ProjectID, &sc.ScanID, &sc.Target, &sc.CommitSHA, &sc.Profile, &sc.PolicyPack, &sc.PolicyVersion,
		&sc.ToolVersion, &sc.Decision, &score, &sc.ScoreLabel, &recv, &sc.UploadedByToken, &sc.PayloadBytes, &sc.PayloadSHA256); err != nil {
		return Scan{}, noRows(err)
	}
	sc.Score = intPtr(score)
	sc.ReceivedAt = fromUS(recv)
	return sc, nil
}

// IngestScan stores one uploaded scan and its index rows in one transaction.
func (s *SQLStore) IngestScan(ctx context.Context, in IngestInput) (Scan, bool, error) {
	var out Scan
	created := false
	err := s.inTx(ctx, func(tx *sql.Tx) error {
		existing, err := scanScan(tx.QueryRowContext(ctx, s.q(`SELECT `+scanCols+` FROM scans
			WHERE project_id = ? AND payload_sha256 = ?`), in.Scan.ProjectID, in.Scan.PayloadSHA256))
		if err == nil {
			out = existing
			return nil
		}
		if !errors.Is(err, ErrNotFound) {
			return err
		}
		sc := in.Scan
		sc.PayloadBytes = len(in.Payload)
		if _, err := tx.ExecContext(ctx, s.q(`INSERT INTO scans (id, project_id, scan_id, target, commit_sha, profile, policy_pack,
			policy_version, tool_version, decision, score, score_label, received_at, uploaded_by_token, payload, payload_bytes, payload_sha256)
			VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`),
			sc.ID, sc.ProjectID, sc.ScanID, sc.Target, sc.CommitSHA, sc.Profile, sc.PolicyPack, sc.PolicyVersion, sc.ToolVersion,
			sc.Decision, nullInt(sc.Score), sc.ScoreLabel, us(sc.ReceivedAt), sc.UploadedByToken, string(in.Payload), sc.PayloadBytes, sc.PayloadSHA256); err != nil {
			if isUniqueViolation(err) {
				return ErrConflict
			}
			return err
		}
		recv := us(sc.ReceivedAt)
		for _, a := range in.Agents {
			if _, err := tx.ExecContext(ctx, s.q(`INSERT INTO scan_agents (scan_row_id, agent_id, decision, score, score_label)
				VALUES (?, ?, ?, ?, ?)`), sc.ID, a.AgentID, a.Decision, nullInt(a.Score), a.ScoreLabel); err != nil {
				return err
			}
			// The newest upload wins. An upload that is older than the
			// recorded one (clock skew between restarts) does not overwrite.
			if _, err := tx.ExecContext(ctx, s.q(`INSERT INTO agents (agent_key, project_id, agent_id, name, framework, language, owner,
				risk_tier, last_scan_id, last_decision, last_score, first_seen, last_seen)
				VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
				ON CONFLICT (project_id, agent_id) DO UPDATE SET
					name = excluded.name, framework = excluded.framework, language = excluded.language,
					owner = excluded.owner, risk_tier = excluded.risk_tier, last_scan_id = excluded.last_scan_id,
					last_decision = excluded.last_decision, last_score = excluded.last_score, last_seen = excluded.last_seen
				WHERE excluded.last_seen >= agents.last_seen`),
				a.NewKey, sc.ProjectID, a.AgentID, a.Name, a.Framework, a.Language, a.Owner, a.RiskTier,
				sc.ID, a.Decision, nullInt(a.Score), recv, recv); err != nil {
				return err
			}
		}
		if len(in.Findings) > 0 {
			st, err := tx.PrepareContext(ctx, s.q(`INSERT INTO findings (scan_row_id, ord, finding_id, fingerprint, control_id, agent_id,
				severity, title, path, line) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`))
			if err != nil {
				return err
			}
			defer st.Close()
			for i, f := range in.Findings {
				if _, err := st.ExecContext(ctx, sc.ID, i, f.FindingID, f.Fingerprint, f.ControlID, f.AgentID, f.Severity, f.Title, f.Path, f.Line); err != nil {
					return err
				}
			}
		}
		if len(in.Controls) > 0 {
			st, err := tx.PrepareContext(ctx, s.q(`INSERT INTO control_results (scan_row_id, agent_id, control_id, status, maturity, mandatory)
				VALUES (?, ?, ?, ?, ?, ?)`))
			if err != nil {
				return err
			}
			defer st.Close()
			for _, c := range in.Controls {
				if _, err := st.ExecContext(ctx, sc.ID, c.AgentID, c.ControlID, c.Status, c.Maturity, boolInt(c.Mandatory)); err != nil {
					return err
				}
			}
		}
		if err := s.appendAuditTx(ctx, tx, in.Audit); err != nil {
			return err
		}
		out = sc
		created = true
		return nil
	})
	if errors.Is(err, ErrConflict) {
		// A concurrent identical upload won the race (possible on
		// PostgreSQL). Return the row it created.
		existing, gerr := scanScan(s.db.QueryRowContext(ctx, s.q(`SELECT `+scanCols+` FROM scans
			WHERE project_id = ? AND payload_sha256 = ?`), in.Scan.ProjectID, in.Scan.PayloadSHA256))
		if gerr == nil {
			return existing, false, nil
		}
	}
	return out, created, err
}

// GetScan returns the metadata of one scan.
func (s *SQLStore) GetScan(ctx context.Context, id string) (Scan, error) {
	return scanScan(s.db.QueryRowContext(ctx, s.q(`SELECT `+scanCols+` FROM scans WHERE id = ?`), id))
}

// GetScanPayload returns the stored ScanResult JSON.
func (s *SQLStore) GetScanPayload(ctx context.Context, id string) ([]byte, error) {
	var p string
	if err := s.db.QueryRowContext(ctx, s.q(`SELECT payload FROM scans WHERE id = ?`), id).Scan(&p); err != nil {
		return nil, noRows(err)
	}
	return []byte(p), nil
}

// ListScans returns the most recent scans of a project.
func (s *SQLStore) ListScans(ctx context.Context, projectID string, limit int) ([]Scan, error) {
	if limit <= 0 || limit > 500 {
		limit = 100
	}
	rows, err := s.db.QueryContext(ctx, s.q(`SELECT `+scanCols+` FROM scans WHERE project_id = ?
		ORDER BY received_at DESC, id DESC LIMIT ?`), projectID, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []Scan{}
	for rows.Next() {
		sc, err := scanScan(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, sc)
	}
	return out, rows.Err()
}

const agentCols = `agent_key, project_id, agent_id, name, framework, language, owner, risk_tier,
	last_scan_id, last_decision, last_score, first_seen, last_seen`

func scanAgent(row interface{ Scan(...any) error }) (Agent, error) {
	var a Agent
	var score sql.NullInt64
	var first, last int64
	if err := row.Scan(&a.Key, &a.ProjectID, &a.AgentID, &a.Name, &a.Framework, &a.Language, &a.Owner, &a.RiskTier,
		&a.LastScanID, &a.LastDecision, &score, &first, &last); err != nil {
		return Agent{}, noRows(err)
	}
	a.LastScore = intPtr(score)
	a.FirstSeen, a.LastSeen = fromUS(first), fromUS(last)
	return a, nil
}

// ListAgents returns the agents of a project ordered by agent ID.
func (s *SQLStore) ListAgents(ctx context.Context, projectID string) ([]Agent, error) {
	rows, err := s.db.QueryContext(ctx, s.q(`SELECT `+agentCols+` FROM agents WHERE project_id = ? ORDER BY agent_id`), projectID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []Agent{}
	for rows.Next() {
		a, err := scanAgent(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, a)
	}
	return out, rows.Err()
}

// GetAgent returns one agent by its opaque key.
func (s *SQLStore) GetAgent(ctx context.Context, key string) (Agent, error) {
	return scanAgent(s.db.QueryRowContext(ctx, s.q(`SELECT `+agentCols+` FROM agents WHERE agent_key = ?`), key))
}

// ListAgentScans returns the scan history of one agent, newest first.
func (s *SQLStore) ListAgentScans(ctx context.Context, projectID, agentID string, limit int) ([]AgentScan, error) {
	if limit <= 0 || limit > 500 {
		limit = 100
	}
	rows, err := s.db.QueryContext(ctx, s.q(`SELECT sc.id, sc.scan_id, sc.received_at, sc.commit_sha, sc.profile, sc.policy_pack,
		sc.policy_version, sc.tool_version, sa.decision, sa.score, sa.score_label
		FROM scan_agents sa JOIN scans sc ON sc.id = sa.scan_row_id
		WHERE sc.project_id = ? AND sa.agent_id = ?
		ORDER BY sc.received_at DESC, sc.id DESC LIMIT ?`), projectID, agentID, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []AgentScan{}
	for rows.Next() {
		var a AgentScan
		var recv int64
		var score sql.NullInt64
		if err := rows.Scan(&a.ScanRowID, &a.ScanID, &recv, &a.CommitSHA, &a.Profile, &a.PolicyPack, &a.PolicyVersion,
			&a.ToolVersion, &a.Decision, &score, &a.ScoreLabel); err != nil {
			return nil, err
		}
		a.ReceivedAt = fromUS(recv)
		a.Score = intPtr(score)
		out = append(out, a)
	}
	return out, rows.Err()
}

// ProjectOverview returns the dashboard summary of one project.
func (s *SQLStore) ProjectOverview(ctx context.Context, projectID string) (Overview, error) {
	ov := Overview{ProjectID: projectID, Decisions: map[string]int{}}
	rows, err := s.db.QueryContext(ctx, s.q(`SELECT last_decision, COUNT(*) FROM agents WHERE project_id = ? GROUP BY last_decision`), projectID)
	if err != nil {
		return ov, err
	}
	for rows.Next() {
		var d string
		var n int
		if err := rows.Scan(&d, &n); err != nil {
			rows.Close()
			return ov, err
		}
		ov.Decisions[d] = n
		ov.AgentCount += n
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return ov, err
	}
	if err := s.db.QueryRowContext(ctx, s.q(`SELECT COUNT(*) FROM scans WHERE project_id = ?`), projectID).Scan(&ov.ScanCount); err != nil {
		return ov, err
	}
	var recv int64
	err = s.db.QueryRowContext(ctx, s.q(`SELECT id, decision, received_at FROM scans WHERE project_id = ?
		ORDER BY received_at DESC, id DESC LIMIT 1`), projectID).Scan(&ov.LatestScanID, &ov.LatestDecision, &recv)
	if errors.Is(err, sql.ErrNoRows) {
		return ov, nil
	}
	if err != nil {
		return ov, err
	}
	t := fromUS(recv)
	ov.LatestScanAt = &t
	frows, err := s.db.QueryContext(ctx, s.q(`SELECT severity, COUNT(*) FROM findings WHERE scan_row_id = ? GROUP BY severity`), ov.LatestScanID)
	if err != nil {
		return ov, err
	}
	defer frows.Close()
	for frows.Next() {
		var sev string
		var n int
		if err := frows.Scan(&sev, &n); err != nil {
			return ov, err
		}
		switch sev {
		case "critical":
			ov.OpenCritical = n
		case "high":
			ov.OpenHigh = n
		}
	}
	return ov, frows.Err()
}

// ---------------------------------------------------------------------------
// Retention and export
// ---------------------------------------------------------------------------

// PruneScans deletes old scans of one project. Index rows go with them
// through ON DELETE CASCADE.
func (s *SQLStore) PruneScans(ctx context.Context, projectID string, olderThan time.Time, ev *AuditEvent) (int64, error) {
	var n int64
	err := s.inTx(ctx, func(tx *sql.Tx) error {
		var latest string
		err := tx.QueryRowContext(ctx, s.q(`SELECT id FROM scans WHERE project_id = ? ORDER BY received_at DESC, id DESC LIMIT 1`), projectID).Scan(&latest)
		if errors.Is(err, sql.ErrNoRows) {
			return nil
		}
		if err != nil {
			return err
		}
		res, err := tx.ExecContext(ctx, s.q(`DELETE FROM scans WHERE project_id = ? AND received_at < ? AND id <> ?
			AND id NOT IN (SELECT last_scan_id FROM agents WHERE project_id = ?)`), projectID, us(olderThan), latest, projectID)
		if err != nil {
			return err
		}
		n, _ = res.RowsAffected()
		if n == 0 {
			return nil
		}
		if ev != nil {
			e := *ev
			e.Detail = fmt.Sprintf(`{"deleted_scans":%d}`, n)
			return s.appendAuditTx(ctx, tx, &e)
		}
		return nil
	})
	return n, err
}

// ExportProject writes one project as a JSON document: the project, its
// members, token metadata (never hashes), agents, scans with their stored
// ScanResult, and the project's audit events. Scans are streamed one at a
// time so memory stays bounded.
func (s *SQLStore) ExportProject(ctx context.Context, projectID string, w io.Writer) error {
	p, err := s.GetProject(ctx, projectID)
	if err != nil {
		return err
	}
	members, err := s.ListMembers(ctx, projectID)
	if err != nil {
		return err
	}
	tokens, err := s.ListTokens(ctx, projectID)
	if err != nil {
		return err
	}
	agents, err := s.ListAgents(ctx, projectID)
	if err != nil {
		return err
	}
	head := map[string]any{
		"format": "agentgov-project-export/1", "exported_at": time.Now().UTC(),
		"project": p, "members": members, "tokens": tokens, "agents": agents,
	}
	hb, err := json.Marshal(head)
	if err != nil {
		return err
	}
	// Reopen the head object to append the streamed arrays.
	if _, err := w.Write(hb[:len(hb)-1]); err != nil {
		return err
	}
	if _, err := io.WriteString(w, `,"scans":[`); err != nil {
		return err
	}
	rows, err := s.db.QueryContext(ctx, s.q(`SELECT `+scanCols+`, payload FROM scans WHERE project_id = ? ORDER BY received_at, id`), projectID)
	if err != nil {
		return err
	}
	defer rows.Close()
	first := true
	for rows.Next() {
		var sc Scan
		var score sql.NullInt64
		var recv int64
		var payload string
		if err := rows.Scan(&sc.ID, &sc.ProjectID, &sc.ScanID, &sc.Target, &sc.CommitSHA, &sc.Profile, &sc.PolicyPack, &sc.PolicyVersion,
			&sc.ToolVersion, &sc.Decision, &score, &sc.ScoreLabel, &recv, &sc.UploadedByToken, &sc.PayloadBytes, &sc.PayloadSHA256, &payload); err != nil {
			return err
		}
		sc.Score = intPtr(score)
		sc.ReceivedAt = fromUS(recv)
		item, err := json.Marshal(struct {
			Scan   Scan            `json:"scan"`
			Result json.RawMessage `json:"result"`
		}{sc, json.RawMessage(payload)})
		if err != nil {
			return err
		}
		if !first {
			if _, err := io.WriteString(w, ","); err != nil {
				return err
			}
		}
		first = false
		if _, err := w.Write(item); err != nil {
			return err
		}
	}
	if err := rows.Err(); err != nil {
		return err
	}
	rows.Close()
	if _, err := io.WriteString(w, `],"audit_events":[`); err != nil {
		return err
	}
	var before int64
	first = true
	for {
		evs, err := s.ListAudit(ctx, AuditFilter{ProjectID: projectID, BeforeSeq: before, Limit: 1000})
		if err != nil {
			return err
		}
		for _, e := range evs {
			item, err := json.Marshal(struct {
				AuditEvent
				Detail json.RawMessage `json:"detail"`
			}{e, json.RawMessage(e.Detail)})
			if err != nil {
				return err
			}
			if !first {
				if _, err := io.WriteString(w, ","); err != nil {
					return err
				}
			}
			first = false
			if _, err := w.Write(item); err != nil {
				return err
			}
			before = e.Seq
		}
		if len(evs) < 1000 {
			break
		}
	}
	_, err = io.WriteString(w, "]}\n")
	return err
}
