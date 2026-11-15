// SPDX-License-Identifier: Apache-2.0

package storage

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

func openTemp(t *testing.T) (*SQLStore, string) {
	t.Helper()
	path := filepath.Join(t.TempDir(), "data dir", "agentgov.db")
	s, err := Open(context.Background(), path)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	t.Cleanup(func() { s.Close() })
	return s, path
}

func seedProject(t *testing.T, s *SQLStore, id string) {
	t.Helper()
	ctx := context.Background()
	if _, err := s.GetUserByID(ctx, "usr_1"); errors.Is(err, ErrNotFound) {
		if err := s.CreateUser(ctx, User{ID: "usr_1", Username: "admin", PasswordHash: "x", Role: RoleAdministrator, CreatedAt: time.Now()}, nil); err != nil {
			t.Fatal(err)
		}
	}
	if err := s.CreateProject(ctx, Project{ID: id, Slug: id, Name: "Project " + id, CreatedBy: "usr_1", CreatedAt: time.Now()}, nil); err != nil {
		t.Fatal(err)
	}
}

func ingest(t *testing.T, s *SQLStore, project, rowID, sha string, at time.Time, agents ...string) (Scan, bool) {
	t.Helper()
	score := 70
	in := IngestInput{
		Scan: Scan{ID: rowID, ProjectID: project, ScanID: "scan-" + sha, CommitSHA: "abc", Profile: "standard", PolicyPack: "builtin/v1",
			PolicyVersion: "1.0", ToolVersion: "0.1.0", Decision: "BLOCK", Score: &score, ScoreLabel: "70/100", ReceivedAt: at,
			UploadedByToken: "tok_1", PayloadSHA256: sha},
		Payload:  []byte(`{"schema_version":"1","n":"` + sha + `"}`),
		Findings: []IngestFinding{{FindingID: "f1", Fingerprint: "fp1", ControlID: "AGC-008", AgentID: "*", Severity: "critical", Title: "t"}, {FindingID: "f2", Fingerprint: "fp2", ControlID: "AGC-001", AgentID: "*", Severity: "high", Title: "t"}},
		Audit:    &AuditEvent{ActorType: ActorToken, ActorID: "tok_1", Action: "scan.ingested", Target: "scan:" + rowID, ProjectID: project},
	}
	for _, a := range agents {
		in.Agents = append(in.Agents, IngestAgent{NewKey: "agk_" + project + "_" + a + "_" + rowID, AgentID: a, Name: a, Decision: "BLOCK", Score: &score, ScoreLabel: "70/100"})
		in.Controls = append(in.Controls, IngestControl{AgentID: a, ControlID: "AGC-001", Status: "failed", Maturity: 0, Mandatory: true})
	}
	sc, created, err := s.IngestScan(context.Background(), in)
	if err != nil {
		t.Fatalf("ingest: %v", err)
	}
	return sc, created
}

func TestParseDatabaseURL(t *testing.T) {
	cases := []struct{ in, dialect, dsn string }{
		{"sqlite:///var/lib/agentgov/agentgov.db", DialectSQLite, "/var/lib/agentgov/agentgov.db"},
		{"sqlite:///C:/data/agentgov.db", DialectSQLite, "C:/data/agentgov.db"},
		{"sqlite://rel/a.db", DialectSQLite, "rel/a.db"},
		{`C:\data\a.db`, DialectSQLite, `C:\data\a.db`},
		{"./a.db", DialectSQLite, "./a.db"},
		{"postgres://u@h/db", DialectPostgres, "postgres://u@h/db"},
		{"postgresql://u@h/db", DialectPostgres, "postgresql://u@h/db"},
	}
	for _, c := range cases {
		d, dsn, err := ParseDatabaseURL(c.in)
		if err != nil || d != c.dialect || dsn != c.dsn {
			t.Errorf("%q: got %q %q %v", c.in, d, dsn, err)
		}
	}
	for _, bad := range []string{"", "mysql://x/y", "sqlite://"} {
		if _, _, err := ParseDatabaseURL(bad); err == nil {
			t.Errorf("%q: expected error", bad)
		}
	}
}

func TestMigrationsIdempotentAndReopen(t *testing.T) {
	s, path := openTemp(t)
	ctx := context.Background()
	seedProject(t, s, "prj_a")
	applied, known, err := s.MigrationStatus(ctx)
	if err != nil || applied != known || applied < 1 {
		t.Fatalf("status: %d %d %v", applied, known, err)
	}
	if err := s.migrate(ctx); err != nil {
		t.Fatalf("second migrate: %v", err)
	}
	s.Close()
	s2, err := Open(ctx, "sqlite:///"+filepath.ToSlash(path))
	if err != nil {
		t.Fatalf("reopen: %v", err)
	}
	defer s2.Close()
	if _, err := s2.GetProject(ctx, "prj_a"); err != nil {
		t.Fatalf("data lost after reopen: %v", err)
	}
	var n int
	if err := s2.db.QueryRow(`SELECT COUNT(*) FROM schema_migrations`).Scan(&n); err != nil || n != known {
		t.Fatalf("schema_migrations rows = %d, want %d (%v)", n, known, err)
	}
}

func TestRefusesNewerSchema(t *testing.T) {
	s, path := openTemp(t)
	if _, err := s.db.Exec(`INSERT INTO schema_migrations (version, name, applied_at) VALUES (9999, 'future', 0)`); err != nil {
		t.Fatal(err)
	}
	s.Close()
	_, err := Open(context.Background(), path)
	if !errors.Is(err, ErrSchemaTooNew) {
		t.Fatalf("want ErrSchemaTooNew, got %v", err)
	}
}

func TestSQLitePragmas(t *testing.T) {
	s, _ := openTemp(t)
	var mode string
	var fk, busy int
	if err := s.db.QueryRow(`PRAGMA journal_mode`).Scan(&mode); err != nil || !strings.EqualFold(mode, "wal") {
		t.Fatalf("journal_mode = %q %v", mode, err)
	}
	if err := s.db.QueryRow(`PRAGMA foreign_keys`).Scan(&fk); err != nil || fk != 1 {
		t.Fatalf("foreign_keys = %d %v", fk, err)
	}
	if err := s.db.QueryRow(`PRAGMA busy_timeout`).Scan(&busy); err != nil || busy <= 0 {
		t.Fatalf("busy_timeout = %d %v", busy, err)
	}
	// Foreign keys are enforced: a session for a missing user is rejected.
	err := s.CreateSession(context.Background(), Session{IDHash: "h", UserID: "missing", CSRFToken: "c", CreatedAt: time.Now(), ExpiresAt: time.Now(), LastSeen: time.Now()}, nil)
	if err == nil {
		t.Fatal("expected a foreign key error")
	}
}

func TestRebind(t *testing.T) {
	pg := &SQLStore{dialect: DialectPostgres}
	if got := pg.q(`a = ? AND b = ? LIMIT ?`); got != `a = $1 AND b = $2 LIMIT $3` {
		t.Fatalf("rebind: %q", got)
	}
	lite := &SQLStore{dialect: DialectSQLite}
	if got := lite.q(`a = ?`); got != `a = ?` {
		t.Fatalf("rebind: %q", got)
	}
}

func TestAuditChainDetectsTampering(t *testing.T) {
	s, _ := openTemp(t)
	ctx := context.Background()
	for i := 0; i < 5; i++ {
		if err := s.AppendAudit(ctx, AuditEvent{ActorType: ActorSystem, ActorID: "system", Action: "test.event", Target: fmt.Sprintf("t%d", i), Detail: `{"i":1}`}); err != nil {
			t.Fatal(err)
		}
	}
	if n, err := s.VerifyAuditChain(ctx); err != nil || n != 5 {
		t.Fatalf("clean chain: n=%d err=%v", n, err)
	}
	evs, err := s.ListAudit(ctx, AuditFilter{})
	if err != nil || len(evs) != 5 || evs[0].Seq != 5 || evs[4].PrevHash != "" {
		t.Fatalf("list: %v %+v", err, evs)
	}

	// Edit a field of one row.
	if _, err := s.db.Exec(`UPDATE audit_events SET target = 'forged' WHERE seq = 3`); err != nil {
		t.Fatal(err)
	}
	if _, err := s.VerifyAuditChain(ctx); err == nil || !strings.Contains(err.Error(), "event 3") {
		t.Fatalf("edited row not detected: %v", err)
	}
	if _, err := s.db.Exec(`UPDATE audit_events SET target = 't2' WHERE seq = 3`); err != nil {
		t.Fatal(err)
	}
	if _, err := s.VerifyAuditChain(ctx); err != nil {
		t.Fatalf("restored chain should verify: %v", err)
	}

	// Edit a row and recompute only its own hash: the next link breaks.
	var e AuditEvent
	var at int64
	if err := s.db.QueryRow(`SELECT seq, occurred_at, actor_type, actor_id, action, target, project_id, detail, prev_hash FROM audit_events WHERE seq = 2`).
		Scan(&e.Seq, &at, &e.ActorType, &e.ActorID, &e.Action, &e.Target, &e.ProjectID, &e.Detail, &e.PrevHash); err != nil {
		t.Fatal(err)
	}
	e.At = time.UnixMicro(at)
	e.Action = "forged.action"
	if _, err := s.db.Exec(`UPDATE audit_events SET action = ?, hash = ? WHERE seq = 2`, e.Action, auditHash(e.PrevHash, e)); err != nil {
		t.Fatal(err)
	}
	if _, err := s.VerifyAuditChain(ctx); err == nil || !strings.Contains(err.Error(), "event 3") {
		t.Fatalf("rehashed row not detected at the next link: %v", err)
	}

	// Delete a row from the middle.
	s2, _ := openTemp(t)
	for i := 0; i < 3; i++ {
		_ = s2.AppendAudit(ctx, AuditEvent{ActorType: ActorSystem, ActorID: "system", Action: "a"})
	}
	if _, err := s2.db.Exec(`DELETE FROM audit_events WHERE seq = 2`); err != nil {
		t.Fatal(err)
	}
	if _, err := s2.VerifyAuditChain(ctx); err == nil {
		t.Fatal("deleted row not detected")
	}
}

func TestIngestIdempotentAgentsAndOverview(t *testing.T) {
	s, _ := openTemp(t)
	ctx := context.Background()
	seedProject(t, s, "prj_a")
	seedProject(t, s, "prj_b")
	t0 := time.Now().Add(-time.Hour)

	sc1, created := ingest(t, s, "prj_a", "scn_1", "sha1", t0, "agent-a", "agent-b")
	if !created {
		t.Fatal("first ingest should create")
	}
	again, created := ingest(t, s, "prj_a", "scn_other", "sha1", t0.Add(time.Minute), "agent-a")
	if created || again.ID != sc1.ID {
		t.Fatalf("re-upload must return the existing row: %v %s", created, again.ID)
	}
	// The same payload hash in another project is a separate scan.
	if _, created := ingest(t, s, "prj_b", "scn_b1", "sha1", t0, "agent-a"); !created {
		t.Fatal("same hash in another project must create")
	}
	ingest(t, s, "prj_a", "scn_2", "sha2", t0.Add(2*time.Minute), "agent-a")

	agents, err := s.ListAgents(ctx, "prj_a")
	if err != nil || len(agents) != 2 {
		t.Fatalf("agents: %v %+v", err, agents)
	}
	if agents[0].AgentID != "agent-a" || agents[0].LastScanID != "scn_2" || agents[1].LastScanID != "scn_1" {
		t.Fatalf("last scan tracking wrong: %+v", agents)
	}
	// The key assigned at first sight is stable across later scans.
	if !strings.HasSuffix(agents[0].Key, "scn_1") {
		t.Fatalf("agent key changed on a later scan: %s", agents[0].Key)
	}
	got, err := s.GetAgent(ctx, agents[0].Key)
	if err != nil || got.ProjectID != "prj_a" {
		t.Fatalf("get agent: %v", err)
	}
	hist, err := s.ListAgentScans(ctx, "prj_a", "agent-a", 0)
	if err != nil || len(hist) != 2 || hist[0].ScanRowID != "scn_2" {
		t.Fatalf("history: %v %+v", err, hist)
	}
	ov, err := s.ProjectOverview(ctx, "prj_a")
	if err != nil || ov.AgentCount != 2 || ov.ScanCount != 2 || ov.OpenCritical != 1 || ov.OpenHigh != 1 || ov.LatestScanID != "scn_2" || ov.Decisions["BLOCK"] != 2 {
		t.Fatalf("overview: %v %+v", err, ov)
	}
	payload, err := s.GetScanPayload(ctx, "scn_1")
	if err != nil || !json.Valid(payload) {
		t.Fatalf("payload: %v", err)
	}
	if n, err := s.VerifyAuditChain(ctx); err != nil || n != 3 {
		t.Fatalf("audit after ingest: %d %v", n, err)
	}
}

func TestPruneKeepsLatestPerAgent(t *testing.T) {
	s, _ := openTemp(t)
	ctx := context.Background()
	seedProject(t, s, "prj_a")
	now := time.Now()
	ingest(t, s, "prj_a", "scn_old_b", "s1", now.Add(-100*24*time.Hour), "agent-b") // latest for agent-b: kept
	ingest(t, s, "prj_a", "scn_old_a", "s2", now.Add(-90*24*time.Hour), "agent-a")  // superseded: deleted
	ingest(t, s, "prj_a", "scn_mid_a", "s3", now.Add(-60*24*time.Hour), "agent-a")  // latest for agent-a and project: kept
	n, err := s.PruneScans(ctx, "prj_a", now.Add(-30*24*time.Hour), &AuditEvent{ActorType: ActorSystem, ActorID: "system", Action: "retention.pruned", ProjectID: "prj_a"})
	if err != nil || n != 1 {
		t.Fatalf("prune: n=%d err=%v", n, err)
	}
	if _, err := s.GetScan(ctx, "scn_old_a"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("old scan should be gone: %v", err)
	}
	for _, id := range []string{"scn_old_b", "scn_mid_a"} {
		if _, err := s.GetScan(ctx, id); err != nil {
			t.Fatalf("%s should be kept: %v", id, err)
		}
	}
	var left int
	if err := s.db.QueryRow(`SELECT COUNT(*) FROM findings WHERE scan_row_id = 'scn_old_a'`).Scan(&left); err != nil || left != 0 {
		t.Fatalf("cascade delete left %d findings (%v)", left, err)
	}
}

func TestExportProjectAndBackup(t *testing.T) {
	s, path := openTemp(t)
	ctx := context.Background()
	seedProject(t, s, "prj_a")
	seedProject(t, s, "prj_b")
	ingest(t, s, "prj_a", "scn_1", "s1", time.Now(), "agent-a")
	ingest(t, s, "prj_b", "scn_b", "s9", time.Now(), "agent-z")
	exp := time.Now().Add(time.Hour)
	if err := s.CreateToken(ctx, APIToken{ID: "tok_1", ProjectID: "prj_a", Name: "ci", TokenHash: "secret-hash-value", Prefix: "abcd1234", Scopes: []string{"scans:write"}, CreatedBy: "usr_1", CreatedAt: time.Now(), ExpiresAt: &exp}, nil); err != nil {
		t.Fatal(err)
	}
	var buf bytes.Buffer
	if err := s.ExportProject(ctx, "prj_a", &buf); err != nil {
		t.Fatal(err)
	}
	var doc struct {
		Format  string `json:"format"`
		Project Project
		Tokens  []map[string]any
		Agents  []Agent
		Scans   []struct {
			Scan   Scan
			Result map[string]any
		}
		AuditEvents []map[string]any `json:"audit_events"`
	}
	if err := json.Unmarshal(buf.Bytes(), &doc); err != nil {
		t.Fatalf("export is not valid JSON: %v\n%s", err, buf.String())
	}
	if doc.Project.ID != "prj_a" || len(doc.Scans) != 1 || doc.Scans[0].Result["schema_version"] != "1" || len(doc.Agents) != 1 || len(doc.AuditEvents) != 1 || len(doc.Tokens) != 1 {
		t.Fatalf("export content: %+v", doc)
	}
	if strings.Contains(buf.String(), "secret-hash-value") || strings.Contains(buf.String(), "agent-z") {
		t.Fatal("export leaked a token hash or another project's data")
	}
	if err := s.ExportProject(ctx, "prj_missing", &buf); !errors.Is(err, ErrNotFound) {
		t.Fatalf("missing project: %v", err)
	}

	dest := filepath.Join(filepath.Dir(path), "backup.db")
	if err := s.Backup(ctx, dest); err != nil {
		t.Fatalf("backup: %v", err)
	}
	restored, err := Open(ctx, dest)
	if err != nil {
		t.Fatalf("open backup: %v", err)
	}
	defer restored.Close()
	if _, err := restored.GetScan(ctx, "scn_1"); err != nil {
		t.Fatalf("backup misses data: %v", err)
	}
	if _, err := restored.VerifyAuditChain(ctx); err != nil {
		t.Fatalf("backup audit chain: %v", err)
	}
	if err := s.Backup(ctx, dest); err == nil {
		t.Fatal("backup must refuse to overwrite")
	}
}

func TestProjectsMembersTokensAndInertMetacharacters(t *testing.T) {
	s, _ := openTemp(t)
	ctx := context.Background()
	seedProject(t, s, "prj_a")
	evil := `Robert'); DROP TABLE projects;-- "x" \ %_`
	if err := s.CreateProject(ctx, Project{ID: "prj_evil", Slug: "evil", Name: evil, CreatedBy: "usr_1", CreatedAt: time.Now()}, nil); err != nil {
		t.Fatal(err)
	}
	p, err := s.GetProject(ctx, "prj_evil")
	if err != nil || p.Name != evil {
		t.Fatalf("metacharacters must round-trip unchanged: %q %v", p.Name, err)
	}
	if _, err := s.GetProject(ctx, `prj_a' OR '1'='1`); !errors.Is(err, ErrNotFound) {
		t.Fatalf("injection in id must not match: %v", err)
	}
	if err := s.CreateProject(ctx, Project{ID: "prj_dup", Slug: "evil", Name: "x", CreatedBy: "usr_1", CreatedAt: time.Now()}, nil); !errors.Is(err, ErrConflict) {
		t.Fatalf("duplicate slug: %v", err)
	}
	if err := s.CreateUser(ctx, User{ID: "usr_2", Username: "admin", PasswordHash: "x", Role: RoleUser, CreatedAt: time.Now()}, nil); !errors.Is(err, ErrConflict) {
		t.Fatalf("duplicate user: %v", err)
	}
	if err := s.CreateFirstUser(ctx, User{ID: "usr_3", Username: "second", PasswordHash: "x", Role: RoleAdministrator, CreatedAt: time.Now()}, "", "", nil, nil); !errors.Is(err, ErrConflict) {
		t.Fatalf("first user when users exist: %v", err)
	}

	if err := s.SetMember(ctx, Member{ProjectID: "prj_a", UserID: "usr_1", Role: ProjectViewer}, nil); err != nil {
		t.Fatal(err)
	}
	if err := s.SetMember(ctx, Member{ProjectID: "prj_a", UserID: "usr_1", Role: ProjectOwner}, nil); err != nil {
		t.Fatal(err)
	}
	if role, err := s.MemberRole(ctx, "prj_a", "usr_1"); err != nil || role != ProjectOwner {
		t.Fatalf("role: %q %v", role, err)
	}
	if _, err := s.MemberRole(ctx, "prj_evil", "usr_1"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("non-member: %v", err)
	}
	mine, err := s.ListProjectsForUser(ctx, "usr_1")
	if err != nil || len(mine) != 1 || mine[0].Role != ProjectOwner {
		t.Fatalf("projects for user: %v %+v", err, mine)
	}

	if err := s.CreateToken(ctx, APIToken{ID: "tok_1", ProjectID: "prj_a", Name: "ci", TokenHash: "h1", Prefix: "p", Scopes: []string{"scans:write"}, CreatedBy: "usr_1", CreatedAt: time.Now()}, nil); err != nil {
		t.Fatal(err)
	}
	// Revoking through the wrong project is "not found".
	if err := s.RevokeToken(ctx, "prj_evil", "tok_1", time.Now(), nil); !errors.Is(err, ErrNotFound) {
		t.Fatalf("cross-project revoke: %v", err)
	}
	if err := s.RevokeToken(ctx, "prj_a", "tok_1", time.Now(), nil); err != nil {
		t.Fatal(err)
	}
	tok, err := s.GetTokenByHash(ctx, "h1")
	if err != nil || tok.RevokedAt == nil || len(tok.Scopes) != 1 {
		t.Fatalf("token: %+v %v", tok, err)
	}

	ingest(t, s, "prj_a", "scn_1", "s1", time.Now(), "agent-a")
	if err := s.DeleteProject(ctx, "prj_a", nil); err != nil {
		t.Fatal(err)
	}
	for _, table := range []string{"scans", "agents", "findings", "control_results", "scan_agents", "api_tokens", "project_members"} {
		var n int
		// Table names come from the fixed list above, not from input.
		if err := s.db.QueryRow(`SELECT COUNT(*) FROM ` + table).Scan(&n); err != nil || n != 0 {
			t.Fatalf("%s has %d rows after project deletion (%v)", table, n, err)
		}
	}
}

func TestSessionsAndSettings(t *testing.T) {
	s, _ := openTemp(t)
	ctx := context.Background()
	seedProject(t, s, "prj_a")
	now := time.Now()
	mk := func(id string, exp, seen time.Time) {
		if err := s.CreateSession(ctx, Session{IDHash: id, UserID: "usr_1", CSRFToken: "c", CreatedAt: now, ExpiresAt: exp, LastSeen: seen}, nil); err != nil {
			t.Fatal(err)
		}
	}
	mk("live", now.Add(time.Hour), now)
	mk("expired", now.Add(-time.Minute), now)
	mk("idle", now.Add(time.Hour), now.Add(-3*time.Hour))
	n, err := s.DeleteExpiredSessions(ctx, now, now.Add(-2*time.Hour))
	if err != nil || n != 2 {
		t.Fatalf("expired sessions: %d %v", n, err)
	}
	if err := s.TouchSession(ctx, "live", now.Add(time.Minute)); err != nil {
		t.Fatal(err)
	}
	se, err := s.GetSession(ctx, "live")
	if err != nil || !se.LastSeen.After(now.Add(30*time.Second)) {
		t.Fatalf("touch: %+v %v", se, err)
	}
	if err := s.SetSettings(ctx, map[string]string{"k": "v1"}, nil); err != nil {
		t.Fatal(err)
	}
	if err := s.SetSettings(ctx, map[string]string{"k": "v2"}, nil); err != nil {
		t.Fatal(err)
	}
	if v, ok, err := s.GetSetting(ctx, "k"); err != nil || !ok || v != "v2" {
		t.Fatalf("setting: %q %v %v", v, ok, err)
	}
	if _, ok, _ := s.GetSetting(ctx, "absent"); ok {
		t.Fatal("absent setting reported present")
	}
}

func TestConcurrentWrites(t *testing.T) {
	s, _ := openTemp(t)
	ctx := context.Background()
	seedProject(t, s, "prj_a")
	var wg sync.WaitGroup
	errs := make(chan error, 40)
	for i := 0; i < 20; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			score := i
			_, _, err := s.IngestScan(ctx, IngestInput{
				Scan: Scan{ID: fmt.Sprintf("scn_%d", i), ProjectID: "prj_a", ScanID: "x", Decision: "ALLOW", Score: &score, ReceivedAt: time.Now(),
					UploadedByToken: "tok", PayloadSHA256: fmt.Sprintf("sha-%d", i%10)},
				Payload: []byte(`{}`),
				Agents:  []IngestAgent{{NewKey: fmt.Sprintf("agk_%d", i), AgentID: "agent-a", Decision: "ALLOW"}},
				Audit:   &AuditEvent{ActorType: ActorToken, ActorID: "tok", Action: "scan.ingested", ProjectID: "prj_a"},
			})
			if err != nil {
				errs <- err
			}
		}(i)
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		t.Fatalf("concurrent ingest: %v", err)
	}
	scans, err := s.ListScans(ctx, "prj_a", 0)
	if err != nil || len(scans) != 10 {
		t.Fatalf("want 10 distinct scans, got %d (%v)", len(scans), err)
	}
	agents, _ := s.ListAgents(ctx, "prj_a")
	if len(agents) != 1 {
		t.Fatalf("want one agent row, got %d", len(agents))
	}
	if n, err := s.VerifyAuditChain(ctx); err != nil || n != 10 {
		t.Fatalf("audit chain after concurrent writes: %d %v", n, err)
	}
}
