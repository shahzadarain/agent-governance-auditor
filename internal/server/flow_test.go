// SPDX-License-Identifier: Apache-2.0

package server

import (
	"context"
	"encoding/json"
	"net/http"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/shahzadarain/agent-governance-auditor/internal/model"
	"github.com/shahzadarain/agent-governance-auditor/internal/storage"
)

// TestFullFlow walks the whole happy path: bootstrap, setup, login, project,
// token, two uploads, every read endpoint, comparison, and the audit chain.
func TestFullFlow(t *testing.T) {
	e := newEnv(t, nil)

	// Before setup: no data is reachable and the version endpoint says so.
	wantError(t, e.anon().do("GET", "/api/v1/projects", nil), http.StatusUnauthorized, "unauthenticated")
	if v := decode[versionResponse](t, e.anon().do("GET", "/api/v1/version", nil)); !v.SetupRequired || v.Version != "test-1.2.3" || v.SchemaVersion != "1" {
		t.Fatalf("version before setup: %+v", v)
	}

	admin := e.setup()
	sess := decode[sessionResponse](t, admin.do("GET", "/api/v1/session", nil))
	if sess.User.Username != adminUsername || sess.User.Role != storage.RoleAdministrator || sess.CSRFToken == "" {
		t.Fatalf("session: %+v", sess)
	}
	if v := decode[versionResponse](t, e.anon().do("GET", "/api/v1/version", nil)); v.SetupRequired {
		t.Fatal("setup_required must be false after setup")
	}

	proj := e.createProject(admin, "payments")
	tok := e.createToken(admin, proj.ID)
	if !strings.HasPrefix(tok.Token, "agt_"+tok.Record.Prefix+"_") || len(tok.Record.Scopes) != 1 || tok.Record.Scopes[0] != ScopeScansWrite {
		t.Fatalf("token format: %q %+v", tok.Token, tok.Record)
	}

	// The CLI can verify its token.
	tc := e.anon()
	tc.bearer = tok.Token
	if v := decode[versionResponse](t, tc.do("GET", "/api/v1/version", nil)); v.Token == nil || v.Token.ProjectID != proj.ID {
		t.Fatalf("version with token: %+v", v)
	}

	first := sampleScan(e.clock.Now(), "1111111")
	up1 := e.mustUpload(tok.Token, first)
	if !up1.Created || up1.ProjectID != proj.ID || up1.ScanID != "scan-1111111" || !strings.HasPrefix(up1.ID, "scn_") {
		t.Fatalf("upload 1: %+v", up1)
	}

	e.clock.Advance(10 * time.Minute)
	second := sampleScan(e.clock.Now(), "2222222")
	second.Findings = second.Findings[1:] // the critical finding is resolved
	second.Findings = append(second.Findings, model.Finding{FindingID: "F-new", Fingerprint: "fp-new", RuleID: "r", ControlID: "AGC-010",
		AgentID: "support-bot", Severity: model.SeverityHigh, Confidence: model.ConfidenceMedium, Title: "New issue", Remediation: []string{}, EvidenceRefs: []string{}, Mappings: []model.Mapping{}})
	second.Assessments[0].Controls[5].Status = model.StatusVerifiedTested // AGC-006: failed -> verified-tested
	second.Assessments[0].Controls[5].Maturity = 3
	second.Assessments[0].Decision = model.Decision{Outcome: model.OutcomeAllow, Reasons: []model.Reason{}}
	second.Assessments[0].Score.Value = intp(77)
	second.Assessments[0].Score.Label = "77/100"
	second.Decision = model.Decision{Outcome: model.OutcomeReviewRequired, Reasons: []model.Reason{}}
	up2 := e.mustUpload(tok.Token, second)

	// Projects.
	projects := decode[listBody[storage.Project]](t, admin.do("GET", "/api/v1/projects", nil))
	if len(projects.Items) != 1 || projects.Items[0].Slug != "payments" {
		t.Fatalf("projects: %+v", projects)
	}
	pd := decode[projectDetail](t, admin.do("GET", "/api/v1/projects/"+proj.ID, nil))
	if pd.Overview.AgentCount != 2 || pd.Overview.ScanCount != 2 || len(pd.RecentScans) != 2 || pd.RecentScans[0].ID != up2.ID {
		t.Fatalf("project detail: %+v", pd)
	}

	// Agents.
	agents := decode[listBody[storage.Agent]](t, admin.do("GET", "/api/v1/projects/"+proj.ID+"/agents", nil))
	if len(agents.Items) != 2 {
		t.Fatalf("agents: %+v", agents)
	}
	var bot storage.Agent
	for _, a := range agents.Items {
		if a.AgentID == "support-bot" {
			bot = a
		}
	}
	if !strings.HasPrefix(bot.Key, "agk_") || bot.LastScanID != up2.ID || bot.LastDecision != "ALLOW" || bot.LastScore == nil || *bot.LastScore != 77 || bot.Owner != "team-support" {
		t.Fatalf("support-bot summary: %+v", bot)
	}

	// Agent detail.
	rec := admin.do("GET", "/api/v1/agents/"+bot.Key+"?project="+proj.ID, nil)
	wantStatus(t, rec, http.StatusOK)
	ad := decode[agentDetail](t, rec)
	if ad.Detail == nil || ad.Detail.Framework != "langgraph" || ad.Assessment == nil || len(ad.Assessment.Controls) != 24 || ad.Scan == nil || ad.Scan.ID != up2.ID {
		t.Fatalf("agent detail: %+v", ad)
	}
	wantError(t, admin.do("GET", "/api/v1/agents/"+bot.Key+"?project=prj_other", nil), http.StatusNotFound, "not_found")

	// History with the fields a client needs to judge comparability.
	hist := decode[listBody[storage.AgentScan]](t, admin.do("GET", "/api/v1/agents/"+bot.Key+"/scans", nil))
	if len(hist.Items) != 2 || hist.Items[0].ScanRowID != up2.ID || hist.Items[0].CommitSHA != "2222222" || hist.Items[1].Decision != "BLOCK" ||
		hist.Items[0].Profile != "standard" || hist.Items[0].PolicyVersion != "1.0" || hist.Items[0].PolicyPack != "builtin/v1" || *hist.Items[1].Score != 41 {
		t.Fatalf("history: %+v", hist.Items)
	}

	// Scan detail: the stored ScanResult plus server metadata.
	rec = admin.do("GET", "/api/v1/scans/"+up1.ID, nil)
	wantStatus(t, rec, http.StatusOK)
	var sd struct {
		Scan   storage.Scan     `json:"scan"`
		Result model.ScanResult `json:"result"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &sd); err != nil {
		t.Fatal(err)
	}
	if sd.Scan.UploadedByToken != tok.Record.ID || sd.Scan.ToolVersion != "0.1.0" || sd.Scan.Decision != "BLOCK" || sd.Scan.CommitSHA != "1111111" ||
		len(sd.Result.Agents) != 2 || len(sd.Result.Evidence) != 3 || sd.Result.Scan.ScanID != "scan-1111111" {
		t.Fatalf("scan detail: %+v", sd.Scan)
	}

	// Findings with filters.
	fl := decode[pageBody[model.Finding]](t, admin.do("GET", "/api/v1/scans/"+up1.ID+"/findings", nil))
	if fl.Total != 4 || len(fl.Items) != 4 || fl.Items[0].WhyItMatters == "" {
		t.Fatalf("findings: %+v", fl)
	}
	fl = decode[pageBody[model.Finding]](t, admin.do("GET", "/api/v1/scans/"+up1.ID+"/findings?severity=critical", nil))
	if fl.Total != 1 || fl.Items[0].FindingID != "F-secret" {
		t.Fatalf("critical findings: %+v", fl)
	}
	fl = decode[pageBody[model.Finding]](t, admin.do("GET", "/api/v1/scans/"+up1.ID+"/findings?agent_id=billing-agent", nil))
	if fl.Total != 2 { // its own finding plus the repository-level one
		t.Fatalf("agent findings: %+v", fl)
	}
	fl = decode[pageBody[model.Finding]](t, admin.do("GET", "/api/v1/scans/"+up1.ID+"/findings?limit=1&offset=3", nil))
	if fl.Total != 4 || len(fl.Items) != 1 || fl.Items[0].FindingID != "F-log" {
		t.Fatalf("paged findings: %+v", fl)
	}

	// Controls: all ten statuses survive the round trip.
	cl := decode[pageBody[model.ControlResult]](t, admin.do("GET", "/api/v1/scans/"+up1.ID+"/controls", nil))
	if cl.Total != 48 {
		t.Fatalf("controls total = %d", cl.Total)
	}
	seen := map[model.Status]bool{}
	for _, c := range cl.Items {
		seen[c.Status] = true
	}
	for _, s := range allStatuses {
		if !seen[s] {
			t.Errorf("status %q missing from controls", s)
		}
	}
	cl = decode[pageBody[model.ControlResult]](t, admin.do("GET", "/api/v1/scans/"+up1.ID+"/controls?agent_id=support-bot&status=failed", nil))
	if cl.Total != 2 || cl.Items[0].ControlID != "AGC-006" {
		t.Fatalf("filtered controls: %+v", cl)
	}

	// Compare: {scanId} is "after", {otherScanId} is "before".
	cmp := decode[compareResponse](t, admin.do("GET", "/api/v1/scans/"+up2.ID+"/compare/"+up1.ID, nil))
	c := cmp.Comparison
	if !c.Comparable || c.BeforeCommit != "1111111" || c.AfterCommit != "2222222" || c.BeforeDecision != model.OutcomeBlock || c.AfterDecision != model.OutcomeReviewRequired ||
		len(c.NewFindings) != 1 || c.NewFindings[0].Fingerprint != "fp-new" || len(c.ResolvedFindings) != 1 || c.ResolvedFindings[0].Fingerprint != "fp-secret" ||
		c.UnchangedCount != 3 || len(c.ControlChanges) != 1 || c.ControlChanges[0].ControlID != "AGC-006" ||
		c.ControlChanges[0].BeforeStatus != model.StatusFailed || c.ControlChanges[0].AfterMaturity != 3 {
		t.Fatalf("comparison: %+v", c)
	}
	if cmp.Before.ID != up1.ID || cmp.After.ID != up2.ID {
		t.Fatalf("compare order: %s %s", cmp.Before.ID, cmp.After.ID)
	}

	// Overview: open findings come from the latest scan.
	ov := decode[overviewResponse](t, admin.do("GET", "/api/v1/overview", nil))
	if len(ov.Projects) != 1 || ov.Totals.Agents != 2 || ov.Totals.Scans != 2 || ov.Totals.OpenCritical != 0 || ov.Totals.OpenHigh != 2 ||
		ov.Totals.Decisions["ALLOW"] != 1 || ov.Totals.Decisions["REVIEW_REQUIRED"] != 1 || ov.Projects[0].Overview.LatestDecision != "REVIEW_REQUIRED" || ov.Totals.LatestScanAt == nil {
		t.Fatalf("overview: %+v", ov)
	}

	// Audit events and the hash chain.
	evs := decode[listBody[struct {
		ID        int64          `json:"id"`
		Action    string         `json:"action"`
		ActorType string         `json:"actor_type"`
		ActorID   string         `json:"actor_id"`
		ProjectID string         `json:"project_id"`
		Detail    map[string]any `json:"detail"`
		Hash      string         `json:"hash"`
	}]](t, admin.do("GET", "/api/v1/audit-events", nil))
	actions := map[string]int{}
	for _, ev := range evs.Items {
		actions[ev.Action]++
		if ev.Hash == "" {
			t.Fatal("audit event without hash")
		}
		if ev.Action == "scan.ingested" && (ev.ActorType != storage.ActorToken || ev.ActorID != tok.Record.ID || ev.ProjectID != proj.ID || ev.Detail["tool_version"] != "0.1.0") {
			t.Fatalf("ingest provenance: %+v", ev)
		}
	}
	for _, want := range []string{"bootstrap.token_generated", "setup.completed", "login.succeeded", "project.created", "token.created"} {
		if actions[want] != 1 {
			t.Errorf("audit action %q count = %d, want 1 (%v)", want, actions[want], actions)
		}
	}
	if actions["scan.ingested"] != 2 {
		t.Errorf("scan.ingested count = %d", actions["scan.ingested"])
	}
	pevs := decode[listBody[map[string]any]](t, admin.do("GET", "/api/v1/audit-events?project="+proj.ID+"&limit=2", nil))
	if len(pevs.Items) != 2 {
		t.Fatalf("project audit events: %d", len(pevs.Items))
	}
	n, err := e.store.VerifyAuditChain(context.Background())
	if err != nil || n != len(evs.Items) {
		t.Fatalf("audit chain: n=%d err=%v", n, err)
	}

	// Logout ends the session.
	wantStatus(t, admin.do("POST", "/api/v1/logout", nil), http.StatusOK)
	wantError(t, admin.do("GET", "/api/v1/session", nil), http.StatusUnauthorized, "unauthenticated")

	// Nothing sensitive reached the log, and requests were logged.
	logs := e.logs.String()
	for name, secret := range map[string]string{"password": testPassword, "bootstrap token": e.bootstrapToken(), "session cookie": admin.cookie.Value,
		"api token": tok.Token, "csrf token": admin.csrf} {
		if strings.Contains(logs, secret) {
			t.Errorf("log contains the %s", name)
		}
	}
	if !strings.Contains(logs, `"route":"POST /api/v1/scans"`) || !strings.Contains(logs, `"request_id"`) || !strings.Contains(logs, `"actor":"token:`+tok.Record.ID) {
		t.Errorf("request log line is missing expected fields")
	}
}

func TestCompareNotComparable(t *testing.T) {
	e := newEnv(t, nil)
	admin := e.setup()
	proj := e.createProject(admin, "p1")
	tok := e.createToken(admin, proj.ID).Token
	a := e.mustUpload(tok, sampleScan(e.clock.Now(), "aaa"))
	other := sampleScan(e.clock.Now(), "bbb")
	other.Scan.PolicyVersion = "2.0"
	other.Scan.Profile = "high-risk"
	b := e.mustUpload(tok, other)
	cmp := decode[compareResponse](t, admin.do("GET", "/api/v1/scans/"+b.ID+"/compare/"+a.ID, nil))
	if cmp.Comparison.Comparable || !strings.Contains(cmp.Comparison.NotComparableWhy, "policy version") || !strings.Contains(cmp.Comparison.NotComparableWhy, "profile") {
		t.Fatalf("comparison must be flagged not comparable: %+v", cmp.Comparison)
	}
}

func TestIngestIdempotent(t *testing.T) {
	e := newEnv(t, nil)
	admin := e.setup()
	proj := e.createProject(admin, "p1")
	tok := e.createToken(admin, proj.ID).Token
	body := rawJSON(t, sampleScan(e.clock.Now(), "abc"))
	c := e.anon()
	c.bearer = tok
	r1 := c.do("POST", "/api/v1/scans", body)
	wantStatus(t, r1, http.StatusCreated)
	e.clock.Advance(time.Minute)
	r2 := c.do("POST", "/api/v1/scans", body, header("Content-Type", "application/json; charset=utf-8"))
	wantStatus(t, r2, http.StatusOK)
	a, b := decode[ingestResponse](t, r1), decode[ingestResponse](t, r2)
	if a.ID != b.ID || !a.Created || b.Created {
		t.Fatalf("re-upload must return the existing scan: %+v %+v", a, b)
	}
	pd := decode[projectDetail](t, admin.do("GET", "/api/v1/projects/"+proj.ID, nil))
	if pd.Overview.ScanCount != 1 {
		t.Fatalf("scan count = %d", pd.Overview.ScanCount)
	}
	toks := decode[listBody[storage.APIToken]](t, admin.do("GET", "/api/v1/projects/"+proj.ID+"/tokens", nil))
	if toks.Items[0].LastUsedAt == nil {
		t.Fatal("last_used_at not recorded")
	}
}

func TestConcurrentUploads(t *testing.T) {
	e := newEnv(t, nil)
	admin := e.setup()
	proj := e.createProject(admin, "p1")
	tok := e.createToken(admin, proj.ID).Token
	const workers, distinct = 16, 8
	bodies := make([][]byte, distinct)
	for i := range bodies {
		bodies[i] = rawJSON(t, sampleScan(e.clock.Now(), strings.Repeat(string(rune('a'+i)), 7)))
	}
	var wg sync.WaitGroup
	codes := make([]int, workers)
	ids := make([]string, workers)
	for i := 0; i < workers; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			c := e.anon()
			c.bearer = tok
			rec := c.do("POST", "/api/v1/scans", bodies[i%distinct])
			codes[i] = rec.Code
			var r ingestResponse
			_ = json.Unmarshal(rec.Body.Bytes(), &r)
			ids[i] = r.ID
		}(i)
	}
	wg.Wait()
	created := 0
	for i, code := range codes {
		switch code {
		case http.StatusCreated:
			created++
		case http.StatusOK:
		default:
			t.Fatalf("worker %d: status %d", i, code)
		}
		if ids[i] != ids[(i+distinct)%workers] {
			t.Fatalf("identical payloads got different scan IDs: %s %s", ids[i], ids[(i+distinct)%workers])
		}
	}
	if created != distinct {
		t.Fatalf("created = %d, want %d", created, distinct)
	}
	pd := decode[projectDetail](t, admin.do("GET", "/api/v1/projects/"+proj.ID, nil))
	if pd.Overview.ScanCount != distinct || pd.Overview.AgentCount != 2 {
		t.Fatalf("after concurrent uploads: %+v", pd.Overview)
	}
	if _, err := e.store.VerifyAuditChain(context.Background()); err != nil {
		t.Fatalf("audit chain after concurrent uploads: %v", err)
	}
}

// TestReopenExistingDatabase restarts the server on an existing database.
func TestReopenExistingDatabase(t *testing.T) {
	e := newEnv(t, nil)
	admin := e.setup()
	proj := e.createProject(admin, "p1")
	tok := e.createToken(admin, proj.ID).Token
	up := e.mustUpload(tok, sampleScan(e.clock.Now(), "abc"))
	e.store.Close()

	e2 := newEnvAt(t, e.path, nil)
	if e2.boot.String() != "" {
		t.Fatal("a restart with existing users must not print a bootstrap token")
	}
	admin2 := e2.login(adminUsername, testPassword)
	wantStatus(t, admin2.do("GET", "/api/v1/scans/"+up.ID, nil), http.StatusOK)
	// The old API token still works after the restart.
	wantStatus(t, e2.upload(tok, sampleScan(e2.clock.Now(), "def")), http.StatusCreated)
	wantStatus(t, e2.anon().do("GET", "/readyz", nil), http.StatusOK)
}
