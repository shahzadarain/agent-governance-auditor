// SPDX-License-Identifier: Apache-2.0

package server

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/shahzadarain/agent-governance-auditor/internal/model"
	"github.com/shahzadarain/agent-governance-auditor/internal/storage"
)

const (
	testPassword  = "correct horse battery staple"
	testArgonKiB  = 64 // small memory keeps the tests fast
	adminUsername = "admin"
)

type fakeClock struct {
	mu sync.Mutex
	t  time.Time
}

func (c *fakeClock) Now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.t
}

func (c *fakeClock) Advance(d time.Duration) {
	c.mu.Lock()
	c.t = c.t.Add(d)
	c.mu.Unlock()
}

// syncBuffer is a goroutine-safe bytes.Buffer for log capture.
type syncBuffer struct {
	mu sync.Mutex
	b  bytes.Buffer
}

func (s *syncBuffer) Write(p []byte) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.b.Write(p)
}

func (s *syncBuffer) String() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.b.String()
}

type env struct {
	t     *testing.T
	h     http.Handler
	store *storage.SQLStore
	clock *fakeClock
	boot  *syncBuffer
	logs  *syncBuffer
	cfg   Config
	path  string
}

func newEnv(t *testing.T, mutate func(*Config)) *env {
	t.Helper()
	return newEnvAt(t, filepath.Join(t.TempDir(), "agentgov.db"), mutate)
}

func newEnvAt(t *testing.T, path string, mutate func(*Config)) *env {
	t.Helper()
	store, err := storage.Open(context.Background(), path)
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	t.Cleanup(func() { store.Close() })
	e := &env{t: t, store: store, path: path, boot: &syncBuffer{}, logs: &syncBuffer{},
		clock: &fakeClock{t: time.Date(2026, 3, 1, 12, 0, 0, 0, time.UTC)}}
	e.cfg = Config{
		Version:         "test-1.2.3",
		Logger:          slog.New(slog.NewJSONHandler(e.logs, &slog.HandlerOptions{Level: slog.LevelDebug})),
		BootstrapOut:    e.boot,
		Now:             e.clock.Now,
		Argon2MemoryKiB: testArgonKiB,
	}
	if mutate != nil {
		mutate(&e.cfg)
	}
	h, err := NewHandler(e.cfg, store)
	if err != nil {
		t.Fatalf("new handler: %v", err)
	}
	e.h = h
	return e
}

var bootTokenRe = regexp.MustCompile(`Bootstrap token: (\S+)`)

func (e *env) bootstrapToken() string {
	e.t.Helper()
	m := bootTokenRe.FindAllStringSubmatch(e.boot.String(), -1)
	if len(m) == 0 {
		e.t.Fatalf("no bootstrap token printed: %q", e.boot.String())
	}
	return m[len(m)-1][1]
}

// client is a test HTTP client that keeps a session cookie and CSRF token.
type client struct {
	e      *env
	cookie *http.Cookie
	csrf   string
	bearer string
	remote string
}

func (e *env) anon() *client { return &client{e: e} }

type reqOpt func(*http.Request)

func header(k, v string) reqOpt { return func(r *http.Request) { r.Header.Set(k, v) } }

func noHeader(k string) reqOpt { return func(r *http.Request) { r.Header.Del(k) } }

func (c *client) do(method, path string, body any, opts ...reqOpt) *httptest.ResponseRecorder {
	c.e.t.Helper()
	var rd io.Reader
	switch b := body.(type) {
	case nil:
	case []byte:
		rd = bytes.NewReader(b)
	case string:
		rd = strings.NewReader(b)
	default:
		data, err := json.Marshal(b)
		if err != nil {
			c.e.t.Fatalf("marshal body: %v", err)
		}
		rd = bytes.NewReader(data)
	}
	req := httptest.NewRequest(method, path, rd)
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	if c.remote != "" {
		req.RemoteAddr = c.remote
	}
	if c.cookie != nil {
		req.AddCookie(c.cookie)
	}
	if c.csrf != "" && isMutating(method) {
		req.Header.Set(csrfHeader, c.csrf)
	}
	if c.bearer != "" {
		req.Header.Set("Authorization", "Bearer "+c.bearer)
	}
	for _, o := range opts {
		o(req)
	}
	rec := httptest.NewRecorder()
	c.e.h.ServeHTTP(rec, req)
	return rec
}

func decode[T any](t *testing.T, rec *httptest.ResponseRecorder) T {
	t.Helper()
	var v T
	if err := json.Unmarshal(rec.Body.Bytes(), &v); err != nil {
		t.Fatalf("decode response (%d): %v\n%s", rec.Code, err, rec.Body.String())
	}
	return v
}

func wantStatus(t *testing.T, rec *httptest.ResponseRecorder, want int) {
	t.Helper()
	if rec.Code != want {
		t.Fatalf("status = %d, want %d\nbody: %s", rec.Code, want, rec.Body.String())
	}
}

func wantError(t *testing.T, rec *httptest.ResponseRecorder, status int, code string) {
	t.Helper()
	wantStatus(t, rec, status)
	if ct := rec.Header().Get("Content-Type"); ct != "application/json; charset=utf-8" {
		t.Fatalf("error content type = %q", ct)
	}
	body := decode[errorBody](t, rec)
	if body.Error.Code != code || body.Error.Message == "" {
		t.Fatalf("error = %+v, want code %q", body.Error, code)
	}
}

// setup performs first-run setup and returns a signed-in administrator.
func (e *env) setup() *client {
	e.t.Helper()
	rec := e.anon().do("POST", "/api/v1/setup", setupRequest{BootstrapToken: e.bootstrapToken(), Username: adminUsername, Password: testPassword})
	wantStatus(e.t, rec, http.StatusCreated)
	return e.login(adminUsername, testPassword)
}

func (e *env) login(username, password string) *client {
	e.t.Helper()
	c := e.anon()
	rec := c.do("POST", "/api/v1/login", loginRequest{Username: username, Password: password})
	wantStatus(e.t, rec, http.StatusOK)
	for _, ck := range rec.Result().Cookies() {
		if ck.Name == sessionCookie {
			c.cookie = ck
		}
	}
	if c.cookie == nil {
		e.t.Fatal("login set no session cookie")
	}
	c.csrf = decode[sessionResponse](e.t, rec).CSRFToken
	return c
}

func (e *env) createUser(admin *client, username string) *client {
	e.t.Helper()
	rec := admin.do("POST", "/api/v1/users", createUserRequest{Username: username, Password: testPassword})
	wantStatus(e.t, rec, http.StatusCreated)
	return e.login(username, testPassword)
}

func (e *env) createProject(admin *client, slug string) storage.Project {
	e.t.Helper()
	rec := admin.do("POST", "/api/v1/projects", createProjectRequest{Slug: slug, Name: "Project " + slug})
	wantStatus(e.t, rec, http.StatusCreated)
	return decode[storage.Project](e.t, rec)
}

func (e *env) addMember(admin *client, projectID, username, role string) {
	e.t.Helper()
	rec := admin.do("POST", "/api/v1/projects/"+projectID+"/members", setMemberRequest{Username: username, Role: role})
	wantStatus(e.t, rec, http.StatusOK)
}

func (e *env) createToken(c *client, projectID string) createTokenResponse {
	e.t.Helper()
	rec := c.do("POST", "/api/v1/projects/"+projectID+"/tokens", createTokenRequest{Name: "ci"})
	wantStatus(e.t, rec, http.StatusCreated)
	return decode[createTokenResponse](e.t, rec)
}

func (e *env) upload(token string, res *model.ScanResult) *httptest.ResponseRecorder {
	e.t.Helper()
	c := e.anon()
	c.bearer = token
	return c.do("POST", "/api/v1/scans", res)
}

func (e *env) mustUpload(token string, res *model.ScanResult) ingestResponse {
	e.t.Helper()
	rec := e.upload(token, res)
	wantStatus(e.t, rec, http.StatusCreated)
	return decode[ingestResponse](e.t, rec)
}

var allStatuses = []model.Status{
	model.StatusVerifiedOperational, model.StatusVerifiedTested, model.StatusVerifiedImplementation, model.StatusDeclaredOnly,
	model.StatusMissing, model.StatusFailed, model.StatusUnknown, model.StatusNotApplicable, model.StatusAcceptedRisk, model.StatusError,
}

func maturityFor(s model.Status) int {
	switch s {
	case model.StatusVerifiedOperational:
		return 4
	case model.StatusVerifiedTested:
		return 3
	case model.StatusVerifiedImplementation:
		return 2
	case model.StatusDeclaredOnly:
		return 1
	}
	return 0
}

func intp(i int) *int { return &i }

// sampleScan builds a realistic ScanResult: two agents, 24 controls each
// covering all ten statuses, four findings, and three evidence items.
func sampleScan(now time.Time, commit string) *model.ScanResult {
	controls := func(agent string, shift int) []model.ControlResult {
		var out []model.ControlResult
		for i := 1; i <= 24; i++ {
			st := allStatuses[(i-1+shift)%len(allStatuses)]
			out = append(out, model.ControlResult{
				ControlID: fmt.Sprintf("AGC-%03d", i), AgentID: agent, Title: fmt.Sprintf("Control %d", i), Domain: "A: Accountability",
				PlainLanguage: "Plain explanation.", Status: st, StatusReason: "test", Maturity: maturityFor(st), MaxStaticMaturity: 2,
				Applicable: st != model.StatusNotApplicable, ApplicabilityBasis: model.BasisAlways, Mandatory: i <= 8, MinMaturity: 2,
				Weight: 3, Severity: model.SeverityHigh, EvidenceRefs: []string{}, FindingRefs: []string{}, NextAction: "Add a test.",
				Remediation: []string{"Do the thing."}, Limitations: []string{},
			})
		}
		return out
	}
	finding := func(id, fp, control, agent string, sev model.Severity, title, path string, line int) model.Finding {
		return model.Finding{FindingID: id, Fingerprint: fp, RuleID: control + ".rule", ControlID: control, AgentID: agent, Severity: sev,
			Confidence: model.ConfidenceHigh, Title: title, Description: "Observed in the repository.", WhyItMatters: "It matters.",
			Remediation: []string{"Fix it."}, Location: &model.Location{Path: path, Line: line}, EvidenceRefs: []string{"ev-1"},
			Mappings: []model.Mapping{{Standard: "NIST AI RMF", Version: "1.0", RequirementID: "GOVERN 1.1", URL: "https://example.invalid/", Rationale: "r"}}}
	}
	score := func(v int) model.Score {
		return model.Score{Value: intp(v), Label: fmt.Sprintf("%d/100", v), ApplicableControls: 22, ControlsWithEvidence: 12, CoveragePercent: 55,
			TestedPercent: 20, OperationalPercent: 10, FindingsBySeverity: map[string]int{"critical": 1, "high": 1, "medium": 1, "low": 1},
			UnresolvedMandatory: []string{"AGC-005"}, StatusCounts: map[string]int{"failed": 3}}
	}
	block := model.Decision{Outcome: model.OutcomeBlock, Reasons: []model.Reason{{Code: "mandatory-control-failed", ControlID: "AGC-006", AgentID: "support-bot", Message: "A mandatory control failed."}}}
	review := model.Decision{Outcome: model.OutcomeReviewRequired, Reasons: []model.Reason{{Code: "accepted-risk", Message: "An accepted risk needs review."}}}
	return &model.ScanResult{
		SchemaVersion: model.SchemaVersion,
		Tool:          model.ToolInfo{Name: "agentgov", Version: "0.1.0"},
		Scan: model.ScanMeta{ScanID: "scan-" + commit, StartedAt: now.Add(-time.Minute), FinishedAt: now.Add(-30 * time.Second), Target: "demo-repo",
			CommitSHA: commit, Profile: "standard", ProfileSource: "default", PolicyPack: "builtin/v1", PolicyVersion: "1.0", Offline: true},
		Agents: []model.Agent{
			{ID: "support-bot", Name: "Support bot", Root: "agents/support", Detection: model.Detected, Confidence: model.ConfidenceHigh,
				Framework: "langgraph", FrameworkVersion: model.Unknown, Language: "python", Entrypoint: "agents/support/main.py", Owner: "team-support",
				RiskTier: "high", InferredRiskTier: "high",
				Tools:        []model.Tool{{Name: "refund", Kind: "function", Location: model.Location{Path: "agents/support/tools.py", Line: 10}, Sensitive: true, SensitiveWhy: "moves money", Capabilities: []string{model.CapSensitiveActions}}},
				Capabilities: []string{model.CapSensitiveActions, model.CapTools}, PermissionsDeclared: []string{}, DataAccessPaths: []string{}, MCPConnections: []model.MCPConnection{},
				Facts: []model.Fact{{Kind: "framework-import", Detail: "imports langgraph", Location: model.Location{Path: "agents/support/main.py", Line: 1}, Confidence: model.ConfidenceHigh, Collector: "python.langgraph", ParserVersion: "1"}}},
			{ID: "billing-agent", Name: "Billing agent", Root: "agents/billing", Detection: model.Suspected, Confidence: model.ConfidenceMedium,
				Framework: "openai-agents", FrameworkVersion: "1.2.0", Language: "typescript", Entrypoint: model.Unknown, Owner: model.Unknown,
				RiskTier: model.Unknown, InferredRiskTier: "standard", Tools: []model.Tool{}, Capabilities: []string{model.CapTools},
				PermissionsDeclared: []string{}, DataAccessPaths: []string{}, MCPConnections: []model.MCPConnection{}, Facts: []model.Fact{}},
		},
		Assessments: []model.AgentAssessment{
			{AgentID: "support-bot", Score: score(41), Decision: block, Controls: controls("support-bot", 0)},
			{AgentID: "billing-agent", Score: score(63), Decision: review, Controls: controls("billing-agent", 3)},
		},
		Evidence: []model.Evidence{
			{EvidenceID: "ev-1", ControlID: "AGC-008", AgentID: "support-bot", CommitSHA: commit, PolicyVersion: "1.0", ScannerVersion: "0.1.0",
				SourceType: model.SourceStatic, SourceLocation: "agents/support/config.py:12", Collector: "rules.secrets", ObservedAt: now.Add(-time.Minute),
				Integrity: model.IntegrityNotAvailable, Result: model.ResultFail, Signal: model.SignalViolation, Strength: model.StrengthImplementation,
				Validity: model.ValidityValid, Summary: "A credential pattern was found (value redacted).", Limitations: []string{}},
			{EvidenceID: "ev-2", ControlID: "AGC-001", AgentID: model.AllAgents, CommitSHA: commit, PolicyVersion: "1.0", ScannerVersion: "0.1.0",
				SourceType: model.SourceConfiguration, SourceLocation: ".agentgov.yaml:3", Collector: "config", ObservedAt: now.Add(-time.Minute),
				Integrity: model.IntegrityUnsigned, Result: model.ResultInconclusive, Signal: model.SignalDeclared, Strength: model.StrengthDeclared,
				Validity: model.ValidityValid, Summary: "Owner declared.", Limitations: []string{}},
			{EvidenceID: "ev-3", ControlID: "AGC-012", AgentID: "billing-agent", CommitSHA: commit, PolicyVersion: "1.0", ScannerVersion: "0.1.0",
				SourceType: model.SourceTest, SourceLocation: "evidence/test.json", Collector: "external", ObservedAt: now.Add(-2 * time.Hour),
				Integrity: model.IntegrityUnsigned, Result: model.ResultPass, Signal: model.SignalPresent, Strength: model.StrengthTested,
				Validity: model.ValidityExpired, ValidityReason: "evidence expired", Summary: "Test evidence.", Limitations: []string{}},
		},
		Findings: []model.Finding{
			finding("F-secret", "fp-secret", "AGC-008", "support-bot", model.SeverityCritical, "Hard-coded credential", "agents/support/config.py", 12),
			finding("F-approval", "fp-approval", "AGC-006", "billing-agent", model.SeverityHigh, "Sensitive tool has no approval step", "agents/billing/tools.ts", 40),
			finding("F-owner", "fp-owner", "AGC-001", model.AllAgents, model.SeverityMedium, "No owner declared", ".agentgov.yaml", 1),
			finding("F-log", "fp-log", "AGC-015", "support-bot", model.SeverityLow, "No audit logging found", "agents/support/main.py", 5),
		},
		Score:       score(41),
		Decision:    block,
		Stats:       model.Stats{FilesScanned: 42, FilesSkipped: 1, BytesRead: 12345, DurationMilli: 250},
		Warnings:    []string{},
		Limitations: []string{"Static analysis only."},
	}
}

func rawJSON(t *testing.T, v any) []byte {
	t.Helper()
	b, err := json.Marshal(v)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func testLogger(w io.Writer) *slog.Logger {
	return slog.New(slog.NewJSONHandler(w, &slog.HandlerOptions{Level: slog.LevelDebug}))
}

func fsGlob(dir string) ([]string, error) {
	entries, err := os.ReadDir(dir)
	var names []string
	for _, e := range entries {
		names = append(names, e.Name())
	}
	return names, err
}
