// SPDX-License-Identifier: Apache-2.0

package policy

import (
	"fmt"
	"testing"
	"time"

	"github.com/shahzadarain/agent-governance-auditor/internal/config"
	"github.com/shahzadarain/agent-governance-auditor/internal/controls"
	"github.com/shahzadarain/agent-governance-auditor/internal/model"
)

// testNow is the injected clock for every test.
var testNow = time.Date(2026, 11, 15, 12, 0, 0, 0, time.UTC)

var allCapabilities = []string{
	model.CapBrowser, model.CapCodeExec, model.CapContainer, model.CapCredentials,
	model.CapDataAccess, model.CapFilesystem, model.CapMCP, model.CapMemory,
	model.CapMultiAgent, model.CapMutatingActions, model.CapNetwork,
	model.CapSensitiveActions, model.CapShellExec, model.CapTools,
}

func catalog(t testing.TB) *model.Catalog {
	t.Helper()
	cat, err := controls.Load()
	if err != nil {
		t.Fatalf("load catalog: %v", err)
	}
	return cat
}

func profile(t testing.TB, name string) *model.Profile {
	t.Helper()
	p, err := LoadProfile(name)
	if err != nil {
		t.Fatalf("load profile %s: %v", name, err)
	}
	return p
}

// agent returns a detected agent with the given capabilities.
func agent(id string, caps ...string) model.Agent {
	return model.Agent{ID: id, Name: id, Root: ".", Detection: model.Detected, Capabilities: caps}
}

// fullAgent has every capability, so all 24 controls apply to it.
func fullAgent(id string) model.Agent { return agent(id, allCapabilities...) }

type evOpt func(*model.Evidence)

var evSeq int

// ev builds a valid, static, present, implementation-strength evidence item
// for agent "a1". Options change it.
func ev(control string, opts ...evOpt) model.Evidence {
	evSeq++
	e := model.Evidence{
		EvidenceID: fmt.Sprintf("ev-%s-%04d", control, evSeq),
		ControlID:  control,
		AgentID:    "a1",
		CommitSHA:  "abc123",
		SourceType: model.SourceStatic,
		Collector:  "test",
		ObservedAt: testNow,
		Integrity:  model.IntegrityNotAvailable,
		Result:     model.ResultPass,
		Signal:     model.SignalPresent,
		Strength:   model.StrengthImplementation,
		Validity:   model.ValidityValid,
		Summary:    "Mechanism found for " + control + ".",
	}
	for _, o := range opts {
		o(&e)
	}
	return e
}

func forAgent(id string) evOpt { return func(e *model.Evidence) { e.AgentID = id } }
func signal(s model.Signal) evOpt {
	return func(e *model.Evidence) {
		e.Signal = s
		switch s {
		case model.SignalViolation:
			e.Result = model.ResultFail
		case model.SignalPresent:
			e.Result = model.ResultPass
		default:
			e.Result = model.ResultInconclusive
		}
	}
}
func strength(s model.Strength) evOpt   { return func(e *model.Evidence) { e.Strength = s } }
func source(s model.SourceType) evOpt   { return func(e *model.Evidence) { e.SourceType = s } }
func integrity(i model.Integrity) evOpt { return func(e *model.Evidence) { e.Integrity = i } }
func validity(v model.Validity) evOpt   { return func(e *model.Evidence) { e.Validity = v } }
func summary(s string) evOpt            { return func(e *model.Evidence) { e.Summary = s } }
func validUntil(tm time.Time) evOpt     { return func(e *model.Evidence) { e.ValidUntil = &tm } }
func withID(id string) evOpt            { return func(e *model.Evidence) { e.EvidenceID = id } }
func runtimeOperational() []evOpt {
	return []evOpt{source(model.SourceRuntime), strength(model.StrengthOperational)}
}
func testTested() []evOpt { return []evOpt{source(model.SourceTest), strength(model.StrengthTested)} }
func signed() evOpt       { return integrity(model.IntegrityVerified) }
func unsigned() evOpt     { return integrity(model.IntegrityUnsigned) }
func opts(groups ...[]evOpt) (out []evOpt) { // flatten option groups
	for _, g := range groups {
		out = append(out, g...)
	}
	return out
}

// evidenceForAll returns one evidence item per catalog control.
func evidenceForAll(cat *model.Catalog, o ...evOpt) []model.Evidence {
	var out []model.Evidence
	for _, c := range cat.Controls {
		out = append(out, ev(c.ID, o...))
	}
	return out
}

// replace swaps the evidence of one control for the given items.
func replace(all []model.Evidence, control string, with ...model.Evidence) []model.Evidence {
	var out []model.Evidence
	for _, e := range all {
		if e.ControlID != control {
			out = append(out, e)
		}
	}
	return append(out, with...)
}

func finding(id, control string, sev model.Severity) model.Finding {
	return model.Finding{FindingID: id, Fingerprint: id, RuleID: control + ".test", ControlID: control,
		AgentID: "a1", Severity: sev, Confidence: model.ConfidenceHigh, Title: "Test finding " + id}
}

type scenario struct {
	agents   []model.Agent
	evidence []model.Evidence
	findings []model.Finding
	profile  *model.Profile
	cfg      *config.Config
	cat      *model.Catalog
}

func run(t testing.TB, s scenario) ([]model.AgentAssessment, model.Score, model.Decision) {
	t.Helper()
	if s.cat == nil {
		s.cat = catalog(t)
	}
	if s.profile == nil {
		s.profile = &model.Profile{Name: "none", Version: "1.0", MandatoryControls: []string{}}
	}
	return Evaluate(Input{
		Detection: &model.Detection{CommitSHA: "abc123", Agents: s.agents, Evidence: s.evidence, Findings: s.findings},
		Catalog:   s.cat,
		Profile:   s.profile,
		Config:    s.cfg,
		Now:       testNow,
	})
}

// control returns the result for one control of the first assessment.
func control(t testing.TB, as []model.AgentAssessment, id string) model.ControlResult {
	t.Helper()
	if len(as) == 0 {
		t.Fatalf("no assessments")
	}
	for _, c := range as[0].Controls {
		if c.ControlID == id {
			return c
		}
	}
	t.Fatalf("control %s not in assessment", id)
	return model.ControlResult{}
}

func reasonCodes(d model.Decision) []string {
	var out []string
	for _, r := range d.Reasons {
		out = append(out, r.Code)
	}
	return out
}

func hasReason(d model.Decision, code, controlID string) bool {
	for _, r := range d.Reasons {
		if r.Code == code && (controlID == "" || r.ControlID == controlID) {
			return true
		}
	}
	return false
}

func exception(control, reason, by, expires string) config.Exception {
	return config.Exception{Control: control, Reason: reason, ApprovedBy: by, Expires: expires}
}

func intPtr(v int) *int { return &v }
