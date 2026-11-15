// SPDX-License-Identifier: Apache-2.0

package policy

import (
	"encoding/json"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/shahzadarain/agent-governance-auditor/internal/config"
	"github.com/shahzadarain/agent-governance-auditor/internal/model"
	"github.com/shahzadarain/agent-governance-auditor/internal/scoring"
)

const (
	alwaysControl     = "AGC-012" // applicability: always, max static maturity 2
	capabilityControl = "AGC-015" // applicability: capability (memory)
	declarationOnly   = "AGC-001" // max static maturity 1
)

func TestEveryAgentGetsAll24ControlsInOrder(t *testing.T) {
	cat := catalog(t)
	p := profile(t, ProfileStandard)
	p.Weights = map[string]int{"AGC-003": 9}
	as, _, _ := run(t, scenario{agents: []model.Agent{fullAgent("a1")}, profile: p})
	if len(as) != 1 || len(as[0].Controls) != 24 {
		t.Fatalf("want 1 assessment with 24 controls, got %d assessments", len(as))
	}
	for i, r := range as[0].Controls {
		c := cat.Controls[i]
		if r.ControlID != c.ID || r.Title != c.Title || r.Domain != c.Domain || r.PlainLanguage != c.PlainLanguage {
			t.Errorf("%s: catalog text not copied: %+v", c.ID, r)
		}
		if r.AgentID != "a1" || r.Severity != c.Severity || r.MaxStaticMaturity != c.VerificationRules.MaxStaticMaturity {
			t.Errorf("%s: agent, severity, or static cap wrong", c.ID)
		}
		if !reflect.DeepEqual(r.Remediation, c.Remediation) || !reflect.DeepEqual(r.Limitations, c.Limitations) {
			t.Errorf("%s: remediation or limitations not copied", c.ID)
		}
		if r.EvidenceRefs == nil || r.FindingRefs == nil {
			t.Errorf("%s: reference lists must not be nil", c.ID)
		}
		if r.StatusReason == "" || r.NextAction == "" || r.ApplicabilityBasis == "" || r.ApplicabilityReason == "" {
			t.Errorf("%s: reason, next action, and applicability must be filled: %+v", c.ID, r)
		}
		wantWeight := c.DefaultWeight
		if c.ID == "AGC-003" {
			wantWeight = 9
		}
		if r.Weight != wantWeight {
			t.Errorf("%s: weight %d, want %d", c.ID, r.Weight, wantWeight)
		}
		mandatory := false
		for _, id := range p.MandatoryControls {
			mandatory = mandatory || id == c.ID
		}
		if r.Mandatory != mandatory {
			t.Errorf("%s: mandatory = %v, want %v", c.ID, r.Mandatory, mandatory)
		}
		if mandatory && r.MinMaturity != RequiredMaturity(p, c.ID) || !mandatory && r.MinMaturity != 0 {
			t.Errorf("%s: min maturity %d", c.ID, r.MinMaturity)
		}
	}
}

// TestStatusPrecedence covers every row of the status-derivation table.
func TestStatusPrecedence(t *testing.T) {
	approvedNA := &config.Config{Policy: config.Policy{NotApplicable: []config.Exception{
		exception(alwaysControl, "Not relevant to this agent.", "review-board", "2027-01-01")}}}
	accepted := &config.Config{Policy: config.Policy{AcceptedRisks: []config.Exception{
		exception(alwaysControl, "Limits arrive next quarter.", "ciso", "")}}}
	both := &config.Config{Policy: config.Policy{
		NotApplicable: approvedNA.Policy.NotApplicable, AcceptedRisks: accepted.Policy.AcceptedRisks}}

	tests := []struct {
		name         string
		control      string
		caps         []string
		cfg          *config.Config
		evidence     func(c string) []model.Evidence
		want         model.Status
		wantMaturity int
		wantApplies  bool
	}{
		{"1 error beats violation and present", alwaysControl, nil, nil, func(c string) []model.Evidence {
			return []model.Evidence{ev(c, signal(model.SignalError)), ev(c, signal(model.SignalViolation)), ev(c, opts(runtimeOperational())...)}
		}, model.StatusError, 0, true},
		{"1 error beats approved not-applicable", alwaysControl, nil, approvedNA, func(c string) []model.Evidence {
			return []model.Evidence{ev(c, signal(model.SignalError))}
		}, model.StatusError, 0, true},
		{"1 error beats inferred not-applicable", capabilityControl, nil, nil, func(c string) []model.Evidence {
			return []model.Evidence{ev(c, signal(model.SignalError))}
		}, model.StatusError, 0, true},
		{"2 violation beats present", alwaysControl, nil, nil, func(c string) []model.Evidence {
			return []model.Evidence{ev(c, signal(model.SignalViolation)), ev(c, opts(runtimeOperational())...)}
		}, model.StatusFailed, 0, true},
		{"2 violation beats approved not-applicable", alwaysControl, nil, approvedNA, func(c string) []model.Evidence {
			return []model.Evidence{ev(c, signal(model.SignalViolation))}
		}, model.StatusFailed, 0, true},
		{"2 violation beats accepted risk", alwaysControl, nil, accepted, func(c string) []model.Evidence {
			return []model.Evidence{ev(c, signal(model.SignalViolation))}
		}, model.StatusFailed, 0, true},
		{"2 violation beats inferred not-applicable", capabilityControl, nil, nil, func(c string) []model.Evidence {
			return []model.Evidence{ev(c, signal(model.SignalViolation))}
		}, model.StatusFailed, 0, true},
		{"3 approved not-applicable beats present", alwaysControl, nil, approvedNA, func(c string) []model.Evidence {
			return []model.Evidence{ev(c, opts(runtimeOperational())...)}
		}, model.StatusNotApplicable, 0, false},
		{"3 accepted risk beats present", alwaysControl, nil, accepted, func(c string) []model.Evidence {
			return []model.Evidence{ev(c, opts(runtimeOperational())...)}
		}, model.StatusAcceptedRisk, 0, true},
		{"3 accepted risk beats not-applicable when both are recorded", alwaysControl, nil, both, func(c string) []model.Evidence {
			return nil
		}, model.StatusAcceptedRisk, 0, true},
		{"4 no triggering capability beats present", capabilityControl, nil, nil, func(c string) []model.Evidence {
			return []model.Evidence{ev(c)}
		}, model.StatusNotApplicable, 0, false},
		{"5 present operational", alwaysControl, nil, nil, func(c string) []model.Evidence {
			return []model.Evidence{ev(c, opts(runtimeOperational())...)}
		}, model.StatusVerifiedOperational, 4, true},
		{"5 present tested", alwaysControl, nil, nil, func(c string) []model.Evidence {
			return []model.Evidence{ev(c, opts(testTested())...)}
		}, model.StatusVerifiedTested, 3, true},
		{"5 present implementation", alwaysControl, nil, nil, func(c string) []model.Evidence {
			return []model.Evidence{ev(c)}
		}, model.StatusVerifiedImplementation, 2, true},
		{"5 strongest present wins", alwaysControl, nil, nil, func(c string) []model.Evidence {
			return []model.Evidence{ev(c), ev(c, opts(testTested())...), ev(c, signal(model.SignalAbsent)), ev(c, signal(model.SignalDeclared))}
		}, model.StatusVerifiedTested, 3, true},
		{"5 present on a capability control with the capability", capabilityControl, []string{model.CapMemory}, nil, func(c string) []model.Evidence {
			return []model.Evidence{ev(c)}
		}, model.StatusVerifiedImplementation, 2, true},
		{"6 only declared", alwaysControl, nil, nil, func(c string) []model.Evidence {
			return []model.Evidence{ev(c, signal(model.SignalDeclared), strength(model.StrengthDeclared))}
		}, model.StatusDeclaredOnly, 1, true},
		{"6 declared beats absent", alwaysControl, nil, nil, func(c string) []model.Evidence {
			return []model.Evidence{ev(c, signal(model.SignalAbsent)), ev(c, signal(model.SignalDeclared))}
		}, model.StatusDeclaredOnly, 1, true},
		{"6 a declaration that claims operational strength stays declared-only", alwaysControl, nil, nil, func(c string) []model.Evidence {
			return []model.Evidence{ev(c, signal(model.SignalDeclared), strength(model.StrengthOperational), source(model.SourceRuntime))}
		}, model.StatusDeclaredOnly, 1, true},
		{"7 only absent", alwaysControl, nil, nil, func(c string) []model.Evidence {
			return []model.Evidence{ev(c, signal(model.SignalAbsent))}
		}, model.StatusMissing, 0, true},
		{"8 nothing", alwaysControl, nil, nil, func(c string) []model.Evidence { return nil }, model.StatusUnknown, 0, true},
		{"8 an unrecognized signal is an error, not a pass", alwaysControl, nil, nil, func(c string) []model.Evidence {
			return []model.Evidence{ev(c, signal("looks-fine"))}
		}, model.StatusError, 0, true},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			as, _, _ := run(t, scenario{agents: []model.Agent{agent("a1", tc.caps...)}, evidence: tc.evidence(tc.control), cfg: tc.cfg})
			r := control(t, as, tc.control)
			if r.Status != tc.want || r.Maturity != tc.wantMaturity || r.Applicable != tc.wantApplies {
				t.Fatalf("status %s maturity %d applicable %v; want %s %d %v (reason: %s)",
					r.Status, r.Maturity, r.Applicable, tc.want, tc.wantMaturity, tc.wantApplies, r.StatusReason)
			}
			if r.StatusReason == "" || r.NextAction == "" {
				t.Errorf("status reason and next action must be set")
			}
		})
	}
}

func TestUnknownMissingAndFailedStayDistinct(t *testing.T) {
	evidence := []model.Evidence{
		ev("AGC-003", signal(model.SignalAbsent), summary("No CI workflow runs governance checks.")),
		ev("AGC-008", signal(model.SignalViolation), summary("A hardcoded secret was found in agent.py at line 12.")),
	}
	as, score, _ := run(t, scenario{agents: []model.Agent{fullAgent("a1")}, evidence: evidence})
	missing, failed, unknown := control(t, as, "AGC-003"), control(t, as, "AGC-008"), control(t, as, "AGC-011")
	if missing.Status != model.StatusMissing || failed.Status != model.StatusFailed || unknown.Status != model.StatusUnknown {
		t.Fatalf("statuses: %s %s %s", missing.Status, failed.Status, unknown.Status)
	}
	if missing.StatusReason != "No CI workflow runs governance checks." {
		t.Errorf("missing reason: %q", missing.StatusReason)
	}
	if failed.StatusReason != "A hardcoded secret was found in agent.py at line 12." {
		t.Errorf("failed reason: %q", failed.StatusReason)
	}
	if unknown.StatusReason != MsgNoDetector {
		t.Errorf("unknown reason: %q", unknown.StatusReason)
	}
	cat := catalog(t)
	if missing.NextAction != cat.Controls[2].Remediation[0] || failed.NextAction != cat.Controls[7].Remediation[0] {
		t.Errorf("missing and failed must point at the first remediation step")
	}
	if unknown.NextAction != NextSupplyEvidence {
		t.Errorf("unknown next action: %q", unknown.NextAction)
	}
	if score.StatusCounts["missing"] != 1 || score.StatusCounts["failed"] != 1 || score.StatusCounts["unknown"] != 22 {
		t.Errorf("status counts: %v", score.StatusCounts)
	}
}

func TestCollectorErrorNeverPasses(t *testing.T) {
	cat := catalog(t)
	evidence := evidenceForAll(cat, opts(runtimeOperational(), []evOpt{signed()})...)
	evidence = append(evidence, ev("AGC-022", signal(model.SignalError), summary("The trace collector timed out")))
	as, score, d := run(t, scenario{agents: []model.Agent{fullAgent("a1")}, evidence: evidence, profile: profile(t, ProfileBaseline)})
	r := control(t, as, "AGC-022")
	if r.Status != model.StatusError || r.Maturity != 0 {
		t.Fatalf("status %s maturity %d", r.Status, r.Maturity)
	}
	if r.StatusReason != "The check could not complete: The trace collector timed out." {
		t.Errorf("reason: %q", r.StatusReason)
	}
	if r.NextAction != NextFixCollector {
		t.Errorf("next action: %q", r.NextAction)
	}
	if d.Outcome != model.OutcomeBlock || !hasReason(d, ReasonMandatoryError, "AGC-022") {
		t.Errorf("decision %s %v", d.Outcome, reasonCodes(d))
	}
	if score.Value == nil || *score.Value != 94 {
		t.Errorf("score %v, want 94", score.Label)
	}
	// Error-only evidence does not count as coverage.
	if score.ControlsWithEvidence != 24 {
		t.Errorf("AGC-022 also has valid present evidence, so coverage stays 24; got %d", score.ControlsWithEvidence)
	}
}

func TestInvalidEvidenceGivesNoCredit(t *testing.T) {
	past := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	tests := []struct {
		name string
		opt  []evOpt
		want string
	}{
		{"expired with date", []evOpt{validity(model.ValidityExpired), validUntil(past)}, "Evidence expired on 2026-01-01."},
		{"expired without date", []evOpt{validity(model.ValidityExpired)}, MsgExpiredNoDate},
		{"marked valid but past valid_until", []evOpt{validUntil(past)}, "Evidence expired on 2026-01-01."},
		{"commit mismatch", []evOpt{validity(model.ValidityCommitMismatch)}, "Evidence is bound to a different commit."},
		{"digest mismatch", []evOpt{validity(model.ValidityDigestMismatch)}, MsgDigestMismatch},
		{"invalid signature", []evOpt{validity(model.ValidityInvalidSignature)}, MsgBadSignature},
		{"marked valid but integrity invalid", []evOpt{integrity(model.IntegrityInvalid)}, MsgBadSignature},
		{"unbound", []evOpt{validity(model.ValidityUnbound)}, MsgUnbound},
		{"malformed", []evOpt{validity(model.ValidityMalformed)}, MsgMalformed},
		{"no validity state", []evOpt{validity("")}, "Evidence has no validity state and was not credited."},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			item := ev("AGC-022", opts(runtimeOperational(), []evOpt{signed()}, tc.opt)...)
			as, score, d := run(t, scenario{agents: []model.Agent{fullAgent("a1")}, evidence: []model.Evidence{item}, profile: profile(t, ProfileBaseline)})
			r := control(t, as, "AGC-022")
			if r.Status != model.StatusUnknown || r.Maturity != 0 {
				t.Fatalf("status %s maturity %d, want unknown 0", r.Status, r.Maturity)
			}
			if r.StatusReason != tc.want {
				t.Errorf("reason %q, want %q", r.StatusReason, tc.want)
			}
			if len(r.EvidenceRefs) != 1 || r.EvidenceRefs[0] != item.EvidenceID {
				t.Errorf("the invalid evidence must stay referenced: %v", r.EvidenceRefs)
			}
			if r.NextAction != NextFreshEvidence {
				t.Errorf("next action %q", r.NextAction)
			}
			if score.ControlsWithEvidence != 0 {
				t.Errorf("invalid evidence must not count as coverage")
			}
			if !hasReason(d, ReasonMandatoryEvidenceInvalid, "AGC-022") || d.Outcome != model.OutcomeBlock {
				t.Errorf("decision %s %v", d.Outcome, reasonCodes(d))
			}
		})
	}

	t.Run("a future valid_until is credited", func(t *testing.T) {
		item := ev("AGC-022", opts(runtimeOperational(), []evOpt{validUntil(testNow.Add(time.Hour))})...)
		as, _, _ := run(t, scenario{agents: []model.Agent{fullAgent("a1")}, evidence: []model.Evidence{item}})
		if r := control(t, as, "AGC-022"); r.Maturity != 4 {
			t.Fatalf("maturity %d", r.Maturity)
		}
	})

	t.Run("valid evidence is kept and the invalid item is named", func(t *testing.T) {
		items := []model.Evidence{ev("AGC-022", summary("Tracing is configured.")), ev("AGC-022", opts(testTested(), []evOpt{validity(model.ValidityCommitMismatch)})...)}
		as, _, d := run(t, scenario{agents: []model.Agent{fullAgent("a1")}, evidence: items, profile: profile(t, ProfileHighRisk)})
		r := control(t, as, "AGC-022")
		if r.Status != model.StatusVerifiedImplementation {
			t.Fatalf("status %s", r.Status)
		}
		want := "Tracing is configured. Other evidence was not credited: Evidence is bound to a different commit."
		if r.StatusReason != want {
			t.Errorf("reason %q, want %q", r.StatusReason, want)
		}
		if !hasReason(d, ReasonMandatoryEvidenceInvalid, "AGC-022") {
			t.Errorf("want evidence-invalid for the shortfall, got %v", reasonCodes(d))
		}
	})

	t.Run("an invalid violation does not fail the control", func(t *testing.T) {
		items := []model.Evidence{ev("AGC-022", signal(model.SignalViolation), validity(model.ValidityMalformed))}
		as, _, _ := run(t, scenario{agents: []model.Agent{fullAgent("a1")}, evidence: items})
		if r := control(t, as, "AGC-022"); r.Status != model.StatusUnknown || r.StatusReason != MsgMalformed {
			t.Fatalf("status %s reason %q", r.Status, r.StatusReason)
		}
	})
}

func TestStaticEvidenceIsCapped(t *testing.T) {
	tests := []struct {
		name    string
		control string
		opt     []evOpt
		want    model.Status
	}{
		{"static claiming operational", alwaysControl, []evOpt{strength(model.StrengthOperational)}, model.StatusVerifiedImplementation},
		{"static claiming tested", alwaysControl, []evOpt{strength(model.StrengthTested)}, model.StatusVerifiedImplementation},
		{"configuration claiming operational", alwaysControl, []evOpt{source(model.SourceConfiguration), strength(model.StrengthOperational)}, model.StatusVerifiedImplementation},
		{"unrecognized source claiming operational", alwaysControl, []evOpt{source("hearsay"), strength(model.StrengthOperational)}, model.StatusVerifiedImplementation},
		{"signed static evidence is still capped", alwaysControl, []evOpt{strength(model.StrengthOperational), signed()}, model.StatusVerifiedImplementation},
		{"static on a declaration-only control", declarationOnly, []evOpt{strength(model.StrengthOperational)}, model.StatusDeclaredOnly},
		{"static implementation on a declaration-only control", declarationOnly, nil, model.StatusDeclaredOnly},
		{"manual review can lift a declaration-only control", declarationOnly, []evOpt{source(model.SourceManualReview)}, model.StatusVerifiedImplementation},
		{"attestation can reach operational", declarationOnly, []evOpt{source(model.SourceAttestation), strength(model.StrengthOperational)}, model.StatusVerifiedOperational},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			as, _, _ := run(t, scenario{agents: []model.Agent{fullAgent("a1")}, evidence: []model.Evidence{ev(tc.control, tc.opt...)}})
			r := control(t, as, tc.control)
			if r.Status != tc.want {
				t.Fatalf("status %s, want %s (%s)", r.Status, tc.want, r.StatusReason)
			}
			if r.Maturity > r.MaxStaticMaturity && strings.HasPrefix(tc.name, "static") {
				t.Errorf("static evidence gave maturity %d above the cap %d", r.Maturity, r.MaxStaticMaturity)
			}
		})
	}

	as, _, _ := run(t, scenario{agents: []model.Agent{fullAgent("a1")}, evidence: []model.Evidence{
		ev(alwaysControl, strength(model.StrengthOperational), summary("Limits are set in config.py."))}})
	r := control(t, as, alwaysControl)
	if want := "Limits are set in config.py. Static evidence cannot support more than level 2 for this control."; r.StatusReason != want {
		t.Errorf("reason %q, want %q", r.StatusReason, want)
	}
	if r.NextAction != NextAddTests {
		t.Errorf("next action %q", r.NextAction)
	}
}

func TestNextActions(t *testing.T) {
	as, _, _ := run(t, scenario{agents: []model.Agent{fullAgent("a1")}, evidence: []model.Evidence{
		ev("AGC-003", opts(testTested())...),
		ev("AGC-004", opts(runtimeOperational())...),
		ev("AGC-001"),
		ev("AGC-011", signal(model.SignalDeclared)),
	}})
	cat := catalog(t)
	for id, want := range map[string]string{
		"AGC-003": NextCollectRuntime,
		"AGC-004": NextKeepCurrent,
		"AGC-001": NextExternalOnly,
		"AGC-011": cat.Controls[10].Remediation[0],
	} {
		if got := control(t, as, id).NextAction; got != want {
			t.Errorf("%s next action %q, want %q", id, got, want)
		}
	}
}

func TestNotApplicable(t *testing.T) {
	t.Run("inferred when no capability is detected", func(t *testing.T) {
		as, _, _ := run(t, scenario{agents: []model.Agent{agent("a1")}})
		r := control(t, as, "AGC-013")
		if r.Status != model.StatusNotApplicable || r.Applicable || r.ApplicabilityBasis != model.BasisInferred {
			t.Fatalf("%+v", r)
		}
		for _, name := range []string{"shell-exec", "code-exec", "container", "inference"} {
			if !strings.Contains(r.ApplicabilityReason, name) {
				t.Errorf("reason must name %q: %s", name, r.ApplicabilityReason)
			}
		}
		if a := control(t, as, "AGC-014"); !a.Applicable || a.ApplicabilityBasis != model.BasisAlways {
			t.Errorf("AGC-014 always applies: %+v", a)
		}
	})

	t.Run("capability modes follow the catalog", func(t *testing.T) {
		want := map[string]string{
			"AGC-005": model.CapTools, "AGC-006": model.CapCredentials, "AGC-007": model.CapDataAccess,
			"AGC-009": model.CapShellExec, "AGC-010": model.CapSensitiveActions, "AGC-013": model.CapContainer,
			"AGC-015": model.CapMemory, "AGC-016": model.CapMultiAgent, "AGC-018": model.CapMutatingActions,
		}
		none, _, _ := run(t, scenario{agents: []model.Agent{agent("a1")}})
		for _, r := range none[0].Controls {
			_, capability := want[r.ControlID]
			if capability == r.Applicable {
				t.Errorf("%s: applicable=%v with no capabilities", r.ControlID, r.Applicable)
			}
		}
		for id, capName := range want {
			as, _, _ := run(t, scenario{agents: []model.Agent{agent("a1", capName)}})
			if r := control(t, as, id); !r.Applicable || r.ApplicabilityBasis != model.BasisDetected {
				t.Errorf("%s with %s: %+v", id, capName, r)
			}
		}
	})

	t.Run("declared in configuration", func(t *testing.T) {
		cfg := &config.Config{Capabilities: config.Capabilities{DeclaredTools: []string{"x.read"}, SensitiveActions: []string{"x.delete"}}}
		as, _, _ := run(t, scenario{agents: []model.Agent{agent("a1")}, cfg: cfg})
		for _, id := range []string{"AGC-005", "AGC-009", "AGC-010", "AGC-018"} {
			if r := control(t, as, id); !r.Applicable || r.ApplicabilityBasis != model.BasisDeclared {
				t.Errorf("%s: %+v", id, r)
			}
		}
		if r := control(t, as, "AGC-007"); r.Applicable {
			t.Errorf("AGC-007 is not declared by tools: %+v", r)
		}
	})

	t.Run("approved exception", func(t *testing.T) {
		cfg := &config.Config{Policy: config.Policy{NotApplicable: []config.Exception{
			exception("AGC-016", "Single agent with no peers.", "review-board", "2026-11-15")}}}
		as, _, d := run(t, scenario{agents: []model.Agent{fullAgent("a1")}, cfg: cfg,
			profile: &model.Profile{Name: "p", MandatoryControls: []string{"AGC-016"}, MinMaturity: 2}})
		r := control(t, as, "AGC-016")
		if r.Status != model.StatusNotApplicable || r.ApplicabilityBasis != model.BasisApproved || r.Applicable {
			t.Fatalf("%+v", r)
		}
		if !strings.Contains(r.ApplicabilityReason, "review-board") || !strings.Contains(r.ApplicabilityReason, "Single agent with no peers.") {
			t.Errorf("reason must carry approver and reason: %s", r.ApplicabilityReason)
		}
		if d.Outcome != model.OutcomeAllow {
			t.Errorf("an approved exception on the expiry day satisfies a mandatory control; got %s %v", d.Outcome, reasonCodes(d))
		}
	})

	t.Run("expired or incomplete exceptions are ignored", func(t *testing.T) {
		for name, x := range map[string]config.Exception{
			"expired":     exception("AGC-016", "Single agent.", "review-board", "2026-11-14"),
			"no approver": exception("AGC-016", "Single agent.", " ", ""),
			"no reason":   exception("AGC-016", "", "review-board", ""),
			"bad date":    exception("AGC-016", "Single agent.", "review-board", "next year"),
		} {
			cfg := &config.Config{Policy: config.Policy{NotApplicable: []config.Exception{x}, AcceptedRisks: []config.Exception{x}}}
			as, _, _ := run(t, scenario{agents: []model.Agent{fullAgent("a1")}, cfg: cfg})
			r := control(t, as, "AGC-016")
			if r.Status != model.StatusUnknown || !r.Applicable {
				t.Errorf("%s: status %s applicable %v", name, r.Status, r.Applicable)
			}
			if name == "expired" && !strings.Contains(r.StatusReason, "expired on 2026-11-14") {
				t.Errorf("expired exception must be named: %s", r.StatusReason)
			}
		}
	})

	t.Run("not-applicable does not hide a violation", func(t *testing.T) {
		cfg := &config.Config{Policy: config.Policy{NotApplicable: []config.Exception{
			exception("AGC-008", "No secrets in this repository.", "review-board", "")}}}
		items := []model.Evidence{ev("AGC-008", signal(model.SignalViolation), summary("A hardcoded secret was found in agent.py at line 12."))}
		as, score, d := run(t, scenario{agents: []model.Agent{fullAgent("a1")}, cfg: cfg, evidence: items, profile: profile(t, ProfileBaseline)})
		r := control(t, as, "AGC-008")
		if r.Status != model.StatusFailed || !r.Applicable {
			t.Fatalf("%+v", r)
		}
		if !strings.Contains(r.StatusReason, "does not hide this result") {
			t.Errorf("reason: %s", r.StatusReason)
		}
		if score.ApplicableControls != 24 || !hasReason(d, ReasonMandatoryFailed, "AGC-008") {
			t.Errorf("the failed control must stay in the denominator and block: %d %v", score.ApplicableControls, reasonCodes(d))
		}
	})

	t.Run("inferred not-applicable on a mandatory control needs review", func(t *testing.T) {
		as, _, d := run(t, scenario{agents: []model.Agent{agent("a1")},
			profile: &model.Profile{Name: "p", MandatoryControls: []string{"AGC-010"}, MinMaturity: 2}})
		if r := control(t, as, "AGC-010"); r.Status != model.StatusNotApplicable {
			t.Fatalf("%+v", r)
		}
		if d.Outcome != model.OutcomeReviewRequired || !hasReason(d, ReasonMandatoryNAInferred, "AGC-010") {
			t.Errorf("decision %s %v", d.Outcome, reasonCodes(d))
		}
	})
}

func TestAcceptedRiskStaysVisibleAtMaturityZero(t *testing.T) {
	cat := catalog(t)
	cfg := &config.Config{Policy: config.Policy{AcceptedRisks: []config.Exception{
		exception("AGC-012", "Limits arrive next quarter.", "ciso", "2027-03-31")}}}
	evidence := evidenceForAll(cat, opts(runtimeOperational())...)
	as, score, d := run(t, scenario{agents: []model.Agent{fullAgent("a1")}, cfg: cfg, evidence: evidence, profile: profile(t, ProfileStandard)})
	r := control(t, as, "AGC-012")
	if r.Status != model.StatusAcceptedRisk || r.Maturity != 0 || !r.Applicable {
		t.Fatalf("%+v", r)
	}
	if !strings.Contains(r.StatusReason, "ciso") || !strings.Contains(r.StatusReason, "not a pass") {
		t.Errorf("reason: %s", r.StatusReason)
	}
	if score.ApplicableControls != 24 || score.StatusCounts["accepted-risk"] != 1 {
		t.Errorf("accepted risk must stay in the denominator: %+v", score)
	}
	// 82 of 85 weight points at maturity 4: round(100*82/85) = 96.
	if score.Value == nil || *score.Value != 96 {
		t.Errorf("score %s, want 96", score.Label)
	}
	if d.Outcome != model.OutcomeReviewRequired || !hasReason(d, ReasonMandatoryAcceptedRisk, "AGC-012") {
		t.Errorf("decision %s %v", d.Outcome, reasonCodes(d))
	}
	if !reflect.DeepEqual(score.UnresolvedMandatory, []string{"AGC-012"}) {
		t.Errorf("unresolved mandatory: %v", score.UnresolvedMandatory)
	}
}

// TestHighScoreCannotOverrideMandatoryFailure is the central guarantee of the
// product: the score never changes the decision.
func TestHighScoreCannotOverrideMandatoryFailure(t *testing.T) {
	cat := catalog(t)
	operational := func() []model.Evidence {
		return evidenceForAll(cat, opts(runtimeOperational(), []evOpt{signed()})...)
	}

	t.Run("23 controls at maturity 4 and one mandatory control failed", func(t *testing.T) {
		evidence := replace(operational(), "AGC-008",
			ev("AGC-008", signal(model.SignalViolation), summary("A hardcoded secret was found in agent.py at line 12.")))
		for _, name := range ProfileNames() {
			as, score, d := run(t, scenario{agents: []model.Agent{fullAgent("a1")}, evidence: evidence, profile: profile(t, name)})
			if score.Value == nil || *score.Value != 95 {
				t.Fatalf("%s: score %s, want 95/100", name, score.Label)
			}
			if score.StatusCounts["verified-operational"] != 23 || score.StatusCounts["failed"] != 1 {
				t.Fatalf("%s: status counts %v", name, score.StatusCounts)
			}
			if d.Outcome != model.OutcomeBlock {
				t.Fatalf("%s: a score of %s must not override a failed mandatory control; got %s", name, score.Label, d.Outcome)
			}
			if !hasReason(d, ReasonMandatoryFailed, "AGC-008") {
				t.Errorf("%s: reasons %v", name, reasonCodes(d))
			}
			if !reflect.DeepEqual(score.UnresolvedMandatory, []string{"AGC-008"}) {
				t.Errorf("%s: unresolved %v", name, score.UnresolvedMandatory)
			}
			if as[0].Decision.Outcome != model.OutcomeBlock {
				t.Errorf("%s: the agent decision must block as well", name)
			}
		}
	})

	t.Run("score exactly 100 and a critical finding on a mandatory control", func(t *testing.T) {
		findings := []model.Finding{finding("f-1", "AGC-008", model.SeverityCritical)}
		_, score, d := run(t, scenario{agents: []model.Agent{fullAgent("a1")}, evidence: operational(), findings: findings, profile: profile(t, ProfileHighRisk)})
		if score.Value == nil || *score.Value != 100 {
			t.Fatalf("score %s, want 100/100", score.Label)
		}
		if d.Outcome != model.OutcomeBlock || !hasReason(d, ReasonCriticalFinding, "AGC-008") {
			t.Fatalf("a perfect score must not override a critical finding; got %s %v", d.Outcome, reasonCodes(d))
		}
		if score.FindingsBySeverity["critical"] != 1 {
			t.Errorf("findings by severity: %v", score.FindingsBySeverity)
		}
	})

	t.Run("score exactly 100 and a critical finding on a control that is not mandatory", func(t *testing.T) {
		findings := []model.Finding{finding("f-1", "AGC-024", model.SeverityCritical)}
		_, score, d := run(t, scenario{agents: []model.Agent{fullAgent("a1")}, evidence: operational(), findings: findings, profile: profile(t, ProfileBaseline)})
		if *score.Value != 100 || d.Outcome != model.OutcomeBlock || !hasReason(d, ReasonCriticalFinding, "AGC-024") {
			t.Fatalf("score %s decision %s %v", score.Label, d.Outcome, reasonCodes(d))
		}
	})

	t.Run("score exactly 100 over applicable controls and a mandatory control in error", func(t *testing.T) {
		// A profile weight cannot hide the error either: the control stays
		// applicable at maturity 0, so the highest reachable score is below
		// 100, and the decision is BLOCK in any case.
		evidence := append(operational(), ev("AGC-022", signal(model.SignalError), summary("Collector crashed.")))
		_, score, d := run(t, scenario{agents: []model.Agent{fullAgent("a1")}, evidence: evidence, profile: profile(t, ProfileBaseline)})
		if *score.Value < 90 || d.Outcome != model.OutcomeBlock || !hasReason(d, ReasonMandatoryError, "AGC-022") {
			t.Fatalf("score %s decision %s %v", score.Label, d.Outcome, reasonCodes(d))
		}
	})

	t.Run("high findings do not block on their own", func(t *testing.T) {
		findings := []model.Finding{finding("f-1", "AGC-024", model.SeverityHigh)}
		_, _, d := run(t, scenario{agents: []model.Agent{fullAgent("a1")}, evidence: operational(), findings: findings, profile: profile(t, ProfileHighRisk)})
		if d.Outcome != model.OutcomeAllow {
			t.Fatalf("decision %s %v", d.Outcome, reasonCodes(d))
		}
	})

	t.Run("everything verified is allowed with one reason", func(t *testing.T) {
		_, score, d := run(t, scenario{agents: []model.Agent{fullAgent("a1")}, evidence: operational(), profile: profile(t, ProfileHighRisk)})
		if d.Outcome != model.OutcomeAllow || len(d.Reasons) != 1 || d.Reasons[0].Code != ReasonPolicySatisfied {
			t.Fatalf("decision %s %v", d.Outcome, reasonCodes(d))
		}
		if !strings.Contains(d.Reasons[0].Message, "not a certification") {
			t.Errorf("the allow message must not read as certification: %s", d.Reasons[0].Message)
		}
		if *score.Value != 100 || score.CoveragePercent != 100 || score.TestedPercent != 100 || score.OperationalPercent != 100 {
			t.Errorf("score %+v", score)
		}
	})

	t.Run("a low score with every mandatory control met is allowed", func(t *testing.T) {
		p := profile(t, ProfileBaseline)
		var evidence []model.Evidence
		for _, id := range p.MandatoryControls {
			evidence = append(evidence, ev(id, source(model.SourceManualReview)))
		}
		_, score, d := run(t, scenario{agents: []model.Agent{fullAgent("a1")}, evidence: evidence, profile: p})
		if d.Outcome != model.OutcomeAllow {
			t.Fatalf("decision %s %v", d.Outcome, reasonCodes(d))
		}
		if *score.Value >= 50 {
			t.Errorf("expected a low score, got %s", score.Label)
		}
	})
}

func TestMandatoryShortfallReasons(t *testing.T) {
	p := &model.Profile{Name: "p", Version: "1", MinMaturity: 3,
		MandatoryControls: []string{"AGC-003", "AGC-011", "AGC-012", "AGC-014", "AGC-017", "AGC-019"}}
	evidence := []model.Evidence{
		ev("AGC-003", signal(model.SignalAbsent)), // missing
		ev("AGC-012"), // implementation, below 3
		ev("AGC-014", signal(model.SignalDeclared)),           // declared-only, below 3
		ev("AGC-017", opts(testTested())...),                  // meets 3
		ev("AGC-019", validity(model.ValidityDigestMismatch)), // invalid
	}
	_, score, d := run(t, scenario{agents: []model.Agent{fullAgent("a1")}, evidence: evidence, profile: p})
	want := []struct{ code, id string }{
		{ReasonMandatoryMissing, "AGC-003"},
		{ReasonMandatoryUnknown, "AGC-011"},
		{ReasonMandatoryBelowMin, "AGC-012"},
		{ReasonMandatoryBelowMin, "AGC-014"},
		{ReasonMandatoryEvidenceInvalid, "AGC-019"},
	}
	if d.Outcome != model.OutcomeBlock || len(d.Reasons) != len(want) {
		t.Fatalf("decision %s %v", d.Outcome, d.Reasons)
	}
	for i, w := range want {
		r := d.Reasons[i]
		if r.Code != w.code || r.ControlID != w.id || r.AgentID != "a1" || r.Message == "" {
			t.Errorf("reason %d: %+v, want %s on %s", i, r, w.code, w.id)
		}
	}
	if !reflect.DeepEqual(score.UnresolvedMandatory, []string{"AGC-003", "AGC-011", "AGC-012", "AGC-014", "AGC-019"}) {
		t.Errorf("unresolved %v", score.UnresolvedMandatory)
	}
	if !strings.Contains(d.Reasons[2].Message, "maturity 2") || !strings.Contains(d.Reasons[2].Message, "requires 3") {
		t.Errorf("below-min message must give both levels: %s", d.Reasons[2].Message)
	}
}

func TestReviewWorkflow(t *testing.T) {
	base := func(review bool) *model.Profile {
		return &model.Profile{Name: "p", Version: "1", MinMaturity: 3, ReviewWorkflow: review,
			MandatoryControls: []string{"AGC-003", "AGC-011", "AGC-012"}}
	}
	soft := []model.Evidence{ev("AGC-003", signal(model.SignalAbsent)), ev("AGC-012")}

	_, _, d := run(t, scenario{agents: []model.Agent{fullAgent("a1")}, evidence: soft, profile: base(false)})
	if d.Outcome != model.OutcomeBlock {
		t.Fatalf("without a review workflow: %s", d.Outcome)
	}

	_, _, d = run(t, scenario{agents: []model.Agent{fullAgent("a1")}, evidence: soft, profile: base(true)})
	if d.Outcome != model.OutcomeReviewRequired {
		t.Fatalf("with a review workflow: %s %v", d.Outcome, reasonCodes(d))
	}
	wantCodes := []string{ReasonMandatoryMissing, ReasonMandatoryUnknown, ReasonMandatoryBelowMin, ReasonReviewWorkflow}
	if !reflect.DeepEqual(reasonCodes(d), wantCodes) {
		t.Errorf("codes %v, want %v", reasonCodes(d), wantCodes)
	}

	for name, hard := range map[string]model.Evidence{
		ReasonMandatoryFailed:          ev("AGC-011", signal(model.SignalViolation)),
		ReasonMandatoryError:           ev("AGC-011", signal(model.SignalError)),
		ReasonMandatoryEvidenceInvalid: ev("AGC-011", validity(model.ValidityExpired)),
	} {
		_, _, d = run(t, scenario{agents: []model.Agent{fullAgent("a1")}, evidence: append(append([]model.Evidence{}, soft...), hard), profile: base(true)})
		if d.Outcome != model.OutcomeBlock || !hasReason(d, name, "AGC-011") {
			t.Errorf("%s must block even with a review workflow: %s %v", name, d.Outcome, reasonCodes(d))
		}
	}

	_, _, d = run(t, scenario{agents: []model.Agent{fullAgent("a1")}, evidence: soft, profile: base(true),
		findings: []model.Finding{finding("f-1", "AGC-020", model.SeverityCritical)}})
	if d.Outcome != model.OutcomeBlock {
		t.Errorf("a critical finding must block even with a review workflow: %s", d.Outcome)
	}
}

func TestSignedEvidenceRequirement(t *testing.T) {
	cat := catalog(t)
	p := profile(t, ProfileHighRisk)
	build := func(i model.Integrity) []model.Evidence {
		return evidenceForAll(cat, opts(testTested(), []evOpt{integrity(i), summary("Governance tests passed.")})...)
	}

	t.Run("unsigned tested evidence is below the minimum", func(t *testing.T) {
		as, score, d := run(t, scenario{agents: []model.Agent{fullAgent("a1")}, evidence: build(model.IntegrityUnsigned), profile: p})
		r := control(t, as, "AGC-010")
		if r.Status != model.StatusVerifiedImplementation || r.Maturity != 2 {
			t.Fatalf("status %s maturity %d", r.Status, r.Maturity)
		}
		if want := "Governance tests passed. " + MsgUnsignedCapped; r.StatusReason != want {
			t.Errorf("reason %q, want %q", r.StatusReason, want)
		}
		if r.NextAction != NextSignEvidence {
			t.Errorf("next action %q", r.NextAction)
		}
		if d.Outcome != model.OutcomeBlock || len(d.Reasons) != len(p.MandatoryControls) {
			t.Fatalf("decision %s with %d reasons", d.Outcome, len(d.Reasons))
		}
		for _, reason := range d.Reasons {
			if reason.Code != ReasonMandatoryBelowMin || !strings.Contains(reason.Message, "unsigned") {
				t.Errorf("reason %+v", reason)
			}
		}
		if *score.Value != 50 || score.TestedPercent != 0 {
			t.Errorf("score %s tested %d%%", score.Label, score.TestedPercent)
		}
	})

	t.Run("not-available integrity is not a signature", func(t *testing.T) {
		_, _, d := run(t, scenario{agents: []model.Agent{fullAgent("a1")}, evidence: build(model.IntegrityNotAvailable), profile: p})
		if d.Outcome != model.OutcomeBlock {
			t.Fatalf("decision %s", d.Outcome)
		}
	})

	t.Run("the same evidence with verified integrity satisfies the profile", func(t *testing.T) {
		as, score, d := run(t, scenario{agents: []model.Agent{fullAgent("a1")}, evidence: build(model.IntegrityVerified), profile: p})
		if r := control(t, as, "AGC-010"); r.Status != model.StatusVerifiedTested || r.StatusReason != "Governance tests passed." {
			t.Fatalf("status %s reason %q", r.Status, r.StatusReason)
		}
		if d.Outcome != model.OutcomeAllow {
			t.Fatalf("decision %s %v", d.Outcome, reasonCodes(d))
		}
		if *score.Value != 75 || score.TestedPercent != 100 || score.OperationalPercent != 0 {
			t.Errorf("score %+v", score)
		}
	})

	t.Run("unsigned evidence counts where signatures are not required", func(t *testing.T) {
		as, _, _ := run(t, scenario{agents: []model.Agent{fullAgent("a1")}, evidence: build(model.IntegrityUnsigned), profile: profile(t, ProfileStandard)})
		if r := control(t, as, "AGC-010"); r.Status != model.StatusVerifiedTested {
			t.Fatalf("status %s", r.Status)
		}
	})
}

func TestScore(t *testing.T) {
	t.Run("not-applicable controls leave the denominator", func(t *testing.T) {
		// No capabilities: nine capability-mode controls do not apply.
		cat := catalog(t)
		var evidence []model.Evidence
		for _, c := range cat.Controls {
			evidence = append(evidence, ev(c.ID, opts(runtimeOperational())...))
		}
		as, score, _ := run(t, scenario{agents: []model.Agent{agent("a1")}, evidence: evidence})
		if score.ApplicableControls != 15 || score.StatusCounts["not-applicable"] != 9 {
			t.Fatalf("applicable %d, counts %v", score.ApplicableControls, score.StatusCounts)
		}
		if *score.Value != 100 || score.ControlsWithEvidence != 15 || score.CoveragePercent != 100 {
			t.Errorf("score %+v", score)
		}
		total := 0
		for _, n := range score.StatusCounts {
			total += n
		}
		if total != 24 || len(score.StatusCounts) != 10 || len(score.FindingsBySeverity) != 5 {
			t.Errorf("counts must cover all 24 controls, 10 statuses, 5 severities: %v %v", score.StatusCounts, score.FindingsBySeverity)
		}
		if len(as[0].Controls) != 24 {
			t.Errorf("not-applicable controls must still be listed")
		}
	})

	t.Run("no applicable controls gives insufficient-evidence", func(t *testing.T) {
		cat := catalog(t)
		small := &model.Catalog{Pack: "test", Version: "1"}
		for _, c := range cat.Controls {
			if c.Applicability.Mode == "capability" {
				small.Controls = append(small.Controls, c)
			}
		}
		_, score, d := run(t, scenario{agents: []model.Agent{agent("a1")}, cat: small})
		if score.Value != nil || score.Label != scoring.InsufficientEvidence || score.ApplicableControls != 0 {
			t.Fatalf("score %+v", score)
		}
		if score.CoveragePercent != 0 || score.TestedPercent != 0 || score.OperationalPercent != 0 {
			t.Errorf("percentages must be 0: %+v", score)
		}
		if d.Outcome != model.OutcomeAllow {
			t.Errorf("no mandatory controls in this profile: %s", d.Outcome)
		}
	})

	t.Run("profile weights change the score and not the decision", func(t *testing.T) {
		evidence := []model.Evidence{ev("AGC-012", opts(runtimeOperational())...)}
		light := &model.Profile{Name: "p", MandatoryControls: []string{"AGC-022"}, MinMaturity: 2}
		heavy := &model.Profile{Name: "p", MandatoryControls: []string{"AGC-022"}, MinMaturity: 2, Weights: map[string]int{"AGC-012": 100}}
		_, s1, d1 := run(t, scenario{agents: []model.Agent{agent("a1")}, evidence: evidence, profile: light})
		_, s2, d2 := run(t, scenario{agents: []model.Agent{agent("a1")}, evidence: evidence, profile: heavy})
		// 15 applicable controls weigh 51 in total; AGC-012 weighs 3.
		// round(100*3/51) = 6 and round(100*100/148) = 68.
		if *s1.Value != 6 || *s2.Value != 68 {
			t.Errorf("scores %s and %s, want 6 and 68", s1.Label, s2.Label)
		}
		if d1.Outcome != model.OutcomeBlock || d2.Outcome != model.OutcomeBlock {
			t.Errorf("decisions %s %s", d1.Outcome, d2.Outcome)
		}
	})
}

// TestWorkedExample pins the numbers used in docs/scoring.md.
func TestWorkedExample(t *testing.T) {
	a := agent("support-agent", model.CapTools, model.CapDataAccess)
	id := forAgent("support-agent")
	evidence := []model.Evidence{
		ev("AGC-001", id, signal(model.SignalDeclared), strength(model.StrengthDeclared), source(model.SourceConfiguration)),
		ev("AGC-004", id, signal(model.SignalViolation), summary("The agent signs in with a shared staff account.")),
		ev("AGC-005", id, source(model.SourceTest), strength(model.StrengthTested)),
		ev("AGC-007", id),
		ev("AGC-008", id),
		ev("AGC-012", id),
		ev("AGC-020", id, signal(model.SignalAbsent)),
		ev("AGC-022", id, source(model.SourceRuntime), strength(model.StrengthOperational)),
	}
	as, score, d := run(t, scenario{agents: []model.Agent{a}, evidence: evidence, profile: profile(t, ProfileStandard)})

	if score.ApplicableControls != 17 {
		t.Fatalf("applicable %d, want 17", score.ApplicableControls)
	}
	var weight, points int
	for _, r := range as[0].Controls {
		if r.Applicable {
			weight += r.Weight
			points += r.Weight * r.Maturity
		}
	}
	if weight != 61 || points != 64 {
		t.Fatalf("weight %d points %d, want 61 and 64", weight, points)
	}
	if score.Label != "26/100" {
		t.Errorf("score %s, want 26/100", score.Label)
	}
	if score.ControlsWithEvidence != 8 || score.CoveragePercent != 47 || score.TestedPercent != 12 || score.OperationalPercent != 6 {
		t.Errorf("coverage %d (%d%%), tested %d%%, operational %d%%", score.ControlsWithEvidence, score.CoveragePercent, score.TestedPercent, score.OperationalPercent)
	}
	if d.Outcome != model.OutcomeBlock {
		t.Errorf("decision %s", d.Outcome)
	}
	if r := control(t, as, "AGC-001"); r.Status != model.StatusDeclaredOnly || r.MinMaturity != 1 {
		t.Errorf("AGC-001: %s, required %d", r.Status, r.MinMaturity)
	}
	// AGC-001 is declared-only and the standard profile accepts that.
	wantCodes := []string{
		ReasonMandatoryFailed,     // AGC-004
		ReasonMandatoryNAInferred, // AGC-010
		ReasonMandatoryUnknown,    // AGC-017
	}
	if !reflect.DeepEqual(reasonCodes(d), wantCodes) {
		t.Errorf("codes %v, want %v", reasonCodes(d), wantCodes)
	}
}

func TestNoAgentIsNotAPass(t *testing.T) {
	for name, det := range map[string]*model.Detection{
		"nil detection":      nil,
		"empty":              {},
		"only not-detected":  {Agents: []model.Agent{{ID: "x", Detection: model.NotDetected}}},
		"evidence, no agent": {Evidence: []model.Evidence{ev("AGC-008")}, Findings: []model.Finding{finding("f-1", "AGC-008", model.SeverityHigh)}},
	} {
		as, score, d := Evaluate(Input{Detection: det, Catalog: catalog(t), Profile: profile(t, ProfileBaseline), Now: testNow})
		if as == nil || len(as) != 0 {
			t.Errorf("%s: assessments must be empty and not nil", name)
		}
		if score.Value != nil || score.Label != scoring.InsufficientEvidence {
			t.Errorf("%s: score %+v", name, score)
		}
		if len(score.StatusCounts) != 10 || len(score.FindingsBySeverity) != 5 || score.UnresolvedMandatory == nil {
			t.Errorf("%s: score maps must be zero-filled: %+v", name, score)
		}
		if d.Outcome != model.OutcomeReviewRequired || len(d.Reasons) != 1 || d.Reasons[0].Code != ReasonNoAgentDetected {
			t.Errorf("%s: decision %s %v", name, d.Outcome, reasonCodes(d))
		}
		if !strings.Contains(d.Reasons[0].Message, "not a pass") {
			t.Errorf("%s: the message must say this is not a pass: %s", name, d.Reasons[0].Message)
		}
	}
}

func TestMissingPolicyInputBlocks(t *testing.T) {
	_, _, d := Evaluate(Input{Detection: &model.Detection{Agents: []model.Agent{fullAgent("a1")}}})
	if d.Outcome != model.OutcomeBlock || d.Reasons[0].Code != ReasonPolicyInputInvalid {
		t.Fatalf("decision %s %v", d.Outcome, reasonCodes(d))
	}
	// A mandatory control the catalog does not define blocks as well.
	small := &model.Catalog{Pack: "t", Version: "1", Controls: catalog(t).Controls[:3]}
	_, _, d = run(t, scenario{agents: []model.Agent{fullAgent("a1")}, cat: small,
		evidence: evidenceForAll(small, source(model.SourceManualReview)),
		profile:  &model.Profile{Name: "p", MandatoryControls: []string{"AGC-022"}}})
	if d.Outcome != model.OutcomeBlock || !hasReason(d, ReasonMandatoryUnknown, "AGC-022") {
		t.Fatalf("decision %s %v", d.Outcome, reasonCodes(d))
	}
}

func TestMultiAgentAggregation(t *testing.T) {
	cat := catalog(t)
	var evidence []model.Evidence
	// alpha: everything operational. beta: everything implementation.
	// gamma: everything implementation as well, so it ties with beta.
	evidence = append(evidence, evidenceForAll(cat, opts(runtimeOperational(), []evOpt{forAgent("alpha")})...)...)
	evidence = append(evidence, evidenceForAll(cat, forAgent("beta"), source(model.SourceManualReview))...)
	evidence = append(evidence, evidenceForAll(cat, forAgent("gamma"), source(model.SourceManualReview))...)
	// A repository-level violation applies to every agent.
	shared := ev("AGC-003", forAgent(model.AllAgents), signal(model.SignalViolation), summary("CI does not run governance checks."))
	findings := []model.Finding{
		{FindingID: "f-all", ControlID: "AGC-003", AgentID: model.AllAgents, Severity: model.SeverityMedium},
		{FindingID: "f-beta", ControlID: "AGC-008", AgentID: "beta", Severity: model.SeverityHigh},
	}
	agents := []model.Agent{fullAgent("gamma"), fullAgent("alpha"), fullAgent("beta")}
	p := profile(t, ProfileBaseline)

	as, score, d := run(t, scenario{agents: agents, evidence: evidence, profile: p})
	if len(as) != 3 || as[0].AgentID != "alpha" || as[1].AgentID != "beta" || as[2].AgentID != "gamma" {
		t.Fatalf("assessments must be in agent-ID order")
	}
	if as[0].Score.Label != "100/100" || as[1].Score.Label != "50/100" || as[2].Score.Label != "50/100" {
		t.Fatalf("agent scores %s %s %s", as[0].Score.Label, as[1].Score.Label, as[2].Score.Label)
	}
	if score.Label != "50/100" {
		t.Errorf("the repository score is the lowest agent score: %s", score.Label)
	}
	if d.Outcome != model.OutcomeAllow || len(d.Reasons) != 3 {
		t.Fatalf("decision %s %v", d.Outcome, d.Reasons)
	}
	for i, id := range []string{"alpha", "beta", "gamma"} {
		if d.Reasons[i].AgentID != id || d.Reasons[i].Code != ReasonPolicySatisfied {
			t.Errorf("reason %d: %+v", i, d.Reasons[i])
		}
	}

	// Now add the shared violation on a mandatory control and beta's finding.
	p.MandatoryControls = append(p.MandatoryControls, "AGC-003")
	for i := range findings {
		findings[i].Fingerprint = findings[i].FindingID
	}
	as, score, d = run(t, scenario{agents: agents, evidence: append(evidence, shared), findings: findings, profile: p})
	if d.Outcome != model.OutcomeBlock || len(d.Reasons) != 3 {
		t.Fatalf("decision %s %v", d.Outcome, d.Reasons)
	}
	for i, id := range []string{"alpha", "beta", "gamma"} {
		r := control(t, as[i:], "AGC-003")
		if r.Status != model.StatusFailed || !reflect.DeepEqual(r.FindingRefs, []string{"f-all"}) {
			t.Errorf("%s: shared evidence and findings apply to every agent: %+v", id, r)
		}
		if d.Reasons[i].AgentID != id || d.Reasons[i].Code != ReasonMandatoryFailed {
			t.Errorf("reason %d: %+v", i, d.Reasons[i])
		}
	}
	if got := control(t, as[1:], "AGC-008").FindingRefs; !reflect.DeepEqual(got, []string{"f-beta"}) {
		t.Errorf("beta finding refs %v", got)
	}
	if got := control(t, as, "AGC-008").FindingRefs; len(got) != 0 {
		t.Errorf("alpha must not see beta's finding: %v", got)
	}
	if as[1].Score.FindingsBySeverity["high"] != 1 || as[0].Score.FindingsBySeverity["high"] != 0 || as[0].Score.FindingsBySeverity["medium"] != 1 {
		t.Errorf("per-agent finding counts wrong")
	}
	// Ties go to the first agent ID; repository findings count every finding.
	if score.Label != as[1].Score.Label || score.FindingsBySeverity["high"] != 1 || score.FindingsBySeverity["medium"] != 1 {
		t.Errorf("repository score %+v", score)
	}
	if !reflect.DeepEqual(score.UnresolvedMandatory, []string{"AGC-003"}) {
		t.Errorf("unresolved %v", score.UnresolvedMandatory)
	}

	// One blocked agent blocks the repository even when the others pass.
	only := ev("AGC-008", forAgent("gamma"), signal(model.SignalViolation))
	_, _, d = run(t, scenario{agents: agents, evidence: append(evidence, only), profile: profile(t, ProfileBaseline)})
	if d.Outcome != model.OutcomeBlock || reasonCodes(d)[2] != ReasonMandatoryFailed || d.Reasons[2].AgentID != "gamma" {
		t.Errorf("decision %s %v", d.Outcome, d.Reasons)
	}
}

func TestDeterminism(t *testing.T) {
	cat := catalog(t)
	evidence := evidenceForAll(cat, forAgent("b"))
	evidence = append(evidence, evidenceForAll(cat, opts(testTested(), []evOpt{forAgent("a")})...)...)
	evidence = append(evidence,
		ev("AGC-008", forAgent("a"), signal(model.SignalViolation), withID("z-violation"), summary("Second violation.")),
		ev("AGC-008", forAgent("a"), signal(model.SignalViolation), withID("a-violation"), summary("First violation.")),
		ev("AGC-022", forAgent(model.AllAgents), validity(model.ValidityExpired)),
		ev("AGC-022", forAgent(model.AllAgents), validity(model.ValidityUnbound)),
	)
	findings := []model.Finding{finding("f-2", "AGC-008", model.SeverityCritical), finding("f-1", "AGC-008", model.SeverityCritical), finding("f-3", "", model.SeverityCritical)}
	for i := range findings {
		findings[i].AgentID = model.AllAgents
	}
	cfg := &config.Config{Policy: config.Policy{AcceptedRisks: []config.Exception{exception("AGC-021", "Planned.", "ciso", "")}}}
	agents := []model.Agent{fullAgent("b"), fullAgent("a")}

	encode := func(agents []model.Agent, evidence []model.Evidence, findings []model.Finding) string {
		as, score, d := run(t, scenario{agents: agents, evidence: evidence, findings: findings, cfg: cfg, profile: profile(t, ProfileHighRisk)})
		raw, err := json.Marshal(struct {
			A []model.AgentAssessment
			S model.Score
			D model.Decision
		}{as, score, d})
		if err != nil {
			t.Fatal(err)
		}
		return string(raw)
	}
	first := encode(agents, evidence, findings)
	if second := encode(agents, evidence, findings); first != second {
		t.Fatal("two runs on the same input differ")
	}

	// Reversed input order must give the same output.
	rev := func(in []model.Evidence) []model.Evidence {
		out := append([]model.Evidence{}, in...)
		for i, j := 0, len(out)-1; i < j; i, j = i+1, j-1 {
			out[i], out[j] = out[j], out[i]
		}
		return out
	}
	reversed := encode([]model.Agent{agents[1], agents[0]}, rev(evidence), []model.Finding{findings[2], findings[1], findings[0]})
	if first != reversed {
		t.Fatal("output depends on the order of the input")
	}
	if !strings.Contains(first, "First violation. 1 more violation recorded in addition.") {
		t.Error("the decisive violation must be the one with the lowest evidence ID")
	}
	if !strings.Contains(first, "Evidence has expired. Evidence is not bound to a commit or to file content.") {
		t.Error("several invalid causes must be listed in evidence-ID order")
	}
}

func TestInputIsNotModified(t *testing.T) {
	cat := catalog(t)
	p := profile(t, ProfileStandard)
	det := &model.Detection{
		Agents:   []model.Agent{fullAgent("b"), fullAgent("a")},
		Evidence: []model.Evidence{ev("AGC-008", withID("z")), ev("AGC-008", withID("a"))},
		Findings: []model.Finding{finding("f-2", "AGC-008", model.SeverityLow), finding("f-1", "AGC-008", model.SeverityLow)},
	}
	before, _ := json.Marshal([]any{det, cat, p})
	Evaluate(Input{Detection: det, Catalog: cat, Profile: p, Now: testNow})
	after, _ := json.Marshal([]any{det, cat, p})
	if string(before) != string(after) {
		t.Fatal("Evaluate must not modify its input")
	}
}

func TestAttachMappings(t *testing.T) {
	cat := catalog(t)
	findings := []model.Finding{finding("f-1", "AGC-005", model.SeverityHigh), finding("f-2", "AGC-022", model.SeverityLow), finding("f-3", "AGC-999", model.SeverityLow)}
	AttachMappings(findings, cat)
	if len(findings[0].Mappings) == 0 || findings[0].Mappings[0].RequirementID != "ASI02" {
		t.Errorf("AGC-005 mappings: %+v", findings[0].Mappings)
	}
	if findings[1].Mappings == nil || len(findings[1].Mappings) != 0 {
		t.Errorf("a control with no verified mapping gets an empty list, not nil")
	}
	if findings[2].Mappings == nil || len(findings[2].Mappings) != 0 {
		t.Errorf("an unknown control gets an empty list")
	}
	findings[0].Mappings[0].RequirementID = "changed"
	if cat.Controls[4].StandardsMappings[0].RequirementID != "ASI02" {
		t.Errorf("attached mappings must be copies")
	}
	AttachMappings(findings, nil)
	if len(findings[0].Mappings) != 0 {
		t.Errorf("a nil catalog clears the mappings")
	}
}
