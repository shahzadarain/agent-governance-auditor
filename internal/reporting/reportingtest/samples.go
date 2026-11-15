// SPDX-License-Identifier: Apache-2.0

// Package reportingtest provides realistic, synthetic scan results for tests
// of the reporting layer and the command line. The values are hand-built
// sample data. They are not output of the scanner, and the scores in them are
// computed by a simple helper in this package, not by the scoring engine.
package reportingtest

import (
	"fmt"
	"math"
	"sort"
	"strings"
	"time"

	"github.com/shahzadarain/agent-governance-auditor/internal/model"
)

// Hostile payloads used by Hostile. Renderers must neutralize all of them.
const (
	XSS          = `<script>alert(1)</script>`
	AttrBreak    = `" onmouseover="alert(1)`
	ImgOnError   = `<img src=x onerror=alert(1)>`
	MarkdownLink = `[click me](javascript:alert(1))`
	LinkBreak    = `](javascript:alert(1))`
	HTMLComment  = `<!-- hidden`
	CodeFence    = "```\n# Injected heading\n```"
	Pipe         = `cell | injected | cells`
	ANSI         = "\x1b[2J\x1b[31mred\x1b[0m"
	CarriageRet  = "safe text\roverwritten"
	JSURL        = `javascript:alert(1)`
)

var (
	scanTime = time.Date(2026, 11, 14, 9, 30, 0, 0, time.UTC)
	observed = time.Date(2026, 11, 14, 9, 29, 58, 0, time.UTC)
)

const (
	blockedCommit = "4f9c2d7a1b3e5f60718293a4b5c6d7e8f9012345"
	allowedCommit = "0a1b2c3d4e5f60718293a4b5c6d7e8f90a1b2c3d"
)

type controlDef struct {
	id, title, domain, plain string
	severity                 model.Severity
	weight                   int
	maxStatic                int
	capability               bool // capability-mode applicability
	remediation              []string
}

const (
	domA = "A: Accountability"
	domB = "B: Identity and Access"
	domC = "C: Action Controls"
	domD = "D: Trust Boundaries"
	domE = "E: Containment and Recovery"
	domF = "F: Assurance and Visibility"
)

// catalog mirrors the 24 controls of the builtin policy pack closely enough
// for report tests. The policy package owns the real catalog.
var catalog = []controlDef{
	{"AGC-001", "Owner and Inventory", domA, "A named person is accountable for the agent, and its tools and data are listed.", model.SeverityHigh, 4, 1, false,
		[]string{"Record the owner, purpose, and registry reference in .agentgov.yaml.", "Attach a signed owner attestation or a registry record as evidence."}},
	{"AGC-002", "Dynamic Risk Tiering", domA, "The agent has a risk level that matches what it can actually do.", model.SeverityMedium, 3, 2, false,
		[]string{"Declare a risk tier with a written rationale.", "Review the tier when the agent gains a new capability."}},
	{"AGC-003", "Integrated Change Control", domA, "Changes to models, tools, and prompts trigger a new assessment before release.", model.SeverityMedium, 3, 2, false,
		[]string{"Run the governance scan in CI on every change to agent files.", "Link each release to its commit and artifact hash."}},
	{"AGC-004", "Dedicated Non-Human Identity", domB, "The agent has its own identity and does not borrow a person's account.", model.SeverityHigh, 5, 2, false,
		[]string{"Create a dedicated workload identity for the agent.", "Remove shared and personal credentials from the agent configuration."}},
	{"AGC-005", "Allowlisted Tool Access", domB, "The agent can only use tools on an approved list.", model.SeverityHigh, 5, 2, true,
		[]string{"Define an explicit tool allowlist with deny by default.", "Add a test that calls a tool outside the list and expects a rejection."}},
	{"AGC-006", "Short-Lived Scoped Tokens", domB, "Access tokens expire quickly and only grant what the task needs.", model.SeverityHigh, 4, 1, true,
		[]string{"Issue tokens with a short lifetime, a narrow scope, and a fixed audience.", "Test expired and wrong-audience tokens against a mock identity provider."}},
	{"AGC-007", "User-Enforced Data Layer", domB, "The agent only sees data that the current user is allowed to see.", model.SeverityCritical, 5, 2, true,
		[]string{"Pass the caller identity to every data-access tool.", "Enforce the filter in the data service, not in the prompt.", "Add a two-user test that expects cross-user reads to fail."}},
	{"AGC-008", "Vault-Injected Secrets", domB, "Secrets come from a vault at run time and are never written in code.", model.SeverityCritical, 5, 2, true,
		[]string{"Remove the hardcoded value and rotate the credential.", "Load secrets from a vault through the workload identity."}},
	{"AGC-009", "External Policy Engine", domC, "A separate rule engine checks sensitive actions before they run.", model.SeverityHigh, 5, 2, true,
		[]string{"Route sensitive tool calls through a policy enforcement point.", "Deny by default when the policy service is unavailable."}},
	{"AGC-010", "Human Approval Gates", domC, "A person must approve risky actions before the agent carries them out.", model.SeverityCritical, 5, 2, true,
		[]string{"Require an external approval bound to the actor, the exact action, and an expiry time.", "Test bypass, replay, and expired approval cases."}},
	{"AGC-011", "Dual Content Guardrails", domC, "Inputs and outputs are checked, including text returned by tools.", model.SeverityMedium, 3, 2, false,
		[]string{"Validate tool returns before the model reads them.", "Add adversarial fixtures for injected instructions."}},
	{"AGC-012", "Multi-Level Resource Limits", domC, "The agent has limits on steps, cost, time, and spending.", model.SeverityMedium, 3, 2, false,
		[]string{"Set limits for steps, tokens, run time, and transaction amounts.", "Test a bounded loop and an over-limit request."}},
	{"AGC-013", "Disposable Sandbox Environments", domC, "Code and commands run in a locked-down environment that is thrown away afterwards.", model.SeverityHigh, 4, 2, true,
		[]string{"Run tool execution as a non-root user with a read-only file system.", "Drop capabilities and restrict network access."}},
	{"AGC-014", "Vetted Tool Supply Chain", domD, "Tools, MCP servers, and dependencies are pinned and come from known sources.", model.SeverityMedium, 3, 2, false,
		[]string{"Pin every MCP server and dependency to a version or digest.", "Record provenance for container images."}},
	{"AGC-015", "Context Memory Integrity", domD, "What the agent remembers is validated and kept separate for each user.", model.SeverityMedium, 3, 2, true,
		[]string{"Validate content before it is written to memory.", "Separate memory by user and set a retention period."}},
	{"AGC-016", "Authenticated Inter-Agent Messages", domD, "Agents prove who they are before they act on each other's messages.", model.SeverityHigh, 3, 2, true,
		[]string{"Authenticate every agent-to-agent request.", "Add replay protection and scoped authority."}},
	{"AGC-017", "Instant Agent Kill Switch", domE, "Operators can stop the agent and revoke its access at once.", model.SeverityHigh, 5, 2, false,
		[]string{"Add central revocation that cancels running jobs.", "Run a stop-and-revoke test and record the time to stop."}},
	{"AGC-018", "Reversible Action Design", domE, "Actions can be undone, or are approved when they cannot be.", model.SeverityMedium, 3, 2, true,
		[]string{"Make mutating operations idempotent.", "Add a compensation step or record why an action is not reversible."}},
	{"AGC-019", "Dedicated Incident Runbook", domE, "There is a written, practiced plan for when the agent misbehaves.", model.SeverityMedium, 2, 1, false,
		[]string{"Write an agent-specific runbook with owner and escalation path.", "Run an exercise and record the result."}},
	{"AGC-020", "Mandatory Regression Evals", domF, "Tests for allowed and forbidden behavior run on every change.", model.SeverityHigh, 4, 2, false,
		[]string{"Add versioned behavior tests that run in CI.", "Submit the CI results as evidence."}},
	{"AGC-021", "Continuous Red Teaming", domF, "The agent is attacked on purpose, repeatedly, to find weaknesses.", model.SeverityMedium, 3, 1, false,
		[]string{"Add repeatable adversarial scenarios for prompt injection and tool misuse.", "Import the results through the evidence adapter."}},
	{"AGC-022", "Complete Step Tracing", domF, "Every decision and tool call is recorded and can be followed end to end.", model.SeverityHigh, 4, 2, false,
		[]string{"Correlate runs, tool calls, and approvals with one trace ID.", "Record a synthetic end-to-end trace as evidence."}},
	{"AGC-023", "Tamper-Evident Audit Trail", domF, "Audit records cannot be changed without detection.", model.SeverityMedium, 3, 2, false,
		[]string{"Write audit records to protected or hash-chained storage.", "Run a tampering test on sample records."}},
	{"AGC-024", "Real-Time Operational Monitoring", domF, "Unusual agent behavior raises an alert while it is happening.", model.SeverityMedium, 3, 1, false,
		[]string{"Define alerts for denied policy decisions and unusual tool use.", "Send a synthetic signal and confirm that an alert fires."}},
}

// state is the assessed state of one control in a sample.
type state struct {
	status    model.Status
	mandatory bool
	reason    string
	next      string
	evidence  []string
	findings  []string
}

func maturityOf(s model.Status) int {
	switch s {
	case model.StatusVerifiedOperational:
		return 4
	case model.StatusVerifiedTested:
		return 3
	case model.StatusVerifiedImplementation:
		return 2
	case model.StatusDeclaredOnly:
		return 1
	default:
		return 0
	}
}

func loc(path string, line int) *model.Location {
	return &model.Location{Path: path, Line: line}
}

func evidence(id, control, agent, commit string, src model.SourceType, signal model.Signal, strength model.Strength, where *model.Location, collector, summary string, limits ...string) model.Evidence {
	result := model.ResultInconclusive
	switch signal {
	case model.SignalPresent:
		result = model.ResultPass
	case model.SignalViolation:
		result = model.ResultFail
	}
	integrity := model.IntegrityNotAvailable
	if src == model.SourceTest || src == model.SourceRuntime || src == model.SourceAttestation {
		integrity = model.IntegrityVerified
	}
	e := model.Evidence{
		EvidenceID:     id,
		ControlID:      control,
		AgentID:        agent,
		CommitSHA:      commit,
		PolicyVersion:  "1.0",
		ScannerVersion: "0.1.0",
		SourceType:     src,
		SourceLocation: "evidence/" + id + ".json",
		Collector:      collector,
		ObservedAt:     observed,
		Integrity:      integrity,
		Result:         result,
		Signal:         signal,
		Strength:       strength,
		Validity:       model.ValidityValid,
		Summary:        summary,
		Limitations:    append([]string{}, limits...),
	}
	if where != nil {
		e.Location = where
		e.SourceLocation = fmt.Sprintf("%s:%d", where.Path, where.Line)
	}
	return e
}

func finding(fp, rule, control, agent string, sev model.Severity, where *model.Location, title, desc, why string, fix []string, evRefs ...string) model.Finding {
	return model.Finding{
		FindingID:    "f-" + fp[:12],
		Fingerprint:  fp,
		RuleID:       rule,
		ControlID:    control,
		AgentID:      agent,
		Severity:     sev,
		Confidence:   model.ConfidenceHigh,
		Title:        title,
		Description:  desc,
		WhyItMatters: why,
		Remediation:  fix,
		Location:     where,
		EvidenceRefs: append([]string{}, evRefs...),
		Mappings: []model.Mapping{{
			Standard:      "OWASP Top 10 for LLM Applications",
			Version:       "2025",
			RequirementID: "LLM06",
			URL:           "https://genai.owasp.org/llmrisk/llm062025-excessive-agency/",
			Rationale:     "Related guidance on excessive agency. This mapping is informative, not an endorsement.",
		}},
	}
}

// assess builds the 24 control results for one agent from the given states.
// Controls without a state are unknown and not mandatory.
func assess(agentID string, minMaturity int, states map[string]state) []model.ControlResult {
	out := make([]model.ControlResult, 0, len(catalog))
	for _, c := range catalog {
		st, ok := states[c.id]
		if !ok {
			st = state{status: model.StatusUnknown, reason: "No detector produced evidence for this control and no external evidence was supplied.",
				next: "Supply test or runtime evidence for this control."}
		}
		cr := model.ControlResult{
			ControlID:           c.id,
			AgentID:             agentID,
			Title:               c.title,
			Domain:              c.domain,
			PlainLanguage:       c.plain,
			Status:              st.status,
			StatusReason:        st.reason,
			Maturity:            maturityOf(st.status),
			MaxStaticMaturity:   c.maxStatic,
			Applicable:          st.status != model.StatusNotApplicable,
			ApplicabilityBasis:  model.BasisAlways,
			ApplicabilityReason: "",
			Mandatory:           st.mandatory,
			Weight:              c.weight,
			Severity:            c.severity,
			EvidenceRefs:        append([]string{}, st.evidence...),
			FindingRefs:         append([]string{}, st.findings...),
			NextAction:          st.next,
			Remediation:         append([]string{}, c.remediation...),
			Limitations:         []string{"A static scan cannot confirm how this control behaves in production."},
		}
		if st.mandatory {
			cr.MinMaturity = minMaturity
		}
		if c.capability {
			cr.ApplicabilityBasis = model.BasisDetected
			cr.ApplicabilityReason = "The agent has a capability that this control governs."
		}
		if st.status == model.StatusNotApplicable {
			cr.ApplicabilityBasis = model.BasisInferred
			cr.ApplicabilityReason = "No capability that triggers this control was detected."
			cr.NextAction = "Confirm that the agent does not have this capability."
		}
		if cr.NextAction == "" && len(c.remediation) > 0 {
			cr.NextAction = c.remediation[0]
		}
		out = append(out, cr)
	}
	return out
}

// score computes a coherent sample score from control results. It is a
// stand-in for the scoring engine: weighted maturity over applicable controls.
func score(controls []model.ControlResult, findings []model.Finding) model.Score {
	s := model.Score{
		FindingsBySeverity:  map[string]int{"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0},
		StatusCounts:        map[string]int{},
		UnresolvedMandatory: []string{},
	}
	var weight, earned float64
	tested, operational := 0, 0
	for _, c := range controls {
		s.StatusCounts[string(c.Status)]++
		if !c.Applicable {
			continue
		}
		s.ApplicableControls++
		// Evidence that was not credited (for example expired) leaves the
		// control unknown and does not count toward coverage.
		if len(c.EvidenceRefs) > 0 && c.Status != model.StatusUnknown {
			s.ControlsWithEvidence++
		}
		if c.Maturity >= 3 {
			tested++
		}
		if c.Maturity == 4 {
			operational++
		}
		weight += float64(c.Weight)
		earned += float64(c.Weight) * float64(c.Maturity) / 4
		if c.Mandatory && (c.Maturity < c.MinMaturity || c.Maturity == 0) {
			s.UnresolvedMandatory = append(s.UnresolvedMandatory, c.ControlID)
		}
	}
	for _, f := range findings {
		s.FindingsBySeverity[string(f.Severity)]++
	}
	if s.ApplicableControls == 0 {
		s.Label = "insufficient-evidence"
		return s
	}
	pct := func(n int) int { return int(math.Round(100 * float64(n) / float64(s.ApplicableControls))) }
	s.CoveragePercent = pct(s.ControlsWithEvidence)
	s.TestedPercent = pct(tested)
	s.OperationalPercent = pct(operational)
	v := int(math.Round(100 * earned / weight))
	s.Value = &v
	s.Label = fmt.Sprintf("%d/100", v)
	return s
}

func meta(target, commit, profile, source string) model.ScanMeta {
	return model.ScanMeta{
		ScanID:        "scan-" + commit[:12],
		StartedAt:     scanTime,
		FinishedAt:    scanTime.Add(1840 * time.Millisecond),
		Target:        target,
		CommitSHA:     commit,
		Profile:       profile,
		ProfileSource: source,
		PolicyPack:    "builtin/v1",
		PolicyVersion: "1.0",
		ConfigPath:    ".agentgov.yaml",
		Offline:       true,
	}
}

// Blocked returns a high-risk finance agent that must not be released. Its 24
// controls cover every one of the ten statuses.
func Blocked() *model.ScanResult {
	const agentID = "finance-processing-agent"
	c := blockedCommit

	agent := model.Agent{
		ID:               agentID,
		Name:             "finance-processing-agent",
		Root:             ".",
		Detection:        model.Detected,
		Confidence:       model.ConfidenceHigh,
		Framework:        "langgraph",
		FrameworkVersion: "0.2.34",
		Language:         "python",
		Entrypoint:       "src/agent/graph.py",
		Owner:            "payments-platform-team",
		RiskTier:         "high",
		InferredRiskTier: "high",
		Tools: []model.Tool{
			{Name: "issue_refund", Kind: "function", Location: model.Location{Path: "src/actions.py", Line: 86}, Sensitive: true,
				SensitiveWhy: "Moves money.", Capabilities: []string{model.CapMutatingActions, model.CapSensitiveActions, model.CapTools}, Declared: true},
			{Name: "lookup_invoice", Kind: "database", Location: model.Location{Path: "src/agent/retrieval.py", Line: 42}, Sensitive: false,
				Capabilities: []string{model.CapDataAccess, model.CapTools}, Declared: true},
			{Name: "run_report_script", Kind: "shell", Location: model.Location{Path: "src/actions.py", Line: 131}, Sensitive: true,
				SensitiveWhy: "Runs shell commands.", Capabilities: []string{model.CapShellExec, model.CapTools}, Declared: false},
			{Name: "send_payment_notice", Kind: "http", Location: model.Location{Path: "src/actions.py", Line: 112}, Sensitive: true,
				SensitiveWhy: "Sends messages to customers.", Capabilities: []string{model.CapNetwork, model.CapSensitiveActions, model.CapTools}, Declared: true},
		},
		PermissionsDeclared: []string{"invoices:read", "refunds:write"},
		DataAccessPaths:     []string{"src/agent/retrieval.py"},
		MCPConnections: []model.MCPConnection{
			{Name: "ledger", Transport: "stdio", Target: "ledger-mcp", Pinned: false, Location: model.Location{Path: "mcp.json", Line: 7}},
		},
		Capabilities: []string{model.CapCredentials, model.CapDataAccess, model.CapMCP, model.CapMutatingActions, model.CapNetwork,
			model.CapSensitiveActions, model.CapShellExec, model.CapTools},
		Facts: []model.Fact{
			{Kind: "framework-import", Detail: "imports langgraph.graph", Location: model.Location{Path: "src/agent/graph.py", Line: 3},
				Confidence: model.ConfidenceHigh, Collector: "python.langgraph", ParserVersion: "1"},
			{Kind: "tool-definition", Detail: "tool function issue_refund", Location: model.Location{Path: "src/actions.py", Line: 86},
				Confidence: model.ConfidenceHigh, Collector: "python.langgraph", ParserVersion: "1"},
		},
	}

	expired := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	ev := []model.Evidence{
		evidence("ev-agc001-01", "AGC-001", agentID, c, model.SourceConfiguration, model.SignalDeclared, model.StrengthDeclared, loc(".agentgov.yaml", 4),
			"config.owner", "The configuration names an owner. No registry record or signed attestation confirms it.", "A name in a file does not prove that the owner exists."),
		evidence("ev-agc002-01", "AGC-002", agentID, c, model.SourceConfiguration, model.SignalPresent, model.StrengthImplementation, loc(".agentgov.yaml", 9),
			"config.risk-tier", "The declared risk tier matches the detected capabilities."),
		evidence("ev-agc004-01", "AGC-004", agentID, c, model.SourceStatic, model.SignalViolation, model.StrengthImplementation, loc("src/agent/config.py", 14),
			"rules.shared-account", "The agent signs in with a shared service account name."),
		evidence("ev-agc005-01", "AGC-005", agentID, c, model.SourceTest, model.SignalPresent, model.StrengthTested, loc("tests/governance/test_tool_allowlist.py", 18),
			"evidence.junit", "The allowlist test rejected a tool that is not on the list."),
		evidence("ev-agc006-01", "AGC-006", agentID, c, model.SourceAttestation, model.SignalPresent, model.StrengthTested, nil,
			"evidence.external", "Token lifetime test result from the identity team."),
		evidence("ev-agc007-01", "AGC-007", agentID, c, model.SourceTest, model.SignalViolation, model.StrengthTested, loc("tests/governance/test_data_scope.py", 31),
			"evidence.junit", "The cross-user access test was not rejected."),
		evidence("ev-agc008-01", "AGC-008", agentID, c, model.SourceStatic, model.SignalViolation, model.StrengthImplementation, loc("src/agent/config.py", 9),
			"rules.hardcoded-secret", "A value that looks like a credential is assigned in code. The value is not shown."),
		evidence("ev-agc009-01", "AGC-009", agentID, c, model.SourceStatic, model.SignalAbsent, model.StrengthImplementation, nil,
			"rules.policy-enforcement", "No policy enforcement point was found around sensitive tool calls."),
		evidence("ev-agc010-01", "AGC-010", agentID, c, model.SourceTest, model.SignalViolation, model.StrengthTested, loc("tests/governance/test_approval.py", 22),
			"evidence.junit", "The approval bypass test failed: issue_refund ran without an approval record."),
		evidence("ev-agc011-01", "AGC-011", agentID, c, model.SourceStatic, model.SignalPresent, model.StrengthImplementation, loc("src/agent/guardrails.py", 12),
			"rules.guardrails", "Input and output validators wrap the model call.", "The presence of a guardrail does not prove that it stops an attack."),
		evidence("ev-agc012-01", "AGC-012", agentID, c, model.SourceRuntime, model.SignalPresent, model.StrengthOperational, nil,
			"evidence.runtime", "Runtime records show the step and spend limits stopping an over-limit run."),
		evidence("ev-agc013-01", "AGC-013", agentID, c, model.SourceManualReview, model.SignalDeclared, model.StrengthDeclared, loc(".agentgov.yaml", 31),
			"config.exceptions", "A recorded exception accepts the risk of running report scripts without a sandbox until 2027-01-31."),
		evidence("ev-agc014-01", "AGC-014", agentID, c, model.SourceStatic, model.SignalAbsent, model.StrengthImplementation, loc("mcp.json", 7),
			"rules.mcp-pinning", "The MCP server ledger-mcp has no pinned version or digest."),
		evidence("ev-agc017-01", "AGC-017", agentID, c, model.SourceStatic, model.SignalPresent, model.StrengthImplementation, loc("src/agent/control.py", 20),
			"rules.kill-switch", "A cancellation path revokes the run token and stops new tool calls.", "Termination was not tested."),
		evidence("ev-agc018-01", "AGC-018", agentID, c, model.SourceConfiguration, model.SignalDeclared, model.StrengthDeclared, loc("docs/operations.md", 40),
			"config.docs", "A document describes a manual refund reversal procedure."),
		evidence("ev-agc019-01", "AGC-019", agentID, c, model.SourceConfiguration, model.SignalDeclared, model.StrengthDeclared, loc("docs/runbook.md", 1),
			"config.docs", "An incident runbook file exists. No exercise record was supplied."),
		evidence("ev-agc020-01", "AGC-020", agentID, c, model.SourceTest, model.SignalError, model.StrengthTested, loc("reports/junit.xml", 0),
			"evidence.junit", "The test report could not be parsed."),
		evidence("ev-agc022-01", "AGC-022", agentID, c, model.SourceTest, model.SignalPresent, model.StrengthTested, loc("tests/governance/test_trace.py", 15),
			"evidence.junit", "A synthetic run produced one correlated trace across model, tool, and approval steps."),
		evidence("ev-agc023-01", "AGC-023", agentID, c, model.SourceStatic, model.SignalAbsent, model.StrengthImplementation, nil,
			"rules.audit-trail", "Only plain application logs were found."),
	}
	// One expired external evidence item: it exists but is not credited.
	for i := range ev {
		if ev[i].EvidenceID == "ev-agc006-01" {
			ev[i].ValidUntil = &expired
			ev[i].Validity = model.ValidityExpired
			ev[i].ValidityReason = "The evidence expired on 2026-01-01."
			ev[i].Integrity = model.IntegrityUnsigned
		}
	}
	sort.Slice(ev, func(i, j int) bool { return ev[i].EvidenceID < ev[j].EvidenceID })

	findings := []model.Finding{
		finding("1f0a9c3e5b7d2a4c6e8f0b1d3a5c7e9f", "AGC-010.approval-bypass", "AGC-010", agentID, model.SeverityCritical, loc("src/actions.py", 86),
			"Refunds run without an enforced approval",
			"The tool issue_refund executes when the approval record is absent. The approval check reads a flag that the model can set.",
			"The agent can move money without any person agreeing to it.",
			[]string{"Require an external approval bound to the actor, the exact action, and an expiry time.", "Reject the call when no valid approval record exists.", "Add tests for bypass, replay, and expired approvals."},
			"ev-agc010-01"),
		finding("2b4d6f8a0c1e3a5b7d9f1c3e5a7b9d0f", "AGC-008.hardcoded-secret", "AGC-008", agentID, model.SeverityCritical, loc("src/agent/config.py", 9),
			"Credential written in source code",
			"A value that looks like an API credential is assigned to a variable. The value is not shown in this report.",
			"Anyone who can read the repository can use the credential.",
			[]string{"Remove the value from the code and rotate the credential.", "Load the secret from a vault at run time."},
			"ev-agc008-01"),
		finding("3c5e7a9b1d2f4a6c8e0b2d4f6a8c0e1b", "AGC-007.cross-user-read", "AGC-007", agentID, model.SeverityCritical, loc("src/agent/retrieval.py", 42),
			"Invoice lookup does not filter by the current user",
			"The query in lookup_invoice has no caller filter, and the cross-user test was not rejected.",
			"One customer can read another customer's invoices through the agent.",
			[]string{"Enforce caller-specific authorization in the data service.", "Pass the caller identity to lookup_invoice.", "Keep the two-user test in CI."},
			"ev-agc007-01"),
		finding("4d6f8b0c2e3a5b7d9f1a3c5e7b9d1f2c", "AGC-004.shared-account", "AGC-004", agentID, model.SeverityHigh, loc("src/agent/config.py", 14),
			"Agent uses a shared service account",
			"The configuration sets the account name svc-finance-shared, which other services also use.",
			"Actions by the agent cannot be told apart from actions by other systems.",
			[]string{"Create a dedicated workload identity for the agent.", "Remove the shared account from the configuration."},
			"ev-agc004-01"),
		finding("5e7a9c1d3f4b6c8e0a2b4d6f8c0e2a3d", "AGC-009.no-enforcement-point", "AGC-009", agentID, model.SeverityHigh, nil,
			"No policy check before sensitive tools",
			"No policy enforcement point was found between the model and the tools issue_refund and send_payment_notice.",
			"Nothing outside the model decides whether a sensitive action is allowed.",
			[]string{"Route sensitive tool calls through a policy enforcement point.", "Deny by default when the policy service does not answer."},
			"ev-agc009-01"),
		finding("6f8b0d2e4a5c7d9f1b3c5e7a9d1f3b4e", "AGC-005.undeclared-tool", "AGC-005", agentID, model.SeverityMedium, loc("src/actions.py", 131),
			"Shell tool is not in the declared tool list",
			"The tool run_report_script is defined in code but is not listed in declared_tools.",
			"A tool that nobody reviewed can still be called by the agent.",
			[]string{"Add the tool to declared_tools with a scope, or remove it."}),
		finding("7a9c1e3f5b6d8e0a2c4d6f8b0e2a4c5f", "AGC-014.unpinned-mcp-server", "AGC-014", agentID, model.SeverityMedium, loc("mcp.json", 7),
			"MCP server version is not pinned",
			"The MCP server ledger-mcp is started without a version or digest.",
			"A changed server could give the agent different tools without a review.",
			[]string{"Pin the MCP server to a version or digest."},
			"ev-agc014-01"),
		finding("8b0d2f4a6c7e9f1b3d5e7a9c1f3b5d6a", "AGC-023.plain-logs-only", "AGC-023", agentID, model.SeverityLow, nil,
			"Audit records are plain application logs",
			"No signed, hash-chained, or write-once audit storage was found.",
			"Someone who changes the logs could hide what the agent did.",
			[]string{"Write audit records to protected or hash-chained storage."},
			"ev-agc023-01"),
	}
	fid := func(i int) string { return findings[i].FindingID }

	states := map[string]state{
		"AGC-001": {status: model.StatusDeclaredOnly, mandatory: true, evidence: []string{"ev-agc001-01"},
			reason: "An owner is declared, but no registry record or signed attestation confirms it. The profile requires maturity 2.",
			next:   "Attach a signed owner attestation or a registry record as evidence."},
		"AGC-002": {status: model.StatusVerifiedImplementation, evidence: []string{"ev-agc002-01"},
			reason: "The declared tier high matches the detected capabilities."},
		"AGC-004": {status: model.StatusFailed, mandatory: true, evidence: []string{"ev-agc004-01"}, findings: []string{fid(3)},
			reason: "A shared service account is configured for the agent."},
		"AGC-005": {status: model.StatusVerifiedTested, mandatory: true, evidence: []string{"ev-agc005-01"}, findings: []string{fid(5)},
			reason: "A test shows that a tool outside the allowlist is rejected."},
		"AGC-006": {status: model.StatusUnknown, evidence: []string{"ev-agc006-01"},
			reason: "Evidence was supplied but it expired on 2026-01-01.", next: "Submit a current token lifetime test result."},
		"AGC-007": {status: model.StatusFailed, mandatory: true, evidence: []string{"ev-agc007-01"}, findings: []string{fid(2)},
			reason: "The cross-user access test was not rejected."},
		"AGC-008": {status: model.StatusFailed, mandatory: true, evidence: []string{"ev-agc008-01"}, findings: []string{fid(1)},
			reason: "A credential is written in source code."},
		"AGC-009": {status: model.StatusMissing, mandatory: true, evidence: []string{"ev-agc009-01"}, findings: []string{fid(4)},
			reason: "The scanner looked for a policy enforcement point and found none."},
		"AGC-010": {status: model.StatusFailed, mandatory: true, evidence: []string{"ev-agc010-01"}, findings: []string{fid(0)},
			reason: "The approval bypass test failed."},
		"AGC-011": {status: model.StatusVerifiedImplementation, evidence: []string{"ev-agc011-01"},
			reason: "Validators are present in code. No adversarial test result was supplied."},
		"AGC-012": {status: model.StatusVerifiedOperational, mandatory: true, evidence: []string{"ev-agc012-01"},
			reason: "Signed runtime records show the limits working."},
		"AGC-013": {status: model.StatusAcceptedRisk, mandatory: true, evidence: []string{"ev-agc013-01"},
			reason: "An approved exception accepts this risk until 2027-01-31.", next: "Have a reviewer confirm that the exception is still acceptable."},
		"AGC-014": {status: model.StatusMissing, evidence: []string{"ev-agc014-01"}, findings: []string{fid(6)},
			reason: "The MCP server is not pinned and no provenance record was found."},
		"AGC-015": {status: model.StatusNotApplicable, reason: "No persistent memory was detected."},
		"AGC-016": {status: model.StatusNotApplicable, reason: "No agent-to-agent messaging was detected."},
		"AGC-017": {status: model.StatusVerifiedImplementation, mandatory: true, evidence: []string{"ev-agc017-01"},
			reason: "A cancellation path exists. Termination was not tested.", next: "Run a synthetic stop-and-revoke test."},
		"AGC-018": {status: model.StatusDeclaredOnly, evidence: []string{"ev-agc018-01"},
			reason: "A document describes a manual reversal. No code path or test confirms it."},
		"AGC-019": {status: model.StatusDeclaredOnly, evidence: []string{"ev-agc019-01"},
			reason: "A runbook file exists. No exercise record was supplied."},
		"AGC-020": {status: model.StatusError, mandatory: true, evidence: []string{"ev-agc020-01"},
			reason: "The test report reports/junit.xml could not be parsed.", next: "Fix the test report and scan again."},
		"AGC-022": {status: model.StatusVerifiedTested, mandatory: true, evidence: []string{"ev-agc022-01"},
			reason: "A synthetic end-to-end trace was recorded and verified."},
		"AGC-023": {status: model.StatusMissing, evidence: []string{"ev-agc023-01"}, findings: []string{fid(7)},
			reason: "Only plain application logs were found."},
	}
	controls := assess(agentID, 2, states)
	sc := score(controls, findings)

	reasons := []model.Reason{
		{Code: "mandatory-below-minimum", ControlID: "AGC-001", AgentID: agentID, Message: "AGC-001 Owner and Inventory is declared only; the profile requires maturity 2."},
		{Code: "mandatory-control-failed", ControlID: "AGC-004", AgentID: agentID, Message: "AGC-004 Dedicated Non-Human Identity failed."},
		{Code: "mandatory-control-failed", ControlID: "AGC-007", AgentID: agentID, Message: "AGC-007 User-Enforced Data Layer failed."},
		{Code: "mandatory-control-failed", ControlID: "AGC-008", AgentID: agentID, Message: "AGC-008 Vault-Injected Secrets failed."},
		{Code: "mandatory-control-missing", ControlID: "AGC-009", AgentID: agentID, Message: "AGC-009 External Policy Engine is missing."},
		{Code: "mandatory-control-failed", ControlID: "AGC-010", AgentID: agentID, Message: "AGC-010 Human Approval Gates failed."},
		{Code: "accepted-risk-needs-review", ControlID: "AGC-013", AgentID: agentID, Message: "AGC-013 Disposable Sandbox Environments has an accepted risk that needs a review."},
		{Code: "mandatory-control-error", ControlID: "AGC-020", AgentID: agentID, Message: "AGC-020 Mandatory Regression Evals could not be assessed because of an error."},
	}
	decision := model.Decision{Outcome: model.OutcomeBlock, Reasons: reasons}

	return &model.ScanResult{
		SchemaVersion: model.SchemaVersion,
		Tool:          model.ToolInfo{Name: "AgentGov Auditor", Version: "0.1.0"},
		Scan:          meta("vulnerable-agent", c, "high-risk", "config"),
		Agents:        []model.Agent{agent},
		Assessments:   []model.AgentAssessment{{AgentID: agentID, Score: sc, Decision: decision, Controls: controls}},
		Evidence:      ev,
		Findings:      findings,
		Score:         sc,
		Decision:      decision,
		Stats:         model.Stats{FilesScanned: 48, FilesSkipped: 3, BytesRead: 182344, DurationMilli: 1840},
		Warnings: []string{
			"reports/junit.xml: the test report is not valid XML and was skipped.",
			"vendor/: 3 files larger than 1 MiB were skipped.",
		},
		Limitations: []string{
			"This was a static, offline scan. No repository code was executed.",
			"Runtime behavior is known only from the evidence files that were supplied.",
			"Python files were analyzed by a lexer, not a full parser. Unusual syntax can hide a tool definition.",
		},
	}
}

// Allowed returns a standard-profile agent whose release policy is satisfied.
// It still has open, non-mandatory gaps and one low-severity finding.
func Allowed() *model.ScanResult {
	const agentID = "support-triage-agent"
	c := allowedCommit

	agent := model.Agent{
		ID:               agentID,
		Name:             "support-triage-agent",
		Root:             "services/triage",
		Detection:        model.Detected,
		Confidence:       model.ConfidenceHigh,
		Framework:        "openai-agents",
		FrameworkVersion: model.Unknown,
		Language:         "typescript",
		Entrypoint:       "services/triage/src/agent.ts",
		Owner:            "support-engineering",
		RiskTier:         "standard",
		InferredRiskTier: "standard",
		Tools: []model.Tool{
			{Name: "search_help_articles", Kind: "http", Location: model.Location{Path: "services/triage/src/tools.ts", Line: 12},
				Capabilities: []string{model.CapNetwork, model.CapTools}, Declared: true},
			{Name: "tag_ticket", Kind: "function", Location: model.Location{Path: "services/triage/src/tools.ts", Line: 40}, Sensitive: true,
				SensitiveWhy: "Changes ticket records.", Capabilities: []string{model.CapMutatingActions, model.CapTools}, Declared: true},
		},
		PermissionsDeclared: []string{"tickets:tag"},
		DataAccessPaths:     []string{},
		MCPConnections:      []model.MCPConnection{},
		Capabilities:        []string{model.CapMutatingActions, model.CapNetwork, model.CapTools},
		Facts: []model.Fact{
			{Kind: "framework-import", Detail: "imports @openai/agents", Location: model.Location{Path: "services/triage/src/agent.ts", Line: 1},
				Confidence: model.ConfidenceHigh, Collector: "typescript.openai-agents", ParserVersion: "1"},
		},
	}

	type e struct {
		control  string
		src      model.SourceType
		strength model.Strength
		path     string
		line     int
		summary  string
	}
	rows := []e{
		{"AGC-001", model.SourceAttestation, model.StrengthTested, "", 0, "A signed owner attestation names support-engineering as the accountable owner."},
		{"AGC-002", model.SourceConfiguration, model.StrengthImplementation, ".agentgov.yaml", 8, "The declared tier standard matches the detected capabilities."},
		{"AGC-003", model.SourceTest, model.StrengthTested, ".github/workflows/governance.yml", 14, "CI records show the governance scan running on the release commit."},
		{"AGC-004", model.SourceRuntime, model.StrengthOperational, "", 0, "Identity provider records show a dedicated workload identity for the agent."},
		{"AGC-005", model.SourceTest, model.StrengthTested, "services/triage/test/allowlist.test.ts", 9, "The allowlist test rejected a tool that is not on the list."},
		{"AGC-011", model.SourceStatic, model.StrengthImplementation, "services/triage/src/guardrails.ts", 5, "Input and output validators wrap the model call."},
		{"AGC-012", model.SourceTest, model.StrengthTested, "services/triage/test/limits.test.ts", 21, "The over-limit test stopped the run at the configured step limit."},
		{"AGC-014", model.SourceStatic, model.StrengthImplementation, "services/triage/package-lock.json", 1, "All dependencies are pinned by a lock file."},
		{"AGC-017", model.SourceTest, model.StrengthTested, "services/triage/test/stop.test.ts", 30, "The stop-and-revoke test denied new actions within 2 seconds."},
		{"AGC-018", model.SourceStatic, model.StrengthImplementation, "services/triage/src/tools.ts", 52, "tag_ticket is idempotent and records the previous tags."},
		{"AGC-019", model.SourceConfiguration, model.StrengthDeclared, "docs/runbook.md", 1, "An incident runbook file exists. No exercise record was supplied."},
		{"AGC-020", model.SourceTest, model.StrengthTested, "services/triage/test/behavior.test.ts", 1, "CI results show 42 behavior tests passing on the release commit."},
		{"AGC-022", model.SourceRuntime, model.StrengthOperational, "", 0, "Runtime traces correlate model, tool, and ticket updates end to end."},
	}
	var ev []model.Evidence
	states := map[string]state{}
	statusFor := map[model.Strength]model.Status{
		model.StrengthDeclared:       model.StatusDeclaredOnly,
		model.StrengthImplementation: model.StatusVerifiedImplementation,
		model.StrengthTested:         model.StatusVerifiedTested,
		model.StrengthOperational:    model.StatusVerifiedOperational,
	}
	mandatory := map[string]bool{"AGC-001": true, "AGC-004": true, "AGC-005": true, "AGC-012": true, "AGC-017": true, "AGC-020": true, "AGC-022": true}
	for _, r := range rows {
		id := "ev-" + strings.ToLower(strings.ReplaceAll(r.control, "-", "")) + "-01"
		var where *model.Location
		if r.path != "" {
			where = loc(r.path, r.line)
		}
		signal := model.SignalPresent
		if r.strength == model.StrengthDeclared {
			signal = model.SignalDeclared
		}
		ev = append(ev, evidence(id, r.control, agentID, c, r.src, signal, r.strength, where, "evidence.sample", r.summary))
		states[r.control] = state{status: statusFor[r.strength], mandatory: mandatory[r.control], evidence: []string{id}, reason: r.summary}
	}
	for _, id := range []string{"AGC-006", "AGC-007", "AGC-008", "AGC-009", "AGC-010", "AGC-013", "AGC-015", "AGC-016"} {
		states[id] = state{status: model.StatusNotApplicable, reason: "No capability that triggers this control was detected."}
	}
	sort.Slice(ev, func(i, j int) bool { return ev[i].EvidenceID < ev[j].EvidenceID })

	findings := []model.Finding{
		finding("9c1e3a5b7d8f0a2c4e6f8b0d2a4c6e7b", "AGC-019.runbook-not-exercised", "AGC-019", agentID, model.SeverityLow, loc("docs/runbook.md", 1),
			"Incident runbook has no exercise record",
			"The runbook exists but no record shows that the team has practiced it.",
			"A plan that nobody has practiced can fail when it is needed.",
			[]string{"Run an incident exercise and record the result as evidence."},
			"ev-agc019-01"),
	}
	st := states["AGC-019"]
	st.findings = []string{findings[0].FindingID}
	states["AGC-019"] = st

	controls := assess(agentID, 2, states)
	sc := score(controls, findings)
	decision := model.Decision{Outcome: model.OutcomeAllow, Reasons: []model.Reason{}}

	return &model.ScanResult{
		SchemaVersion: model.SchemaVersion,
		Tool:          model.ToolInfo{Name: "AgentGov Auditor", Version: "0.1.0"},
		Scan:          meta("support-platform", c, "standard", "default"),
		Agents:        []model.Agent{agent},
		Assessments:   []model.AgentAssessment{{AgentID: agentID, Score: sc, Decision: decision, Controls: controls}},
		Evidence:      ev,
		Findings:      findings,
		Score:         sc,
		Decision:      decision,
		Stats:         model.Stats{FilesScanned: 212, FilesSkipped: 0, BytesRead: 1048112, DurationMilli: 2310},
		Warnings:      []string{},
		Limitations: []string{
			"This was a static, offline scan. No repository code was executed.",
			"Runtime behavior is known only from the evidence files that were supplied.",
		},
	}
}

// NoAgent returns the result of scanning a repository in which no agent was
// detected. It is not a pass: there is no score and a person must review.
func NoAgent() *model.ScanResult {
	c := model.Unknown
	sc := model.Score{
		Label:               "insufficient-evidence",
		FindingsBySeverity:  map[string]int{"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0},
		UnresolvedMandatory: []string{},
		StatusCounts:        map[string]int{},
	}
	m := meta("static-website", "000000000000", "baseline", "default")
	m.ScanID = "scan-static-website"
	m.CommitSHA = c
	m.ConfigPath = ""
	return &model.ScanResult{
		SchemaVersion: model.SchemaVersion,
		Tool:          model.ToolInfo{Name: "AgentGov Auditor", Version: "0.1.0"},
		Scan:          m,
		Agents:        []model.Agent{},
		Assessments:   []model.AgentAssessment{},
		Evidence:      []model.Evidence{},
		Findings:      []model.Finding{},
		Score:         sc,
		Decision: model.Decision{Outcome: model.OutcomeReviewRequired, Reasons: []model.Reason{
			{Code: "no-agent-detected", Message: "No AI agent was detected, so no control could be assessed."},
		}},
		Stats:    model.Stats{FilesScanned: 17, FilesSkipped: 0, BytesRead: 40211, DurationMilli: 120},
		Warnings: []string{"The directory is not a Git repository, so the commit is unknown."},
		Limitations: []string{
			"This was a static, offline scan. No repository code was executed.",
			"Agents written in languages other than Python, TypeScript, and JavaScript are not detected.",
		},
	}
}

// Hostile returns the blocked sample with injection strings in every
// repository-derived field: names, paths, titles, descriptions, reasons,
// warnings, evidence summaries, and mapping URLs. Enumerated values and
// identifiers stay valid, so the result still conforms to the JSON schema.
func Hostile() *model.ScanResult {
	r := Blocked()
	r.Scan.Target = "repo" + XSS + ANSI
	r.Scan.Profile = "high-risk" + AttrBreak
	r.Scan.ConfigPath = ".agentgov.yaml" + HTMLComment
	r.Tool.Version = "0.1.0" + XSS

	a := &r.Agents[0]
	a.Name = XSS + AttrBreak + ANSI
	a.Owner = ImgOnError + " " + MarkdownLink
	a.Entrypoint = "src/" + ANSI + "evil\r.py"
	a.Framework = "langgraph" + Pipe
	a.FrameworkVersion = CodeFence
	a.Root = "." + LinkBreak
	for i := range a.Tools {
		a.Tools[i].Name = AttrBreak + XSS + a.Tools[i].Name
		a.Tools[i].Kind = "function" + ImgOnError
		a.Tools[i].Location.Path = "src/\x1b[2Jevil\r" + XSS + ".py"
		a.Tools[i].SensitiveWhy = MarkdownLink + " " + Pipe
	}
	for i := range a.MCPConnections {
		a.MCPConnections[i].Name = XSS
		a.MCPConnections[i].Target = AttrBreak + ANSI
		a.MCPConnections[i].Version = HTMLComment
		a.MCPConnections[i].Location.Path = "mcp" + LinkBreak + ".json"
	}
	a.PermissionsDeclared = []string{XSS, Pipe}
	a.DataAccessPaths = []string{"data/" + ANSI + CarriageRet}
	for i := range a.Facts {
		a.Facts[i].Detail = XSS + CodeFence
		a.Facts[i].Location.Path = "src/" + AttrBreak + ".py"
	}

	for i := range r.Evidence {
		e := &r.Evidence[i]
		e.Summary = XSS + " " + AttrBreak + " " + ANSI + " " + MarkdownLink
		e.SourceLocation = "evidence/" + XSS + ".json"
		e.Collector = "collector" + ImgOnError
		e.ValidityReason = HTMLComment + Pipe
		e.IdentityContext = AttrBreak
		e.Limitations = []string{CodeFence, XSS}
		if e.Location != nil {
			e.Location.Path = "src/\x1b[2Jevil\r" + AttrBreak + ".py"
		}
	}

	for i := range r.Findings {
		f := &r.Findings[i]
		f.Title = XSS + " " + Pipe + " " + LinkBreak + " " + HTMLComment + " " + CodeFence + " " + AttrBreak
		f.Description = ImgOnError + " " + MarkdownLink + " " + ANSI + " " + CarriageRet
		f.WhyItMatters = XSS + "\n\n# Injected heading\n" + Pipe
		f.Remediation = []string{AttrBreak + XSS, CodeFence, MarkdownLink}
		f.Reproduction = XSS + ANSI
		if f.Location != nil {
			f.Location.Path = "src/\x1b[2Jevil\r" + XSS + " " + LinkBreak + "|.py"
		}
		for j := range f.Mappings {
			f.Mappings[j].Standard = XSS
			f.Mappings[j].RequirementID = AttrBreak
			f.Mappings[j].URL = JSURL
			f.Mappings[j].Rationale = MarkdownLink
		}
	}

	hostileControls := func(cs []model.ControlResult) {
		for i := range cs {
			c := &cs[i]
			c.Title = c.Title + " " + XSS + Pipe
			c.PlainLanguage = ImgOnError + " " + c.PlainLanguage
			c.StatusReason = XSS + " " + AttrBreak + " " + ANSI + " " + LinkBreak
			c.ApplicabilityReason = HTMLComment + " " + MarkdownLink
			c.NextAction = CodeFence + " " + XSS
			c.Remediation = []string{XSS, AttrBreak + Pipe}
			c.Limitations = []string{ImgOnError, CarriageRet}
		}
	}
	for i := range r.Assessments {
		hostileControls(r.Assessments[i].Controls)
		for j := range r.Assessments[i].Decision.Reasons {
			r.Assessments[i].Decision.Reasons[j].Message = XSS + " " + AttrBreak + " " + ANSI + " " + Pipe
		}
	}
	reasons := make([]model.Reason, len(r.Decision.Reasons))
	copy(reasons, r.Decision.Reasons)
	for j := range reasons {
		reasons[j].Message = XSS + " " + AttrBreak + " " + ANSI + " " + Pipe
	}
	r.Decision.Reasons = reasons

	r.Warnings = []string{
		XSS,
		AttrBreak + " " + ImgOnError,
		"path/" + ANSI + "/" + CarriageRet,
		MarkdownLink + " " + LinkBreak + " " + HTMLComment + " " + CodeFence + " " + Pipe,
	}
	r.Limitations = []string{XSS + " " + AttrBreak, CodeFence + " " + HTMLComment}
	return r
}
