// SPDX-License-Identifier: Apache-2.0

package policy

import (
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/shahzadarain/agent-governance-auditor/internal/config"
	"github.com/shahzadarain/agent-governance-auditor/internal/model"
	"github.com/shahzadarain/agent-governance-auditor/internal/scoring"
)

// Machine-readable decision reason codes.
const (
	ReasonMandatoryFailed          = "mandatory-control-failed"
	ReasonMandatoryError           = "mandatory-control-error"
	ReasonMandatoryMissing         = "mandatory-control-missing"
	ReasonMandatoryUnknown         = "mandatory-control-unknown"
	ReasonMandatoryBelowMin        = "mandatory-below-min-maturity"
	ReasonMandatoryEvidenceInvalid = "mandatory-evidence-invalid"
	ReasonMandatoryAcceptedRisk    = "mandatory-accepted-risk"
	ReasonMandatoryNAInferred      = "mandatory-not-applicable-inferred"
	ReasonCriticalFinding          = "critical-finding"
	ReasonReviewWorkflow           = "review-workflow"
	ReasonPolicySatisfied          = "policy-satisfied"
	ReasonNoAgentDetected          = "no-agent-detected"
	ReasonPolicyInputInvalid       = "policy-input-invalid"
)

// Fixed status reasons. Reports and tests rely on the exact wording.
const (
	MsgCommitMismatch = "Evidence is bound to a different commit."
	MsgDigestMismatch = "Evidence is bound to files that changed after it was collected."
	MsgBadSignature   = "Evidence signature failed verification."
	MsgUnbound        = "Evidence is not bound to a commit or to file content."
	MsgMalformed      = "Evidence failed schema validation."
	MsgExpiredNoDate  = "Evidence has expired."
	MsgNoDetector     = "No detector could assess this control from source code. Supply test or runtime evidence."
	MsgUnsignedCapped = "Test or runtime evidence is unsigned, so it is credited only up to implementation level. This profile requires signed evidence."
)

// Next-action texts for statuses that do not use a remediation step.
const (
	NextAddTests        = "Add governance tests for this control and record the results as evidence."
	NextCollectRuntime  = "Collect runtime evidence that the control works in the deployed environment."
	NextKeepCurrent     = "Keep the evidence current and verify again after each material change."
	NextFixCollector    = "Fix the collector error and run the scan again."
	NextFreshEvidence   = "Collect fresh evidence that is bound to the current commit."
	NextSupplyEvidence  = "Supply test, runtime, or reviewed evidence for this control."
	NextSignEvidence    = "Sign the test or runtime evidence with a trusted key."
	NextConfirmNA       = "Confirm that this control does not apply and record an approved exception, or declare the capability."
	NextReviewException = "Review this exception before it expires."
	NextReviewRisk      = "Plan the remediation and review the accepted risk on a set date."
	NextExternalOnly    = "Supply reviewed or attested evidence. A static scan cannot verify this control beyond a declaration."
)

// Input is everything the policy engine needs. Evaluate does not read files,
// the clock, or the environment.
type Input struct {
	Detection *model.Detection
	Catalog   *model.Catalog
	Profile   *model.Profile // the effective profile, see Effective
	Config    *config.Config // may be nil
	Now       time.Time      // injected clock; the zero value disables expiry checks
}

// Evaluate assesses every catalog control for every detected agent, computes
// the scores, and makes the decision.
//
// The result is deterministic for identical input. The repository score is
// the score of the lowest-scoring agent, and the repository decision is the
// most restrictive agent decision. With no agent the decision is
// REVIEW_REQUIRED, never ALLOW.
func Evaluate(in Input) (assessments []model.AgentAssessment, score model.Score, decision model.Decision) {
	assessments = []model.AgentAssessment{}
	if in.Catalog == nil || in.Profile == nil {
		return assessments, scoring.Empty(), model.Decision{
			Outcome: model.OutcomeBlock,
			Reasons: []model.Reason{{
				Code:    ReasonPolicyInputInvalid,
				Message: "The policy engine was called without a control catalog or a profile. No assessment was made.",
			}},
		}
	}

	var det model.Detection
	if in.Detection != nil {
		det = *in.Detection
	}
	agents := make([]model.Agent, 0, len(det.Agents))
	for _, a := range det.Agents {
		if a.Detection != model.NotDetected {
			agents = append(agents, a)
		}
	}
	sort.SliceStable(agents, func(i, j int) bool { return agents[i].ID < agents[j].ID })

	if len(agents) == 0 {
		score = scoring.Empty()
		scoring.CountFindings(score.FindingsBySeverity, det.Findings)
		return assessments, score, model.Decision{
			Outcome: model.OutcomeReviewRequired,
			Reasons: []model.Reason{{
				Code:    ReasonNoAgentDetected,
				Message: "No AI agent was detected in this repository. This is not a pass: nothing was assessed. Confirm that the scan covered the right directory, or declare the agent in .agentgov.yaml.",
			}},
		}
	}

	evidence := append([]model.Evidence(nil), det.Evidence...)
	sort.SliceStable(evidence, func(i, j int) bool {
		if evidence[i].EvidenceID != evidence[j].EvidenceID {
			return evidence[i].EvidenceID < evidence[j].EvidenceID
		}
		return evidence[i].SourceLocation < evidence[j].SourceLocation
	})
	findings := append([]model.Finding(nil), det.Findings...)
	sort.SliceStable(findings, func(i, j int) bool {
		if findings[i].FindingID != findings[j].FindingID {
			return findings[i].FindingID < findings[j].FindingID
		}
		return findings[i].Fingerprint < findings[j].Fingerprint
	})

	e := engine{in: in, mandatory: map[string]bool{}}
	for _, id := range in.Profile.MandatoryControls {
		e.mandatory[id] = true
	}

	for _, a := range agents {
		assessments = append(assessments, e.assessAgent(a, evidence, findings))
	}

	// Repository level: lowest score, most restrictive decision.
	low := scoring.Lowest(assessments)
	score = scoring.Clone(assessments[low].Score)
	score.FindingsBySeverity = scoring.Empty().FindingsBySeverity
	scoring.CountFindings(score.FindingsBySeverity, findings)
	var unresolved []string
	decision = model.Decision{Outcome: model.OutcomeAllow, Reasons: []model.Reason{}}
	for _, a := range assessments {
		unresolved = append(unresolved, a.Score.UnresolvedMandatory...)
		decision.Reasons = append(decision.Reasons, a.Decision.Reasons...)
		if restrictiveness(a.Decision.Outcome) > restrictiveness(decision.Outcome) {
			decision.Outcome = a.Decision.Outcome
		}
	}
	score.UnresolvedMandatory = sortedUnique(unresolved)
	return assessments, score, decision
}

func restrictiveness(o model.Outcome) int {
	switch o {
	case model.OutcomeBlock:
		return 2
	case model.OutcomeReviewRequired:
		return 1
	}
	return 0
}

type engine struct {
	in        Input
	mandatory map[string]bool
}

// assessed is a control result plus the facts the decision needs.
type assessed struct {
	res model.ControlResult
	// invalidCreditable is true when evidence that could have supported the
	// control (signal present or declared) existed but was not valid.
	invalidCreditable bool
	// hasEvidence is true when at least one valid evidence item with a signal
	// other than "error" exists.
	hasEvidence bool
	// note is an extra sentence for the decision message.
	note string
}

func (e engine) assessAgent(a model.Agent, evidence []model.Evidence, findings []model.Finding) model.AgentAssessment {
	var agentFindings []model.Finding
	for _, f := range findings {
		if f.AgentID == a.ID || f.AgentID == model.AllAgents {
			agentFindings = append(agentFindings, f)
		}
	}

	results := make([]model.ControlResult, 0, len(e.in.Catalog.Controls))
	withEvidence := map[string]bool{}
	byID := map[string]assessed{}
	for _, c := range e.in.Catalog.Controls {
		var evs []model.Evidence
		for _, ev := range evidence {
			if ev.ControlID == c.ID && (ev.AgentID == a.ID || ev.AgentID == model.AllAgents) {
				evs = append(evs, ev)
			}
		}
		var fs []model.Finding
		for _, f := range agentFindings {
			if f.ControlID == c.ID {
				fs = append(fs, f)
			}
		}
		as := e.assessControl(c, a, evs, fs)
		if as.hasEvidence && as.res.Applicable {
			withEvidence[c.ID] = true
		}
		byID[c.ID] = as
		results = append(results, as.res)
	}
	sort.SliceStable(results, func(i, j int) bool { return results[i].ControlID < results[j].ControlID })

	decision, unresolved := e.decide(a, results, byID, agentFindings)
	score := scoring.Compute(scoring.Input{
		Controls:            results,
		WithEvidence:        withEvidence,
		Findings:            agentFindings,
		UnresolvedMandatory: unresolved,
	})
	return model.AgentAssessment{AgentID: a.ID, Score: score, Decision: decision, Controls: results}
}

// applicability is the natural applicability of a control, before any
// exception and before any recorded problem.
type applicability struct {
	applicable bool
	basis      string
	reason     string
}

func (e engine) naturalApplicability(c model.Control, a model.Agent) applicability {
	if c.Applicability.Mode != "capability" {
		return applicability{true, model.BasisAlways, "This control applies to every agent."}
	}
	have := map[string]bool{}
	for _, name := range a.Capabilities {
		have[name] = true
	}
	var detected []string
	for _, name := range c.Applicability.CapabilitiesAny {
		if have[name] {
			detected = append(detected, name)
		}
	}
	if len(detected) > 0 {
		return applicability{true, model.BasisDetected, "The agent has a triggering capability: " + strings.Join(detected, ", ") + "."}
	}
	if cfg := e.in.Config; cfg != nil {
		declared := map[string]bool{
			model.CapTools:            len(cfg.Capabilities.DeclaredTools) > 0,
			model.CapSensitiveActions: len(cfg.Capabilities.SensitiveActions) > 0,
		}
		var names []string
		for _, name := range c.Applicability.CapabilitiesAny {
			if declared[name] {
				names = append(names, name)
			}
		}
		if len(names) > 0 {
			return applicability{true, model.BasisDeclared, "The configuration declares a triggering capability: " + strings.Join(names, ", ") + "."}
		}
	}
	return applicability{false, model.BasisInferred,
		"No triggering capability was detected (" + strings.Join(c.Applicability.CapabilitiesAny, ", ") + "). This is an inference, not an approval."}
}

func (e engine) assessControl(c model.Control, a model.Agent, evs []model.Evidence, fs []model.Finding) assessed {
	p := e.in.Profile
	weight := c.DefaultWeight
	if w, ok := p.Weights[c.ID]; ok && w > 0 {
		weight = w
	}
	res := model.ControlResult{
		ControlID:         c.ID,
		AgentID:           a.ID,
		Title:             c.Title,
		Domain:            c.Domain,
		PlainLanguage:     c.PlainLanguage,
		MaxStaticMaturity: c.VerificationRules.MaxStaticMaturity,
		Mandatory:         e.mandatory[c.ID],
		Weight:            weight,
		Severity:          c.Severity,
		EvidenceRefs:      []string{},
		FindingRefs:       []string{},
		Remediation:       append([]string{}, c.Remediation...),
		Limitations:       append([]string{}, c.Limitations...),
	}
	if res.Mandatory {
		res.MinMaturity = RequiredMaturity(p, c.ID)
	}
	for _, ev := range evs {
		res.EvidenceRefs = append(res.EvidenceRefs, ev.EvidenceID)
	}
	res.EvidenceRefs = sortedUnique(res.EvidenceRefs)
	for _, f := range fs {
		res.FindingRefs = append(res.FindingRefs, f.FindingID)
	}
	res.FindingRefs = sortedUnique(res.FindingRefs)

	firstStep := ""
	if len(c.Remediation) > 0 {
		firstStep = c.Remediation[0]
	}

	// Split evidence into valid and not valid, then by signal.
	var errs, viols, present, declared, absent []model.Evidence
	var invalidReasons []string
	out := assessed{}
	for _, ev := range evs {
		if why := e.invalidReason(ev); why != "" {
			invalidReasons = append(invalidReasons, why)
			if ev.Signal == model.SignalPresent || ev.Signal == model.SignalDeclared {
				out.invalidCreditable = true
			}
			continue
		}
		switch ev.Signal {
		case model.SignalError:
			errs = append(errs, ev)
		case model.SignalViolation:
			viols = append(viols, ev)
		case model.SignalPresent:
			present = append(present, ev)
		case model.SignalDeclared:
			declared = append(declared, ev)
		case model.SignalAbsent:
			absent = append(absent, ev)
		default:
			// An unrecognized signal is a collector problem. It must not pass.
			errs = append(errs, ev)
		}
	}
	out.hasEvidence = len(viols)+len(present)+len(declared)+len(absent) > 0
	invalidNote := strings.Join(uniqueInOrder(invalidReasons), " ")

	nat := e.naturalApplicability(c, a)
	notApplicable, naState := e.exception(e.notApplicableList(), c.ID)
	acceptedRisk, arState := e.exception(e.acceptedRiskList(), c.ID)

	// A recorded problem makes the control applicable even when no
	// triggering capability was detected, and even when an exception exists.
	problemApplicability := func() {
		res.Applicable = true
		res.ApplicabilityBasis = nat.basis
		res.ApplicabilityReason = nat.reason
		if !nat.applicable {
			res.ApplicabilityBasis = model.BasisDetected
			res.ApplicabilityReason = "No triggering capability was detected, but evidence of a problem was recorded for this control, so it is assessed."
		}
	}
	exceptionOverride := ""
	if naState == exceptionActive {
		exceptionOverride = " The approved not-applicable exception does not hide this result."
	} else if arState == exceptionActive {
		exceptionOverride = " The accepted risk does not cover this result."
	}

	switch {
	// 1. A collector error never passes.
	case len(errs) > 0:
		problemApplicability()
		res.Status = model.StatusError
		res.StatusReason = "The check could not complete: " + sentenceOr(errs[0].Summary, "a collector reported an error for this control.") + more(len(errs)-1, "error") + exceptionOverride
		res.NextAction = NextFixCollector

	// 2. A violation fails the control.
	case len(viols) > 0:
		problemApplicability()
		res.Status = model.StatusFailed
		res.StatusReason = sentenceOr(viols[0].Summary, "A violation was recorded for this control.") + more(len(viols)-1, "violation") + exceptionOverride
		res.NextAction = firstStep

	// 3. Approved exceptions. An accepted risk is the less lenient of the
	// two, so it wins when both are recorded.
	case arState == exceptionActive:
		res.Applicable = true
		res.ApplicabilityBasis = nat.basis
		res.ApplicabilityReason = nat.reason
		if !nat.applicable {
			res.ApplicabilityBasis = model.BasisDeclared
			res.ApplicabilityReason = "The configuration records an accepted risk for this control, so it is treated as applicable."
		}
		res.Status = model.StatusAcceptedRisk
		res.StatusReason = "Risk accepted in configuration by " + clip(acceptedRisk.ApprovedBy, 120) + ". Reason: " + sentenceOr(clip(acceptedRisk.Reason, 300), "none given.") + expiryNote(acceptedRisk) + " An accepted risk is not a pass."
		res.NextAction = NextReviewRisk

	case naState == exceptionActive:
		res.Applicable = false
		res.ApplicabilityBasis = model.BasisApproved
		res.ApplicabilityReason = "Marked not applicable in configuration by " + clip(notApplicable.ApprovedBy, 120) + ". Reason: " + sentenceOr(clip(notApplicable.Reason, 300), "none given.") + expiryNote(notApplicable)
		res.Status = model.StatusNotApplicable
		res.StatusReason = "Not applicable by approved exception."
		res.NextAction = NextReviewException

	// 4. Capability-mode control with no triggering capability.
	case !nat.applicable:
		res.Applicable = false
		res.ApplicabilityBasis = nat.basis
		res.ApplicabilityReason = nat.reason
		res.Status = model.StatusNotApplicable
		res.StatusReason = nat.reason
		res.NextAction = NextConfirmNA

	default:
		res.Applicable = true
		res.ApplicabilityBasis = nat.basis
		res.ApplicabilityReason = nat.reason
		e.creditEvidence(&res, &out, c, present, declared, absent, invalidNote, firstStep)
	}

	// Say so when an exception was recorded but could not be applied.
	if res.Status != model.StatusNotApplicable && res.Status != model.StatusAcceptedRisk {
		for _, st := range []struct {
			state exceptionState
			exc   config.Exception
			kind  string
		}{{naState, notApplicable, "not-applicable exception"}, {arState, acceptedRisk, "accepted risk"}} {
			switch st.state {
			case exceptionExpired:
				res.StatusReason += " The " + st.kind + " for this control expired on " + st.exc.Expires + "."
			case exceptionIncomplete:
				res.StatusReason += " The " + st.kind + " for this control was ignored because it lacks a reason, an approver, or a valid expiry date."
			}
		}
	}

	res.Maturity = scoring.Maturity(res.Status)
	out.res = res
	return out
}

// creditEvidence applies rules 5 to 8: present, declared, absent, nothing.
func (e engine) creditEvidence(res *model.ControlResult, out *assessed, c model.Control, present, declared, absent []model.Evidence, invalidNote, firstStep string) {
	maxStatic := c.VerificationRules.MaxStaticMaturity
	best, bestRaw := 0, 0
	var decisive *model.Evidence
	staticCapped, signCapped := false, false
	for i := range present {
		ev := &present[i]
		raw := scoring.StrengthLevel(ev.Strength)
		level := raw
		if !independentSource(ev.SourceType) {
			// Static and configuration evidence can never exceed the cap of
			// the control, whatever strength it claims.
			if level > maxStatic {
				level = maxStatic
				staticCapped = true
			}
		} else if level >= 3 && e.in.Profile.RequireSignedEvidence && ev.Integrity != model.IntegrityVerified {
			level = 2
			signCapped = true
		}
		if raw > bestRaw {
			bestRaw = raw
		}
		if level > best {
			best = level
			decisive = ev
		}
	}
	declaredOnly := false
	if best < 1 && len(declared) > 0 {
		best = 1
		decisive = &declared[0]
		declaredOnly = true
	}

	appendInvalid := func() {
		if invalidNote != "" {
			res.StatusReason += " Other evidence was not credited: " + invalidNote
		}
	}

	switch {
	case best >= 1:
		res.Status = scoring.StatusForMaturity(best)
		res.StatusReason = sentenceOr(decisive.Summary, "Evidence supports this control at "+levelName(best)+" level.")
		if declaredOnly || best == 1 {
			res.StatusReason += " A declaration alone is not proof that the control works."
		}
		reduced := bestRaw > best
		if reduced && signCapped {
			res.StatusReason += " " + MsgUnsignedCapped
			out.note = MsgUnsignedCapped
		}
		if reduced && staticCapped {
			res.StatusReason += fmt.Sprintf(" Static evidence cannot support more than level %d for this control.", maxStatic)
		}
		appendInvalid()
		switch {
		case reduced && signCapped:
			res.NextAction = NextSignEvidence
		case best == 4:
			res.NextAction = NextKeepCurrent
		case best == 3:
			res.NextAction = NextCollectRuntime
		case best == 2:
			res.NextAction = NextAddTests
		case maxStatic < 2:
			res.NextAction = NextExternalOnly
		default:
			res.NextAction = firstStep
		}

	case len(present) > 0:
		// Valid evidence exists, but the cap of the control gives it no credit.
		res.Status = model.StatusUnknown
		res.StatusReason = "Static evidence cannot support any maturity level for this control. Supply test or runtime evidence."
		appendInvalid()
		res.NextAction = NextSupplyEvidence

	case len(absent) > 0:
		res.Status = model.StatusMissing
		res.StatusReason = sentenceOr(absent[0].Summary, "A detector looked for this control and found no mechanism.")
		appendInvalid()
		res.NextAction = firstStep

	case invalidNote != "":
		res.Status = model.StatusUnknown
		res.StatusReason = invalidNote
		res.NextAction = NextFreshEvidence

	default:
		res.Status = model.StatusUnknown
		res.StatusReason = MsgNoDetector
		res.NextAction = NextSupplyEvidence
	}
}

// independentSource reports whether a source type can support maturity
// levels 3 and 4. Static and configuration evidence cannot, and neither can
// an unrecognized source type.
func independentSource(s model.SourceType) bool {
	switch s {
	case model.SourceTest, model.SourceRuntime, model.SourceAttestation, model.SourceManualReview:
		return true
	}
	return false
}

// invalidReason returns "" when the evidence may be credited, and the exact
// reason otherwise. It trusts the validity set by the evidence loader and
// adds two checks of its own: expiry against the injected clock, and a
// signature that failed verification.
func (e engine) invalidReason(ev model.Evidence) string {
	switch ev.Validity {
	case model.ValidityValid:
		if ev.Integrity == model.IntegrityInvalid {
			return MsgBadSignature
		}
		if ev.ValidUntil != nil && !e.in.Now.IsZero() && ev.ValidUntil.Before(e.in.Now) {
			return expiredMessage(ev.ValidUntil)
		}
		return ""
	case model.ValidityExpired:
		return expiredMessage(ev.ValidUntil)
	case model.ValidityCommitMismatch:
		return MsgCommitMismatch
	case model.ValidityDigestMismatch:
		return MsgDigestMismatch
	case model.ValidityUnbound:
		return MsgUnbound
	case model.ValidityInvalidSignature:
		return MsgBadSignature
	case model.ValidityMalformed:
		return MsgMalformed
	case "":
		return "Evidence has no validity state and was not credited."
	}
	return "Evidence has an unrecognized validity state and was not credited."
}

func expiredMessage(until *time.Time) string {
	if until == nil {
		return MsgExpiredNoDate
	}
	return "Evidence expired on " + until.UTC().Format("2006-01-02") + "."
}

type exceptionState int

const (
	exceptionNone exceptionState = iota
	exceptionActive
	exceptionExpired
	exceptionIncomplete
)

func (e engine) notApplicableList() []config.Exception {
	if e.in.Config == nil {
		return nil
	}
	return e.in.Config.Policy.NotApplicable
}

func (e engine) acceptedRiskList() []config.Exception {
	if e.in.Config == nil {
		return nil
	}
	return e.in.Config.Policy.AcceptedRisks
}

// exception finds the exception for a control. An exception counts only with
// a reason and an approver, and only through the end of its expiry date. An
// active entry wins over an expired or incomplete one for the same control.
func (e engine) exception(list []config.Exception, id string) (config.Exception, exceptionState) {
	var found config.Exception
	state := exceptionNone
	for _, x := range list {
		if x.Control != id {
			continue
		}
		s := exceptionActive
		if strings.TrimSpace(x.Reason) == "" || strings.TrimSpace(x.ApprovedBy) == "" {
			s = exceptionIncomplete
		} else if x.Expires != "" {
			day, err := time.Parse("2006-01-02", x.Expires)
			switch {
			case err != nil:
				s = exceptionIncomplete
			case !e.in.Now.IsZero() && !e.in.Now.UTC().Before(day.AddDate(0, 0, 1)):
				s = exceptionExpired
			}
		}
		if s == exceptionActive {
			return x, s
		}
		if state == exceptionNone {
			found, state = x, s
		}
	}
	return found, state
}

func expiryNote(x config.Exception) string {
	if x.Expires == "" {
		return " No expiry date is set."
	}
	return " Expires on " + x.Expires + "."
}

// decide turns the control results of one agent into a decision.
func (e engine) decide(a model.Agent, results []model.ControlResult, byID map[string]assessed, findings []model.Finding) (model.Decision, []string) {
	p := e.in.Profile
	var reasons []model.Reason
	var unresolved []string
	block, review, downgraded := false, false, 0

	critical := map[string][]model.Finding{}
	for _, f := range findings {
		if f.Severity == model.SeverityCritical {
			critical[f.ControlID] = append(critical[f.ControlID], f)
		}
	}
	criticalReason := func(controlID string, fs []model.Finding) model.Reason {
		subject := "this agent"
		if controlID != "" {
			subject = controlID
		}
		msg := fmt.Sprintf("%s on %s", countNoun(len(fs), "critical finding"), subject)
		if t := strings.TrimSpace(fs[0].Title); t != "" {
			msg += ": " + sentenceOr(clip(t, 200), "")
		} else {
			msg += "."
		}
		return model.Reason{Code: ReasonCriticalFinding, ControlID: controlID, AgentID: a.ID,
			Message: msg + " A critical finding blocks release whatever the score is."}
	}

	for _, r := range results {
		if r.Mandatory {
			code, softenable, reviewOnly := "", false, false
			name := fmt.Sprintf("Mandatory control %s (%s)", r.ControlID, r.Title)
			msg := ""
			as := byID[r.ControlID]
			switch {
			case r.Status == model.StatusFailed:
				code = ReasonMandatoryFailed
				msg = name + " failed. " + r.StatusReason
			case r.Status == model.StatusError:
				code = ReasonMandatoryError
				msg = name + " could not be assessed because of an error. " + r.StatusReason
			case r.Status == model.StatusAcceptedRisk:
				code, reviewOnly = ReasonMandatoryAcceptedRisk, true
				msg = name + " has an accepted risk. A reviewer must confirm it. " + r.StatusReason
			case r.Status == model.StatusNotApplicable && r.ApplicabilityBasis == model.BasisApproved:
				// An approved not-applicable decision satisfies the policy.
			case r.Status == model.StatusNotApplicable:
				code, reviewOnly = ReasonMandatoryNAInferred, true
				msg = name + " was treated as not applicable by inference. A reviewer must confirm it. " + r.ApplicabilityReason
			case r.Status == model.StatusMissing || r.Status == model.StatusUnknown || r.Maturity < r.MinMaturity:
				shortfall := fmt.Sprintf("%s is at maturity %d (%s). The profile requires %d.", name, r.Maturity, r.Status, r.MinMaturity)
				switch {
				case as.invalidCreditable:
					code = ReasonMandatoryEvidenceInvalid
					msg = shortfall + " Evidence for it was not valid. " + r.StatusReason
				case r.Status == model.StatusMissing:
					code, softenable = ReasonMandatoryMissing, true
					msg = name + " is missing. " + r.StatusReason
				case r.Status == model.StatusUnknown:
					code, softenable = ReasonMandatoryUnknown, true
					msg = name + " could not be verified. " + r.StatusReason
				default:
					code, softenable = ReasonMandatoryBelowMin, true
					msg = shortfall
					if as.note != "" {
						msg += " " + as.note
					}
				}
			}
			if code != "" {
				unresolved = append(unresolved, r.ControlID)
				switch {
				case reviewOnly:
					review = true
				case softenable && p.ReviewWorkflow:
					review = true
					downgraded++
				default:
					block = true
				}
				reasons = append(reasons, model.Reason{Code: code, ControlID: r.ControlID, AgentID: a.ID, Message: strings.TrimSpace(msg)})
			}
		}
		if fs := critical[r.ControlID]; len(fs) > 0 {
			block = true
			reasons = append(reasons, criticalReason(r.ControlID, fs))
			delete(critical, r.ControlID)
		}
	}

	// Critical findings that name no catalog control still block.
	var rest []string
	for id := range critical {
		rest = append(rest, id)
	}
	sort.Strings(rest)
	for _, id := range rest {
		block = true
		reasons = append(reasons, criticalReason(id, critical[id]))
	}

	// A mandatory control that the catalog does not define cannot be shown
	// to be met, so it blocks instead of disappearing.
	var orphan []string
	for id := range e.mandatory {
		if _, ok := byID[id]; !ok {
			orphan = append(orphan, id)
		}
	}
	sort.Strings(orphan)
	for _, id := range orphan {
		block = true
		unresolved = append(unresolved, id)
		reasons = append(reasons, model.Reason{Code: ReasonMandatoryUnknown, ControlID: id, AgentID: a.ID,
			Message: "Mandatory control " + id + " is not defined in the control catalog, so it could not be verified."})
	}

	if downgraded > 0 {
		reasons = append(reasons, model.Reason{Code: ReasonReviewWorkflow, AgentID: a.ID,
			Message: fmt.Sprintf("The profile enables a review workflow. %s on mandatory controls need a reviewer decision instead of blocking. This is not a pass.", countNoun(downgraded, "shortfall"))})
	}

	d := model.Decision{Reasons: reasons}
	switch {
	case block:
		d.Outcome = model.OutcomeBlock
	case review:
		d.Outcome = model.OutcomeReviewRequired
	default:
		d.Outcome = model.OutcomeAllow
		d.Reasons = []model.Reason{{Code: ReasonPolicySatisfied, AgentID: a.ID,
			Message: fmt.Sprintf("Every mandatory control of profile %q meets its requirement, and no critical finding is open. This is a policy decision, not a certification.", p.Name)}}
	}
	return d, sortedUnique(unresolved)
}

// AttachMappings fills Finding.Mappings from the catalog control each finding
// belongs to. A finding whose control is not in the catalog gets an empty
// list. Mappings are references to published standards. They are not a
// certification or an endorsement.
func AttachMappings(findings []model.Finding, cat *model.Catalog) {
	byID := map[string][]model.Mapping{}
	if cat != nil {
		for _, c := range cat.Controls {
			byID[c.ID] = c.StandardsMappings
		}
	}
	for i := range findings {
		findings[i].Mappings = append([]model.Mapping{}, byID[findings[i].ControlID]...)
	}
}

// --- small text helpers ----------------------------------------------------

// sentenceOr returns s as one trimmed sentence that ends with punctuation,
// or the fallback when s is blank.
func sentenceOr(s, fallback string) string {
	s = strings.Join(strings.Fields(s), " ")
	if s == "" {
		return fallback
	}
	switch s[len(s)-1] {
	case '.', '!', '?':
		return s
	}
	return s + "."
}

func more(n int, noun string) string {
	if n <= 0 {
		return ""
	}
	return fmt.Sprintf(" %s recorded in addition.", countNoun(n, "more "+noun))
}

func countNoun(n int, noun string) string {
	if n == 1 {
		return "1 " + noun
	}
	return fmt.Sprintf("%d %ss", n, noun)
}

func clip(s string, max int) string {
	s = strings.Join(strings.Fields(s), " ")
	r := []rune(s)
	if len(r) <= max {
		return s
	}
	return string(r[:max]) + "..."
}

func levelName(level int) string {
	switch level {
	case 4:
		return "operational"
	case 3:
		return "tested"
	case 2:
		return "implementation"
	}
	return "declared"
}

func uniqueInOrder(in []string) []string {
	seen := map[string]bool{}
	var out []string
	for _, s := range in {
		if !seen[s] {
			seen[s] = true
			out = append(out, s)
		}
	}
	return out
}
