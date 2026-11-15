// SPDX-License-Identifier: Apache-2.0

package reporting

import (
	"strings"

	"github.com/shahzadarain/agent-governance-auditor/internal/model"
)

// ScoreNote is attached to every numeric score.
const ScoreNote = "illustrative only"

// Disclaimer closes every human-readable report.
const Disclaimer = "This is an evidence-based assessment, not a certification."

// StatusLabel returns the plain-language label for a control status.
func StatusLabel(s model.Status) string {
	switch s {
	case model.StatusVerifiedOperational:
		return "Verified in operation"
	case model.StatusVerifiedTested:
		return "Verified by tests"
	case model.StatusVerifiedImplementation:
		return "Implemented (not yet tested)"
	case model.StatusDeclaredOnly:
		return "Declared only"
	case model.StatusMissing:
		return "Missing"
	case model.StatusFailed:
		return "Failed"
	case model.StatusNotApplicable:
		return "Not applicable"
	case model.StatusAcceptedRisk:
		return "Accepted risk"
	case model.StatusError:
		return "Assessment error"
	default:
		// StatusUnknown and any value this build does not recognize.
		return "Unknown (needs evidence)"
	}
}

// StatusMeaning returns one sentence that explains a status to a reader with
// no security training.
func StatusMeaning(s model.Status) string {
	switch s {
	case model.StatusVerifiedOperational:
		return "Evidence from the running system shows the control works."
	case model.StatusVerifiedTested:
		return "A test result shows the control works."
	case model.StatusVerifiedImplementation:
		return "The control exists in the code or configuration. No test result proves it works yet."
	case model.StatusDeclaredOnly:
		return "A document or setting says the control exists. Nothing confirms it."
	case model.StatusMissing:
		return "The scanner looked for the control and did not find it."
	case model.StatusFailed:
		return "The scanner found a concrete problem or a failed test."
	case model.StatusNotApplicable:
		return "The control does not apply to this agent. It is left out of the score."
	case model.StatusAcceptedRisk:
		return "A recorded exception covers this control. It does not count as a pass."
	case model.StatusError:
		return "The check itself did not complete. Run it again or review it by hand."
	default:
		return "The scanner could not assess the control. More evidence is needed."
	}
}

// AllStatuses lists every status in display order.
func AllStatuses() []model.Status {
	return []model.Status{
		model.StatusVerifiedOperational,
		model.StatusVerifiedTested,
		model.StatusVerifiedImplementation,
		model.StatusDeclaredOnly,
		model.StatusAcceptedRisk,
		model.StatusUnknown,
		model.StatusMissing,
		model.StatusFailed,
		model.StatusError,
		model.StatusNotApplicable,
	}
}

// DecisionName returns the short display name of a release decision.
func DecisionName(o model.Outcome) string {
	switch o {
	case model.OutcomeAllow:
		return "ALLOW"
	case model.OutcomeBlock:
		return "BLOCK"
	case model.OutcomeReviewRequired:
		return "REVIEW REQUIRED"
	default:
		return "UNDETERMINED"
	}
}

// DecisionLabel returns the release decision with its plain-language meaning.
func DecisionLabel(o model.Outcome) string {
	switch o {
	case model.OutcomeAllow:
		return "ALLOW: the release policy is satisfied"
	case model.OutcomeBlock:
		return "BLOCK: do not release until the listed controls are fixed"
	case model.OutcomeReviewRequired:
		return "REVIEW REQUIRED: a person must review before release"
	default:
		return "UNDETERMINED: the decision could not be read, so do not treat this as a pass"
	}
}

// DecisionExplanation returns the meaning part of DecisionLabel as a sentence,
// for layouts that already show the decision name.
func DecisionExplanation(o model.Outcome) string {
	label := DecisionLabel(o)
	_, rest, ok := strings.Cut(label, ": ")
	if !ok || rest == "" {
		return label
	}
	return strings.ToUpper(rest[:1]) + rest[1:] + "."
}

// Rollup is one of the five summary groups used in compact views.
type Rollup int

// The five roll-up groups, in display order.
const (
	RollupVerified      Rollup = iota // maturity 3 or 4
	RollupPartial                     // maturity 1 or 2, and accepted risks
	RollupUnknown                     // could not be assessed
	RollupFailed                      // failed, missing, or assessment error
	RollupNotApplicable               // left out of the score
)

// Rollups lists the five groups in display order.
func Rollups() []Rollup {
	return []Rollup{RollupVerified, RollupPartial, RollupUnknown, RollupFailed, RollupNotApplicable}
}

// RollupOf maps a status to its roll-up group. An accepted risk is counted as
// partial: it is a recorded exception, not a pass and not a failure.
func RollupOf(s model.Status) Rollup {
	switch s {
	case model.StatusVerifiedOperational, model.StatusVerifiedTested:
		return RollupVerified
	case model.StatusVerifiedImplementation, model.StatusDeclaredOnly, model.StatusAcceptedRisk:
		return RollupPartial
	case model.StatusFailed, model.StatusMissing, model.StatusError:
		return RollupFailed
	case model.StatusNotApplicable:
		return RollupNotApplicable
	default:
		return RollupUnknown
	}
}

// Label returns the display name of the group.
func (r Rollup) Label() string {
	switch r {
	case RollupVerified:
		return "Verified"
	case RollupPartial:
		return "Partial"
	case RollupFailed:
		return "Failed"
	case RollupNotApplicable:
		return "Not applicable"
	default:
		return "Unknown"
	}
}

// Meaning returns one sentence that explains the group.
func (r Rollup) Meaning() string {
	switch r {
	case RollupVerified:
		return "Test or operational evidence shows the control works."
	case RollupPartial:
		return "The control is implemented or declared but not proven by tests, or a recorded exception covers it."
	case RollupFailed:
		return "The control failed, is missing, or could not be checked because of an error."
	case RollupNotApplicable:
		return "The control does not apply and is left out of the score."
	default:
		return "There is not enough evidence to assess the control."
	}
}

// Symbol returns the ASCII symbol that accompanies the group, so that status
// never depends on color alone.
func (r Rollup) Symbol() string {
	switch r {
	case RollupVerified:
		return "[ok]"
	case RollupPartial:
		return "[!]"
	case RollupFailed:
		return "[x]"
	case RollupNotApplicable:
		return "[-]"
	default:
		return "[?]"
	}
}

func (r Rollup) key() string {
	switch r {
	case RollupVerified:
		return "verified"
	case RollupPartial:
		return "partial"
	case RollupFailed:
		return "failed"
	case RollupNotApplicable:
		return "na"
	default:
		return "unknown"
	}
}

func outcomeSymbol(o model.Outcome) string {
	switch o {
	case model.OutcomeAllow:
		return "[ok]"
	case model.OutcomeBlock:
		return "[x]"
	case model.OutcomeReviewRequired:
		return "[!]"
	default:
		return "[?]"
	}
}

func outcomeKey(o model.Outcome) string {
	switch o {
	case model.OutcomeAllow:
		return "allow"
	case model.OutcomeBlock:
		return "block"
	case model.OutcomeReviewRequired:
		return "review"
	default:
		return "unknown"
	}
}

// severityOrder lists severities from most to least serious.
var severityOrder = []model.Severity{
	model.SeverityCritical, model.SeverityHigh, model.SeverityMedium, model.SeverityLow, model.SeverityInfo,
}

func severityRank(s model.Severity) int {
	for i, v := range severityOrder {
		if v == s {
			return i
		}
	}
	return len(severityOrder)
}

func severityLabel(s model.Severity) string {
	switch s {
	case model.SeverityCritical:
		return "Critical"
	case model.SeverityHigh:
		return "High"
	case model.SeverityMedium:
		return "Medium"
	case model.SeverityLow:
		return "Low"
	case model.SeverityInfo:
		return "Info"
	default:
		return "Unrated"
	}
}

func severityKey(s model.Severity) string {
	if severityRank(s) < len(severityOrder) {
		return string(s)
	}
	return "unrated"
}

func profileSourceLabel(src string) string {
	switch src {
	case "flag":
		return "set on the command line"
	case "config":
		return "set in the configuration file"
	case "baseline-lock":
		return "locked by the organization baseline"
	case "inferred":
		return "inferred from the detected capabilities"
	case "default":
		return "default profile"
	case "":
		return "source not recorded"
	default:
		return src
	}
}

func sourceTypeLabel(s model.SourceType) string {
	switch s {
	case model.SourceStatic:
		return "Static scan"
	case model.SourceConfiguration:
		return "Configuration"
	case model.SourceTest:
		return "Test result"
	case model.SourceRuntime:
		return "Runtime record"
	case model.SourceAttestation:
		return "External attestation"
	case model.SourceManualReview:
		return "Manual review"
	default:
		return "Unknown source"
	}
}

func validityLabel(v model.Validity) string {
	switch v {
	case model.ValidityValid:
		return "Valid"
	case model.ValidityExpired:
		return "Expired"
	case model.ValidityCommitMismatch:
		return "Bound to a different commit"
	case model.ValidityDigestMismatch:
		return "Files changed since collection"
	case model.ValidityUnbound:
		return "Not bound to a commit or digest"
	case model.ValidityInvalidSignature:
		return "Signature did not verify"
	case model.ValidityMalformed:
		return "Malformed"
	default:
		return "Unknown validity"
	}
}

func integrityLabel(i model.Integrity) string {
	switch i {
	case model.IntegrityVerified:
		return "Signature verified"
	case model.IntegrityUnsigned:
		return "Unsigned"
	case model.IntegrityInvalid:
		return "Signature invalid"
	case model.IntegrityNotAvailable:
		return "Observed by the scanner"
	default:
		return "Unknown integrity"
	}
}

func detectionLabel(d model.DetectionState) string {
	switch d {
	case model.Detected:
		return "detected"
	case model.Suspected:
		return "suspected"
	case model.NotDetected:
		return "not detected"
	default:
		return "unknown"
	}
}

func confidenceLabel(c model.Confidence) string {
	switch c {
	case model.ConfidenceHigh:
		return "high confidence"
	case model.ConfidenceMedium:
		return "medium confidence"
	case model.ConfidenceLow:
		return "low confidence"
	default:
		return "confidence unknown"
	}
}

// noAgentLines is the plain explanation shown when discovery found no agent.
var noAgentLines = []string{
	"Discovery looks for agent framework imports, tool definitions, MCP server or client configuration, and model client calls in Python, TypeScript, and JavaScript files.",
	"This is not a pass. No control was assessed, so there is no score.",
	"If this repository contains an agent, declare it: run agentgov init, fill in the generated .agentgov.yaml file, and scan again.",
}

const noAgentTitle = "No AI agent was detected"
