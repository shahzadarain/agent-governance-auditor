// SPDX-License-Identifier: Apache-2.0

// Package scoring computes the transparent maturity score and its companion
// measures from assessed control results.
//
// The score is illustrative. It is never a certification, a compliance
// statement, or a probability of safety, and it never changes a policy
// decision. Decisions are made in internal/policy from mandatory controls.
package scoring

import (
	"fmt"
	"sort"

	"github.com/shahzadarain/agent-governance-auditor/internal/model"
)

// InsufficientEvidence is the score label used when no control is applicable.
const InsufficientEvidence = "insufficient-evidence"

// MaxMaturity is the highest verification maturity level.
const MaxMaturity = 4

// AllStatuses lists every status in display order.
var AllStatuses = []model.Status{
	model.StatusVerifiedOperational,
	model.StatusVerifiedTested,
	model.StatusVerifiedImplementation,
	model.StatusDeclaredOnly,
	model.StatusMissing,
	model.StatusFailed,
	model.StatusUnknown,
	model.StatusNotApplicable,
	model.StatusAcceptedRisk,
	model.StatusError,
}

// AllSeverities lists every severity from most to least severe.
var AllSeverities = []model.Severity{
	model.SeverityCritical,
	model.SeverityHigh,
	model.SeverityMedium,
	model.SeverityLow,
	model.SeverityInfo,
}

// Maturity returns the verification maturity of a status: operational 4,
// tested 3, implementation 2, declared-only 1, and 0 for every other status.
func Maturity(s model.Status) int {
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

// StatusForMaturity returns the status that corresponds to a credited
// maturity level from 1 to 4. Level 0 has no single status and returns
// StatusUnknown.
func StatusForMaturity(level int) model.Status {
	switch level {
	case 4:
		return model.StatusVerifiedOperational
	case 3:
		return model.StatusVerifiedTested
	case 2:
		return model.StatusVerifiedImplementation
	case 1:
		return model.StatusDeclaredOnly
	}
	return model.StatusUnknown
}

// StrengthLevel returns the maturity an evidence strength can support on its
// own. An unrecognized strength supports only level 1.
func StrengthLevel(s model.Strength) int {
	switch s {
	case model.StrengthOperational:
		return 4
	case model.StrengthTested:
		return 3
	case model.StrengthImplementation:
		return 2
	}
	return 1
}

// Weighted returns round(100 * sum(w_i * m_i / 4) / sum(w_i)) over the
// applicable controls. ok is false when no applicable control carries weight,
// in which case there is no score.
func Weighted(controls []model.ControlResult) (value int, ok bool) {
	var num, den int64
	for _, c := range controls {
		if !c.Applicable {
			continue
		}
		m := c.Maturity
		if m < 0 {
			m = 0
		}
		if m > MaxMaturity {
			m = MaxMaturity
		}
		num += int64(c.Weight) * int64(m)
		den += int64(c.Weight)
	}
	if den <= 0 {
		return 0, false
	}
	return Percent(num, den*MaxMaturity), true
}

// Percent returns round(100 * num / den) with halves rounded up, using
// integer arithmetic so the result is identical on every platform. It
// returns 0 when den is not positive.
func Percent(num, den int64) int {
	if den <= 0 {
		return 0
	}
	return int((200*num + den) / (2 * den))
}

// Label formats a score value as "NN/100", or the insufficient-evidence
// label for nil.
func Label(v *int) string {
	if v == nil {
		return InsufficientEvidence
	}
	return fmt.Sprintf("%d/100", *v)
}

// Input is everything Compute needs for one agent.
type Input struct {
	Controls []model.ControlResult
	// WithEvidence holds the IDs of controls that have at least one valid
	// evidence item whose signal is not "error".
	WithEvidence map[string]bool
	// Findings are the findings that apply to the agent.
	Findings []model.Finding
	// UnresolvedMandatory are the IDs of mandatory controls with a shortfall.
	UnresolvedMandatory []string
}

// Compute builds the Score for one agent. Not-applicable controls are left
// out of the denominator. Accepted risks stay in it at maturity 0.
func Compute(in Input) model.Score {
	s := Empty()
	var tested, operational int
	for _, c := range in.Controls {
		s.StatusCounts[string(c.Status)]++
		if !c.Applicable {
			continue
		}
		s.ApplicableControls++
		if in.WithEvidence[c.ControlID] {
			s.ControlsWithEvidence++
		}
		if c.Maturity >= 3 {
			tested++
		}
		if c.Maturity >= 4 {
			operational++
		}
	}
	if v, ok := Weighted(in.Controls); ok {
		s.Value = &v
	}
	s.Label = Label(s.Value)
	n := int64(s.ApplicableControls)
	s.CoveragePercent = Percent(int64(s.ControlsWithEvidence), n)
	s.TestedPercent = Percent(int64(tested), n)
	s.OperationalPercent = Percent(int64(operational), n)
	CountFindings(s.FindingsBySeverity, in.Findings)
	s.UnresolvedMandatory = append([]string{}, in.UnresolvedMandatory...)
	sort.Strings(s.UnresolvedMandatory)
	return s
}

// Empty returns a score with no value, the insufficient-evidence label, and
// zero-filled maps that hold every severity and every status.
func Empty() model.Score {
	s := model.Score{
		Label:               InsufficientEvidence,
		FindingsBySeverity:  make(map[string]int, len(AllSeverities)),
		StatusCounts:        make(map[string]int, len(AllStatuses)),
		UnresolvedMandatory: []string{},
	}
	for _, sev := range AllSeverities {
		s.FindingsBySeverity[string(sev)] = 0
	}
	for _, st := range AllStatuses {
		s.StatusCounts[string(st)] = 0
	}
	return s
}

// CountFindings adds the findings to a severity map. A finding with an
// unrecognized severity is not counted under a new key, so the map keeps
// exactly the five known keys; such a finding counts as "info".
func CountFindings(into map[string]int, findings []model.Finding) {
	for _, f := range findings {
		key := string(f.Severity)
		if _, known := into[key]; !known {
			key = string(model.SeverityInfo)
		}
		into[key]++
	}
}

// Clone returns a deep copy of a score.
func Clone(s model.Score) model.Score {
	out := s
	if s.Value != nil {
		v := *s.Value
		out.Value = &v
	}
	out.FindingsBySeverity = make(map[string]int, len(s.FindingsBySeverity))
	for k, v := range s.FindingsBySeverity {
		out.FindingsBySeverity[k] = v
	}
	out.StatusCounts = make(map[string]int, len(s.StatusCounts))
	for k, v := range s.StatusCounts {
		out.StatusCounts[k] = v
	}
	out.UnresolvedMandatory = append([]string{}, s.UnresolvedMandatory...)
	return out
}

// Lowest returns the index of the lowest-scoring assessment. A score with no
// value ranks below every number, because it gives the least assurance. Ties
// go to the lexicographically first agent ID. It returns -1 for an empty
// list.
func Lowest(assessments []model.AgentAssessment) int {
	best := -1
	for i, a := range assessments {
		if best < 0 || less(a, assessments[best]) {
			best = i
		}
	}
	return best
}

func less(a, b model.AgentAssessment) bool {
	av, bv := rank(a.Score), rank(b.Score)
	if av != bv {
		return av < bv
	}
	return a.AgentID < b.AgentID
}

func rank(s model.Score) int {
	if s.Value == nil {
		return -1
	}
	return *s.Value
}
