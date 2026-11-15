// SPDX-License-Identifier: Apache-2.0

package scoring

import (
	"reflect"
	"testing"

	"github.com/shahzadarain/agent-governance-auditor/internal/model"
)

func cr(id string, status model.Status, weight int) model.ControlResult {
	return model.ControlResult{ControlID: id, Status: status, Maturity: Maturity(status), Weight: weight,
		Applicable: status != model.StatusNotApplicable}
}

func TestMaturityLevels(t *testing.T) {
	want := map[model.Status]int{
		model.StatusVerifiedOperational:    4,
		model.StatusVerifiedTested:         3,
		model.StatusVerifiedImplementation: 2,
		model.StatusDeclaredOnly:           1,
		model.StatusMissing:                0,
		model.StatusFailed:                 0,
		model.StatusUnknown:                0,
		model.StatusNotApplicable:          0,
		model.StatusAcceptedRisk:           0,
		model.StatusError:                  0,
		model.Status("made-up"):            0,
	}
	if len(AllStatuses) != 10 {
		t.Fatalf("want 10 statuses, got %d", len(AllStatuses))
	}
	for _, s := range AllStatuses {
		if _, ok := want[s]; !ok {
			t.Errorf("status %s is not covered by this test", s)
		}
	}
	for s, m := range want {
		if got := Maturity(s); got != m {
			t.Errorf("Maturity(%s) = %d, want %d", s, got, m)
		}
	}
	for level := 1; level <= 4; level++ {
		if Maturity(StatusForMaturity(level)) != level {
			t.Errorf("StatusForMaturity(%d) does not round-trip", level)
		}
	}
	if StatusForMaturity(0) != model.StatusUnknown || StatusForMaturity(9) != model.StatusUnknown {
		t.Errorf("levels outside 1..4 have no verified status")
	}
	for s, level := range map[model.Strength]int{
		model.StrengthDeclared: 1, model.StrengthImplementation: 2, model.StrengthTested: 3,
		model.StrengthOperational: 4, model.Strength(""): 1, model.Strength("heroic"): 1,
	} {
		if got := StrengthLevel(s); got != level {
			t.Errorf("StrengthLevel(%q) = %d, want %d", s, got, level)
		}
	}
}

func TestWeighted(t *testing.T) {
	op, te, im, de := model.StatusVerifiedOperational, model.StatusVerifiedTested, model.StatusVerifiedImplementation, model.StatusDeclaredOnly
	tests := []struct {
		name     string
		controls []model.ControlResult
		want     int
		ok       bool
	}{
		{"all operational", []model.ControlResult{cr("a", op, 5), cr("b", op, 1)}, 100, true},
		{"all tested", []model.ControlResult{cr("a", te, 5), cr("b", te, 1)}, 75, true},
		{"all implementation", []model.ControlResult{cr("a", im, 3)}, 50, true},
		{"all declared", []model.ControlResult{cr("a", de, 3)}, 25, true},
		{"all missing", []model.ControlResult{cr("a", model.StatusMissing, 3)}, 0, true},
		{"failed, unknown, error, accepted risk count as 0", []model.ControlResult{
			cr("a", model.StatusFailed, 1), cr("b", model.StatusUnknown, 1), cr("c", model.StatusError, 1),
			cr("d", model.StatusAcceptedRisk, 1), cr("e", op, 4)}, 50, true},
		{"weights matter: heavy control operational", []model.ControlResult{cr("a", op, 9), cr("b", model.StatusMissing, 1)}, 90, true},
		{"weights matter: light control operational", []model.ControlResult{cr("a", op, 1), cr("b", model.StatusMissing, 9)}, 10, true},
		{"mixed levels", []model.ControlResult{cr("a", op, 5), cr("b", te, 4), cr("c", im, 3), cr("d", de, 2), cr("e", model.StatusFailed, 1)}, 67, true},
		// (5*4 + 4*3 + 3*2 + 2*1 + 0) / (15*4) = 40/60 = 66.67
		{"not-applicable leaves the denominator", []model.ControlResult{cr("a", op, 2), cr("b", model.StatusNotApplicable, 50)}, 100, true},
		{"accepted risk stays in the denominator", []model.ControlResult{cr("a", op, 1), cr("b", model.StatusAcceptedRisk, 1)}, 50, true},
		{"rounds down below half", []model.ControlResult{cr("a", de, 1), cr("b", model.StatusMissing, 2)}, 8, true}, // 8.33
		{"rounds up above half", []model.ControlResult{cr("a", de, 2), cr("b", model.StatusMissing, 1)}, 17, true},  // 16.67
		{"rounds half up", []model.ControlResult{cr("a", de, 1), cr("b", model.StatusMissing, 1)}, 13, true},        // 12.5
		{"rounds half up again", []model.ControlResult{cr("a", te, 1), cr("b", model.StatusMissing, 1)}, 38, true},  // 37.5
		{"no applicable controls", []model.ControlResult{cr("a", model.StatusNotApplicable, 3)}, 0, false},
		{"no controls", nil, 0, false},
		{"zero weights give no score", []model.ControlResult{cr("a", op, 0)}, 0, false},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got, ok := Weighted(tc.controls)
			if got != tc.want || ok != tc.ok {
				t.Fatalf("got %d %v, want %d %v", got, ok, tc.want, tc.ok)
			}
		})
	}
}

func TestWeightedClampsMaturity(t *testing.T) {
	got, _ := Weighted([]model.ControlResult{{Applicable: true, Weight: 1, Maturity: 99}, {Applicable: true, Weight: 1, Maturity: -5}})
	if got != 50 {
		t.Fatalf("out-of-range maturity must be clamped to 0..4, got %d", got)
	}
}

func TestPercent(t *testing.T) {
	for _, tc := range []struct {
		num, den int64
		want     int
	}{
		{0, 10, 0}, {10, 10, 100}, {1, 3, 33}, {2, 3, 67}, {1, 8, 13}, {1, 200, 1}, {1, 201, 0}, {5, 0, 0}, {5, -1, 0},
	} {
		if got := Percent(tc.num, tc.den); got != tc.want {
			t.Errorf("Percent(%d, %d) = %d, want %d", tc.num, tc.den, got, tc.want)
		}
	}
}

func TestCompute(t *testing.T) {
	controls := []model.ControlResult{
		cr("AGC-001", model.StatusVerifiedOperational, 5),
		cr("AGC-002", model.StatusVerifiedTested, 2),
		cr("AGC-003", model.StatusVerifiedImplementation, 3),
		cr("AGC-004", model.StatusFailed, 5),
		cr("AGC-005", model.StatusNotApplicable, 5),
		cr("AGC-006", model.StatusAcceptedRisk, 3),
	}
	s := Compute(Input{
		Controls:     controls,
		WithEvidence: map[string]bool{"AGC-001": true, "AGC-002": true, "AGC-003": true, "AGC-004": true, "AGC-005": true},
		Findings: []model.Finding{{Severity: model.SeverityCritical}, {Severity: model.SeverityLow}, {Severity: model.SeverityLow},
			{Severity: "odd"}},
		UnresolvedMandatory: []string{"AGC-004", "AGC-001"},
	})
	// (5*4 + 2*3 + 3*2 + 0 + 0) / (18*4) = 32/72 = 44.4
	if s.Value == nil || *s.Value != 44 || s.Label != "44/100" {
		t.Fatalf("score %v %q", s.Value, s.Label)
	}
	if s.ApplicableControls != 5 || s.ControlsWithEvidence != 4 || s.CoveragePercent != 80 {
		t.Errorf("coverage: %+v", s)
	}
	if s.TestedPercent != 40 || s.OperationalPercent != 20 {
		t.Errorf("tested %d operational %d", s.TestedPercent, s.OperationalPercent)
	}
	wantSev := map[string]int{"critical": 1, "high": 0, "medium": 0, "low": 2, "info": 1}
	if !reflect.DeepEqual(s.FindingsBySeverity, wantSev) {
		t.Errorf("findings %v", s.FindingsBySeverity)
	}
	if len(s.StatusCounts) != 10 || s.StatusCounts["failed"] != 1 || s.StatusCounts["not-applicable"] != 1 || s.StatusCounts["missing"] != 0 {
		t.Errorf("status counts %v", s.StatusCounts)
	}
	if !reflect.DeepEqual(s.UnresolvedMandatory, []string{"AGC-001", "AGC-004"}) {
		t.Errorf("unresolved must be sorted: %v", s.UnresolvedMandatory)
	}
}

func TestEmptyAndLabel(t *testing.T) {
	s := Empty()
	if s.Value != nil || s.Label != InsufficientEvidence || len(s.FindingsBySeverity) != 5 || len(s.StatusCounts) != 10 || s.UnresolvedMandatory == nil {
		t.Fatalf("%+v", s)
	}
	none := Compute(Input{Controls: []model.ControlResult{cr("a", model.StatusNotApplicable, 3)}})
	if none.Value != nil || none.Label != InsufficientEvidence || none.CoveragePercent != 0 {
		t.Fatalf("%+v", none)
	}
	zero, hundred := 0, 100
	if Label(&zero) != "0/100" || Label(&hundred) != "100/100" || Label(nil) != InsufficientEvidence {
		t.Error("labels")
	}
}

func TestCloneIsDeep(t *testing.T) {
	v := 40
	a := Empty()
	a.Value = &v
	a.UnresolvedMandatory = []string{"AGC-001"}
	b := Clone(a)
	*b.Value = 1
	b.FindingsBySeverity["high"] = 7
	b.StatusCounts["failed"] = 7
	b.UnresolvedMandatory[0] = "x"
	if *a.Value != 40 || a.FindingsBySeverity["high"] != 0 || a.StatusCounts["failed"] != 0 || a.UnresolvedMandatory[0] != "AGC-001" {
		t.Fatal("Clone must not share state")
	}
}

func TestLowest(t *testing.T) {
	val := func(v int) *int { return &v }
	mk := func(id string, v *int) model.AgentAssessment {
		return model.AgentAssessment{AgentID: id, Score: model.Score{Value: v}}
	}
	if Lowest(nil) != -1 {
		t.Error("empty list")
	}
	list := []model.AgentAssessment{mk("c", val(70)), mk("b", val(40)), mk("a", val(40)), mk("d", val(90))}
	if got := Lowest(list); list[got].AgentID != "a" {
		t.Errorf("ties go to the first agent ID, got %s", list[got].AgentID)
	}
	list = append(list, mk("z", nil))
	if got := Lowest(list); list[got].AgentID != "z" {
		t.Errorf("a score with no value ranks lowest, got %s", list[got].AgentID)
	}
}
