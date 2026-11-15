// SPDX-License-Identifier: Apache-2.0

package policy

import (
	"io/fs"
	"os"
	"path/filepath"
	"reflect"
	"sort"
	"strings"
	"testing"

	"github.com/shahzadarain/agent-governance-auditor/internal/config"
	"github.com/shahzadarain/agent-governance-auditor/internal/model"
	"github.com/shahzadarain/agent-governance-auditor/policies"
)

func TestBuiltInProfiles(t *testing.T) {
	want := map[string]struct {
		mandatory []string
		min       int
		signed    bool
	}{
		ProfileBaseline: {[]string{"AGC-001", "AGC-005", "AGC-008", "AGC-022"}, 2, false},
		ProfileStandard: {[]string{"AGC-001", "AGC-004", "AGC-005", "AGC-007", "AGC-008", "AGC-010", "AGC-012", "AGC-017", "AGC-022"}, 2, false},
		ProfileHighRisk: {[]string{"AGC-001", "AGC-004", "AGC-005", "AGC-007", "AGC-008", "AGC-009", "AGC-010", "AGC-012", "AGC-017", "AGC-020", "AGC-022", "AGC-023"}, 3, true},
	}
	if !reflect.DeepEqual(ProfileNames(), []string{"baseline", "standard", "high-risk"}) {
		t.Fatalf("profile names %v", ProfileNames())
	}
	for _, name := range ProfileNames() {
		p, err := LoadProfile(name)
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		w := want[name]
		if p.Name != name || p.Version != "1.0" {
			t.Errorf("%s: name %q version %q", name, p.Name, p.Version)
		}
		if !reflect.DeepEqual(p.MandatoryControls, w.mandatory) || p.MinMaturity != w.min || p.RequireSignedEvidence != w.signed || p.ReviewWorkflow {
			t.Errorf("%s: %+v", name, p)
		}
		if !strings.Contains(p.Description, "roject default") {
			t.Errorf("%s: the description must label the profile as a project default", name)
		}
	}

	// Every embedded profile file is reachable by name.
	entries, err := fs.ReadDir(policies.FS, policies.ProfilesDir)
	if err != nil {
		t.Fatal(err)
	}
	var files []string
	for _, e := range entries {
		files = append(files, strings.TrimSuffix(e.Name(), ".yaml"))
	}
	names := ProfileNames()
	sort.Strings(names)
	sort.Strings(files)
	if !reflect.DeepEqual(files, names) {
		t.Errorf("embedded profiles %v do not match ProfileNames %v", files, names)
	}

	if _, err := LoadProfile("lenient"); err == nil || !strings.Contains(err.Error(), "baseline, standard, high-risk") {
		t.Errorf("unknown profile error: %v", err)
	}
	// Callers get a copy.
	a, _ := LoadProfile(ProfileBaseline)
	a.MandatoryControls[0] = "changed"
	b, _ := LoadProfile(ProfileBaseline)
	if b.MandatoryControls[0] != "AGC-001" {
		t.Errorf("LoadProfile must return a fresh copy")
	}
}

func TestParseProfileRejectsBadInput(t *testing.T) {
	valid := "name: org\nversion: \"2.1\"\ndescription: Organization baseline for all agents.\nmandatory_controls: [AGC-023, AGC-003]\nmin_maturity: 3\n"
	p, err := ParseProfile([]byte(valid))
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(p.MandatoryControls, []string{"AGC-003", "AGC-023"}) {
		t.Errorf("mandatory controls must be sorted: %v", p.MandatoryControls)
	}
	for name, doc := range map[string]string{
		"unknown field":    valid + "allow_everything: true\n",
		"bad control ID":   strings.Replace(valid, "AGC-023", "AGC-025", 1),
		"maturity too big": strings.Replace(valid, "min_maturity: 3", "min_maturity: 5", 1),
		"negative":         strings.Replace(valid, "min_maturity: 3", "min_maturity: -1", 1),
		"missing name":     strings.Replace(valid, "name: org\n", "", 1),
		"zero weight":      valid + "weights:\n  AGC-001: 0\n",
		"bad weight key":   valid + "weights:\n  AGC-099: 3\n",
		"malformed":        "name: [unclosed",
		"empty":            "",
	} {
		if _, err := ParseProfile([]byte(doc)); err == nil {
			t.Errorf("%s: expected an error", name)
		}
	}
}

func TestLoadBaseline(t *testing.T) {
	dir := t.TempDir()
	good := filepath.Join(dir, "org-baseline.yaml")
	doc := "name: org-baseline\nversion: \"3\"\ndescription: Organization baseline kept outside the repository.\nmandatory_controls: [AGC-023]\nmin_maturity: 3\nrequire_signed_evidence: true\n"
	if err := os.WriteFile(good, []byte(doc), 0o600); err != nil {
		t.Fatal(err)
	}
	p, err := LoadBaseline(good)
	if err != nil {
		t.Fatal(err)
	}
	if p.Name != "org-baseline" || p.MinMaturity != 3 || !p.RequireSignedEvidence {
		t.Errorf("%+v", p)
	}

	bad := filepath.Join(dir, "bad.yaml")
	os.WriteFile(bad, []byte(doc+"surprise: 1\n"), 0o600)
	big := filepath.Join(dir, "big.yaml")
	os.WriteFile(big, []byte(doc+"# "+strings.Repeat("x", MaxBaselineSize)+"\n"), 0o600)
	for name, path := range map[string]string{"schema": bad, "oversized": big, "missing": filepath.Join(dir, "none.yaml"), "directory": dir, "empty path": ""} {
		if _, err := LoadBaseline(path); err == nil || !strings.HasPrefix(err.Error(), "baseline:") {
			t.Errorf("%s: want a baseline error, got %v", name, err)
		}
	}
}

func TestEffectiveCanOnlyTighten(t *testing.T) {
	std := profile(t, ProfileStandard)
	original := profile(t, ProfileStandard)

	t.Run("nil config and nil baseline change nothing", func(t *testing.T) {
		if got := Effective(std, nil, nil); !reflect.DeepEqual(got, original) {
			t.Fatalf("%+v", got)
		}
	})

	t.Run("weakening attempts in the configuration are ignored", func(t *testing.T) {
		for name, cfg := range map[string]*config.Config{
			"min maturity 0":          {Policy: config.Policy{MinMaturity: intPtr(0)}},
			"min maturity 1":          {Policy: config.Policy{MinMaturity: intPtr(1)}},
			"negative maturity":       {Policy: config.Policy{MinMaturity: intPtr(-3)}},
			"empty mandatory list":    {Policy: config.Policy{MandatoryControls: []string{}}},
			"nil mandatory list":      {Policy: config.Policy{}},
			"subset of the mandatory": {Policy: config.Policy{MandatoryControls: []string{"AGC-001"}, MinMaturity: intPtr(1)}},
			"weaker profile named":    {Verification: config.Verification{Profile: ProfileBaseline}},
			"junk control IDs":        {Policy: config.Policy{MandatoryControls: []string{"", "AGC-999", "none"}}},
		} {
			if got := Effective(std, cfg, nil); !reflect.DeepEqual(got, original) {
				t.Errorf("%s: the configuration weakened or changed the profile: %+v", name, got)
			}
		}
	})

	t.Run("the configuration can add controls and raise the minimum", func(t *testing.T) {
		cfg := &config.Config{Policy: config.Policy{MandatoryControls: []string{"AGC-023", "AGC-001", "AGC-003"}, MinMaturity: intPtr(3)}}
		got := Effective(std, cfg, nil)
		want := append(append([]string{}, original.MandatoryControls...), "AGC-003", "AGC-023")
		sort.Strings(want)
		if !reflect.DeepEqual(got.MandatoryControls, want) || got.MinMaturity != 3 {
			t.Fatalf("%+v", got)
		}
		if got.Version != "1.0+config" || got.Name != "standard" {
			t.Errorf("the version must record the change: %q", got.Version)
		}
		if got.RequireSignedEvidence || got.ReviewWorkflow {
			t.Errorf("the configuration cannot set these: %+v", got)
		}
		if !reflect.DeepEqual(std, original) {
			t.Errorf("Effective must not modify the base profile")
		}
		if c := Effective(std, &config.Config{Policy: config.Policy{MinMaturity: intPtr(9)}}, nil); c.MinMaturity != 4 {
			t.Errorf("min maturity is clamped to 4, got %d", c.MinMaturity)
		}
	})

	t.Run("the baseline wins on strictness", func(t *testing.T) {
		baseline := &model.Profile{Name: "org", Version: "2.1", MandatoryControls: []string{"AGC-023"}, MinMaturity: 3,
			RequireSignedEvidence: true, Weights: map[string]int{"AGC-023": 9}}
		cfg := &config.Config{Policy: config.Policy{MinMaturity: intPtr(0), MandatoryControls: []string{}}}
		got := Effective(std, cfg, baseline)
		if got.MinMaturity != 3 || !got.RequireSignedEvidence || got.Weights["AGC-023"] != 9 {
			t.Fatalf("%+v", got)
		}
		if !contains(got.MandatoryControls, "AGC-023") || len(got.MandatoryControls) != len(original.MandatoryControls)+1 {
			t.Errorf("mandatory %v", got.MandatoryControls)
		}
		if got.Version != "1.0+baseline.org.2.1" {
			t.Errorf("version %q", got.Version)
		}

		// A weak baseline cannot lower a strict profile.
		weak := &model.Profile{Name: "weak", Version: "1", MandatoryControls: []string{}, MinMaturity: 0, ReviewWorkflow: true}
		hr := profile(t, ProfileHighRisk)
		got = Effective(hr, nil, weak)
		if got.MinMaturity != 3 || !got.RequireSignedEvidence || got.ReviewWorkflow || len(got.MandatoryControls) != 12 {
			t.Errorf("a weak baseline lowered the profile: %+v", got)
		}
	})

	t.Run("review workflow needs every source to enable it", func(t *testing.T) {
		on := &model.Profile{Name: "p", Version: "1", ReviewWorkflow: true}
		if !Effective(on, nil, nil).ReviewWorkflow {
			t.Errorf("base alone keeps its setting")
		}
		if Effective(on, nil, &model.Profile{Name: "org", Version: "1"}).ReviewWorkflow {
			t.Errorf("a baseline without review workflow turns it off")
		}
		if !Effective(on, nil, &model.Profile{Name: "org", Version: "1", ReviewWorkflow: true}).ReviewWorkflow {
			t.Errorf("both enabled keeps it on")
		}
		if Effective(&model.Profile{Name: "p"}, nil, &model.Profile{Name: "org", ReviewWorkflow: true}).ReviewWorkflow {
			t.Errorf("a baseline cannot turn it on")
		}
	})

	t.Run("nil base", func(t *testing.T) {
		got := Effective(nil, &config.Config{Policy: config.Policy{MandatoryControls: []string{"AGC-008"}}}, nil)
		if got == nil || !reflect.DeepEqual(got.MandatoryControls, []string{"AGC-008"}) {
			t.Fatalf("%+v", got)
		}
	})
}

// TestTighteningChangesTheDecision shows the effect of a policy change end to
// end: the same evidence passes the profile and fails the tightened one.
func TestTighteningChangesTheDecision(t *testing.T) {
	cat := catalog(t)
	evidence := evidenceForAll(cat, source(model.SourceManualReview)) // maturity 2 everywhere
	std := profile(t, ProfileStandard)
	agents := []model.Agent{fullAgent("a1")}

	_, _, d := run(t, scenario{agents: agents, evidence: evidence, profile: Effective(std, nil, nil)})
	if d.Outcome != model.OutcomeAllow {
		t.Fatalf("standard: %s %v", d.Outcome, reasonCodes(d))
	}

	weaken := &config.Config{Policy: config.Policy{MinMaturity: intPtr(0), MandatoryControls: []string{}}}
	_, _, d = run(t, scenario{agents: agents, evidence: replace(evidence, "AGC-022"), profile: Effective(std, weaken, nil), cfg: weaken})
	if d.Outcome != model.OutcomeBlock || !hasReason(d, ReasonMandatoryUnknown, "AGC-022") {
		t.Fatalf("a weakening configuration must not remove AGC-022: %s %v", d.Outcome, reasonCodes(d))
	}

	raise := &config.Config{Policy: config.Policy{MinMaturity: intPtr(3)}}
	_, _, d = run(t, scenario{agents: agents, evidence: evidence, profile: Effective(std, raise, nil), cfg: raise})
	// AGC-001 keeps its per-control minimum of 1, so it raises no reason.
	if d.Outcome != model.OutcomeBlock || len(d.Reasons) != len(std.MandatoryControls)-1 || hasReason(d, "", "AGC-001") {
		t.Fatalf("raised minimum: %s %v", d.Outcome, reasonCodes(d))
	}

	baseline := &model.Profile{Name: "org", Version: "2", MandatoryControls: []string{"AGC-024"}, MinMaturity: 2}
	eff := Effective(std, weaken, baseline)
	as, _, d := run(t, scenario{agents: agents, evidence: replace(evidence, "AGC-024", ev("AGC-024", signal(model.SignalAbsent))), profile: eff, cfg: weaken})
	if d.Outcome != model.OutcomeBlock || !hasReason(d, ReasonMandatoryMissing, "AGC-024") {
		t.Fatalf("baseline control: %s %v", d.Outcome, reasonCodes(d))
	}
	if r := control(t, as, "AGC-024"); !r.Mandatory || r.MinMaturity != 2 {
		t.Errorf("the baseline control must show as mandatory: %+v", r)
	}
	if eff.Version == std.Version {
		t.Errorf("a tightened policy must carry a different version")
	}
}

func TestSelectProfileName(t *testing.T) {
	tier := func(inferred, declared string) model.Agent {
		return model.Agent{ID: "a", InferredRiskTier: inferred, RiskTier: declared}
	}
	cfgProfile := func(p string) *config.Config { return &config.Config{Verification: config.Verification{Profile: p}} }
	cfgTier := func(tr string) *config.Config { return &config.Config{Agent: config.Agent{RiskTier: tr}} }

	tests := []struct {
		name       string
		flag       string
		cfg        *config.Config
		agents     []model.Agent
		wantName   string
		wantSource string
	}{
		{"flag wins", "baseline", cfgProfile("high-risk"), []model.Agent{tier("high", "")}, "baseline", "flag"},
		{"flag is trimmed", " standard ", nil, nil, "standard", "flag"},
		{"config wins over inferred", "", cfgProfile("standard"), []model.Agent{tier("high", "")}, "standard", "config"},
		{"inferred high", "", nil, []model.Agent{tier("high", "")}, "high-risk", "inferred"},
		{"inferred medium", "", nil, []model.Agent{tier("medium", "")}, "standard", "inferred"},
		{"inferred low", "", nil, []model.Agent{tier("low", "")}, "baseline", "inferred"},
		{"highest tier among agents", "", nil, []model.Agent{tier("low", ""), tier("high", ""), tier("medium", "")}, "high-risk", "inferred"},
		{"declared low does not lower inferred high", "", cfgTier("low"), []model.Agent{tier("high", "low")}, "high-risk", "inferred"},
		{"declared low does not lower inferred medium", "", nil, []model.Agent{tier("medium", "low")}, "standard", "inferred"},
		{"declared high raises inferred low", "", cfgTier("high"), []model.Agent{tier("low", "")}, "high-risk", "config"},
		{"declared tier on the agent raises", "", nil, []model.Agent{tier("low", "medium")}, "standard", "config"},
		{"declared tier in a monorepo list", "", &config.Config{Agents: []config.Agent{{ID: "x", RiskTier: "high"}}}, []model.Agent{tier("unknown", "")}, "high-risk", "config"},
		{"unknown tiers give the default", "", nil, []model.Agent{tier("unknown", "unknown")}, "baseline", "default"},
		{"no agents gives the default", "", nil, nil, "baseline", "default"},
		{"empty config gives the default", "", &config.Config{}, nil, "baseline", "default"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			name, src := SelectProfileName(tc.flag, tc.cfg, tc.agents)
			if name != tc.wantName || src != tc.wantSource {
				t.Fatalf("got %s (%s), want %s (%s)", name, src, tc.wantName, tc.wantSource)
			}
		})
	}
}

func contains(list []string, s string) bool {
	for _, x := range list {
		if x == s {
			return true
		}
	}
	return false
}

func TestProfileRank(t *testing.T) {
	for name, want := range map[string]int{"baseline": 1, "standard": 2, "high-risk": 3, " standard ": 2, "": 0, "custom": 0} {
		if got := ProfileRank(name); got != want {
			t.Errorf("ProfileRank(%q) = %d, want %d", name, got, want)
		}
	}
}

func TestBuiltInControlMinMaturity(t *testing.T) {
	for name, want := range map[string]int{ProfileBaseline: 1, ProfileStandard: 1, ProfileHighRisk: 3} {
		p := profile(t, name)
		if got := RequiredMaturity(p, "AGC-001"); got != want {
			t.Errorf("%s: AGC-001 requires %d, want %d", name, got, want)
		}
		if got := RequiredMaturity(p, "AGC-008"); got != p.MinMaturity {
			t.Errorf("%s: AGC-008 requires %d, want the general minimum", name, got)
		}
	}
	if len(profile(t, ProfileHighRisk).ControlMinMaturity) != 0 {
		t.Errorf("high-risk must not lower any control")
	}
	if RequiredMaturity(nil, "AGC-001") != 0 {
		t.Errorf("nil profile")
	}
	doc := "name: org\nversion: \"1\"\ndescription: Organization baseline for tests.\nmandatory_controls: []\nmin_maturity: 2\ncontrol_min_maturity:\n  @@\n"
	for _, bad := range []string{"AGC-001: 5", "AGC-001: -1", "AGC-031: 1", "AGC-001: high"} {
		if _, err := ParseProfile([]byte(strings.Replace(doc, "@@", bad, 1))); err == nil {
			t.Errorf("%s: expected an error", bad)
		}
	}
	if p, err := ParseProfile([]byte(strings.Replace(doc, "@@", "AGC-010: 4", 1))); err != nil || p.ControlMinMaturity["AGC-010"] != 4 {
		t.Errorf("a valid override must parse: %v", err)
	}
}

// TestDeclaredOwnerIsEnoughBelowHighRisk covers the per-control minimum end
// to end.
func TestDeclaredOwnerIsEnoughBelowHighRisk(t *testing.T) {
	cat := catalog(t)
	owner := ev("AGC-001", signal(model.SignalDeclared), strength(model.StrengthDeclared), source(model.SourceConfiguration))
	evidence := replace(evidenceForAll(cat, source(model.SourceManualReview)), "AGC-001", owner)
	agents := []model.Agent{fullAgent("a1")}

	for _, name := range []string{ProfileBaseline, ProfileStandard} {
		as, _, d := run(t, scenario{agents: agents, evidence: evidence, profile: profile(t, name)})
		r := control(t, as, "AGC-001")
		if r.Status != model.StatusDeclaredOnly || r.MinMaturity != 1 || !r.Mandatory {
			t.Fatalf("%s: %+v", name, r)
		}
		if d.Outcome != model.OutcomeAllow || len(d.Reasons) != 1 || d.Reasons[0].Code != ReasonPolicySatisfied {
			t.Fatalf("%s: %s %v", name, d.Outcome, reasonCodes(d))
		}
		if o := control(t, as, "AGC-008"); o.MinMaturity != 2 {
			t.Errorf("%s: other controls keep the general minimum, got %d", name, o.MinMaturity)
		}
	}

	// No declaration at all still blocks.
	_, _, d := run(t, scenario{agents: agents, evidence: replace(evidence, "AGC-001"), profile: profile(t, ProfileBaseline)})
	if d.Outcome != model.OutcomeBlock || !hasReason(d, ReasonMandatoryUnknown, "AGC-001") {
		t.Fatalf("no owner: %s %v", d.Outcome, reasonCodes(d))
	}

	// High-risk: the same declaration, with signed tested evidence elsewhere.
	hr := replace(evidenceForAll(cat, opts(testTested(), []evOpt{signed()})...), "AGC-001", owner)
	as, _, d := run(t, scenario{agents: agents, evidence: hr, profile: profile(t, ProfileHighRisk)})
	if r := control(t, as, "AGC-001"); r.MinMaturity != 3 {
		t.Fatalf("high-risk AGC-001 requires %d", r.MinMaturity)
	}
	if d.Outcome != model.OutcomeBlock || len(d.Reasons) != 1 || !hasReason(d, ReasonMandatoryBelowMin, "AGC-001") {
		t.Fatalf("high-risk: %s %v", d.Outcome, reasonCodes(d))
	}
}

func TestEffectiveControlMinMaturityOnlyTightens(t *testing.T) {
	req := RequiredMaturity
	std := profile(t, ProfileStandard)
	hr := profile(t, ProfileHighRisk)
	original := profile(t, ProfileStandard)

	// Configuration: the general minimum does not touch a control that has
	// an explicit per-control value in the base profile.
	for min, want := range map[int]int{0: 1, 1: 1, 2: 1, 3: 1, 4: 1} {
		got := Effective(std, &config.Config{Policy: config.Policy{MinMaturity: intPtr(min)}}, nil)
		if req(got, "AGC-001") != want {
			t.Errorf("config min %d: AGC-001 requires %d, want %d", min, req(got, "AGC-001"), want)
		}
		if wantGeneral := max(2, min); req(got, "AGC-008") != wantGeneral {
			t.Errorf("config min %d: AGC-008 requires %d, want %d", min, req(got, "AGC-008"), wantGeneral)
		}
	}
	if got := Effective(std, &config.Config{Policy: config.Policy{MinMaturity: intPtr(2)}}, nil); !reflect.DeepEqual(got, original) {
		t.Errorf("a configuration minimum equal to the profile minimum changes nothing: %+v", got)
	}

	// Baseline overrides lower than the current requirement are ignored.
	weak := &model.Profile{Name: "weak", Version: "1", MinMaturity: 0,
		ControlMinMaturity: map[string]int{"AGC-001": 0, "AGC-008": 0, "AGC-010": 1, "AGC-022": -4}}
	for _, base := range []*model.Profile{std, hr} {
		got := Effective(base, &config.Config{Policy: config.Policy{MinMaturity: intPtr(0)}}, weak)
		for _, id := range base.MandatoryControls {
			if req(got, id) != req(base, id) {
				t.Errorf("%s: a weak baseline changed %s from %d to %d", base.Name, id, req(base, id), req(got, id))
			}
		}
	}

	// Baseline overrides and the baseline minimum raise.
	strict := &model.Profile{Name: "org", Version: "2", MinMaturity: 2, MandatoryControls: []string{"AGC-023"},
		ControlMinMaturity: map[string]int{"AGC-001": 1, "AGC-010": 4, "AGC-023": 3}}
	got := Effective(std, nil, strict)
	for id, want := range map[string]int{"AGC-001": 1, "AGC-010": 4, "AGC-023": 3, "AGC-008": 2} {
		if req(got, id) != want {
			t.Errorf("strict baseline: %s requires %d, want %d", id, req(got, id), want)
		}
	}
	got = Effective(std, nil, &model.Profile{Name: "org", Version: "2", MinMaturity: 1})
	if req(got, "AGC-001") != 1 || req(got, "AGC-008") != 2 {
		t.Errorf("a baseline minimum of 1 changes nothing here: %+v", got)
	}

	// Every combination: the result equals the highest request and is never
	// lower than the base for any control.
	for _, base := range []*model.Profile{profile(t, ProfileBaseline), std, hr} {
		for cm := 0; cm <= 4; cm++ {
			for bm := 0; bm <= 4; bm++ {
				for bo := 0; bo <= 4; bo++ {
					b := &model.Profile{Name: "b", Version: "1", MinMaturity: bm, ControlMinMaturity: map[string]int{"AGC-001": bo, "AGC-005": bo}}
					got := Effective(base, &config.Config{Policy: config.Policy{MinMaturity: intPtr(cm)}}, b)
					for _, id := range base.MandatoryControls {
						want := req(base, id)
						if _, explicit := base.ControlMinMaturity[id]; !explicit {
							want = max(want, cm, bm)
						}
						if id == "AGC-001" || id == "AGC-005" {
							want = max(want, bo)
						}
						if req(got, id) != want {
							t.Fatalf("%s cm=%d bm=%d bo=%d: %s requires %d, want %d", base.Name, cm, bm, bo, id, req(got, id), want)
						}
						if req(got, id) < req(base, id) {
							t.Fatalf("%s: %s was lowered", base.Name, id)
						}
					}
				}
			}
		}
	}
	if !reflect.DeepEqual(std, original) {
		t.Errorf("Effective must not modify the base profile")
	}
}

// TestBaselineFloorKeepsBaseException is the regression test for a baseline
// whose general minimum blocked every repository on AGC-001.
func TestBaselineFloorKeepsBaseException(t *testing.T) {
	cat := catalog(t)
	owner := ev("AGC-001", signal(model.SignalDeclared), strength(model.StrengthDeclared), source(model.SourceConfiguration))
	evidence := replace(evidenceForAll(cat), "AGC-001", owner) // static implementation everywhere else
	agents := []model.Agent{fullAgent("a1")}

	// The example baseline from docs/policy-reference.md.
	docBaseline, err := ParseProfile([]byte("name: org-baseline\nversion: \"2.1\"\ndescription: Organization baseline for all agent repositories.\nmandatory_controls:\n  - AGC-008\n  - AGC-022\n  - AGC-023\nmin_maturity: 2\nrequire_signed_evidence: false\nreview_workflow: false\n"))
	if err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{ProfileBaseline, ProfileStandard} {
		eff := Effective(profile(t, name), nil, docBaseline)
		if RequiredMaturity(eff, "AGC-001") != 1 || RequiredMaturity(eff, "AGC-023") != 2 {
			t.Fatalf("%s: AGC-001 requires %d, AGC-023 requires %d", name, RequiredMaturity(eff, "AGC-001"), RequiredMaturity(eff, "AGC-023"))
		}
		as, _, d := run(t, scenario{agents: agents, evidence: evidence, profile: eff})
		if hasReason(d, "", "AGC-001") || d.Outcome != model.OutcomeAllow {
			t.Fatalf("%s: a general baseline minimum must not block on AGC-001: %s %v", name, d.Outcome, d.Reasons)
		}
		if r := control(t, as, "AGC-001"); r.Status != model.StatusDeclaredOnly || r.MinMaturity != 1 {
			t.Errorf("%s: %+v", name, r)
		}
	}

	// A baseline minimum of 3 raises the other controls, not AGC-001.
	eff := Effective(profile(t, ProfileBaseline), nil, &model.Profile{Name: "org", Version: "1", MinMaturity: 3})
	_, _, d := run(t, scenario{agents: agents, evidence: evidence, profile: eff})
	if hasReason(d, "", "AGC-001") || !hasReason(d, ReasonMandatoryBelowMin, "AGC-008") {
		t.Fatalf("minimum 3: %v", d.Reasons)
	}

	// A baseline that names AGC-001 with a higher value does raise it.
	named := &model.Profile{Name: "org", Version: "1", MinMaturity: 2, ControlMinMaturity: map[string]int{"AGC-001": 3}}
	eff = Effective(profile(t, ProfileBaseline), nil, named)
	if RequiredMaturity(eff, "AGC-001") != 3 {
		t.Fatalf("AGC-001 requires %d, want 3", RequiredMaturity(eff, "AGC-001"))
	}
	as, _, d := run(t, scenario{agents: agents, evidence: evidence, profile: eff})
	if d.Outcome != model.OutcomeBlock || len(d.Reasons) != 1 || !hasReason(d, ReasonMandatoryBelowMin, "AGC-001") {
		t.Fatalf("named override: %s %v", d.Outcome, d.Reasons)
	}
	if r := control(t, as, "AGC-001"); r.MinMaturity != 3 {
		t.Errorf("min maturity shown: %d", r.MinMaturity)
	}

	// High-risk has no base exception, so the general minimum applies to AGC-001.
	if got := RequiredMaturity(Effective(profile(t, ProfileHighRisk), nil, docBaseline), "AGC-001"); got != 3 {
		t.Errorf("high-risk AGC-001 requires %d", got)
	}
}
