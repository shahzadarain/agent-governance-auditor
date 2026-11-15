// SPDX-License-Identifier: Apache-2.0

// Package policy holds the deterministic policy engine: risk profiles, the
// rule that configuration can only tighten a profile, the derivation of a
// status for every control, and the release decision.
//
// The decision is made from mandatory controls and critical findings. The
// numeric score never changes it.
package policy

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"os"
	"sort"
	"strings"

	"gopkg.in/yaml.v3"

	"github.com/shahzadarain/agent-governance-auditor/internal/config"
	"github.com/shahzadarain/agent-governance-auditor/internal/controls"
	"github.com/shahzadarain/agent-governance-auditor/internal/model"
	"github.com/shahzadarain/agent-governance-auditor/policies"
)

// Built-in profile names, from least to most strict.
const (
	ProfileBaseline = "baseline"
	ProfileStandard = "standard"
	ProfileHighRisk = "high-risk"
)

// Profile source values for model.ScanMeta.ProfileSource.
const (
	SourceFlag     = "flag"
	SourceConfig   = "config"
	SourceInferred = "inferred"
	SourceDefault  = "default"
)

// MaxBaselineSize is the largest organization baseline file that is read.
const MaxBaselineSize = 256 * 1024

var profileNames = []string{ProfileBaseline, ProfileStandard, ProfileHighRisk}

// ProfileNames returns the built-in profile names from least to most strict.
func ProfileNames() []string {
	return append([]string(nil), profileNames...)
}

// LoadProfile returns a fresh copy of a built-in profile.
func LoadProfile(name string) (*model.Profile, error) {
	known := false
	for _, n := range profileNames {
		if n == name {
			known = true
		}
	}
	if !known {
		return nil, fmt.Errorf("unknown profile %q; choose one of: %s", name, strings.Join(profileNames, ", "))
	}
	raw, err := policies.FS.ReadFile(policies.ProfilesDir + "/" + name + ".yaml")
	if err != nil {
		return nil, fmt.Errorf("profile %s: %w", name, err)
	}
	p, err := ParseProfile(raw)
	if err != nil {
		return nil, fmt.Errorf("profile %s: %w", name, err)
	}
	if p.Name != name {
		return nil, fmt.Errorf("profile %s: file declares the name %q", name, p.Name)
	}
	return p, nil
}

// LoadBaseline reads an organization baseline: a profile YAML file kept
// outside the scanned repository, for example in a protected CI location.
// The file is validated against the profile schema. Effective merges it so
// that it can only tighten the result.
func LoadBaseline(path string) (*model.Profile, error) {
	if strings.TrimSpace(path) == "" {
		return nil, errors.New("baseline: no path given")
	}
	info, err := os.Stat(path)
	if err != nil {
		return nil, fmt.Errorf("baseline: %w", err)
	}
	if info.IsDir() {
		return nil, fmt.Errorf("baseline: %s is a directory", path)
	}
	if info.Size() > MaxBaselineSize {
		return nil, fmt.Errorf("baseline: file is %d bytes; the limit is %d bytes", info.Size(), MaxBaselineSize)
	}
	f, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("baseline: %w", err)
	}
	defer f.Close()
	raw, err := io.ReadAll(io.LimitReader(f, MaxBaselineSize+1))
	if err != nil {
		return nil, fmt.Errorf("baseline: %w", err)
	}
	if len(raw) > MaxBaselineSize {
		return nil, fmt.Errorf("baseline: file is larger than the limit of %d bytes", MaxBaselineSize)
	}
	p, err := ParseProfile(raw)
	if err != nil {
		return nil, fmt.Errorf("baseline: %w", err)
	}
	return p, nil
}

// ParseProfile validates profile YAML against the profile schema and the
// semantic rules, and returns the decoded profile with a sorted mandatory
// list.
func ParseProfile(data []byte) (*model.Profile, error) {
	diags, err := policies.ValidateYAML(policies.ProfileSchema, data)
	if err != nil {
		return nil, err
	}
	if len(diags) > 0 {
		return nil, fmt.Errorf("schema validation failed: %s", strings.Join(diags, "; "))
	}
	var p model.Profile
	dec := yaml.NewDecoder(bytes.NewReader(data))
	dec.KnownFields(true)
	if err := dec.Decode(&p); err != nil {
		return nil, fmt.Errorf("decode: %w", err)
	}
	if p.MinMaturity < 0 || p.MinMaturity > 4 {
		return nil, errors.New("min_maturity must be between 0 and 4")
	}
	for _, id := range p.MandatoryControls {
		if !validControlID(id) {
			return nil, fmt.Errorf("mandatory_controls: %q is not a control ID from AGC-001 to AGC-024", id)
		}
	}
	for id, w := range p.Weights {
		if !validControlID(id) || w <= 0 {
			return nil, fmt.Errorf("weights: %q needs a known control ID and a weight above 0", id)
		}
	}
	for id, m := range p.ControlMinMaturity {
		if !validControlID(id) || m < 0 || m > 4 {
			return nil, fmt.Errorf("control_min_maturity: %q needs a known control ID and a level from 0 to 4", id)
		}
	}
	p.MandatoryControls = sortedUnique(p.MandatoryControls)
	return &p, nil
}

func validControlID(id string) bool {
	for n := 1; n <= controls.Count; n++ {
		if controls.ID(n) == id {
			return true
		}
	}
	return false
}

func sortedUnique(in []string) []string {
	seen := map[string]bool{}
	out := []string{}
	for _, s := range in {
		if s != "" && !seen[s] {
			seen[s] = true
			out = append(out, s)
		}
	}
	sort.Strings(out)
	return out
}

// Effective returns the profile that a scan enforces. It starts from base
// and merges the repository configuration and the organization baseline.
// Both can only tighten:
//
//   - mandatory controls: the union of all three lists; nothing is removed;
//   - min_maturity: the highest of the three values; nothing lowers it;
//   - require_signed_evidence: true when the base or the baseline sets it;
//   - review_workflow: stays on only when every profile source enables it,
//     because it turns some BLOCK results into REVIEW_REQUIRED;
//   - control_min_maturity: a control with an explicit per-control value in
//     the base profile keeps that value when the configuration or the
//     baseline raise only the general min_maturity. Only a baseline entry
//     that names the control with a higher value raises it. A control with
//     no per-control value follows the general minimum. A baseline entry
//     lower than the current requirement is ignored. No control ends below
//     the requirement of the base profile;
//   - weights: the base weights, with baseline weights taking precedence.
//     Weights affect the illustrative score only, never the decision.
//
// A configuration with min_maturity 0 or an empty mandatory list therefore
// changes nothing. The inputs are not modified. cfg and baseline may be nil.
//
// The version of the result records what was merged, so that scans made
// under different effective policies are not treated as comparable.
func Effective(base *model.Profile, cfg *config.Config, baseline *model.Profile) *model.Profile {
	out := &model.Profile{Name: "custom", Version: "0", MandatoryControls: []string{}}
	if base != nil {
		*out = *base
		out.MandatoryControls = sortedUnique(base.MandatoryControls)
		out.Weights = copyWeights(base.Weights)
		out.ControlMinMaturity = copyWeights(base.ControlMinMaturity)
		for id, m := range out.ControlMinMaturity {
			out.ControlMinMaturity[id] = clampMaturity(m)
		}
	}
	baseVersion := out.Version

	configTightened := false
	if cfg != nil {
		merged := sortedUnique(append(append([]string{}, out.MandatoryControls...), validIDs(cfg.Policy.MandatoryControls)...))
		if len(merged) != len(out.MandatoryControls) {
			configTightened = true
		}
		out.MandatoryControls = merged
		if cfg.Policy.MinMaturity != nil {
			if m := clampMaturity(*cfg.Policy.MinMaturity); m > out.MinMaturity {
				out.MinMaturity = m
				configTightened = true
			}
		}
	}

	if baseline != nil {
		out.MandatoryControls = sortedUnique(append(out.MandatoryControls, validIDs(baseline.MandatoryControls)...))
		if bm := clampMaturity(baseline.MinMaturity); bm > out.MinMaturity {
			out.MinMaturity = bm
		}
		for id, m := range baseline.ControlMinMaturity {
			// A baseline override lower than the current requirement is ignored.
			if m = clampMaturity(m); validControlID(id) && m > RequiredMaturity(out, id) {
				if out.ControlMinMaturity == nil {
					out.ControlMinMaturity = map[string]int{}
				}
				out.ControlMinMaturity[id] = m
			}
		}
		out.RequireSignedEvidence = out.RequireSignedEvidence || baseline.RequireSignedEvidence
		out.ReviewWorkflow = out.ReviewWorkflow && baseline.ReviewWorkflow
		for id, w := range baseline.Weights {
			if w > 0 && validControlID(id) {
				if out.Weights == nil {
					out.Weights = map[string]int{}
				}
				out.Weights[id] = w
			}
		}
	}

	if len(out.ControlMinMaturity) == 0 {
		out.ControlMinMaturity = nil
	}

	version := baseVersion
	if configTightened {
		version += "+config"
	}
	if baseline != nil {
		version += "+baseline." + baseline.Name + "." + baseline.Version
	}
	out.Version = version
	return out
}

// RequiredMaturity returns the maturity a mandatory control must reach under
// a profile: the per-control override when one exists, else MinMaturity.
func RequiredMaturity(p *model.Profile, id string) int {
	if p == nil {
		return 0
	}
	if m, ok := p.ControlMinMaturity[id]; ok {
		return clampMaturity(m)
	}
	return p.MinMaturity
}

// ProfileRank orders the built-in profiles by strictness: baseline 1,
// standard 2, high-risk 3. An unknown name gives 0.
func ProfileRank(name string) int {
	for i, n := range profileNames {
		if n == strings.TrimSpace(name) {
			return i + 1
		}
	}
	return 0
}

func validIDs(in []string) []string {
	var out []string
	for _, id := range in {
		if validControlID(id) {
			out = append(out, id)
		}
	}
	return out
}

func clampMaturity(m int) int {
	if m < 0 {
		return 0
	}
	if m > 4 {
		return 4
	}
	return m
}

func copyWeights(in map[string]int) map[string]int {
	if in == nil {
		return nil
	}
	out := make(map[string]int, len(in))
	for k, v := range in {
		out[k] = v
	}
	return out
}

func tierRank(t string) int {
	switch strings.ToLower(strings.TrimSpace(t)) {
	case "high":
		return 3
	case "medium":
		return 2
	case "low":
		return 1
	}
	return 0
}

func profileForTier(rank int) string {
	switch rank {
	case 3:
		return ProfileHighRisk
	case 2:
		return ProfileStandard
	}
	return ProfileBaseline
}

// SelectProfileName decides which built-in profile a scan uses and says
// where the choice came from. Precedence:
//
//  1. the command-line flag (source "flag");
//  2. verification.profile in the configuration (source "config");
//  3. the highest risk tier among the agents (source "inferred"). A declared
//     tier can raise this choice (source "config") and can never lower it;
//  4. the baseline profile (source "default").
//
// The name is returned as given. LoadProfile rejects an unknown name.
func SelectProfileName(flag string, cfg *config.Config, agents []model.Agent) (name, source string) {
	if f := strings.TrimSpace(flag); f != "" {
		return f, SourceFlag
	}
	if cfg != nil {
		if p := strings.TrimSpace(cfg.Verification.Profile); p != "" {
			return p, SourceConfig
		}
	}
	inferred, declared := 0, 0
	for _, a := range agents {
		if r := tierRank(a.InferredRiskTier); r > inferred {
			inferred = r
		}
		if r := tierRank(a.RiskTier); r > declared {
			declared = r
		}
	}
	if cfg != nil {
		if r := tierRank(cfg.Agent.RiskTier); r > declared {
			declared = r
		}
		for _, a := range cfg.Agents {
			if r := tierRank(a.RiskTier); r > declared {
				declared = r
			}
		}
	}
	switch {
	case inferred == 0 && declared == 0:
		return ProfileBaseline, SourceDefault
	case declared > inferred:
		return profileForTier(declared), SourceConfig
	default:
		return profileForTier(inferred), SourceInferred
	}
}
