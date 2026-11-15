// SPDX-License-Identifier: Apache-2.0

// Package controls loads and validates the embedded control catalog.
//
// The catalog is versioned policy data (policies/controls/v1). Loading
// validates every control against the JSON Schema and against semantic rules,
// so a broken catalog fails loudly instead of producing a partial assessment.
package controls

import (
	"bytes"
	"errors"
	"fmt"
	"io/fs"
	"sort"
	"strings"

	"gopkg.in/yaml.v3"

	"github.com/shahzadarain/agent-governance-auditor/internal/model"
	"github.com/shahzadarain/agent-governance-auditor/policies"
)

// Count is the number of controls in the builtin/v1 catalog.
const Count = 24

// The six domains, in catalog order.
const (
	DomainAccountability = "A: Accountability"
	DomainIdentity       = "B: Identity and Access"
	DomainAction         = "C: Action Controls"
	DomainTrust          = "D: Trust Boundaries"
	DomainContainment    = "E: Containment and Recovery"
	DomainAssurance      = "F: Assurance and Visibility"
)

var domainOrder = []string{
	DomainAccountability,
	DomainIdentity,
	DomainAction,
	DomainTrust,
	DomainContainment,
	DomainAssurance,
}

var knownCapabilities = map[string]bool{
	model.CapTools: true, model.CapSensitiveActions: true, model.CapMutatingActions: true,
	model.CapShellExec: true, model.CapCodeExec: true, model.CapFilesystem: true,
	model.CapNetwork: true, model.CapBrowser: true, model.CapDataAccess: true,
	model.CapMemory: true, model.CapMultiAgent: true, model.CapMCP: true,
	model.CapCredentials: true, model.CapContainer: true,
}

var knownSeverities = map[model.Severity]bool{
	model.SeverityCritical: true, model.SeverityHigh: true, model.SeverityMedium: true,
	model.SeverityLow: true, model.SeverityInfo: true,
}

var knownEvidenceTypes = map[string]bool{
	string(model.SourceStatic): true, string(model.SourceConfiguration): true,
	string(model.SourceTest): true, string(model.SourceRuntime): true,
	string(model.SourceAttestation): true, string(model.SourceManualReview): true,
}

// DomainGroup is one domain with the IDs of its controls in ID order.
type DomainGroup struct {
	Name       string   `json:"name"`
	ControlIDs []string `json:"control_ids"`
}

type packMeta struct {
	Name        string `yaml:"name"`
	Version     string `yaml:"version"`
	Description string `yaml:"description"`
}

// Load reads and validates the embedded builtin/v1 catalog. Controls are
// returned in ID order. Every call returns a fresh copy, so callers may not
// corrupt each other's view of the catalog.
func Load() (*model.Catalog, error) {
	return LoadFS(policies.FS, policies.ControlsDir)
}

// LoadFS loads a catalog from dir inside fsys. It exists so tests can prove
// that a broken pack is rejected. Production code calls Load.
func LoadFS(fsys fs.FS, dir string) (*model.Catalog, error) {
	rawPack, err := fs.ReadFile(fsys, dir+"/pack.yaml")
	if err != nil {
		return nil, fmt.Errorf("control catalog: read pack.yaml: %w", err)
	}
	var meta packMeta
	dec := yaml.NewDecoder(bytes.NewReader(rawPack))
	dec.KnownFields(true)
	if err := dec.Decode(&meta); err != nil {
		return nil, fmt.Errorf("control catalog: pack.yaml: %w", err)
	}
	if meta.Name == "" || meta.Version == "" {
		return nil, errors.New("control catalog: pack.yaml must set name and version")
	}

	entries, err := fs.ReadDir(fsys, dir)
	if err != nil {
		return nil, fmt.Errorf("control catalog: %w", err)
	}
	var names []string
	for _, e := range entries {
		n := e.Name()
		if e.IsDir() || n == "pack.yaml" || !strings.HasSuffix(n, ".yaml") {
			continue
		}
		names = append(names, n)
	}
	sort.Strings(names)

	cat := &model.Catalog{Pack: meta.Name, Version: meta.Version}
	var problems []string
	for _, n := range names {
		raw, err := fs.ReadFile(fsys, dir+"/"+n)
		if err != nil {
			return nil, fmt.Errorf("control catalog: %w", err)
		}
		c, err := ParseControl(raw)
		if err != nil {
			problems = append(problems, fmt.Sprintf("%s: %v", n, err))
			continue
		}
		if want := c.ID + ".yaml"; n != want {
			problems = append(problems, fmt.Sprintf("%s: file name must be %s to match the control ID", n, want))
		}
		cat.Controls = append(cat.Controls, c)
	}
	if len(problems) > 0 {
		return nil, fmt.Errorf("control catalog is invalid:\n  %s", strings.Join(problems, "\n  "))
	}
	sort.SliceStable(cat.Controls, func(i, j int) bool { return cat.Controls[i].ID < cat.Controls[j].ID })
	if err := ValidateCatalog(cat); err != nil {
		return nil, err
	}
	return cat, nil
}

// ParseControl validates one control YAML document against the JSON Schema
// and the semantic rules, and returns the decoded control.
func ParseControl(data []byte) (model.Control, error) {
	var c model.Control
	diags, err := policies.ValidateYAML(policies.ControlSchema, data)
	if err != nil {
		return c, err
	}
	if len(diags) > 0 {
		return c, fmt.Errorf("schema validation failed: %s", strings.Join(diags, "; "))
	}
	dec := yaml.NewDecoder(bytes.NewReader(data))
	dec.KnownFields(true)
	if err := dec.Decode(&c); err != nil {
		return c, fmt.Errorf("decode: %w", err)
	}
	if problems := checkControl(c); len(problems) > 0 {
		return c, fmt.Errorf("semantic validation failed: %s", strings.Join(problems, "; "))
	}
	return c, nil
}

// ValidateCatalog applies the catalog-level rules: exactly 24 controls with
// contiguous, unique IDs AGC-001 to AGC-024 in order, each one valid.
func ValidateCatalog(cat *model.Catalog) error {
	if cat == nil {
		return errors.New("control catalog is nil")
	}
	var problems []string
	if len(cat.Controls) != Count {
		problems = append(problems, fmt.Sprintf("expected exactly %d controls, found %d", Count, len(cat.Controls)))
	}
	seen := map[string]bool{}
	for i, c := range cat.Controls {
		if seen[c.ID] {
			problems = append(problems, fmt.Sprintf("duplicate control ID %s", c.ID))
		}
		seen[c.ID] = true
		if want := ID(i + 1); i < Count && c.ID != want {
			problems = append(problems, fmt.Sprintf("position %d: expected %s, found %s", i+1, want, c.ID))
		}
		for _, p := range checkControl(c) {
			problems = append(problems, c.ID+": "+p)
		}
	}
	if len(problems) > 0 {
		return fmt.Errorf("control catalog is invalid:\n  %s", strings.Join(problems, "\n  "))
	}
	return nil
}

// ID returns the control ID for a number from 1 to 24, for example "AGC-007".
func ID(n int) string { return fmt.Sprintf("AGC-%03d", n) }

func checkControl(c model.Control) []string {
	var p []string
	blank := func(s string) bool { return strings.TrimSpace(s) == "" }
	if !knownDomain(c.Domain) {
		p = append(p, fmt.Sprintf("unknown domain %q", c.Domain))
	}
	if blank(c.Title) {
		p = append(p, "title is empty")
	}
	if blank(c.Intent) {
		p = append(p, "intent is empty")
	}
	if blank(c.PlainLanguage) {
		p = append(p, "plain_language is empty")
	}
	switch c.Applicability.Mode {
	case "always":
		if len(c.Applicability.CapabilitiesAny) > 0 {
			p = append(p, "applicability mode always must not list capabilities")
		}
	case "capability":
		if len(c.Applicability.CapabilitiesAny) == 0 {
			p = append(p, "applicability mode capability needs at least one capability")
		}
	default:
		p = append(p, fmt.Sprintf("unknown applicability mode %q", c.Applicability.Mode))
	}
	for _, name := range c.Applicability.CapabilitiesAny {
		if !knownCapabilities[name] {
			p = append(p, fmt.Sprintf("unknown capability %q", name))
		}
	}
	if blank(c.Applicability.Rationale) {
		p = append(p, "applicability rationale is empty")
	}
	if len(c.EvidenceTypes) == 0 {
		p = append(p, "evidence_types is empty")
	}
	for _, t := range c.EvidenceTypes {
		if !knownEvidenceTypes[t] {
			p = append(p, fmt.Sprintf("unknown evidence type %q", t))
		}
	}
	for _, d := range c.Detectors {
		if !strings.HasPrefix(d, c.ID+".") {
			p = append(p, fmt.Sprintf("detector %q must start with %s.", d, c.ID))
		}
	}
	if c.DefaultWeight <= 0 {
		p = append(p, "default_weight must be greater than 0")
	}
	if m := c.VerificationRules.MaxStaticMaturity; m < 0 || m > 2 {
		p = append(p, "max_static_maturity must be between 0 and 2")
	}
	if blank(c.VerificationRules.Implementation) || blank(c.VerificationRules.Tested) || blank(c.VerificationRules.Operational) {
		p = append(p, "verification_rules must describe implementation, tested, and operational")
	}
	if !knownSeverities[c.Severity] {
		p = append(p, fmt.Sprintf("unknown severity %q", c.Severity))
	}
	if len(c.Remediation) == 0 {
		p = append(p, "remediation is empty")
	}
	for i, s := range c.Remediation {
		if blank(s) {
			p = append(p, fmt.Sprintf("remediation[%d] is empty", i))
		}
	}
	if len(c.Limitations) == 0 {
		p = append(p, "limitations is empty")
	}
	for i, s := range c.Limitations {
		if blank(s) {
			p = append(p, fmt.Sprintf("limitations[%d] is empty", i))
		}
	}
	if blank(c.Examples.Positive) || blank(c.Examples.Negative) {
		p = append(p, "examples need a positive and a negative entry")
	}
	for i, m := range c.StandardsMappings {
		if blank(m.Standard) || blank(m.Version) || blank(m.RequirementID) || blank(m.URL) || blank(m.Rationale) {
			p = append(p, fmt.Sprintf("standards_mappings[%d] must set standard, version, requirement_id, url, and rationale", i))
		}
		if !strings.HasPrefix(m.URL, "https://") {
			p = append(p, fmt.Sprintf("standards_mappings[%d] url must start with https://", i))
		}
	}
	return p
}

func knownDomain(d string) bool {
	for _, k := range domainOrder {
		if k == d {
			return true
		}
	}
	return false
}

// Find returns the control with the given ID.
func Find(cat *model.Catalog, id string) (model.Control, bool) {
	if cat == nil {
		return model.Control{}, false
	}
	for _, c := range cat.Controls {
		if c.ID == id {
			return c, true
		}
	}
	return model.Control{}, false
}

// DomainNames returns the six domain names in catalog order.
func DomainNames() []string {
	return append([]string(nil), domainOrder...)
}

// Domains returns the six domains in order, each with its control IDs in ID
// order. A domain with no controls in cat is still returned, with an empty
// list.
func Domains(cat *model.Catalog) []DomainGroup {
	out := make([]DomainGroup, 0, len(domainOrder))
	for _, d := range domainOrder {
		g := DomainGroup{Name: d, ControlIDs: []string{}}
		if cat != nil {
			for _, c := range cat.Controls {
				if c.Domain == d {
					g.ControlIDs = append(g.ControlIDs, c.ID)
				}
			}
		}
		sort.Strings(g.ControlIDs)
		out = append(out, g)
	}
	return out
}
