// SPDX-License-Identifier: Apache-2.0

package controls

import (
	"reflect"
	"regexp"
	"strings"
	"testing"
	"testing/fstest"

	"github.com/shahzadarain/agent-governance-auditor/internal/model"
	"github.com/shahzadarain/agent-governance-auditor/policies"
)

// expected is the control list from the project specification: ID, title,
// and domain.
var expected = []struct{ id, title, domain string }{
	{"AGC-001", "Owner and Inventory", DomainAccountability},
	{"AGC-002", "Dynamic Risk Tiering", DomainAccountability},
	{"AGC-003", "Integrated Change Control", DomainAccountability},
	{"AGC-004", "Dedicated Non-Human Identity", DomainIdentity},
	{"AGC-005", "Allowlisted Tool Access", DomainIdentity},
	{"AGC-006", "Short-Lived Scoped Tokens", DomainIdentity},
	{"AGC-007", "User-Enforced Data Layer", DomainIdentity},
	{"AGC-008", "Vault-Injected Secrets", DomainIdentity},
	{"AGC-009", "External Policy Engine", DomainAction},
	{"AGC-010", "Human Approval Gates", DomainAction},
	{"AGC-011", "Dual Content Guardrails", DomainAction},
	{"AGC-012", "Multi-Level Resource Limits", DomainAction},
	{"AGC-013", "Disposable Sandbox Environments", DomainAction},
	{"AGC-014", "Vetted Tool Supply Chain", DomainTrust},
	{"AGC-015", "Context Memory Integrity", DomainTrust},
	{"AGC-016", "Authenticated Inter-Agent Messages", DomainTrust},
	{"AGC-017", "Instant Agent Kill Switch", DomainContainment},
	{"AGC-018", "Reversible Action Design", DomainContainment},
	{"AGC-019", "Dedicated Incident Runbook", DomainContainment},
	{"AGC-020", "Mandatory Regression Evals", DomainAssurance},
	{"AGC-021", "Continuous Red Teaming", DomainAssurance},
	{"AGC-022", "Complete Step Tracing", DomainAssurance},
	{"AGC-023", "Tamper-Evident Audit Trail", DomainAssurance},
	{"AGC-024", "Real-Time Operational Monitoring", DomainAssurance},
}

func load(t testing.TB) *model.Catalog {
	t.Helper()
	cat, err := Load()
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	return cat
}

func TestCatalogLoadsAll24Controls(t *testing.T) {
	cat := load(t)
	if cat.Pack != "builtin/v1" || cat.Version != "1.0" {
		t.Errorf("pack %q version %q", cat.Pack, cat.Version)
	}
	if len(cat.Controls) != Count || len(expected) != Count {
		t.Fatalf("want %d controls, got %d", Count, len(cat.Controls))
	}
	for i, want := range expected {
		c := cat.Controls[i]
		if c.ID != want.id || c.Title != want.title || c.Domain != want.domain {
			t.Errorf("position %d: got %s %q %q, want %s %q %q", i+1, c.ID, c.Title, c.Domain, want.id, want.title, want.domain)
		}
		if c.ID != ID(i+1) {
			t.Errorf("ID(%d) = %s, catalog has %s", i+1, ID(i+1), c.ID)
		}
	}
}

func TestEveryControlIsComplete(t *testing.T) {
	sentenceEnd := regexp.MustCompile(`[.!?]`)
	for _, c := range load(t).Controls {
		if len(c.EvidenceTypes) == 0 {
			t.Errorf("%s: needs at least one evidence type", c.ID)
		}
		if n := len(c.Remediation); n < 3 || n > 5 {
			t.Errorf("%s: needs 3 to 5 remediation steps, has %d", c.ID, n)
		}
		if len(c.Limitations) == 0 {
			t.Errorf("%s: needs at least one limitation", c.ID)
		}
		if len(c.Detectors) != 1 || c.Detectors[0] != c.ID+".*" {
			t.Errorf("%s: detectors must list the rule-ID prefix, got %v", c.ID, c.Detectors)
		}
		if c.DefaultWeight <= 0 {
			t.Errorf("%s: weight %d", c.ID, c.DefaultWeight)
		}
		if c.Examples.Positive == "" || c.Examples.Negative == "" {
			t.Errorf("%s: needs both examples", c.ID)
		}
		if c.VerificationRules.Implementation == "" || c.VerificationRules.Tested == "" || c.VerificationRules.Operational == "" {
			t.Errorf("%s: needs all three verification rules", c.ID)
		}
		// plain_language is exactly one sentence.
		pl := strings.TrimSpace(c.PlainLanguage)
		if !strings.HasSuffix(pl, ".") || len(sentenceEnd.FindAllString(pl, -1)) != 1 {
			t.Errorf("%s: plain_language must be one sentence: %q", c.ID, pl)
		}
		if c.StandardsMappings == nil {
			t.Errorf("%s: standards_mappings must be a list, even when empty", c.ID)
		}
		for _, m := range c.StandardsMappings {
			if m.Standard == "" || m.Version == "" || m.RequirementID == "" || m.Rationale == "" || !strings.HasPrefix(m.URL, "https://") {
				t.Errorf("%s: incomplete mapping %+v", c.ID, m)
			}
		}
	}
}

func TestApplicabilityAndWeightsMatchTheDesign(t *testing.T) {
	capability := map[string][]string{
		"AGC-005": {model.CapTools},
		"AGC-006": {model.CapCredentials},
		"AGC-007": {model.CapDataAccess},
		"AGC-009": {model.CapSensitiveActions, model.CapMutatingActions, model.CapShellExec, model.CapCodeExec},
		"AGC-010": {model.CapSensitiveActions},
		"AGC-013": {model.CapShellExec, model.CapCodeExec, model.CapContainer},
		"AGC-015": {model.CapMemory},
		"AGC-016": {model.CapMultiAgent},
		"AGC-018": {model.CapMutatingActions, model.CapSensitiveActions},
	}
	declarationOnly := map[string]bool{"AGC-001": true, "AGC-002": true, "AGC-019": true}
	priority := map[string]bool{"AGC-001": true, "AGC-004": true, "AGC-005": true, "AGC-007": true,
		"AGC-009": true, "AGC-010": true, "AGC-017": true, "AGC-022": true}

	maxOther := 0
	minPriority := 1 << 30
	for _, c := range load(t).Controls {
		if caps, ok := capability[c.ID]; ok {
			if c.Applicability.Mode != "capability" || !reflect.DeepEqual(c.Applicability.CapabilitiesAny, caps) {
				t.Errorf("%s: applicability %+v, want capability %v", c.ID, c.Applicability, caps)
			}
		} else if c.Applicability.Mode != "always" || len(c.Applicability.CapabilitiesAny) != 0 {
			t.Errorf("%s: applicability %+v, want always", c.ID, c.Applicability)
		}
		if c.Applicability.Rationale == "" {
			t.Errorf("%s: applicability needs a rationale", c.ID)
		}
		wantStatic := 2
		if declarationOnly[c.ID] {
			wantStatic = 1
		}
		if c.VerificationRules.MaxStaticMaturity != wantStatic {
			t.Errorf("%s: max_static_maturity %d, want %d", c.ID, c.VerificationRules.MaxStaticMaturity, wantStatic)
		}
		if priority[c.ID] {
			if c.DefaultWeight < minPriority {
				minPriority = c.DefaultWeight
			}
		} else if c.DefaultWeight > maxOther {
			maxOther = c.DefaultWeight
		}
	}
	if minPriority <= maxOther {
		t.Errorf("priority controls must weigh more than the others: min priority %d, max other %d", minPriority, maxOther)
	}
}

func TestWritingRules(t *testing.T) {
	banned := []string{"leverage", "unlock", "elevate", "delve", "navigate", "realm", "stellar", "cutting edge", "cutting-edge", "game changer", "game-changer", "supercharge"}
	contraction := regexp.MustCompile(`(?i)\b\w+(n't|'re|'ve|'ll|'d)\b|\b(it|that|there|here|what|who|let)'s\b`)
	for _, c := range load(t).Controls {
		texts := []string{c.Intent, c.PlainLanguage, c.Applicability.Rationale, c.VerificationRules.Implementation,
			c.VerificationRules.Tested, c.VerificationRules.Operational, c.Examples.Positive, c.Examples.Negative}
		texts = append(texts, c.Remediation...)
		texts = append(texts, c.Limitations...)
		texts = append(texts, c.DynamicTests...)
		for _, m := range c.StandardsMappings {
			texts = append(texts, m.Rationale)
		}
		for _, s := range texts {
			lower := strings.ToLower(s)
			for _, w := range banned {
				if strings.Contains(lower, w) {
					t.Errorf("%s: banned word %q in %q", c.ID, w, s)
				}
			}
			if m := contraction.FindString(s); m != "" {
				t.Errorf("%s: contraction %q in %q", c.ID, m, s)
			}
			for _, r := range s {
				if r > 0x2000 {
					t.Errorf("%s: unexpected symbol %q in %q", c.ID, r, s)
					break
				}
			}
		}
	}
}

func TestFindAndDomains(t *testing.T) {
	cat := load(t)
	c, ok := Find(cat, "AGC-010")
	if !ok || c.Title != "Human Approval Gates" {
		t.Fatalf("Find AGC-010: %v %q", ok, c.Title)
	}
	if c.PlainLanguage != "A person must approve risky actions before the agent carries them out." {
		t.Errorf("AGC-010 plain language: %q", c.PlainLanguage)
	}
	for _, id := range []string{"AGC-000", "AGC-025", "agc-001", ""} {
		if _, ok := Find(cat, id); ok {
			t.Errorf("Find(%q) must fail", id)
		}
	}
	if _, ok := Find(nil, "AGC-001"); ok {
		t.Errorf("Find on a nil catalog must fail")
	}

	groups := Domains(cat)
	wantSizes := []int{3, 5, 5, 3, 3, 5}
	if len(groups) != 6 {
		t.Fatalf("want 6 domains, got %d", len(groups))
	}
	n := 0
	for i, g := range groups {
		if g.Name != DomainNames()[i] || len(g.ControlIDs) != wantSizes[i] {
			t.Errorf("domain %d: %q with %d controls, want %q with %d", i, g.Name, len(g.ControlIDs), DomainNames()[i], wantSizes[i])
		}
		for _, id := range g.ControlIDs {
			n++
			if id != ID(n) {
				t.Errorf("domain %q: got %s at position %d", g.Name, id, n)
			}
		}
	}
	if empty := Domains(nil); len(empty) != 6 || empty[0].ControlIDs == nil {
		t.Errorf("Domains(nil) must still list six domains with empty lists")
	}
}

func TestLoadReturnsIndependentCopies(t *testing.T) {
	a := load(t)
	a.Controls[0].Title = "changed"
	a.Controls[0].Remediation[0] = "changed"
	b := load(t)
	if b.Controls[0].Title != "Owner and Inventory" || b.Controls[0].Remediation[0] == "changed" {
		t.Fatal("Load must return a fresh catalog")
	}
}

func controlYAML(t testing.TB, id string) string {
	t.Helper()
	raw, err := policies.FS.ReadFile(policies.ControlsDir + "/" + id + ".yaml")
	if err != nil {
		t.Fatal(err)
	}
	return string(raw)
}

func TestSchemaRejectsABrokenControl(t *testing.T) {
	good := controlYAML(t, "AGC-005")
	if _, err := ParseControl([]byte(good)); err != nil {
		t.Fatalf("the shipped control must parse: %v", err)
	}
	tests := []struct {
		name     string
		mutate   func(string) string
		wantText string
	}{
		{"unknown field", func(s string) string { return s + "auto_pass: true\n" }, "auto_pass"},
		{"bad ID", func(s string) string { return strings.Replace(s, "id: AGC-005", "id: AGC-025", 1) }, "id"},
		{"unknown domain", func(s string) string { return strings.Replace(s, `"B: Identity and Access"`, `"Z: Other"`, 1) }, "domain"},
		{"unknown capability", func(s string) string { return strings.Replace(s, "    - tools", "    - telepathy", 1) }, "capabilities_any"},
		{"capability mode without capabilities", func(s string) string {
			return strings.Replace(s, "  capabilities_any:\n    - tools\n", "", 1)
		}, "applicability"},
		{"zero weight", func(s string) string { return strings.Replace(s, "default_weight: 5", "default_weight: 0", 1) }, "default_weight"},
		{"static maturity above 2", func(s string) string {
			return strings.Replace(s, "max_static_maturity: 2", "max_static_maturity: 4", 1)
		}, "max_static_maturity"},
		{"missing plain_language", func(s string) string {
			return regexp.MustCompile(`(?m)^plain_language:.*\n`).ReplaceAllString(s, "")
		}, "plain_language"},
		{"empty limitations", func(s string) string {
			return regexp.MustCompile(`(?s)limitations:\n.*?examples:`).ReplaceAllString(s, "limitations: []\nexamples:")
		}, "limitations"},
		{"empty remediation", func(s string) string {
			return regexp.MustCompile(`(?s)remediation:\n.*?severity:`).ReplaceAllString(s, "remediation: []\nseverity:")
		}, "remediation"},
		{"unknown severity", func(s string) string { return strings.Replace(s, "severity: high", "severity: extreme", 1) }, "severity"},
		{"mapping with http URL", func(s string) string { return strings.Replace(s, "url: https://", "url: http://", 1) }, "url"},
		{"mapping without rationale", func(s string) string {
			return regexp.MustCompile(`(?m)^    rationale:.*\n`).ReplaceAllString(s, "")
		}, "rationale"},
		{"detector for another control", func(s string) string { return strings.Replace(s, "- AGC-005.*", "- AGC-006.*", 1) }, "detector"},
		{"malformed YAML", func(s string) string { return "id: [AGC-005\n" }, "malformed YAML"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			broken := tc.mutate(good)
			if broken == good {
				t.Fatal("the mutation did not change the document")
			}
			_, err := ParseControl([]byte(broken))
			if err == nil {
				t.Fatal("expected an error")
			}
			if !strings.Contains(err.Error(), tc.wantText) {
				t.Errorf("error should mention %q: %v", tc.wantText, err)
			}
		})
	}
}

func packFS(t testing.TB, change func(files fstest.MapFS)) fstest.MapFS {
	t.Helper()
	files := fstest.MapFS{}
	pack, err := policies.FS.ReadFile(policies.PackFile)
	if err != nil {
		t.Fatal(err)
	}
	files["c/pack.yaml"] = &fstest.MapFile{Data: pack}
	for i := 1; i <= Count; i++ {
		files["c/"+ID(i)+".yaml"] = &fstest.MapFile{Data: []byte(controlYAML(t, ID(i)))}
	}
	change(files)
	return files
}

func TestLoadRejectsABrokenPack(t *testing.T) {
	if _, err := LoadFS(packFS(t, func(fstest.MapFS) {}), "c"); err != nil {
		t.Fatalf("an unchanged copy must load: %v", err)
	}
	tests := []struct {
		name     string
		change   func(files fstest.MapFS)
		wantText string
	}{
		{"missing control", func(f fstest.MapFS) { delete(f, "c/AGC-013.yaml") }, "expected exactly 24 controls, found 23"},
		{"gap in IDs", func(f fstest.MapFS) {
			delete(f, "c/AGC-013.yaml")
			f["c/AGC-024b.yaml"] = &fstest.MapFile{Data: []byte(controlYAML(t, "AGC-024"))}
		}, "AGC-024b.yaml"},
		{"duplicate ID under another name", func(f fstest.MapFS) {
			f["c/AGC-013.yaml"] = &fstest.MapFile{Data: []byte(controlYAML(t, "AGC-012"))}
		}, "file name must be AGC-012.yaml"},
		{"one broken file", func(f fstest.MapFS) {
			f["c/AGC-007.yaml"] = &fstest.MapFile{Data: []byte(strings.Replace(controlYAML(t, "AGC-007"), "severity: high", "severity: none", 1))}
		}, "AGC-007.yaml"},
		{"no pack file", func(f fstest.MapFS) { delete(f, "c/pack.yaml") }, "pack.yaml"},
		{"pack without version", func(f fstest.MapFS) { f["c/pack.yaml"] = &fstest.MapFile{Data: []byte("name: builtin/v1\n")} }, "name and version"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			cat, err := LoadFS(packFS(t, tc.change), "c")
			if err == nil || cat != nil {
				t.Fatal("a broken pack must not load")
			}
			if !strings.Contains(err.Error(), tc.wantText) {
				t.Errorf("error should mention %q: %v", tc.wantText, err)
			}
		})
	}
}

func TestValidateCatalogSemantics(t *testing.T) {
	if err := ValidateCatalog(nil); err == nil {
		t.Error("nil catalog must fail")
	}
	check := func(name, want string, change func(*model.Catalog)) {
		t.Helper()
		cat := load(t)
		change(cat)
		err := ValidateCatalog(cat)
		if err == nil || !strings.Contains(err.Error(), want) {
			t.Errorf("%s: want an error with %q, got %v", name, want, err)
		}
	}
	check("duplicate", "duplicate control ID AGC-001", func(c *model.Catalog) { c.Controls[1].ID = "AGC-001" })
	check("out of order", "position 1: expected AGC-001", func(c *model.Catalog) {
		c.Controls[0], c.Controls[1] = c.Controls[1], c.Controls[0]
	})
	check("25 controls", "expected exactly 24", func(c *model.Catalog) { c.Controls = append(c.Controls, c.Controls[0]) })
	check("unknown domain", "unknown domain", func(c *model.Catalog) { c.Controls[3].Domain = "G: Extra" })
	check("unknown capability", "unknown capability", func(c *model.Catalog) {
		c.Controls[4].Applicability.CapabilitiesAny = []string{"mind-reading"}
	})
	check("weight", "default_weight", func(c *model.Catalog) { c.Controls[5].DefaultWeight = 0 })
	check("static maturity", "max_static_maturity", func(c *model.Catalog) { c.Controls[6].VerificationRules.MaxStaticMaturity = 3 })
	check("plain language", "plain_language is empty", func(c *model.Catalog) { c.Controls[7].PlainLanguage = " " })
	check("remediation", "remediation is empty", func(c *model.Catalog) { c.Controls[8].Remediation = nil })
	check("limitations", "limitations is empty", func(c *model.Catalog) { c.Controls[9].Limitations = nil })
	check("mapping fields", "standards_mappings[0] must set", func(c *model.Catalog) {
		c.Controls[10].StandardsMappings = []model.Mapping{{Standard: "X", URL: "https://example.org"}}
	})
	check("mapping URL", "must start with https://", func(c *model.Catalog) {
		c.Controls[10].StandardsMappings = []model.Mapping{{Standard: "X", Version: "1", RequirementID: "R1", URL: "ftp://example.org", Rationale: "Because."}}
	})
}

func TestMappingsUseOnlyVerifiedIdentifiers(t *testing.T) {
	// Identifiers verified against the published sources on 2026-11-15. See
	// docs/control-catalog.md. A new identifier needs a new verification.
	verified := map[string]map[string]bool{
		"OWASP Top 10 for Agentic Applications|2026|https://genai.owasp.org/resource/owasp-top-10-for-agentic-applications-for-2026/": {
			"ASI01": true, "ASI02": true, "ASI03": true, "ASI04": true, "ASI05": true,
			"ASI06": true, "ASI07": true, "ASI08": true, "ASI09": true, "ASI10": true,
		},
		"NIST AI Risk Management Framework|1.0|https://airc.nist.gov/airmf-resources/airmf/5-sec-core/": {
			"GOVERN": true, "MAP": true, "MEASURE": true, "MANAGE": true,
		},
	}
	total := 0
	for _, c := range load(t).Controls {
		for _, m := range c.StandardsMappings {
			total++
			ids, ok := verified[m.Standard+"|"+m.Version+"|"+m.URL]
			if !ok || !ids[m.RequirementID] {
				t.Errorf("%s: mapping %+v is not in the verified list", c.ID, m)
			}
		}
	}
	if total == 0 {
		t.Error("expected at least one verified mapping")
	}
}
