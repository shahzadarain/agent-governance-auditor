// SPDX-License-Identifier: Apache-2.0

package config

import (
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
)

// minimal is the smallest valid configuration.
const minimal = "schema_version: \"1\"\n"

func exampleBytes(t testing.TB) []byte {
	t.Helper()
	data, err := os.ReadFile(filepath.Join("..", "..", ".agentgov.example.yaml"))
	if err != nil {
		t.Fatalf("read example: %v", err)
	}
	return data
}

func write(t testing.TB, dir, name, content string) string {
	t.Helper()
	p := filepath.Join(dir, name)
	if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(p, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
	return p
}

func TestExampleFileIsValid(t *testing.T) {
	data := exampleBytes(t)
	if diags := Validate(data); len(diags) != 0 {
		t.Fatalf("the example must validate:\n%s", strings.Join(diags, "\n"))
	}
	dir := t.TempDir()
	write(t, dir, FileName, string(data))
	cfg, diags, err := Load(dir, "")
	if err != nil || len(diags) != 0 || cfg == nil {
		t.Fatalf("Load: %v %v", err, diags)
	}
	if cfg.Path != ".agentgov.yaml" || cfg.SchemaVersion != "1" {
		t.Errorf("path %q version %q", cfg.Path, cfg.SchemaVersion)
	}
	if cfg.Agent.ID != "finance-processing-agent" || cfg.Agent.Owner != "finance-technology" || cfg.Agent.RiskTier != "high" || cfg.Agent.DataClassification != "confidential" {
		t.Errorf("agent %+v", cfg.Agent)
	}
	if !reflect.DeepEqual(cfg.Capabilities.DeclaredTools, []string{"finance.read", "finance.adjust"}) ||
		!reflect.DeepEqual(cfg.Capabilities.SensitiveActions, []string{"finance.adjust"}) ||
		cfg.Capabilities.ExternalConnectivity == nil || *cfg.Capabilities.ExternalConnectivity {
		t.Errorf("capabilities %+v", cfg.Capabilities)
	}
	if cfg.Verification.Profile != "high-risk" || cfg.Verification.TestsPath != "tests/governance" ||
		!reflect.DeepEqual(cfg.Verification.EvidencePaths, []string{".agentgov/evidence"}) || cfg.Verification.Offline == nil || !*cfg.Verification.Offline {
		t.Errorf("verification %+v", cfg.Verification)
	}
	wantMandatory := []string{"AGC-004", "AGC-005", "AGC-007", "AGC-009", "AGC-010", "AGC-017", "AGC-022"}
	if cfg.Policy.Pack != "builtin/v1" || !reflect.DeepEqual(cfg.Policy.MandatoryControls, wantMandatory) || cfg.Policy.MinMaturity == nil || *cfg.Policy.MinMaturity != 3 {
		t.Errorf("policy %+v", cfg.Policy)
	}
	if len(cfg.Policy.NotApplicable) != 1 || cfg.Policy.NotApplicable[0].Control != "AGC-016" || cfg.Policy.NotApplicable[0].Expires != "2027-06-30" {
		t.Errorf("not_applicable %+v", cfg.Policy.NotApplicable)
	}
	if len(cfg.Policy.AcceptedRisks) != 1 || cfg.Policy.AcceptedRisks[0].ApprovedBy != "chief-information-security-officer" {
		t.Errorf("accepted_risks %+v", cfg.Policy.AcceptedRisks)
	}
	if !reflect.DeepEqual(cfg.Report.Formats, []string{"terminal", "json"}) || cfg.Report.RedactSensitiveData == nil || !*cfg.Report.RedactSensitiveData {
		t.Errorf("report %+v", cfg.Report)
	}
	if len(cfg.Scan.Include) != 2 || len(cfg.Scan.Exclude) != 2 || cfg.Scan.MaxFileSize != 1048576 {
		t.Errorf("scan %+v", cfg.Scan)
	}
}

func TestMinimalAndOptionalForms(t *testing.T) {
	for name, doc := range map[string]string{
		"minimal":              minimal,
		"single-quoted":        "schema_version: '1'\n",
		"unquoted dates":       minimal + "agent:\n  last_reviewed: 2026-10-01\npolicy:\n  not_applicable:\n    - control: AGC-016\n      reason: Single agent with no peers.\n      approved_by: board\n      expires: 2027-06-30\n",
		"monorepo":             minimal + "agents:\n  - id: a\n    root: services/a\n  - id: b\n    root: services/b\n    risk_tier: low\n",
		"dot paths":            minimal + "verification:\n  tests_path: ./tests\n  evidence_paths: [\".agentgov/evidence\", \"a..b/c\", \"...\"]\n",
		"all formats":          minimal + "report:\n  formats: [terminal, json, markdown, html, sarif]\n",
		"maturity bounds":      minimal + "policy:\n  min_maturity: 0\n  mandatory_controls: []\n",
		"comments and anchors": "# comment\nschema_version: \"1\"\nscan:\n  include: &g [\"src/**\"]\n  exclude: *g\n",
	} {
		if diags := Validate([]byte(doc)); len(diags) != 0 {
			t.Errorf("%s: unexpected diagnostics: %v", name, diags)
		}
	}
}

func TestValidateDiagnostics(t *testing.T) {
	tests := []struct {
		name string
		doc  string
		want []string // each must appear in some diagnostic
	}{
		{"missing schema_version", "agent:\n  id: x\n", []string{"schema_version: required field is missing"}},
		{"empty file", "", []string{"schema_version: required field is missing"}},
		{"only comments", "# nothing here\n", []string{"schema_version: required field is missing"}},
		{"schema_version as number", "schema_version: 1\n", []string{`schema_version: must be the string "1" in quotes`}},
		{"schema_version null", "schema_version:\n", []string{`schema_version: must be the string "1"`}},
		{"unsupported version", "schema_version: \"2\"\n", []string{`schema_version: unsupported version "2"`, "migration"}},
		{"unknown top-level field", minimal + "polcy:\n  pack: builtin/v1\n", []string{"polcy: unknown field"}},
		{"unknown nested field", minimal + "agent:\n  id: x\n  ownr: me\n", []string{"agent.ownr: unknown field"}},
		{"unknown field in exception", minimal + "policy:\n  accepted_risks:\n    - control: AGC-001\n      reason: Accepted for one quarter.\n      approved_by: ciso\n      waive: true\n", []string{"policy.accepted_risks[0].waive: unknown field"}},
		{"wrong enum risk_tier", minimal + "agent:\n  risk_tier: extreme\n", []string{"agent.risk_tier:"}},
		{"wrong enum data_classification", minimal + "agent:\n  data_classification: secret\n", []string{"agent.data_classification:"}},
		{"wrong enum profile", minimal + "verification:\n  profile: lenient\n", []string{"verification.profile:"}},
		{"wrong enum format", minimal + "report:\n  formats: [terminal, pdf]\n", []string{"report.formats[1]:"}},
		{"wrong pack", minimal + "policy:\n  pack: custom/v9\n", []string{"policy.pack:"}},
		{"bad control ID", minimal + "policy:\n  mandatory_controls: [AGC-004, AGC-025]\n", []string{"policy.mandatory_controls[1]: must be a control ID from AGC-001 to AGC-024"}},
		{"bad control ID zero", minimal + "policy:\n  mandatory_controls: [AGC-000]\n", []string{"policy.mandatory_controls[0]: must be a control ID"}},
		{"bad control ID lowercase", minimal + "policy:\n  mandatory_controls: [agc-004]\n", []string{"policy.mandatory_controls[0]: must be a control ID"}},
		{"bad control ID in exception", minimal + "policy:\n  not_applicable:\n    - control: AGC-24\n      reason: Not relevant here at all.\n      approved_by: board\n", []string{"policy.not_applicable[0].control: must be a control ID"}},
		{"path traversal in evidence_paths", minimal + "verification:\n  evidence_paths: [\"../../etc\"]\n", []string{`verification.evidence_paths[0]: must be a repository-relative path`}},
		{"path traversal in the middle", minimal + "verification:\n  evidence_paths: [\"ok\", \"a/../../b\"]\n", []string{"verification.evidence_paths[1]: must be a repository-relative path"}},
		{"path traversal at the end", minimal + "verification:\n  evidence_paths: [\"a/..\"]\n", []string{"verification.evidence_paths[0]:"}},
		{"bare dot-dot", minimal + "verification:\n  tests_path: \"..\"\n", []string{"verification.tests_path: must be a repository-relative path"}},
		{"absolute path", minimal + "verification:\n  tests_path: /etc/passwd\n", []string{"verification.tests_path: must be a repository-relative path"}},
		{"windows drive path", minimal + "verification:\n  evidence_paths: [\"C:/Users/x\"]\n", []string{"verification.evidence_paths[0]:"}},
		{"backslash traversal", minimal + "verification:\n  evidence_paths: ['..\\..\\secrets']\n", []string{"verification.evidence_paths[0]:"}},
		{"traversal in agent root", minimal + "agents:\n  - id: a\n    root: ../other\n", []string{"agents[0].root: must be a repository-relative path"}},
		{"traversal in scan include", minimal + "scan:\n  include: [\"../**\"]\n", []string{"scan.include[0]: must be a repository-relative path"}},
		{"exception without reason", minimal + "policy:\n  not_applicable:\n    - control: AGC-016\n      approved_by: board\n", []string{"policy.not_applicable[0].reason: required field is missing"}},
		{"exception without approver", minimal + "policy:\n  accepted_risks:\n    - control: AGC-016\n      reason: Accepted for one quarter.\n", []string{"policy.accepted_risks[0].approved_by: required field is missing"}},
		{"exception without control", minimal + "policy:\n  accepted_risks:\n    - reason: Accepted for one quarter.\n      approved_by: ciso\n", []string{"policy.accepted_risks[0].control: required field is missing"}},
		{"exception with blank approver", minimal + "policy:\n  accepted_risks:\n    - control: AGC-016\n      reason: Accepted for one quarter.\n      approved_by: \"\"\n", []string{"policy.accepted_risks[0].approved_by:"}},
		{"exception with bad date format", minimal + "policy:\n  not_applicable:\n    - control: AGC-016\n      reason: Single agent with no peers.\n      approved_by: board\n      expires: next year\n", []string{"policy.not_applicable[0].expires: must be a date in the form YYYY-MM-DD"}},
		{"exception with impossible date", minimal + "policy:\n  not_applicable:\n    - control: AGC-016\n      reason: Single agent with no peers.\n      approved_by: board\n      expires: \"2027-02-31\"\n", []string{`policy.not_applicable[0].expires: "2027-02-31" is not a real calendar date`}},
		{"same control in both exception lists", minimal + "policy:\n  not_applicable:\n    - control: AGC-016\n      reason: Single agent with no peers.\n      approved_by: board\n  accepted_risks:\n    - control: AGC-016\n      reason: Accepted for one quarter.\n      approved_by: ciso\n", []string{"policy.accepted_risks[0].control: AGC-016 already has an exception at policy.not_applicable[0]"}},
		{"min_maturity too high", minimal + "policy:\n  min_maturity: 5\n", []string{"policy.min_maturity:"}},
		{"min_maturity negative", minimal + "policy:\n  min_maturity: -1\n", []string{"policy.min_maturity:"}},
		{"min_maturity as text", minimal + "policy:\n  min_maturity: high\n", []string{"policy.min_maturity:"}},
		{"wrong type for list", minimal + "capabilities:\n  declared_tools: finance.read\n", []string{"capabilities.declared_tools:"}},
		{"wrong type for boolean", minimal + "verification:\n  offline: maybe\n", []string{"verification.offline:"}},
		{"monorepo agent without root", minimal + "agents:\n  - id: a\n", []string{"agents[0].root: required field is missing"}},
		{"duplicate agent IDs", minimal + "agents:\n  - id: a\n    root: x\n  - id: a\n    root: y\n", []string{`agents[1].id: agent ID "a" is already used by agents[0].id`}},
		{"agent ID with spaces", minimal + "agent:\n  id: \"my agent\"\n", []string{"agent.id:"}},
		{"malformed YAML", "schema_version: \"1\"\nagent: [unclosed\n", []string{"(document): malformed YAML"}},
		{"tabs for indentation", "schema_version: \"1\"\nagent:\n\tid: x\n", []string{"malformed YAML"}},
		{"duplicate key", minimal + "agent:\n  id: a\nagent:\n  id: b\n", []string{"duplicate key \"agent\""}},
		{"two documents", minimal + "---\nschema_version: \"1\"\n", []string{"more than one document"}},
		{"top level is a list", "- schema_version\n", []string{"must be a mapping"}},
		{"top level is a string", "just text\n", []string{"must be a mapping"}},
		{"oversized", minimal + "# " + strings.Repeat("x", MaxSize) + "\n", []string{"larger than the limit of 262144 bytes"}},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			diags := Validate([]byte(tc.doc))
			if len(diags) == 0 {
				t.Fatal("expected diagnostics")
			}
			all := strings.Join(diags, "\n")
			for _, w := range tc.want {
				if !strings.Contains(all, w) {
					t.Errorf("want a diagnostic containing %q, got:\n%s", w, all)
				}
			}
			for _, d := range diags {
				if !strings.Contains(d, ": ") {
					t.Errorf("a diagnostic must start with a field path: %q", d)
				}
			}
		})
	}
}

func TestValidateReportsSeveralProblemsInStableOrder(t *testing.T) {
	doc := minimal + "agent:\n  risk_tier: extreme\n  nickname: x\nverification:\n  profile: lenient\n  evidence_paths: [\"../x\"]\npolicy:\n  mandatory_controls: [AGC-099]\n"
	first := Validate([]byte(doc))
	if len(first) != 5 {
		t.Fatalf("want 5 diagnostics, got %d:\n%s", len(first), strings.Join(first, "\n"))
	}
	for i := 0; i < 20; i++ {
		if again := Validate([]byte(doc)); !reflect.DeepEqual(first, again) {
			t.Fatalf("diagnostics are not stable:\n%v\n%v", first, again)
		}
	}
}

func TestAliasExpansionIsBounded(t *testing.T) {
	var b strings.Builder
	b.WriteString("schema_version: \"1\"\nscan:\n  include: &a0 [\"x\",\"x\",\"x\",\"x\",\"x\",\"x\",\"x\",\"x\",\"x\",\"x\"]\n")
	b.WriteString("x1: &a1 [*a0,*a0,*a0,*a0,*a0,*a0,*a0,*a0,*a0,*a0]\n")
	for i := 2; i <= 8; i++ {
		prev := string(rune('0' + i - 1))
		b.WriteString("x" + string(rune('0'+i)) + ": &a" + string(rune('0'+i)) + " [")
		b.WriteString(strings.TrimSuffix(strings.Repeat("*a"+prev+",", 10), ","))
		b.WriteString("]\n")
	}
	diags := Validate([]byte(b.String()))
	if len(diags) != 1 || !strings.Contains(diags[0], "malformed YAML") {
		t.Fatalf("a document that expands aliases without bound must be rejected, got %v", diags)
	}
}

func TestLoad(t *testing.T) {
	t.Run("no file is not an error", func(t *testing.T) {
		cfg, diags, err := Load(t.TempDir(), "")
		if cfg != nil || diags != nil || err != nil {
			t.Fatalf("want (nil, nil, nil), got %v %v %v", cfg, diags, err)
		}
	})

	t.Run("finds the yml name", func(t *testing.T) {
		dir := t.TempDir()
		write(t, dir, AltFileName, minimal)
		cfg, _, err := Load(dir, "")
		if err != nil || cfg == nil || cfg.Path != ".agentgov.yml" {
			t.Fatalf("%v %+v", err, cfg)
		}
	})

	t.Run("prefers the yaml name", func(t *testing.T) {
		dir := t.TempDir()
		write(t, dir, FileName, minimal+"agent:\n  id: from-yaml\n")
		write(t, dir, AltFileName, minimal+"agent:\n  id: from-yml\n")
		cfg, _, err := Load(dir, "")
		if err != nil || cfg.Agent.ID != "from-yaml" {
			t.Fatalf("%v %+v", err, cfg)
		}
	})

	t.Run("does not search subdirectories or parents", func(t *testing.T) {
		dir := t.TempDir()
		write(t, dir, "sub/"+FileName, minimal)
		if cfg, _, err := Load(dir, ""); cfg != nil || err != nil {
			t.Fatalf("a file in a subdirectory must not be picked up: %v %v", cfg, err)
		}
		write(t, dir, FileName, minimal)
		if cfg, _, err := Load(filepath.Join(dir, "sub", "deeper"), ""); cfg != nil || err != nil {
			t.Fatalf("a file in a parent must not be picked up: %v %v", cfg, err)
		}
	})

	t.Run("explicit path", func(t *testing.T) {
		dir := t.TempDir()
		p := write(t, dir, "conf/custom.yaml", minimal+"agent:\n  id: custom\n")
		write(t, dir, FileName, minimal+"agent:\n  id: default\n")
		cfg, _, err := Load(dir, p)
		if err != nil || cfg.Agent.ID != "custom" || cfg.Path != "conf/custom.yaml" {
			t.Fatalf("%v %+v", err, cfg)
		}
		outside := write(t, t.TempDir(), "org.yaml", minimal)
		cfg, _, err = Load(dir, outside)
		if err != nil || cfg.Path != filepath.ToSlash(outside) {
			t.Fatalf("%v %+v", err, cfg)
		}
	})

	t.Run("explicit path that does not exist", func(t *testing.T) {
		cfg, diags, err := Load(t.TempDir(), filepath.Join(t.TempDir(), "missing.yaml"))
		if cfg != nil || err == nil || len(diags) != 1 || !strings.Contains(err.Error(), "not found") {
			t.Fatalf("%v %v %v", cfg, diags, err)
		}
	})

	t.Run("invalid file returns diagnostics and an error", func(t *testing.T) {
		dir := t.TempDir()
		write(t, dir, FileName, minimal+"agent:\n  risk_tier: extreme\nsurprise: 1\n")
		cfg, diags, err := Load(dir, "")
		if cfg != nil || err == nil {
			t.Fatalf("an invalid file must not load: %v %v", cfg, err)
		}
		if len(diags) != 2 || !strings.Contains(err.Error(), ".agentgov.yaml: configuration is invalid (2 problems)") {
			t.Fatalf("diags %v err %v", diags, err)
		}
	})

	t.Run("malformed YAML", func(t *testing.T) {
		dir := t.TempDir()
		write(t, dir, FileName, "schema_version: \"1\"\n  bad: [indent\n")
		cfg, diags, err := Load(dir, "")
		if cfg != nil || err == nil || len(diags) != 1 || !strings.Contains(diags[0], "malformed YAML") {
			t.Fatalf("%v %v %v", cfg, diags, err)
		}
	})

	t.Run("oversized file is rejected before parsing", func(t *testing.T) {
		dir := t.TempDir()
		write(t, dir, FileName, minimal+"# "+strings.Repeat("x", MaxSize)+"\n")
		cfg, diags, err := Load(dir, "")
		if cfg != nil || err == nil || len(diags) != 1 || !strings.Contains(err.Error(), "the limit is 262144 bytes") {
			t.Fatalf("%v %v %v", cfg, diags, err)
		}
	})

	t.Run("a file at exactly the limit is read", func(t *testing.T) {
		dir := t.TempDir()
		pad := MaxSize - len(minimal) - 3
		write(t, dir, FileName, minimal+"# "+strings.Repeat("x", pad)+"\n")
		if cfg, diags, err := Load(dir, ""); cfg == nil || err != nil {
			t.Fatalf("%v %v", diags, err)
		}
	})

	t.Run("a directory with the configuration name is rejected", func(t *testing.T) {
		dir := t.TempDir()
		if err := os.Mkdir(filepath.Join(dir, FileName), 0o755); err != nil {
			t.Fatal(err)
		}
		cfg, _, err := Load(dir, "")
		if cfg != nil || err == nil || !strings.Contains(err.Error(), "regular file") {
			t.Fatalf("%v %v", cfg, err)
		}
	})

	t.Run("a symbolic link is rejected", func(t *testing.T) {
		dir := t.TempDir()
		target := write(t, t.TempDir(), "outside.yaml", minimal)
		if err := os.Symlink(target, filepath.Join(dir, FileName)); err != nil {
			t.Skipf("symbolic links are not available here: %v", err)
		}
		cfg, _, err := Load(dir, "")
		if cfg != nil || err == nil || !strings.Contains(err.Error(), "regular file") {
			t.Fatalf("a link must not be followed: %v %v", cfg, err)
		}
	})
}

func TestConfigCannotCarrySecretsIntoDiagnostics(t *testing.T) {
	// A long unknown value must not be echoed back in full.
	secret := strings.Repeat("S3CR3T", 50)
	diags := Validate([]byte(minimal + "agent:\n  risk_tier: " + secret + "\n"))
	if len(diags) == 0 {
		t.Fatal("expected a diagnostic")
	}
	for _, d := range diags {
		if strings.Contains(d, secret) {
			t.Errorf("the diagnostic echoes the full value: %.80s...", d)
		}
	}
}
