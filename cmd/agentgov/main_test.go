// SPDX-License-Identifier: Apache-2.0

package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/shahzadarain/agent-governance-auditor/internal/model"
	"github.com/shahzadarain/agent-governance-auditor/internal/scanner"
)

const (
	vulnerable = "../../examples/vulnerable-agent"
	safe       = "../../examples/safe-agent"
	noAgent    = "../../tests/fixtures/no-agent"
)

// runCLI executes the CLI in-process and returns stdout, stderr, and the
// exit code that main would return.
func runCLI(t *testing.T, args ...string) (string, string, int) {
	t.Helper()
	root := newRootCmd()
	var out, errOut bytes.Buffer
	root.SetOut(&out)
	root.SetErr(&errOut)
	root.SetArgs(args)
	err := root.ExecuteContext(context.Background())
	code := exitOK
	var pf *policyFailure
	switch {
	case err == nil:
	case errors.As(err, &pf):
		code = exitPolicy
	default:
		code = exitError
		errOut.WriteString(err.Error())
	}
	return out.String(), errOut.String(), code
}

func TestExitCodesSeparatePolicyFailureFromScanError(t *testing.T) {
	cases := []struct {
		name string
		args []string
		want int
	}{
		{"vulnerable example is blocked", []string{"scan", vulnerable, "--no-color"}, exitPolicy},
		{"safe example is allowed", []string{"scan", safe, "--no-color"}, exitOK},
		{"fail-on never reports without failing", []string{"scan", vulnerable, "--fail-on", "never", "-q"}, exitOK},
		{"no agent is review-required, not a failure by default", []string{"scan", noAgent, "-q"}, exitOK},
		{"no agent fails when review must fail", []string{"scan", noAgent, "-q", "--fail-on", "review"}, exitPolicy},
		{"missing path is a scan error", []string{"scan", "does-not-exist"}, exitError},
		{"unknown format is a scan error", []string{"scan", safe, "--format", "pdf"}, exitError},
		{"unknown fail-on is a scan error", []string{"scan", safe, "--fail-on", "sometimes"}, exitError},
		{"unknown profile is a scan error", []string{"scan", safe, "--profile", "nope"}, exitError},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, stderr, code := runCLI(t, tc.args...)
			if code != tc.want {
				t.Fatalf("exit code = %d, want %d (stderr: %s)", code, tc.want, stderr)
			}
		})
	}
}

func TestHighScoreStillBlocksUnderHighRiskProfile(t *testing.T) {
	dir := t.TempDir()
	jsonPath := filepath.Join(dir, "r.json")
	_, _, code := runCLI(t, "scan", safe, "--profile", "high-risk", "-q", "--json-out", jsonPath)
	if code != exitPolicy {
		t.Fatalf("exit code = %d, want %d", code, exitPolicy)
	}
	res, err := readResult(jsonPath)
	if err != nil {
		t.Fatal(err)
	}
	if res.Decision.Outcome != model.OutcomeBlock {
		t.Fatalf("decision = %s, want BLOCK", res.Decision.Outcome)
	}
	// Unsigned test evidence is capped at implementation level under this
	// profile, so the score is lower than under "standard" but far from zero.
	if res.Score.Value == nil || *res.Score.Value < 40 {
		t.Fatalf("expected a substantial score alongside the BLOCK, got %v", res.Score.Label)
	}
}

func TestAllFormatsWriteFilesAndRoundTrip(t *testing.T) {
	dir := t.TempDir()
	j := filepath.Join(dir, "r.json")
	_, stderr, code := runCLI(t, "scan", vulnerable, "--fail-on", "never", "-q",
		"--json-out", j,
		"--sarif-out", filepath.Join(dir, "r.sarif"),
		"--html-out", filepath.Join(dir, "r.html"),
		"--markdown-out", filepath.Join(dir, "r.md"))
	if code != exitOK {
		t.Fatalf("exit %d: %s", code, stderr)
	}
	for _, name := range []string{"r.json", "r.sarif", "r.html", "r.md"} {
		info, err := os.Stat(filepath.Join(dir, name))
		if err != nil || info.Size() == 0 {
			t.Fatalf("%s was not written", name)
		}
	}
	var sarif map[string]any
	data, _ := os.ReadFile(filepath.Join(dir, "r.sarif"))
	if err := json.Unmarshal(data, &sarif); err != nil || sarif["version"] != "2.1.0" {
		t.Fatalf("SARIF is not version 2.1.0: %v", err)
	}
	for _, format := range []string{"terminal", "markdown", "html", "sarif", "json"} {
		out, stderr, code := runCLI(t, "report", j, "--format", format, "--no-color")
		if code != exitOK || len(out) == 0 {
			t.Fatalf("report --format %s: exit %d, %s", format, code, stderr)
		}
	}
	out, _, code := runCLI(t, "compare", j, j, "--format", "markdown")
	if code != exitOK || !strings.Contains(out, "0 new") {
		t.Fatalf("compare of a result with itself should show no new findings:\n%s", out)
	}
}

func TestNoSecretValueInAnyOutput(t *testing.T) {
	// The vulnerable example holds inert, fake credentials. Their bodies must
	// never reach any report. Collect quoted literals on lines the scanner
	// flags, straight from the fixture, and search every output for them.
	src, err := os.ReadFile(filepath.Join(vulnerable, "agent.py"))
	if err != nil {
		t.Fatal(err)
	}
	var secrets []string
	for _, line := range strings.Split(string(src), "\n") {
		lower := strings.ToLower(line)
		if !strings.Contains(lower, "key") && !strings.Contains(lower, "password") && !strings.Contains(lower, "token") {
			continue
		}
		for _, q := range []string{`"`, `'`} {
			parts := strings.Split(line, q)
			for i := 1; i < len(parts); i += 2 {
				if v := parts[i]; len(v) >= 12 && !strings.Contains(v, " ") && !strings.Contains(v, "{") {
					secrets = append(secrets, v)
				}
			}
		}
	}
	if len(secrets) == 0 {
		t.Fatal("found no secret-shaped literals in the fixture; the test would prove nothing")
	}
	dir := t.TempDir()
	files := map[string]string{"json": "r.json", "sarif": "r.sarif", "html": "r.html", "markdown": "r.md"}
	args := []string{"scan", vulnerable, "--fail-on", "never", "--no-color", "--full"}
	for format, name := range files {
		args = append(args, "--"+format+"-out", filepath.Join(dir, name))
	}
	stdout, stderr, code := runCLI(t, args...)
	if code != exitOK {
		t.Fatalf("exit %d: %s", code, stderr)
	}
	outputs := map[string]string{"terminal": stdout + stderr}
	for format, name := range files {
		data, _ := os.ReadFile(filepath.Join(dir, name))
		outputs[format] = string(data)
	}
	for format, text := range outputs {
		for _, s := range secrets {
			if strings.Contains(text, s) {
				t.Errorf("%s output contains a secret literal from the fixture", format)
			}
		}
	}
}

func TestRepositoryInstructionsDoNotChangeTheResult(t *testing.T) {
	readme, err := os.ReadFile(filepath.Join(vulnerable, "README.md"))
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(strings.ToLower(string(readme)), "ignore all findings") {
		t.Fatal("fixture README no longer carries the injected instruction")
	}
	_, _, code := runCLI(t, "scan", vulnerable, "-q")
	if code != exitPolicy {
		t.Fatalf("an instruction inside the scanned repository changed the outcome: exit %d", code)
	}
}

func TestScanIsDeterministic(t *testing.T) {
	now := time.Date(2026, 1, 2, 3, 4, 5, 0, time.UTC)
	render := func() []byte {
		res, err := scanner.Scan(context.Background(), scanner.Options{Root: vulnerable, Version: "test", Now: now})
		if err != nil {
			t.Fatal(err)
		}
		res.Stats.DurationMilli = 0
		data, err := json.Marshal(res)
		if err != nil {
			t.Fatal(err)
		}
		return data
	}
	a, b := render(), render()
	if !bytes.Equal(a, b) {
		t.Fatal("two scans of the same input produced different results")
	}
}

func TestScanDoesNotModifyTheTarget(t *testing.T) {
	snapshot := func() map[string]int64 {
		files := map[string]int64{}
		_ = filepath.Walk(vulnerable, func(p string, info os.FileInfo, err error) error {
			if err == nil && !info.IsDir() {
				files[p] = info.Size()*1_000_000_007 + info.ModTime().UnixNano()%1_000_000_007
			}
			return nil
		})
		return files
	}
	before := snapshot()
	runCLI(t, "scan", vulnerable, "-q", "--fail-on", "never")
	after := snapshot()
	if len(before) != len(after) {
		t.Fatalf("file count changed from %d to %d", len(before), len(after))
	}
	for p, v := range before {
		if after[p] != v {
			t.Fatalf("%s changed during a scan", p)
		}
	}
}

func TestInitNeverOverwritesAndWritesValidConfig(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "agent.py"), []byte("print('hello')\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, stderr, code := runCLI(t, "init", dir, "--yes"); code != exitOK {
		t.Fatalf("init failed: %s", stderr)
	}
	cfg := filepath.Join(dir, ".agentgov.yaml")
	first, err := os.ReadFile(cfg)
	if err != nil {
		t.Fatal(err)
	}
	if _, _, code := runCLI(t, "policy", "validate", cfg); code != exitOK {
		t.Fatal("generated configuration does not validate")
	}
	if _, _, code := runCLI(t, "init", dir, "--yes"); code != exitError {
		t.Fatal("second init should refuse to overwrite")
	}
	second, _ := os.ReadFile(cfg)
	if !bytes.Equal(first, second) {
		t.Fatal("existing configuration was modified")
	}
}

func TestNewCreatesStarterAndRefusesNonEmptyFolder(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "starter")
	if _, stderr, code := runCLI(t, "new", dir); code != exitOK {
		t.Fatalf("new failed: %s", stderr)
	}
	for _, want := range []string{".agentgov.yaml", "tools/run_governance_tests.py", "tests/governance"} {
		if _, err := os.Stat(filepath.Join(dir, filepath.FromSlash(want))); err != nil {
			t.Errorf("starter is missing %s", want)
		}
	}
	if _, err := os.Stat(filepath.Join(dir, ".agentgov", "evidence")); err == nil {
		t.Error("evidence must not be copied; it has to be produced by running the tests")
	}
	// Without test evidence the starter still scans, at implementation level.
	out, _, code := runCLI(t, "scan", dir, "--summary-only", "--no-color")
	if code == exitError {
		t.Fatalf("scan of the fresh starter errored:\n%s", out)
	}
	if _, _, code := runCLI(t, "new", dir); code != exitError {
		t.Fatal("new should refuse a non-empty folder")
	}
}

func TestExplainAcceptsShortIDs(t *testing.T) {
	for _, id := range []string{"AGC-010", "agc-010", "10", "010"} {
		out, _, code := runCLI(t, "explain", id)
		if code != exitOK || !strings.Contains(out, "AGC-010") {
			t.Errorf("explain %q failed", id)
		}
	}
	if _, _, code := runCLI(t, "explain", "AGC-099"); code != exitError {
		t.Error("unknown control should be an error")
	}
}

func TestUploadRefusesPlainHTTPToRemoteHost(t *testing.T) {
	t.Setenv("AGENTGOV_TOKEN", "agt_test_token")
	_, err := uploadResult(context.Background(), &model.ScanResult{}, "http://example.invalid", "AGENTGOV_TOKEN", false)
	if err == nil || !strings.Contains(err.Error(), "plain HTTP") {
		t.Fatalf("expected refusal, got %v", err)
	}
	t.Setenv("AGENTGOV_TOKEN", "")
	if _, err := uploadResult(context.Background(), &model.ScanResult{}, "https://example.invalid", "AGENTGOV_TOKEN", false); err == nil {
		t.Fatal("expected an error when the token variable is empty")
	}
}
