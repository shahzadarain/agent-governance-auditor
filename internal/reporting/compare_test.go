// SPDX-License-Identifier: Apache-2.0

package reporting

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"

	"github.com/shahzadarain/agent-governance-auditor/internal/model"
	"github.com/shahzadarain/agent-governance-auditor/internal/reporting/reportingtest"
)

// afterFix returns the blocked sample after one fix and one regression: the
// hardcoded secret is gone and a new finding has appeared.
func afterFix() *model.ScanResult {
	res := reportingtest.Blocked()
	res.Scan.CommitSHA = "9e8d7c6b5a4f3e2d1c0b9a8f7e6d5c4b3a291807"
	var kept []model.Finding
	for _, f := range res.Findings {
		if f.RuleID != "AGC-008.hardcoded-secret" {
			kept = append(kept, f)
		}
	}
	kept = append(kept, model.Finding{
		FindingID:   "f-aaaabbbbcccc",
		Fingerprint: "aaaabbbbccccddddeeeeffff00001111",
		RuleID:      "AGC-012.no-step-limit",
		ControlID:   "AGC-012",
		AgentID:     "finance-processing-agent",
		Severity:    model.SeverityMedium,
		Confidence:  model.ConfidenceMedium,
		Title:       "Agent loop has no step limit",
		Location:    &model.Location{Path: "src/agent/graph.py", Line: 57},
	})
	res.Findings = kept
	for i := range res.Assessments[0].Controls {
		c := &res.Assessments[0].Controls[i]
		switch c.ControlID {
		case "AGC-008":
			c.Status, c.Maturity = model.StatusVerifiedImplementation, 2
		case "AGC-012":
			c.Status, c.Maturity = model.StatusVerifiedTested, 3
		}
	}
	v := *res.Score.Value + 4
	res.Score.Value = &v
	return res
}

func renderComparison(t *testing.T, c *model.Comparison, format string, opts Options) string {
	t.Helper()
	var buf bytes.Buffer
	if err := RenderComparison(&buf, c, format, opts); err != nil {
		t.Fatalf("RenderComparison(%s): %v", format, err)
	}
	return buf.String()
}

func TestCompare(t *testing.T) {
	before, after := reportingtest.Blocked(), afterFix()
	c := Compare(before, after)
	if !c.Comparable || c.NotComparableWhy != "" {
		t.Fatalf("scans with the same policy and profile must be comparable: %q", c.NotComparableWhy)
	}
	if len(c.NewFindings) != 1 || c.NewFindings[0].RuleID != "AGC-012.no-step-limit" {
		t.Errorf("new findings = %+v", c.NewFindings)
	}
	if len(c.ResolvedFindings) != 1 || c.ResolvedFindings[0].RuleID != "AGC-008.hardcoded-secret" {
		t.Errorf("resolved findings = %+v", c.ResolvedFindings)
	}
	if c.UnchangedCount != 7 {
		t.Errorf("unchanged = %d, want 7", c.UnchangedCount)
	}
	want := []model.ControlChange{
		{ControlID: "AGC-008", AgentID: "finance-processing-agent", BeforeStatus: model.StatusFailed, AfterStatus: model.StatusVerifiedImplementation, BeforeMaturity: 0, AfterMaturity: 2},
		{ControlID: "AGC-012", AgentID: "finance-processing-agent", BeforeStatus: model.StatusVerifiedOperational, AfterStatus: model.StatusVerifiedTested, BeforeMaturity: 4, AfterMaturity: 3},
	}
	if len(c.ControlChanges) != len(want) {
		t.Fatalf("control changes = %+v", c.ControlChanges)
	}
	for i := range want {
		if c.ControlChanges[i] != want[i] {
			t.Errorf("control change %d = %+v, want %+v", i, c.ControlChanges[i], want[i])
		}
	}
	if c.BeforeCommit != before.Scan.CommitSHA || c.AfterCommit != after.Scan.CommitSHA {
		t.Error("commits are not carried over")
	}
	if c.BeforeDecision != model.OutcomeBlock || c.AfterDecision != model.OutcomeBlock {
		t.Error("decisions are not carried over")
	}

	// Identical scans: nothing new, nothing resolved.
	same := Compare(before, reportingtest.Blocked())
	if len(same.NewFindings) != 0 || len(same.ResolvedFindings) != 0 || same.UnchangedCount != 8 || len(same.ControlChanges) != 0 {
		t.Errorf("identical scans differ: %+v", same)
	}

	// Findings match by fingerprint, not by position or location.
	moved := reportingtest.Blocked()
	moved.Findings[0].Location.Line = 99
	moved.Findings[0], moved.Findings[3] = moved.Findings[3], moved.Findings[0]
	if m := Compare(before, moved); len(m.NewFindings) != 0 || len(m.ResolvedFindings) != 0 {
		t.Error("a finding that moved to another line must stay matched by fingerprint")
	}
}

func TestCompareNotComparable(t *testing.T) {
	cases := map[string]func(r *model.ScanResult){
		"policy version": func(r *model.ScanResult) { r.Scan.PolicyVersion = "2.0" },
		"policy pack":    func(r *model.ScanResult) { r.Scan.PolicyPack = "custom/v3" },
		"profile":        func(r *model.ScanResult) { r.Scan.Profile = "baseline" },
	}
	for name, change := range cases {
		after := afterFix()
		change(after)
		c := Compare(reportingtest.Blocked(), after)
		if c.Comparable {
			t.Errorf("%s: scans must not be comparable", name)
		}
		if !strings.Contains(c.NotComparableWhy, name) {
			t.Errorf("%s: reason %q does not name the cause", name, c.NotComparableWhy)
		}
		if len(c.NewFindings) != 1 || len(c.ResolvedFindings) != 1 {
			t.Errorf("%s: finding changes must still be listed", name)
		}
		for _, f := range []string{FormatTerminal, FormatMarkdown} {
			out := renderComparison(t, c, f, Options{})
			if numericScore.MatchString(out) {
				t.Errorf("%s/%s: a score is shown for scans that are not comparable:\n%s", name, f, out)
			}
			if strings.Contains(out, "(up ") || strings.Contains(out, "(down ") {
				t.Errorf("%s/%s: a score trend is shown for scans that are not comparable", name, f)
			}
			if !strings.Contains(out, "not comparable") || !strings.Contains(out, name) {
				t.Errorf("%s/%s: output does not say why the scans are not comparable:\n%s", name, f, out)
			}
			if !strings.Contains(out, "Agent loop has no step limit") {
				t.Errorf("%s/%s: new findings are not listed", name, f)
			}
		}
	}
}

func TestRenderComparison(t *testing.T) {
	c := Compare(reportingtest.Blocked(), afterFix())
	term := renderComparison(t, c, FormatTerminal, Options{})
	for _, want := range []string{
		"AgentGov Auditor - Scan comparison",
		"Commits:  4f9c2d7 -> 9e8d7c6",
		"Decision: BLOCK -> BLOCK",
		"(up 4) (illustrative only)",
		"Findings: 1 new, 1 resolved, 7 unchanged",
		"New findings",
		"[x] MEDIUM AGC-012 Agent loop has no step limit",
		"Where: src/agent/graph.py:57",
		"Resolved findings",
		"[ok] CRITICAL AGC-008 Credential written in source code",
		"AGC-008  Failed (0/4) -> Implemented (not yet tested) (2/4)",
		"AGC-012  Verified in operation (4/4) -> Verified by tests (3/4)",
	} {
		if !strings.Contains(term, want) {
			t.Errorf("terminal comparison is missing %q:\n%s", want, term)
		}
	}
	if strings.ContainsRune(term, 0x1b) {
		t.Error("comparison without color contains an ESC byte")
	}
	colored := renderComparison(t, c, FormatTerminal, Options{Color: true})
	if sgr.ReplaceAllString(colored, "") != term {
		t.Error("colored comparison differs from plain output in more than color")
	}
	golden(t, "compare.terminal.txt", term)

	md := renderComparison(t, c, FormatMarkdown, Options{})
	for _, want := range []string{
		"## AgentGov Auditor scan comparison",
		"| Release decision | BLOCK | BLOCK |",
		"| Assessment maturity (illustrative only) |",
		"**Findings:** 1 new, 1 resolved, 7 unchanged",
		"### New findings",
		"### Resolved findings",
		"### Control changes",
		Disclaimer,
	} {
		if !strings.Contains(md, want) {
			t.Errorf("markdown comparison is missing %q", want)
		}
	}
	golden(t, "compare.md", md)

	js := renderComparison(t, c, FormatJSON, Options{})
	var back model.Comparison
	if err := json.Unmarshal([]byte(js), &back); err != nil {
		t.Fatalf("comparison JSON does not decode: %v", err)
	}
	if !back.Comparable || len(back.NewFindings) != 1 || back.UnchangedCount != 7 || len(back.ControlChanges) != 2 {
		t.Errorf("comparison JSON lost data: %+v", back)
	}
	if !strings.HasSuffix(js, "}\n") || !strings.Contains(js, "\n  \"comparable\": true") {
		t.Error("comparison JSON is not indented with two spaces and a trailing newline")
	}
	golden(t, "compare.json", js)

	for _, f := range ComparisonFormats() {
		if renderComparison(t, c, f, Options{}) != renderComparison(t, c, f, Options{}) {
			t.Errorf("%s: comparison output is not deterministic", f)
		}
	}
}

func TestRenderComparisonErrors(t *testing.T) {
	var buf bytes.Buffer
	c := Compare(reportingtest.Blocked(), afterFix())
	err := RenderComparison(&buf, c, FormatHTML, Options{})
	if err == nil {
		t.Fatal("expected an error for an unsupported comparison format")
	}
	for _, f := range ComparisonFormats() {
		if !strings.Contains(err.Error(), f) {
			t.Errorf("error %q does not list %q", err, f)
		}
	}
	if err := RenderComparison(&buf, nil, FormatJSON, Options{}); err == nil {
		t.Error("expected an error for a nil comparison")
	}
	if buf.Len() != 0 {
		t.Error("output was written although rendering failed")
	}
}

func TestCompareHandlesNilAndEmpty(t *testing.T) {
	c := Compare(nil, reportingtest.Blocked())
	if len(c.NewFindings) != 8 || len(c.ResolvedFindings) != 0 || c.UnchangedCount != 0 {
		t.Errorf("comparison against nothing: %d new, %d resolved", len(c.NewFindings), len(c.ResolvedFindings))
	}
	if c.Comparable {
		t.Error("a scan cannot be compared with an empty result that has no policy")
	}
	empty := Compare(nil, nil)
	js := renderComparison(t, empty, FormatJSON, Options{})
	for _, want := range []string{`"new_findings": []`, `"resolved_findings": []`, `"control_changes": []`} {
		if !strings.Contains(js, want) {
			t.Errorf("empty comparison JSON is missing %s", want)
		}
	}
	for _, f := range []string{FormatTerminal, FormatMarkdown} {
		if out := renderComparison(t, empty, f, Options{}); numericScore.MatchString(out) {
			t.Errorf("%s: an empty comparison shows a numeric score", f)
		}
	}
}

func TestComparisonEscapesHostileContent(t *testing.T) {
	for name, res := range hostileResults() {
		c := Compare(reportingtest.NoAgent(), res)
		before, _ := json.Marshal(c)
		term := renderComparison(t, c, FormatTerminal, Options{Color: true})
		if strings.ContainsRune(sgr.ReplaceAllString(term, ""), 0x1b) || strings.Contains(term, "\r") {
			t.Errorf("%s: terminal comparison carries an injected escape or carriage return", name)
		}
		md := renderComparison(t, c, FormatMarkdown, Options{})
		for _, raw := range []string{"<script", "<!--", "```", "](", "\x1b", "\r"} {
			if strings.Contains(md, raw) {
				t.Errorf("%s: markdown comparison contains raw %q", name, raw)
			}
		}
		renderComparison(t, c, FormatJSON, Options{})
		if after, _ := json.Marshal(c); !bytes.Equal(before, after) {
			t.Errorf("%s: rendering changed the comparison", name)
		}
	}
}
