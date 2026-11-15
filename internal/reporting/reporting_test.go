// SPDX-License-Identifier: Apache-2.0

package reporting

import (
	"bytes"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"regexp"
	"strings"
	"testing"
	"unicode/utf8"

	"github.com/shahzadarain/agent-governance-auditor/internal/model"
	"github.com/shahzadarain/agent-governance-auditor/internal/reporting/reportingtest"
)

var update = flag.Bool("update", false, "rewrite golden files and the JSON schema")

type sample struct {
	name string
	make func() *model.ScanResult
}

var samples = []sample{
	{"blocked", reportingtest.Blocked},
	{"allowed", reportingtest.Allowed},
	{"noagent", reportingtest.NoAgent},
	{"hostile", reportingtest.Hostile},
}

func render(t *testing.T, res *model.ScanResult, format string, opts Options) string {
	t.Helper()
	var buf bytes.Buffer
	if err := Render(&buf, res, format, opts); err != nil {
		t.Fatalf("Render(%s): %v", format, err)
	}
	return buf.String()
}

// golden compares got with testdata/name, or rewrites the file with -update.
// Line endings in the stored file are normalized so that a checkout with
// automatic CRLF conversion does not break the comparison.
func golden(t *testing.T, name, got string) {
	t.Helper()
	path := filepath.Join("testdata", name)
	if *update {
		if err := os.MkdirAll("testdata", 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, []byte(got), 0o644); err != nil {
			t.Fatal(err)
		}
		return
	}
	want, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read golden file (run the tests with -update to create it): %v", err)
	}
	if w := strings.ReplaceAll(string(want), "\r\n", "\n"); w != got {
		t.Errorf("%s differs from the golden file. Run the tests with -update after checking the change.\n%s", name, firstDiff(w, got))
	}
}

func firstDiff(want, got string) string {
	wl, gl := strings.Split(want, "\n"), strings.Split(got, "\n")
	for i := 0; i < len(wl) || i < len(gl); i++ {
		var w, g string
		if i < len(wl) {
			w = wl[i]
		}
		if i < len(gl) {
			g = gl[i]
		}
		if w != g {
			return fmt.Sprintf("first difference at line %d:\n  want: %q\n  got:  %q", i+1, w, g)
		}
	}
	return "no line difference found"
}

func TestFormats(t *testing.T) {
	want := []string{"terminal", "json", "markdown", "html", "sarif"}
	if got := Formats(); !reflect.DeepEqual(got, want) {
		t.Fatalf("Formats() = %v, want %v", got, want)
	}
}

func TestEveryFormatRendersEverySample(t *testing.T) {
	for _, s := range samples {
		for _, f := range Formats() {
			t.Run(s.name+"/"+f, func(t *testing.T) {
				out := render(t, s.make(), f, Options{})
				if len(out) == 0 {
					t.Fatal("empty output")
				}
				if !strings.HasSuffix(out, "\n") {
					t.Error("output does not end with a newline")
				}
				if !utf8.ValidString(out) {
					t.Error("output is not valid UTF-8")
				}
			})
		}
	}
}

func TestRenderIsDeterministic(t *testing.T) {
	variants := []Options{{}, {Full: true}, {Color: true, Full: true}, {SummaryOnly: true}, {Width: 60, Full: true}}
	for _, s := range samples {
		for _, f := range Formats() {
			for i, o := range variants {
				a := render(t, s.make(), f, o)
				b := render(t, s.make(), f, o)
				if a != b {
					t.Errorf("%s/%s variant %d: two renders differ", s.name, f, i)
				}
			}
		}
	}
}

func TestRenderDoesNotModifyInput(t *testing.T) {
	for _, s := range samples {
		res := s.make()
		before, err := json.Marshal(res)
		if err != nil {
			t.Fatal(err)
		}
		for _, f := range Formats() {
			render(t, res, f, Options{Full: true})
		}
		after, _ := json.Marshal(res)
		if !bytes.Equal(before, after) {
			t.Errorf("%s: rendering changed the scan result", s.name)
		}
	}
}

func TestUnknownFormat(t *testing.T) {
	var buf bytes.Buffer
	err := Render(&buf, reportingtest.Blocked(), "pdf\x1b[2J", Options{})
	if err == nil {
		t.Fatal("expected an error for an unknown format")
	}
	msg := err.Error()
	for _, f := range Formats() {
		if !strings.Contains(msg, f) {
			t.Errorf("error %q does not list the valid format %q", msg, f)
		}
	}
	if strings.ContainsRune(msg, 0x1b) {
		t.Error("error message carries an escape character from the input")
	}
	if buf.Len() != 0 {
		t.Error("output was written for an unknown format")
	}
	if err := Render(&buf, nil, FormatJSON, Options{}); err == nil {
		t.Error("expected an error for a nil scan result")
	}
}

func TestGoldenFiles(t *testing.T) {
	for _, s := range samples {
		golden(t, s.name+".terminal.txt", render(t, s.make(), FormatTerminal, Options{}))
		golden(t, s.name+".md", render(t, s.make(), FormatMarkdown, Options{}))
		golden(t, s.name+".sarif.json", render(t, s.make(), FormatSARIF, Options{}))
		golden(t, s.name+".json", render(t, s.make(), FormatJSON, Options{}))
	}
	golden(t, "blocked.terminal-full.txt", render(t, reportingtest.Blocked(), FormatTerminal, Options{Full: true}))
	golden(t, "blocked.terminal-summary.txt", render(t, reportingtest.Blocked(), FormatTerminal, Options{SummaryOnly: true}))
}

func TestTerminalWithoutColorHasNoEscapeBytes(t *testing.T) {
	for _, s := range samples {
		for _, o := range []Options{{}, {Full: true}, {SummaryOnly: true}} {
			out := render(t, s.make(), FormatTerminal, o)
			if strings.ContainsRune(out, 0x1b) {
				t.Errorf("%s: output without color contains an ESC byte", s.name)
			}
		}
	}
}

var sgr = regexp.MustCompile(`\x1b\[(0|1|2|31|32|33|36)m`)

func TestTerminalColorUsesOnlyKnownSequences(t *testing.T) {
	for _, s := range samples {
		colored := render(t, s.make(), FormatTerminal, Options{Color: true, Full: true})
		if !strings.ContainsRune(colored, 0x1b) {
			t.Fatalf("%s: colored output has no escape sequences", s.name)
		}
		stripped := sgr.ReplaceAllString(colored, "")
		if strings.ContainsRune(stripped, 0x1b) {
			t.Errorf("%s: colored output contains an escape sequence that the renderer did not write", s.name)
		}
		// Color is decoration only: the text is the same without it.
		if plain := render(t, s.make(), FormatTerminal, Options{Full: true}); stripped != plain {
			t.Errorf("%s: colored output differs from plain output in more than color\n%s", s.name, firstDiff(plain, stripped))
		}
	}
}

func TestTerminalContent(t *testing.T) {
	out := render(t, reportingtest.Blocked(), FormatTerminal, Options{})
	for _, want := range []string{
		"AgentGov Auditor 0.1.0 - Local assessment",
		"Target:   vulnerable-agent",
		"Commit:   4f9c2d7",
		"Profile:  high-risk (set in the configuration file)",
		"Offline:  yes",
		"finance-processing-agent",
		"Detection:    detected (high confidence)",
		"Tools:        4 (3 sensitive)",
		"(illustrative only)",
		"applicable controls have evidence",
		"Release decision: BLOCK",
		"Do not release until the listed controls are fixed.",
		"A person must approve risky actions before the agent carries them out.",
		"Found: Refunds run without an enforced approval",
		"Where: src/actions.py:86",
		"Fix:   Require an external approval bound to the actor, the exact action, and an expiry",
		"[Failed]",
		"Findings: 3 critical, 2 high, 2 medium, 1 low, 0 info",
		"Warnings: 2",
		"agentgov explain AGC-",
		"agentgov scan . --format html --output report.html",
		Disclaimer,
	} {
		if !strings.Contains(out, want) {
			t.Errorf("terminal output is missing %q", want)
		}
	}
	if n := strings.Count(out, "\n        Found: "); n != maxPriority {
		t.Errorf("priority items = %d, want %d", n, maxPriority)
	}
	// Mandatory blockers come first, the most severe first.
	first := strings.Index(out, "BLOCK   ")
	review := strings.Index(out, "REVIEW  ")
	warn := strings.Index(out, "WARN    ")
	if first < 0 {
		t.Fatal("no BLOCK item")
	}
	if review >= 0 && review < first || warn >= 0 && warn < first {
		t.Error("a REVIEW or WARN item is listed before the first BLOCK item")
	}
	if !regexp.MustCompile(`(?m)^BLOCK   AGC-007 `).MatchString(out) {
		t.Error("the first blockers should include the critical control AGC-007")
	}
	for _, word := range []string{"compliance", "compliant", "certified", "probability"} {
		if strings.Contains(strings.ToLower(out), word) {
			t.Errorf("terminal output uses the word %q", word)
		}
	}
}

func TestPriorityOrderAndLabels(t *testing.T) {
	v, err := buildView(reportingtest.Blocked())
	if err != nil {
		t.Fatal(err)
	}
	got := map[string]string{}
	lastRank, lastSev := 0, 0
	for _, p := range v.priority {
		got[p.Control.ControlID] = p.Label
		r := labelRank(p.Label)
		if r < lastRank {
			t.Errorf("%s: label order is wrong", p.Control.ControlID)
		}
		if r > lastRank {
			lastSev = 0
		}
		if s := severityRank(p.Severity); s < lastSev {
			t.Errorf("%s: severity order is wrong inside label %s", p.Control.ControlID, p.Label)
		} else {
			lastSev = s
		}
		lastRank = r
	}
	want := map[string]string{
		"AGC-001": labelBlock,  // mandatory, below the required maturity
		"AGC-004": labelBlock,  // mandatory, failed
		"AGC-007": labelBlock,  // mandatory, failed
		"AGC-008": labelBlock,  // mandatory, failed
		"AGC-009": labelBlock,  // mandatory, missing
		"AGC-010": labelBlock,  // mandatory, failed
		"AGC-020": labelBlock,  // mandatory, assessment error
		"AGC-013": labelReview, // mandatory, accepted risk
		"AGC-005": labelWarn,   // verified, but has an open finding
		"AGC-014": labelWarn,   // not mandatory, missing
		"AGC-023": labelWarn,   // not mandatory, missing
	}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("priority labels = %v\nwant %v", got, want)
	}

	allowed, err := buildView(reportingtest.Allowed())
	if err != nil {
		t.Fatal(err)
	}
	for _, p := range allowed.priority {
		if p.Label != labelWarn {
			t.Errorf("allowed sample: %s has label %s, want WARN", p.Control.ControlID, p.Label)
		}
	}
}

func TestReviewWorkflowTurnsShortfallsIntoReviews(t *testing.T) {
	res := reportingtest.Blocked()
	as := &res.Assessments[0]
	as.Decision.Outcome = model.OutcomeReviewRequired
	res.Decision.Outcome = model.OutcomeReviewRequired
	v, err := buildView(res)
	if err != nil {
		t.Fatal(err)
	}
	for _, p := range v.priority {
		if p.Label == labelBlock {
			t.Errorf("%s is labelled BLOCK although the agent decision is REVIEW_REQUIRED", p.Control.ControlID)
		}
	}
}

func TestAllControlsAppearInFullOutputs(t *testing.T) {
	for _, s := range samples {
		if s.name == "noagent" {
			continue
		}
		res := s.make()
		outputs := map[string]string{
			"terminal": render(t, res, FormatTerminal, Options{Full: true}),
			"markdown": render(t, res, FormatMarkdown, Options{}),
			"html":     render(t, res, FormatHTML, Options{}),
			"json":     render(t, res, FormatJSON, Options{}),
		}
		for format, out := range outputs {
			for i := 1; i <= 24; i++ {
				id := fmt.Sprintf("AGC-%03d", i)
				if !strings.Contains(out, id) {
					t.Errorf("%s/%s: control %s is missing", s.name, format, id)
				}
			}
		}
	}
}

func TestEveryStatusLabelAppears(t *testing.T) {
	res := reportingtest.Blocked()
	seen := map[model.Status]bool{}
	for _, c := range res.Assessments[0].Controls {
		seen[c.Status] = true
	}
	if len(seen) != 10 {
		t.Fatalf("the blocked sample covers %d statuses, want all 10", len(seen))
	}
	outputs := map[string]string{
		"terminal": render(t, res, FormatTerminal, Options{Full: true}),
		"markdown": render(t, res, FormatMarkdown, Options{}),
		"html":     render(t, res, FormatHTML, Options{}),
	}
	for _, st := range AllStatuses() {
		for format, out := range outputs {
			if !strings.Contains(out, StatusLabel(st)) {
				t.Errorf("%s: status label %q is missing", format, StatusLabel(st))
			}
		}
	}
}

func TestLabels(t *testing.T) {
	statuses := map[model.Status]string{
		model.StatusVerifiedOperational:    "Verified in operation",
		model.StatusVerifiedTested:         "Verified by tests",
		model.StatusVerifiedImplementation: "Implemented (not yet tested)",
		model.StatusDeclaredOnly:           "Declared only",
		model.StatusMissing:                "Missing",
		model.StatusFailed:                 "Failed",
		model.StatusUnknown:                "Unknown (needs evidence)",
		model.StatusNotApplicable:          "Not applicable",
		model.StatusAcceptedRisk:           "Accepted risk",
		model.StatusError:                  "Assessment error",
		model.Status("made-up"):            "Unknown (needs evidence)",
	}
	for st, want := range statuses {
		if got := StatusLabel(st); got != want {
			t.Errorf("StatusLabel(%q) = %q, want %q", st, got, want)
		}
		if StatusMeaning(st) == "" {
			t.Errorf("StatusMeaning(%q) is empty", st)
		}
	}
	decisions := map[model.Outcome]string{
		model.OutcomeAllow:          "ALLOW: the release policy is satisfied",
		model.OutcomeBlock:          "BLOCK: do not release until the listed controls are fixed",
		model.OutcomeReviewRequired: "REVIEW REQUIRED: a person must review before release",
	}
	for o, want := range decisions {
		if got := DecisionLabel(o); got != want {
			t.Errorf("DecisionLabel(%q) = %q, want %q", o, got, want)
		}
	}
	if got := DecisionExplanation(model.OutcomeBlock); got != "Do not release until the listed controls are fixed." {
		t.Errorf("DecisionExplanation(BLOCK) = %q", got)
	}
	if got := DecisionLabel("SHIP_IT"); strings.Contains(got, "ALLOW") || !strings.Contains(got, "do not treat this as a pass") {
		t.Errorf("an unrecognized outcome must not read as a pass: %q", got)
	}
	rollups := map[model.Status]Rollup{
		model.StatusVerifiedOperational:    RollupVerified,
		model.StatusVerifiedTested:         RollupVerified,
		model.StatusVerifiedImplementation: RollupPartial,
		model.StatusDeclaredOnly:           RollupPartial,
		model.StatusAcceptedRisk:           RollupPartial,
		model.StatusUnknown:                RollupUnknown,
		model.StatusFailed:                 RollupFailed,
		model.StatusMissing:                RollupFailed,
		model.StatusError:                  RollupFailed,
		model.StatusNotApplicable:          RollupNotApplicable,
	}
	for st, want := range rollups {
		if got := RollupOf(st); got != want {
			t.Errorf("RollupOf(%q) = %v, want %v", st, got, want)
		}
	}
	if len(AllStatuses()) != 10 {
		t.Errorf("AllStatuses has %d entries, want 10", len(AllStatuses()))
	}
}

var numericScore = regexp.MustCompile(`\d+\s*/\s*100`)

func TestNoAgentIsNotAPass(t *testing.T) {
	res := reportingtest.NoAgent()
	for _, o := range []Options{{}, {Full: true}, {SummaryOnly: true}} {
		for _, f := range []string{FormatTerminal, FormatMarkdown, FormatHTML} {
			out := render(t, res, f, o)
			if strings.Contains(out, "ALLOW") {
				t.Errorf("%s: no-agent output says ALLOW", f)
			}
			if numericScore.MatchString(out) {
				t.Errorf("%s: no-agent output shows a numeric score", f)
			}
			if !strings.Contains(out, noAgentTitle) {
				t.Errorf("%s: no-agent output does not say %q", f, noAgentTitle)
			}
			if !strings.Contains(out, "not a pass") {
				t.Errorf("%s: no-agent output does not say that this is not a pass", f)
			}
			if !strings.Contains(strings.ToLower(out), "insufficient evidence") {
				t.Errorf("%s: no-agent output does not say insufficient evidence", f)
			}
			if !strings.Contains(out, "REVIEW REQUIRED") {
				t.Errorf("%s: no-agent output does not show the review decision", f)
			}
		}
	}
	out := render(t, res, FormatTerminal, Options{})
	if !strings.Contains(out, "agentgov init") {
		t.Error("terminal no-agent output does not explain how to declare an agent")
	}

	// A numeric score value is never shown without an assessed agent, even
	// when a producer sets one by mistake.
	wrong := reportingtest.NoAgent()
	n := 100
	wrong.Score.Value = &n
	wrong.Score.Label = "100/100"
	for _, f := range []string{FormatTerminal, FormatMarkdown, FormatHTML} {
		if numericScore.MatchString(render(t, wrong, f, Options{})) {
			t.Errorf("%s: a score is shown although no agent was assessed", f)
		}
	}
}

func TestScoreIsLabelledIllustrative(t *testing.T) {
	for _, s := range []sample{samples[0], samples[1]} {
		for _, f := range []string{FormatTerminal, FormatMarkdown, FormatHTML} {
			out := render(t, s.make(), f, Options{})
			if !numericScore.MatchString(out) {
				t.Errorf("%s/%s: no numeric score", s.name, f)
			}
			if !strings.Contains(out, ScoreNote) {
				t.Errorf("%s/%s: the score is not labelled %q", s.name, f, ScoreNote)
			}
		}
	}
}

func TestSummaryOnlyIsShort(t *testing.T) {
	out := render(t, reportingtest.Blocked(), FormatTerminal, Options{SummaryOnly: true})
	lines := strings.Split(strings.TrimRight(out, "\n"), "\n")
	if len(lines) < 5 || len(lines) > 10 {
		t.Errorf("summary has %d lines, want about 8:\n%s", len(lines), out)
	}
	for _, want := range []string{"Local assessment", "Assessment maturity:", "Release decision: BLOCK", "Reasons:", "and 5 more"} {
		if !strings.Contains(out, want) {
			t.Errorf("summary is missing %q", want)
		}
	}
	if strings.Contains(out, "What to fix first") {
		t.Error("summary contains the priority list")
	}
}

func TestTerminalWrapsToWidth(t *testing.T) {
	for _, s := range samples {
		for _, width := range []int{0, 60, 80, 120} {
			limit := width
			if limit == 0 {
				limit = DefaultWidth
			}
			out := render(t, s.make(), FormatTerminal, Options{Full: true, Width: width})
			for i, line := range strings.Split(out, "\n") {
				if n := utf8.RuneCountInString(line); n > limit {
					t.Errorf("%s width %d: line %d has %d characters: %q", s.name, width, i+1, n, line)
				}
			}
		}
	}
}

func TestTerminalIsASCIIForTrustedSamples(t *testing.T) {
	for _, s := range samples[:3] {
		out := render(t, s.make(), FormatTerminal, Options{Full: true})
		for i := 0; i < len(out); i++ {
			if out[i] >= 0x80 {
				t.Fatalf("%s: non-ASCII byte in terminal output near %q", s.name, out[max(0, i-20):i])
			}
		}
	}
}

func TestMultipleAgents(t *testing.T) {
	res := reportingtest.Blocked()
	other := reportingtest.Allowed()
	res.Agents = append(res.Agents, other.Agents...)
	res.Assessments = append(res.Assessments, other.Assessments...)
	res.Evidence = append(res.Evidence, other.Evidence...)
	res.Findings = append(res.Findings, other.Findings...)
	term := render(t, res, FormatTerminal, Options{Full: true})
	for _, want := range []string{"Agents (2)", "All 24 controls for finance-processing-agent", "All 24 controls for support-triage-agent", "Agent: finance-processing-agent"} {
		if !strings.Contains(term, want) {
			t.Errorf("terminal output is missing %q", want)
		}
	}
	md := render(t, res, FormatMarkdown, Options{})
	if !strings.Contains(md, "All 48 control results") {
		t.Error("markdown does not report 48 control results")
	}
	html := render(t, res, FormatHTML, Options{})
	if n := strings.Count(html, `<details class="tile`); n != 48 {
		t.Errorf("html has %d control tiles, want 48", n)
	}
	checkBalanced(t, html)
}

func TestJSONRoundTrip(t *testing.T) {
	for _, s := range samples {
		out := render(t, s.make(), FormatJSON, Options{})
		if !strings.HasPrefix(out, "{\n  \"schema_version\": \"1\",") {
			t.Errorf("%s: JSON does not start with a two-space indented schema_version", s.name)
		}
		var back model.ScanResult
		if err := json.Unmarshal([]byte(out), &back); err != nil {
			t.Fatalf("%s: %v", s.name, err)
		}
		want, err := copyResult(s.make())
		if err != nil {
			t.Fatal(err)
		}
		got, _ := copyResult(&back)
		if !reflect.DeepEqual(got, want) {
			t.Errorf("%s: JSON does not round-trip to the same scan result", s.name)
		}
		// HTML escaping stays on, so the document is safe to embed.
		for _, raw := range []string{"<script>", "</script>", "<!--"} {
			if strings.Contains(out, raw) {
				t.Errorf("%s: JSON contains raw %q", s.name, raw)
			}
		}
	}
}

func TestJSONWritesEmptyArraysForNilSlices(t *testing.T) {
	out := render(t, &model.ScanResult{SchemaVersion: model.SchemaVersion}, FormatJSON, Options{})
	if strings.Contains(out, "null") && !strings.Contains(out, `"value": null`) {
		t.Errorf("unexpected null in JSON:\n%s", out)
	}
	for _, want := range []string{`"agents": []`, `"assessments": []`, `"evidence": []`, `"findings": []`, `"warnings": []`, `"limitations": []`, `"reasons": []`, `"findings_by_severity": {}`} {
		if !strings.Contains(out, want) {
			t.Errorf("JSON is missing %s", want)
		}
	}
}

// A suspected agent without an assessment is listed, but nothing is scored
// and the report does not claim that no agent exists.
func TestAgentWithoutAssessment(t *testing.T) {
	res := reportingtest.NoAgent()
	agent := reportingtest.Allowed().Agents[0]
	agent.Detection = model.Suspected
	agent.Confidence = model.ConfidenceLow
	res.Agents = []model.Agent{agent}
	res.Decision.Reasons = []model.Reason{{Code: "suspected-agent-needs-review", Message: "A suspected agent needs a person to confirm it."}}
	for _, f := range []string{FormatTerminal, FormatMarkdown, FormatHTML} {
		out := render(t, res, f, Options{Full: true})
		if strings.Contains(out, noAgentTitle) {
			t.Errorf("%s: output says no agent was detected although one is listed", f)
		}
		if !strings.Contains(out, "support-triage-agent") || !strings.Contains(out, "suspected (low confidence)") {
			t.Errorf("%s: the suspected agent is not listed", f)
		}
		if numericScore.MatchString(out) || strings.Contains(out, "ALLOW") {
			t.Errorf("%s: an unassessed agent must not get a score or an ALLOW", f)
		}
		if !strings.Contains(strings.ToLower(out), "insufficient evidence") {
			t.Errorf("%s: output does not say insufficient evidence", f)
		}
	}
	checkBalanced(t, render(t, res, FormatHTML, Options{}))
}
