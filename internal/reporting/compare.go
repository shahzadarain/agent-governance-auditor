// SPDX-License-Identifier: Apache-2.0

package reporting

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"reflect"
	"sort"
	"strings"

	"github.com/shahzadarain/agent-governance-auditor/internal/model"
)

// Compare returns the difference between two scan results. Findings are
// matched by fingerprint. The result is marked not comparable when the policy
// pack, policy version, or profile differ; finding changes are still listed,
// but a score trend between the two scans would be misleading.
//
// A nil argument is treated as an empty scan result.
func Compare(before, after *model.ScanResult) *model.Comparison {
	if before == nil {
		before = &model.ScanResult{}
	}
	if after == nil {
		after = &model.ScanResult{}
	}
	c := &model.Comparison{
		Comparable:       true,
		BeforeCommit:     orDefault(before.Scan.CommitSHA, model.Unknown),
		AfterCommit:      orDefault(after.Scan.CommitSHA, model.Unknown),
		BeforeScore:      before.Score,
		AfterScore:       after.Score,
		BeforeDecision:   before.Decision.Outcome,
		AfterDecision:    after.Decision.Outcome,
		NewFindings:      []model.Finding{},
		ResolvedFindings: []model.Finding{},
		ControlChanges:   []model.ControlChange{},
	}

	var why []string
	if before.Scan.PolicyPack != after.Scan.PolicyPack {
		why = append(why, fmt.Sprintf("the policy pack changed from %q to %q", before.Scan.PolicyPack, after.Scan.PolicyPack))
	}
	if before.Scan.PolicyVersion != after.Scan.PolicyVersion {
		why = append(why, fmt.Sprintf("the policy version changed from %q to %q", before.Scan.PolicyVersion, after.Scan.PolicyVersion))
	}
	if before.Scan.Profile != after.Scan.Profile {
		why = append(why, fmt.Sprintf("the profile changed from %q to %q", before.Scan.Profile, after.Scan.Profile))
	}
	if len(why) > 0 {
		c.Comparable = false
		c.NotComparableWhy = "The two scans used different rules: " + strings.Join(why, "; ") + ". Scores and decisions are not compared."
	}

	key := func(f *model.Finding) string {
		if f.Fingerprint != "" {
			return f.Fingerprint
		}
		return "id:" + f.FindingID
	}
	beforeKeys := map[string]bool{}
	for i := range before.Findings {
		beforeKeys[key(&before.Findings[i])] = true
	}
	afterKeys := map[string]bool{}
	for i := range after.Findings {
		f := &after.Findings[i]
		k := key(f)
		if afterKeys[k] {
			continue
		}
		afterKeys[k] = true
		if beforeKeys[k] {
			c.UnchangedCount++
		} else {
			c.NewFindings = append(c.NewFindings, *f)
		}
	}
	seen := map[string]bool{}
	for i := range before.Findings {
		f := &before.Findings[i]
		k := key(f)
		if seen[k] {
			continue
		}
		seen[k] = true
		if !afterKeys[k] {
			c.ResolvedFindings = append(c.ResolvedFindings, *f)
		}
	}
	sort.SliceStable(c.NewFindings, func(i, j int) bool { return findingLess(&c.NewFindings[i], &c.NewFindings[j]) })
	sort.SliceStable(c.ResolvedFindings, func(i, j int) bool { return findingLess(&c.ResolvedFindings[i], &c.ResolvedFindings[j]) })

	// Control changes are reported for controls assessed in both scans.
	type ck struct{ agent, control string }
	beforeControls := map[ck]model.ControlResult{}
	for _, as := range before.Assessments {
		for _, cr := range as.Controls {
			beforeControls[ck{as.AgentID, cr.ControlID}] = cr
		}
	}
	for _, as := range after.Assessments {
		for _, cr := range as.Controls {
			b, ok := beforeControls[ck{as.AgentID, cr.ControlID}]
			if !ok || (b.Status == cr.Status && b.Maturity == cr.Maturity) {
				continue
			}
			c.ControlChanges = append(c.ControlChanges, model.ControlChange{
				ControlID:      cr.ControlID,
				AgentID:        as.AgentID,
				BeforeStatus:   b.Status,
				AfterStatus:    cr.Status,
				BeforeMaturity: b.Maturity,
				AfterMaturity:  cr.Maturity,
			})
		}
	}
	sort.SliceStable(c.ControlChanges, func(i, j int) bool {
		a, b := c.ControlChanges[i], c.ControlChanges[j]
		if a.AgentID != b.AgentID {
			return a.AgentID < b.AgentID
		}
		return a.ControlID < b.ControlID
	})
	return c
}

// RenderComparison writes a comparison as terminal text, JSON, or Markdown.
// When the comparison is not comparable, no score trend is shown and the
// reason is stated.
func RenderComparison(w io.Writer, c *model.Comparison, format string, opts Options) error {
	if c == nil {
		return errors.New("reporting: comparison is nil")
	}
	var buf bytes.Buffer
	switch format {
	case FormatJSON:
		cp := copyComparison(c)
		walk(reflect.ValueOf(cp).Elem(), nil)
		if err := writeJSON(&buf, cp); err != nil {
			return fmt.Errorf("reporting: render comparison: %w", err)
		}
	case FormatTerminal:
		compareTerminal(&buf, sanitizeComparison(c), opts)
	case FormatMarkdown:
		compareMarkdown(&buf, sanitizeComparison(c))
	default:
		return unknownFormat(format, ComparisonFormats())
	}
	_, err := w.Write(buf.Bytes())
	return err
}

// sanitizeComparison returns a copy with every string cleaned.
func sanitizeComparison(c *model.Comparison) *model.Comparison {
	cp := copyComparison(c)
	walk(reflect.ValueOf(cp).Elem(), clean)
	return cp
}

// copyComparison copies the findings, control changes, and scores so that
// rendering never modifies the caller's value.
func copyComparison(c *model.Comparison) *model.Comparison {
	cp := *c
	cp.NewFindings = copyFindings(c.NewFindings)
	cp.ResolvedFindings = copyFindings(c.ResolvedFindings)
	cp.ControlChanges = append([]model.ControlChange(nil), c.ControlChanges...)
	cp.BeforeScore = copyScore(c.BeforeScore)
	cp.AfterScore = copyScore(c.AfterScore)
	return &cp
}

func copyFindings(in []model.Finding) []model.Finding {
	out := make([]model.Finding, len(in))
	for i, f := range in {
		f.Remediation = append([]string(nil), f.Remediation...)
		f.EvidenceRefs = append([]string(nil), f.EvidenceRefs...)
		f.Mappings = append([]model.Mapping(nil), f.Mappings...)
		if f.Location != nil {
			l := *f.Location
			f.Location = &l
		}
		out[i] = f
	}
	return out
}

func copyScore(s model.Score) model.Score {
	if s.Value != nil {
		v := *s.Value
		s.Value = &v
	}
	s.UnresolvedMandatory = append([]string(nil), s.UnresolvedMandatory...)
	s.FindingsBySeverity = copyCounts(s.FindingsBySeverity)
	s.StatusCounts = copyCounts(s.StatusCounts)
	return s
}

func copyCounts(m map[string]int) map[string]int {
	out := make(map[string]int, len(m))
	for k, v := range m {
		out[k] = v
	}
	return out
}

func scoreLabel(s model.Score) string {
	if s.Value == nil {
		return "insufficient evidence"
	}
	return fmt.Sprintf("%d/100", clamp(*s.Value, 0, 100))
}

// scoreTrend describes the score change in words. It is used only when the
// two scans are comparable.
func scoreTrend(c *model.Comparison) string {
	b, a := c.BeforeScore.Value, c.AfterScore.Value
	if b == nil || a == nil {
		return fmt.Sprintf("%s -> %s", scoreLabel(c.BeforeScore), scoreLabel(c.AfterScore))
	}
	d := clamp(*a, 0, 100) - clamp(*b, 0, 100)
	switch {
	case d > 0:
		return fmt.Sprintf("%s -> %s (up %d)", scoreLabel(c.BeforeScore), scoreLabel(c.AfterScore), d)
	case d < 0:
		return fmt.Sprintf("%s -> %s (down %d)", scoreLabel(c.BeforeScore), scoreLabel(c.AfterScore), -d)
	default:
		return fmt.Sprintf("%s -> %s (no change)", scoreLabel(c.BeforeScore), scoreLabel(c.AfterScore))
	}
}

func controlChangeText(ch model.ControlChange) string {
	return fmt.Sprintf("%s (%d/4) -> %s (%d/4)",
		StatusLabel(ch.BeforeStatus), clamp(ch.BeforeMaturity, 0, 4),
		StatusLabel(ch.AfterStatus), clamp(ch.AfterMaturity, 0, 4))
}

func multiAgentChanges(changes []model.ControlChange) bool {
	for i := 1; i < len(changes); i++ {
		if changes[i].AgentID != changes[0].AgentID {
			return true
		}
	}
	return false
}

func compareTerminal(buf *bytes.Buffer, c *model.Comparison, opts Options) {
	width := opts.Width
	if width <= 0 {
		width = DefaultWidth
	}
	if width < 40 {
		width = 40
	}
	t := &term{buf: buf, color: opts.Color, width: width}

	t.line(t.paint(sgrBold, "AgentGov Auditor") + " - Scan comparison")
	t.para("Commits:  ", fmt.Sprintf("%s -> %s", shortSHA(c.BeforeCommit), shortSHA(c.AfterCommit)))
	if c.Comparable {
		t.para("Decision: ", fmt.Sprintf("%s -> %s", DecisionName(c.BeforeDecision), DecisionName(c.AfterDecision)))
		t.para("Maturity: ", fmt.Sprintf("%s (%s)", scoreTrend(c), ScoreNote))
	} else {
		t.blank()
		t.line(t.paint(sgrBold+sgrYellow, "[!] These scans are not comparable"))
		t.para("    ", orDefault(c.NotComparableWhy, "The two scans used different rules. Scores and decisions are not compared."))
		t.para("    ", fmt.Sprintf("Before: %s under its own rules. After: %s under its own rules.",
			DecisionName(c.BeforeDecision), DecisionName(c.AfterDecision)))
	}
	t.blank()

	t.line(fmt.Sprintf("Findings: %d new, %d resolved, %d unchanged", len(c.NewFindings), len(c.ResolvedFindings), c.UnchangedCount))
	t.blank()
	list := func(title, mark string, code string, fs []model.Finding) {
		if len(fs) == 0 {
			return
		}
		t.heading(title)
		for _, f := range fs {
			head := fmt.Sprintf("%s %s %s", strings.ToUpper(severityKey(f.Severity)), f.ControlID, f.Title)
			t.paraStyled("  "+mark+" ", "  "+t.paint(code, mark)+" ", "", head)
			if loc := locationText(f.Location); loc != "" {
				t.para("      Where: ", loc)
			}
		}
		t.blank()
	}
	list("New findings", "[x]", sgrRed, c.NewFindings)
	list("Resolved findings", "[ok]", sgrGreen, c.ResolvedFindings)

	if len(c.ControlChanges) > 0 {
		t.heading("Control changes")
		multi := multiAgentChanges(c.ControlChanges)
		for _, ch := range c.ControlChanges {
			prefix := "  " + ch.ControlID + "  "
			if multi {
				prefix = "  " + ch.ControlID + " [" + ch.AgentID + "]  "
			}
			t.para(prefix, controlChangeText(ch))
		}
		t.blank()
	} else {
		t.line("Control changes: none")
		t.blank()
	}
	t.paraStyled("", "", sgrDim, Disclaimer)
}

func compareMarkdown(buf *bytes.Buffer, c *model.Comparison) {
	w := func(format string, args ...any) { fmt.Fprintf(buf, format, args...) }
	w("## AgentGov Auditor scan comparison\n\n")
	w("Commits: %s to %s\n\n", md(shortSHA(c.BeforeCommit)), md(shortSHA(c.AfterCommit)))
	if c.Comparable {
		w("| Measure | Before | After |\n|---|---|---|\n")
		w("| Release decision | %s | %s |\n", DecisionName(c.BeforeDecision), DecisionName(c.AfterDecision))
		w("| Assessment maturity (%s) | %s | %s |\n\n", ScoreNote, scoreLabel(c.BeforeScore), scoreLabel(c.AfterScore))
	} else {
		w("**These scans are not comparable.** %s\n\n",
			md(orDefault(c.NotComparableWhy, "The two scans used different rules. Scores and decisions are not compared.")))
	}
	w("**Findings:** %d new, %d resolved, %d unchanged\n\n", len(c.NewFindings), len(c.ResolvedFindings), c.UnchangedCount)

	table := func(title string, fs []model.Finding) {
		if len(fs) == 0 {
			return
		}
		w("### %s\n\n| Severity | Control | Finding | Location |\n|---|---|---|---|\n", title)
		for _, f := range fs {
			loc := locationText(f.Location)
			if loc == "" {
				loc = "No file location"
			} else {
				loc = md(loc)
			}
			w("| %s | %s | %s | %s |\n", severityLabel(f.Severity), md(f.ControlID), md(f.Title), loc)
		}
		w("\n")
	}
	table("New findings", c.NewFindings)
	table("Resolved findings", c.ResolvedFindings)

	if len(c.ControlChanges) > 0 {
		w("### Control changes\n\n| Control | Agent | Before | After |\n|---|---|---|---|\n")
		for _, ch := range c.ControlChanges {
			w("| %s | %s | %s (%d/4) | %s (%d/4) |\n", md(ch.ControlID), md(ch.AgentID),
				StatusLabel(ch.BeforeStatus), clamp(ch.BeforeMaturity, 0, 4),
				StatusLabel(ch.AfterStatus), clamp(ch.AfterMaturity, 0, 4))
		}
		w("\n")
	}
	w("---\n\n%s\n", Disclaimer)
}
