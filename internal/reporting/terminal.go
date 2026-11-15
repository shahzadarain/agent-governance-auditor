// SPDX-License-Identifier: Apache-2.0

package reporting

import (
	"bytes"
	"fmt"
	"strings"
	"unicode/utf8"

	"github.com/shahzadarain/agent-governance-auditor/internal/model"
)

// ANSI SGR codes. They are written only when Options.Color is true.
const (
	sgrReset  = "\x1b[0m"
	sgrBold   = "\x1b[1m"
	sgrDim    = "\x1b[2m"
	sgrRed    = "\x1b[31m"
	sgrGreen  = "\x1b[32m"
	sgrYellow = "\x1b[33m"
	sgrCyan   = "\x1b[36m"
)

// maxSummaryReasons bounds the reasons shown in the short summary.
const maxSummaryReasons = 3

// term writes wrapped, optionally colored terminal text.
type term struct {
	buf   *bytes.Buffer
	color bool
	width int
}

func (t *term) paint(code, s string) string {
	if !t.color || s == "" {
		return s
	}
	return code + s + sgrReset
}

func (t *term) line(s string) { t.buf.WriteString(s); t.buf.WriteByte('\n') }
func (t *term) blank()        { t.buf.WriteByte('\n') }

func (t *term) heading(s string) { t.line(t.paint(sgrBold+sgrCyan, s)) }

// para writes text wrapped to the terminal width. first is the prefix of the
// first line; continuation lines are indented to the same visible width.
func (t *term) para(first, text string) { t.paraStyled(first, first, "", text) }

// paraStyled is para with color applied after wrapping, so that color never
// changes where lines break. shown is the first-line prefix as written, which
// may contain color codes; first is the same prefix without them. code, when
// not empty, colors the text of every line.
func (t *term) paraStyled(first, shown, code, text string) {
	indent := strings.Repeat(" ", utf8.RuneCountInString(first))
	for i, l := range wrap(text, t.width-len(indent)) {
		if code != "" {
			l = t.paint(code, l)
		}
		if i == 0 {
			t.line(shown + l)
		} else {
			t.line(indent + l)
		}
	}
}

func renderTerminal(buf *bytes.Buffer, raw *model.ScanResult, opts Options) error {
	v, err := buildView(raw)
	if err != nil {
		return err
	}
	width := opts.Width
	if width <= 0 {
		width = DefaultWidth
	}
	if width < 40 {
		width = 40
	}
	t := &term{buf: buf, color: opts.Color, width: width}

	t.paraStyled("", "", sgrBold, v.toolName+" "+v.toolVersion+" - Local assessment")
	if opts.SummaryOnly {
		t.termSummary(v)
		return nil
	}

	t.para("Target:   ", v.target)
	t.para("Commit:   ", v.commit)
	t.para("Profile:  ", fmt.Sprintf("%s (%s)", v.profile, v.profileHow))
	t.para("Policy:   ", v.policy)
	t.para("Offline:  ", v.offline)
	t.blank()

	t.termAgents(v)
	t.termScore(v)
	t.blank()
	t.termDecision(v)
	t.blank()

	if top := v.topPriority(); len(top) > 0 {
		t.heading("What to fix first")
		for _, p := range top {
			t.termPriority(v, p)
		}
		if extra := len(v.priority) - len(top); extra > 0 {
			t.para("", fmt.Sprintf("%s need attention. Run with --full to see every control.", plural(extra, "more control", "more controls")))
			t.blank()
		}
	} else if len(v.res.Decision.Reasons) > 0 {
		t.heading("Reasons")
		for _, r := range v.res.Decision.Reasons {
			t.para("  - ", reasonText(r))
		}
		t.blank()
	}

	if v.hasAgents {
		t.termDomains(v)
		if opts.Full {
			t.termMatrix(v)
		}
	}

	t.para("Findings: ", v.severitySummary())
	t.para("Warnings: ", fmt.Sprintf("%d", len(v.res.Warnings)))
	if opts.Full {
		for _, w := range v.res.Warnings {
			t.para("  - ", w)
		}
		if len(v.res.Limitations) > 0 {
			t.line("Limitations of this scan:")
			for _, l := range v.res.Limitations {
				t.para("  - ", l)
			}
		}
	}
	t.blank()

	t.heading("Next:")
	if v.noAgent {
		t.line("  agentgov init")
	}
	if id := v.topBlocker(); id != "" {
		t.line("  agentgov explain " + id)
	}
	if v.hasAgents && !opts.Full {
		t.line("  agentgov scan . --full")
	}
	t.line("  agentgov scan . --format html --output report.html")
	t.blank()
	t.paraStyled("", "", sgrDim, Disclaimer)
	return nil
}

func (t *term) termSummary(v *view) {
	t.para("Target: ", fmt.Sprintf("%s | Commit: %s | Profile: %s", v.target, v.commit, v.profile))
	if v.noAgent {
		t.line(noAgentTitle + ". This is not a pass.")
	}
	t.termScoreLine(v)
	t.termDecision(v)
	reasons := v.res.Decision.Reasons
	if len(reasons) == 0 {
		return
	}
	t.line("Reasons:")
	shown := reasons
	if len(shown) > maxSummaryReasons {
		shown = shown[:maxSummaryReasons]
	}
	for _, r := range shown {
		t.para("  - ", reasonText(r))
	}
	if extra := len(reasons) - len(shown); extra > 0 {
		t.line(fmt.Sprintf("  - and %d more", extra))
	}
}

func (t *term) termAgents(v *view) {
	if len(v.agents) == 0 {
		t.heading(noAgentTitle)
		for _, l := range noAgentLines {
			t.para("  ", l)
		}
		t.blank()
		return
	}
	t.heading(fmt.Sprintf("Agents (%d)", len(v.agents)))
	for _, av := range v.agents {
		a := av.Agent
		t.paraStyled("  ", "  ", sgrBold, orDefault(a.Name, a.ID))
		fw := orDefault(a.Framework, model.Unknown)
		if a.FrameworkVersion != "" && a.FrameworkVersion != model.Unknown {
			fw += " " + a.FrameworkVersion
		}
		t.para("    Framework:    ", fw)
		t.para("    Language:     ", orDefault(a.Language, model.Unknown))
		t.para("    Detection:    ", fmt.Sprintf("%s (%s)", detectionLabel(a.Detection), confidenceLabel(a.Confidence)))
		t.para("    Risk tier:    ", riskTierText(a))
		t.para("    Tools:        ", fmt.Sprintf("%d (%d sensitive)", len(a.Tools), av.Sensitive))
		caps := "none detected"
		if len(a.Capabilities) > 0 {
			caps = strings.Join(a.Capabilities, ", ")
		}
		t.para("    Capabilities: ", caps)
		if v.multiAgent && av.Assessment != nil {
			t.para("    Decision:     ", DecisionName(av.Assessment.Decision.Outcome))
		}
	}
	t.blank()
}

func riskTierText(a model.Agent) string {
	declared := orDefault(a.RiskTier, model.Unknown)
	inferred := orDefault(a.InferredRiskTier, model.Unknown)
	if declared == model.Unknown {
		return fmt.Sprintf("not declared (capabilities suggest %s)", inferred)
	}
	if inferred != model.Unknown && inferred != declared {
		return fmt.Sprintf("%s (declared; capabilities suggest %s)", declared, inferred)
	}
	return declared + " (declared)"
}

func (t *term) termScoreLine(v *view) {
	if v.hasScore {
		t.line(fmt.Sprintf("Assessment maturity: %s (%s)", t.paint(sgrBold, v.scoreText), ScoreNote))
	} else {
		t.line("Assessment maturity: " + v.scoreText)
	}
}

func (t *term) termScore(v *view) {
	t.termScoreLine(v)
	if !v.hasAgents {
		t.line("Coverage: no controls were assessed")
		return
	}
	s := v.res.Score
	t.line(fmt.Sprintf("Coverage: %d of %d applicable controls have evidence", s.ControlsWithEvidence, s.ApplicableControls))
	t.line(fmt.Sprintf("Verified by tests: %d%%   Verified in operation: %d%%", s.TestedPercent, s.OperationalPercent))
}

func (t *term) termDecision(v *view) {
	code := sgrYellow
	switch v.outcome {
	case model.OutcomeAllow:
		code = sgrGreen
	case model.OutcomeBlock:
		code = sgrRed
	}
	t.line("Release decision: " + t.paint(sgrBold+code, DecisionName(v.outcome)))
	t.para("  "+outcomeSymbol(v.outcome)+" ", DecisionExplanation(v.outcome))
}

func (t *term) termPriority(v *view, p priorityItem) {
	code := sgrYellow
	if p.Label == labelBlock {
		code = sgrRed
	}
	status := "[" + StatusLabel(p.Control.Status) + "]"
	// The status label is right-aligned, at most at column 84.
	lineWidth := t.width
	if lineWidth > 84 {
		lineWidth = 84
	}
	const indent = "        "
	titleWidth := lineWidth - len(indent) - len(status) - 1
	title := truncate(p.Control.ControlID+" "+p.Control.Title, titleWidth)
	gap := titleWidth - utf8.RuneCountInString(title) + 1
	if gap < 1 {
		gap = 1
	}
	pad := strings.Repeat(" ", gap)
	t.line(t.paint(sgrBold+code, fmt.Sprintf("%-8s", p.Label)) + t.paint(sgrBold, title) + pad + status)
	if p.Control.PlainLanguage != "" {
		t.para(indent, p.Control.PlainLanguage)
	}
	if v.multiAgent {
		t.para(indent+"Agent: ", p.AgentName)
	}
	t.para(indent+"Found: ", p.Found)
	if p.Where != "" {
		t.para(indent+"Where: ", p.Where)
	}
	if p.Fix != "" {
		t.para(indent+"Fix:   ", p.Fix)
	}
	t.blank()
}

func (t *term) termDomains(v *view) {
	t.heading("Controls by domain")
	nameWidth := 0
	for _, d := range v.domains {
		if n := utf8.RuneCountInString(d.Name); n > nameWidth {
			nameWidth = n
		}
	}
	if nameWidth > 34 {
		nameWidth = 34
	}
	if nameWidth < 12 {
		nameWidth = 12
	}
	// Narrow terminals get the counts on a second line.
	stacked := 2+nameWidth+2+len(rollupCounts(v.totals)) > t.width
	row := func(name string, counts [5]int) {
		if stacked {
			t.line("  " + truncate(name, t.width-2))
			t.line("      " + rollupCounts(counts))
			return
		}
		t.line("  " + padRight(truncate(name, nameWidth), nameWidth) + "  " + rollupCounts(counts))
	}
	for _, d := range v.domains {
		row(d.Name, d.Counts)
	}
	row("All controls", v.totals)
	t.para("  ", "Key: [ok] verified, [!] partial, [?] unknown, [x] failed or missing, [-] not applicable")
	t.blank()
}

func rollupCounts(counts [5]int) string {
	parts := make([]string, 0, 5)
	for _, r := range Rollups() {
		parts = append(parts, fmt.Sprintf("%-4s %-2d", r.Symbol(), counts[r]))
	}
	return strings.TrimRight(strings.Join(parts, " "), " ")
}

func (t *term) termMatrix(v *view) {
	for _, av := range v.agents {
		if av.Assessment == nil {
			continue
		}
		title := fmt.Sprintf("All %d controls", len(av.Assessment.Controls))
		if v.multiAgent {
			title += " for " + orDefault(av.Agent.Name, av.Agent.ID)
		}
		t.heading(title)
		t.para("  ", "Maturity runs from 0 (no credited evidence) to 4 (verified in operation). M marks a mandatory control.")
		for _, d := range av.Domains {
			t.line("  " + t.paint(sgrBold, d.Name))
			for _, c := range d.Controls {
				r := RollupOf(c.Status)
				mark := " "
				if c.Mandatory {
					mark = "M"
				}
				code := sgrDim
				switch r {
				case RollupVerified:
					code = sgrGreen
				case RollupPartial, RollupUnknown:
					code = sgrYellow
				case RollupFailed:
					code = sgrRed
				}
				sym := t.paint(code, fmt.Sprintf("%-4s", r.Symbol()))
				id := padRight(truncate(c.ControlID, 12), 7)
				idWidth := utf8.RuneCountInString(id)
				if t.width < 72 {
					// Narrow terminals: title on one line, status below.
					t.line(fmt.Sprintf("    %s %s %s  %s", sym, mark, id, truncate(c.Title, t.width-14-idWidth)))
					t.line(fmt.Sprintf("             %s, maturity %s", StatusLabel(c.Status), maturityText(&c)))
					continue
				}
				titleWidth := t.width - 53 - idWidth
				if titleWidth > 36 {
					titleWidth = 36
				}
				row := fmt.Sprintf("    %s %s %s  %s  %s  %s",
					sym, mark, id,
					padRight(truncate(c.Title, titleWidth), titleWidth),
					padRight(StatusLabel(c.Status), 28),
					maturityText(&c))
				t.line(strings.TrimRight(row, " "))
			}
		}
		t.blank()
	}
}

func reasonText(r model.Reason) string {
	msg := orDefault(r.Message, r.Code)
	if r.ControlID != "" && !strings.Contains(msg, r.ControlID) {
		return r.ControlID + ": " + msg
	}
	return msg
}

// wrap splits text into lines of at most width runes, breaking at spaces.
// Words longer than the width are split.
func wrap(text string, width int) []string {
	if width < 10 {
		width = 10
	}
	words := strings.Fields(text)
	if len(words) == 0 {
		return []string{""}
	}
	var lines []string
	var cur []rune
	flush := func() {
		lines = append(lines, string(cur))
		cur = cur[:0]
	}
	for _, w := range words {
		rs := []rune(w)
		for len(rs) > width {
			if len(cur) > 0 {
				flush()
			}
			lines = append(lines, string(rs[:width]))
			rs = rs[width:]
		}
		if len(cur) > 0 && len(cur)+1+len(rs) > width {
			flush()
		}
		if len(cur) > 0 {
			cur = append(cur, ' ')
		}
		cur = append(cur, rs...)
	}
	if len(cur) > 0 {
		flush()
	}
	return lines
}

func truncate(s string, n int) string {
	if n < 4 {
		n = 4
	}
	rs := []rune(s)
	if len(rs) <= n {
		return s
	}
	return string(rs[:n-3]) + "..."
}

func padRight(s string, n int) string {
	if d := n - utf8.RuneCountInString(s); d > 0 {
		return s + strings.Repeat(" ", d)
	}
	return s
}
