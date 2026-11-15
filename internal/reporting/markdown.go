// SPDX-License-Identifier: Apache-2.0

package reporting

import (
	"bytes"
	"fmt"
	"strings"

	"github.com/shahzadarain/agent-governance-auditor/internal/model"
)

// maxMarkdownFindings bounds the findings table in the pull request summary.
const maxMarkdownFindings = 10

// md escapes one untrusted, already cleaned string for use in Markdown text
// and table cells. Markdown metacharacters get a backslash; HTML
// metacharacters become entities, so no tag, comment, link, or code fence can
// start inside repository-derived text.
func md(s string) string {
	if s == "" {
		return s
	}
	var b strings.Builder
	b.Grow(len(s) + 8)
	for _, r := range s {
		switch r {
		case '&':
			b.WriteString("&amp;")
		case '<':
			b.WriteString("&lt;")
		case '>':
			b.WriteString("&gt;")
		case '\\', '`', '*', '_', '[', ']', '(', ')', '#', '~', '|', '!', '{', '}', '$', '@':
			if r == '@' {
				// An entity keeps hostile text from notifying people or
				// teams when the summary is posted as a comment.
				b.WriteString("&#64;")
				continue
			}
			b.WriteByte('\\')
			b.WriteRune(r)
		default:
			b.WriteRune(r)
		}
	}
	return b.String()
}

func renderMarkdown(buf *bytes.Buffer, raw *model.ScanResult) error {
	v, err := buildView(raw)
	if err != nil {
		return err
	}
	w := func(format string, args ...any) { fmt.Fprintf(buf, format, args...) }

	w("## AgentGov Auditor report\n\n")
	w("**Release decision: %s.** %s\n\n", DecisionName(v.outcome), DecisionExplanation(v.outcome))

	if v.hasScore {
		w("**Assessment maturity: %s** (%s). ", v.scoreText, ScoreNote)
	} else {
		w("**Assessment maturity: %s.** ", v.scoreText)
	}
	if v.hasAgents {
		s := v.res.Score
		w("%d of %d applicable controls have evidence. Verified by tests: %d%%. Verified in operation: %d%%.\n\n",
			s.ControlsWithEvidence, s.ApplicableControls, s.TestedPercent, s.OperationalPercent)
	} else {
		w("No controls were assessed.\n\n")
	}

	w("| Target | Profile | Commit | Policy | Offline |\n|---|---|---|---|---|\n")
	w("| %s | %s (%s) | %s | %s | %s |\n\n", md(v.target), md(v.profile), md(v.profileHow), md(v.commit), md(v.policy), v.offline)

	if v.noAgent {
		w("### %s\n\n", noAgentTitle)
		for _, l := range noAgentLines {
			w("- %s\n", l)
		}
		w("\n")
	}
	if !v.hasAgents && len(v.res.Decision.Reasons) > 0 {
		w("### Reasons\n\n")
		for _, r := range v.res.Decision.Reasons {
			w("- %s\n", md(reasonText(r)))
		}
		w("\n")
	}
	if len(v.agents) > 0 {
		w("### Agents\n\n")
		for _, av := range v.agents {
			a := av.Agent
			w("- **%s**: %s, %s, %s (%s), %s\n", md(orDefault(a.Name, a.ID)),
				md(orDefault(a.Framework, model.Unknown)), md(orDefault(a.Language, model.Unknown)),
				detectionLabel(a.Detection), confidenceLabel(a.Confidence),
				plural(len(a.Tools), "tool", "tools"))
		}
		w("\n")
	}
	if !v.hasAgents && !v.noAgent {
		w("No agent was assessed, so there are no control results. This is not a pass.\n\n")
	}
	if v.hasAgents {
		w("### Control summary\n\n| Group | Controls | Meaning |\n|---|---:|---|\n")
		for _, r := range Rollups() {
			w("| %s | %d | %s |\n", r.Label(), v.totals[r], r.Meaning())
		}
		w("\n")
	}

	if len(v.findings) > 0 {
		w("### Top findings\n\n| Severity | Control | Finding | Location |\n|---|---|---|---|\n")
		shown := v.findings
		if len(shown) > maxMarkdownFindings {
			shown = shown[:maxMarkdownFindings]
		}
		for _, f := range shown {
			loc := locationText(f.Location)
			if loc == "" {
				loc = "No file location"
			} else {
				loc = md(loc)
			}
			w("| %s | %s | %s | %s |\n", severityLabel(f.Severity), md(f.ControlID), md(f.Title), loc)
		}
		if extra := len(v.findings) - len(shown); extra > 0 {
			w("\n%s in the full report.\n", plural(extra, "more finding is", "more findings are"))
		}
		w("\nFindings by severity: %s.\n\n", v.severitySummary())
	} else {
		w("### Top findings\n\nThe scan reported no findings. This does not prove that the agent is safe.\n\n")
	}

	if len(v.mandatory) > 0 {
		w("### Unresolved mandatory controls\n\n")
		for _, p := range v.mandatory {
			agent := ""
			if v.multiAgent {
				agent = ", agent " + md(p.AgentName)
			}
			w("- **%s %s** (%s%s). ", md(p.Control.ControlID), md(p.Control.Title), StatusLabel(p.Control.Status), agent)
			if p.Fix != "" {
				w("Next action: %s", md(p.Fix))
			} else {
				w("Next action: run agentgov explain %s", md(p.Control.ControlID))
			}
			w("\n")
		}
		w("\n")
	}

	if v.hasAgents {
		w("<details>\n<summary>All %s</summary>\n\n", plural(v.controlsN, "control result", "control results"))
		for _, av := range v.agents {
			if av.Assessment == nil {
				continue
			}
			if v.multiAgent {
				w("**%s**\n\n", md(orDefault(av.Agent.Name, av.Agent.ID)))
			}
			w("| Control | Title | Domain | Status | Maturity | Mandatory |\n|---|---|---|---|---:|---|\n")
			for _, d := range av.Domains {
				for _, c := range d.Controls {
					w("| %s | %s | %s | %s | %s | %s |\n", md(c.ControlID), md(c.Title), md(c.Domain),
						StatusLabel(c.Status), maturityText(&c), yesNo(c.Mandatory))
				}
			}
			w("\n")
		}
		w("</details>\n\n")
	}

	if n := len(v.res.Warnings); n > 0 {
		w("%s. See the full report for details.\n\n", plural(n, "scan warning", "scan warnings"))
	}

	w("---\n\nGenerated by %s %s. %s\n", md(v.toolName), md(v.toolVersion), Disclaimer)
	return nil
}
