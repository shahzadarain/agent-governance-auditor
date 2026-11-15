// SPDX-License-Identifier: Apache-2.0

package reporting

import (
	"fmt"
	"sort"
	"strings"

	"github.com/shahzadarain/agent-governance-auditor/internal/model"
)

// Priority labels for the "what to fix first" list.
const (
	labelBlock  = "BLOCK"
	labelReview = "REVIEW"
	labelWarn   = "WARN"
)

// maxPriority is the number of priority items shown in summaries.
const maxPriority = 5

// view is the format-independent presentation model. Every string in it comes
// from a sanitized copy of the scan result.
type view struct {
	res *model.ScanResult

	toolName    string
	toolVersion string
	target      string
	commit      string // short SHA or "unknown"
	profile     string
	profileHow  string
	policy      string // "pack version"
	offline     string // "yes" or "no"

	hasAgents  bool // at least one agent was assessed
	noAgent    bool // discovery found no agent at all
	multiAgent bool
	scoreText  string // "41/100" or "insufficient evidence"
	scoreValue int    // valid only when hasScore
	hasScore   bool

	outcome     model.Outcome
	priority    []priorityItem // every item, most urgent first
	domains     []domainCount  // across all agents
	totals      [5]int         // roll-up counts across all agents
	controlsN   int            // number of control results across all agents
	agents      []agentView
	findings    []model.Finding // sorted by severity, control, location
	sevCounts   []sevCount      // five severities, most serious first
	mandatory   []priorityItem  // unresolved mandatory controls
	agentNames  map[string]string
	controlByID map[string]*model.ControlResult // "agent\x00control"
}

type sevCount struct {
	Severity model.Severity
	Count    int
}

type domainCount struct {
	Name   string
	Counts [5]int
}

type agentView struct {
	Agent      model.Agent
	Assessment *model.AgentAssessment // nil when the agent has no assessment
	Sensitive  int                    // number of sensitive tools
	Domains    []domainControls
}

type domainControls struct {
	Name     string
	Controls []model.ControlResult
}

// priorityItem is one control that needs attention, with the most useful
// finding, location, and fix attached.
type priorityItem struct {
	Label     string // BLOCK, REVIEW, or WARN
	AgentID   string
	AgentName string
	Control   model.ControlResult
	Severity  model.Severity
	Found     string
	Where     string
	Fix       string
	Steps     []string
}

func buildView(raw *model.ScanResult) (*view, error) {
	res, err := sanitizedCopy(raw)
	if err != nil {
		return nil, err
	}
	v := &view{
		res:         res,
		toolName:    orDefault(res.Tool.Name, "AgentGov Auditor"),
		toolVersion: orDefault(res.Tool.Version, "(version unknown)"),
		target:      orDefault(res.Scan.Target, model.Unknown),
		commit:      shortSHA(res.Scan.CommitSHA),
		profile:     orDefault(res.Scan.Profile, model.Unknown),
		profileHow:  profileSourceLabel(res.Scan.ProfileSource),
		policy:      strings.TrimSpace(orDefault(res.Scan.PolicyPack, model.Unknown) + " " + res.Scan.PolicyVersion),
		offline:     yesNo(res.Scan.Offline),
		outcome:     res.Decision.Outcome,
		hasAgents:   len(res.Assessments) > 0,
		noAgent:     len(res.Agents) == 0 && len(res.Assessments) == 0,
		multiAgent:  len(res.Assessments) > 1,
		agentNames:  map[string]string{},
		controlByID: map[string]*model.ControlResult{},
	}

	// A numeric score is shown only when at least one agent was assessed and
	// the score has a value. Otherwise the report says so in words.
	v.scoreText = "insufficient evidence"
	if v.hasAgents && res.Score.Value != nil {
		v.hasScore = true
		v.scoreValue = clamp(*res.Score.Value, 0, 100)
		v.scoreText = fmt.Sprintf("%d/100", v.scoreValue)
	}

	for _, a := range res.Agents {
		v.agentNames[a.ID] = orDefault(a.Name, a.ID)
	}

	v.findings = append([]model.Finding(nil), res.Findings...)
	sort.SliceStable(v.findings, func(i, j int) bool { return findingLess(&v.findings[i], &v.findings[j]) })
	counts := map[model.Severity]int{}
	for _, f := range v.findings {
		counts[f.Severity]++
	}
	for _, s := range severityOrder {
		v.sevCounts = append(v.sevCounts, sevCount{s, counts[s]})
	}

	assessments := map[string]*model.AgentAssessment{}
	for i := range res.Assessments {
		assessments[res.Assessments[i].AgentID] = &res.Assessments[i]
	}
	seen := map[string]bool{}
	for _, a := range res.Agents {
		seen[a.ID] = true
		v.agents = append(v.agents, v.agentView(a, assessments[a.ID]))
	}
	// An assessment without a matching inventory entry is still shown.
	for i := range res.Assessments {
		as := &res.Assessments[i]
		if !seen[as.AgentID] {
			v.agents = append(v.agents, v.agentView(model.Agent{ID: as.AgentID, Name: as.AgentID}, as))
		}
	}

	domainIndex := map[string]int{}
	for i := range res.Assessments {
		as := &res.Assessments[i]
		for j := range as.Controls {
			c := &as.Controls[j]
			v.controlByID[as.AgentID+"\x00"+c.ControlID] = c
			v.controlsN++
			r := RollupOf(c.Status)
			v.totals[r]++
			idx, ok := domainIndex[c.Domain]
			if !ok {
				idx = len(v.domains)
				domainIndex[c.Domain] = idx
				v.domains = append(v.domains, domainCount{Name: c.Domain})
			}
			v.domains[idx].Counts[r]++
			if item, ok := v.priorityFor(as, c); ok {
				v.priority = append(v.priority, item)
			}
		}
	}
	sort.SliceStable(v.domains, func(i, j int) bool { return v.domains[i].Name < v.domains[j].Name })
	sort.SliceStable(v.priority, func(i, j int) bool {
		a, b := &v.priority[i], &v.priority[j]
		if ra, rb := labelRank(a.Label), labelRank(b.Label); ra != rb {
			return ra < rb
		}
		if ra, rb := severityRank(a.Severity), severityRank(b.Severity); ra != rb {
			return ra < rb
		}
		if a.Control.ControlID != b.Control.ControlID {
			return a.Control.ControlID < b.Control.ControlID
		}
		return a.AgentID < b.AgentID
	})
	for _, p := range v.priority {
		if p.Control.Mandatory && p.Label != labelWarn {
			v.mandatory = append(v.mandatory, p)
		}
	}
	return v, nil
}

func (v *view) agentView(a model.Agent, as *model.AgentAssessment) agentView {
	av := agentView{Agent: a, Assessment: as}
	for _, t := range a.Tools {
		if t.Sensitive {
			av.Sensitive++
		}
	}
	if as == nil {
		return av
	}
	idx := map[string]int{}
	for _, c := range as.Controls {
		i, ok := idx[c.Domain]
		if !ok {
			i = len(av.Domains)
			idx[c.Domain] = i
			av.Domains = append(av.Domains, domainControls{Name: c.Domain})
		}
		av.Domains[i].Controls = append(av.Domains[i].Controls, c)
	}
	sort.SliceStable(av.Domains, func(i, j int) bool { return av.Domains[i].Name < av.Domains[j].Name })
	for i := range av.Domains {
		cs := av.Domains[i].Controls
		sort.SliceStable(cs, func(a, b int) bool { return cs[a].ControlID < cs[b].ControlID })
	}
	return av
}

// priorityFor decides whether a control belongs in the "what to fix first"
// list and with which label. It follows the decision rules of the policy
// engine: a mandatory, applicable control that failed, errored, is missing, is
// unknown, or is below the required maturity is a blocker; accepted risks and
// inferred not-applicable results on mandatory controls need a review.
func (v *view) priorityFor(as *model.AgentAssessment, c *model.ControlResult) (priorityItem, bool) {
	findings := v.findingsFor(as.AgentID, c)
	label := ""
	hard := c.Status == model.StatusFailed || c.Status == model.StatusError
	switch {
	case c.Mandatory && c.Applicable:
		switch c.Status {
		case model.StatusFailed, model.StatusError, model.StatusMissing, model.StatusUnknown:
			label = labelBlock
		case model.StatusAcceptedRisk:
			label = labelReview
		case model.StatusNotApplicable:
			label = ""
		default:
			if c.Maturity < c.MinMaturity {
				label = labelBlock
			}
		}
	case c.Mandatory && c.Status == model.StatusNotApplicable && c.ApplicabilityBasis == model.BasisInferred:
		label = labelReview
	case c.Mandatory && c.Status == model.StatusAcceptedRisk:
		label = labelReview
	}
	if label == labelBlock {
		// The agent's own decision is authoritative. A profile with a review
		// workflow turns shortfalls that are not failures into reviews.
		switch {
		case as.Decision.Outcome == model.OutcomeReviewRequired:
			label = labelReview
		case as.Decision.Outcome == model.OutcomeAllow:
			label = labelWarn
		case !hard && reasonSaysReview(as.Decision.Reasons, c.ControlID):
			label = labelReview
		}
	}
	if label == "" {
		switch {
		case !c.Applicable && c.Status == model.StatusNotApplicable:
			if len(findings) == 0 {
				return priorityItem{}, false
			}
			label = labelWarn
		case RollupOf(c.Status) == RollupFailed, len(findings) > 0:
			label = labelWarn
		default:
			return priorityItem{}, false
		}
	}

	item := priorityItem{
		Label:     label,
		AgentID:   as.AgentID,
		AgentName: orDefault(v.agentNames[as.AgentID], as.AgentID),
		Control:   *c,
		Severity:  c.Severity,
		Found:     c.StatusReason,
		Fix:       c.NextAction,
		Steps:     c.Remediation,
	}
	if len(findings) > 0 {
		top := findings[0]
		if severityRank(top.Severity) < severityRank(item.Severity) {
			item.Severity = top.Severity
		}
		if top.Title != "" {
			item.Found = top.Title
		}
		item.Where = locationText(top.Location)
		if len(top.Remediation) > 0 {
			item.Fix = top.Remediation[0]
			item.Steps = top.Remediation
		}
	}
	if item.Where == "" {
		item.Where = v.evidenceLocation(c)
	}
	if item.Fix == "" && len(c.Remediation) > 0 {
		item.Fix = c.Remediation[0]
	}
	if item.Found == "" {
		item.Found = StatusMeaning(c.Status)
	}
	if len(item.Steps) == 0 && item.Fix != "" {
		item.Steps = []string{item.Fix}
	}
	return item, true
}

func reasonSaysReview(reasons []model.Reason, controlID string) bool {
	for _, r := range reasons {
		if r.ControlID == controlID && strings.Contains(strings.ToLower(r.Code), "review") {
			return true
		}
	}
	return false
}

// findingsFor returns the findings linked to a control result, most serious
// first. It uses the explicit references and falls back to matching by
// control and agent.
func (v *view) findingsFor(agentID string, c *model.ControlResult) []model.Finding {
	var out []model.Finding
	if len(c.FindingRefs) > 0 {
		want := map[string]bool{}
		for _, id := range c.FindingRefs {
			want[id] = true
		}
		for _, f := range v.findings {
			if want[f.FindingID] {
				out = append(out, f)
			}
		}
		return out
	}
	for _, f := range v.findings {
		if f.ControlID == c.ControlID && (f.AgentID == agentID || f.AgentID == model.AllAgents) {
			out = append(out, f)
		}
	}
	return out
}

// evidenceFor returns the evidence items referenced by a control result, in
// reference order.
func (v *view) evidenceFor(c *model.ControlResult) []model.Evidence {
	var out []model.Evidence
	for _, id := range c.EvidenceRefs {
		for i := range v.res.Evidence {
			if v.res.Evidence[i].EvidenceID == id {
				out = append(out, v.res.Evidence[i])
				break
			}
		}
	}
	return out
}

func (v *view) evidenceLocation(c *model.ControlResult) string {
	for _, e := range v.evidenceFor(c) {
		if s := locationText(e.Location); s != "" {
			return s
		}
	}
	return ""
}

// controlStatus returns the status of the control a finding belongs to, and
// false when no assessment covers it.
func (v *view) controlStatus(f *model.Finding) (model.Status, bool) {
	if c, ok := v.controlByID[f.AgentID+"\x00"+f.ControlID]; ok {
		return c.Status, true
	}
	// Repository-level findings: use the first agent that has the control.
	for _, as := range v.res.Assessments {
		if c, ok := v.controlByID[as.AgentID+"\x00"+f.ControlID]; ok {
			return c.Status, true
		}
	}
	return "", false
}

// topPriority returns at most maxPriority items.
func (v *view) topPriority() []priorityItem {
	if len(v.priority) > maxPriority {
		return v.priority[:maxPriority]
	}
	return v.priority
}

// topBlocker returns the control ID to suggest for `agentgov explain`.
func (v *view) topBlocker() string {
	if len(v.priority) == 0 {
		return ""
	}
	return v.priority[0].Control.ControlID
}

func labelRank(l string) int {
	switch l {
	case labelBlock:
		return 0
	case labelReview:
		return 1
	default:
		return 2
	}
}

func findingLess(a, b *model.Finding) bool {
	if ra, rb := severityRank(a.Severity), severityRank(b.Severity); ra != rb {
		return ra < rb
	}
	if a.ControlID != b.ControlID {
		return a.ControlID < b.ControlID
	}
	if a.RuleID != b.RuleID {
		return a.RuleID < b.RuleID
	}
	pa, la := locationKey(a.Location)
	pb, lb := locationKey(b.Location)
	if pa != pb {
		return pa < pb
	}
	if la != lb {
		return la < lb
	}
	if a.Fingerprint != b.Fingerprint {
		return a.Fingerprint < b.Fingerprint
	}
	return a.FindingID < b.FindingID
}

func locationKey(l *model.Location) (string, int) {
	if l == nil {
		return "", 0
	}
	return l.Path, l.Line
}

// locationText formats a location as "path:line". It returns "" when there is
// no file location.
func locationText(l *model.Location) string {
	if l == nil || l.Path == "" {
		return ""
	}
	if l.Line > 0 {
		return fmt.Sprintf("%s:%d", l.Path, l.Line)
	}
	return l.Path
}

func shortSHA(sha string) string {
	if sha == "" || sha == model.Unknown {
		return model.Unknown
	}
	if len(sha) > 7 && isHex(sha) {
		return sha[:7]
	}
	return sha
}

func isHex(s string) bool {
	for _, r := range s {
		if !(r >= '0' && r <= '9' || r >= 'a' && r <= 'f' || r >= 'A' && r <= 'F') {
			return false
		}
	}
	return true
}

func orDefault(s, def string) string {
	if strings.TrimSpace(s) == "" {
		return def
	}
	return s
}

func yesNo(b bool) string {
	if b {
		return "yes"
	}
	return "no"
}

func clamp(n, lo, hi int) int {
	if n < lo {
		return lo
	}
	if n > hi {
		return hi
	}
	return n
}

func plural(n int, one, many string) string {
	if n == 1 {
		return fmt.Sprintf("%d %s", n, one)
	}
	return fmt.Sprintf("%d %s", n, many)
}

// severitySummary returns "2 critical, 1 high, 0 medium, 0 low, 0 info".
func (v *view) severitySummary() string {
	parts := make([]string, 0, len(v.sevCounts))
	for _, sc := range v.sevCounts {
		parts = append(parts, fmt.Sprintf("%d %s", sc.Count, sc.Severity))
	}
	return strings.Join(parts, ", ")
}

// maturityText returns "n/4", or "-" for a control that is not applicable and
// therefore has no maturity.
func maturityText(c *model.ControlResult) string {
	if c.Status == model.StatusNotApplicable {
		return "-"
	}
	return fmt.Sprintf("%d/4", clamp(c.Maturity, 0, 4))
}
