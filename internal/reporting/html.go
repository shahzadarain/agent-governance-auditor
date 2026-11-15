// SPDX-License-Identifier: Apache-2.0

package reporting

import (
	"bytes"
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"html/template"
	"net/url"
	"strings"
	"time"

	"github.com/shahzadarain/agent-governance-auditor/internal/model"
)

// The report is one self-contained file. Scan data reaches the page only as
// server-rendered, contextually escaped HTML. The inline script toggles
// visibility and never writes markup. The Content-Security-Policy allows no
// remote source of any kind and pins the inline style and script by hash, so
// markup injected through scan data could not run even if escaping failed.
var (
	htmlTmpl = template.Must(template.New("report").Parse(htmlTemplateText()))
	htmlCSP  = "default-src 'none'; style-src '" + cspHash(htmlCSS) + "'; script-src '" + cspHash(htmlJS) +
		"'; img-src data:; base-uri 'none'; form-action 'none'"
)

func htmlTemplateText() string {
	s := strings.Replace(htmlPageTemplate, "/*CSS*/", htmlCSS, 1)
	return strings.Replace(s, "/*JS*/", htmlJS, 1)
}

func cspHash(content string) string {
	sum := sha256.Sum256([]byte(content))
	return "sha256-" + base64.StdEncoding.EncodeToString(sum[:])
}

type htmlPage struct {
	CSP             string
	ToolName        string
	ToolVersion     string
	Meta            []htmlKV
	OutcomeKey      string
	DecisionName    string
	DecisionExplain string
	Reasons         []string
	MoreReasons     int
	HasAgents       bool
	NoAgent         bool
	HasScore        bool
	ScoreText       string
	ScoreValue      int
	ScoreNote       string
	DialDash        string
	Metrics         []htmlMetric
	NoAgentTitle    string
	NoAgentLines    []string
	Priority        []htmlPriority
	MorePriority    int
	Agents          []htmlAgent
	MultiAgent      bool
	Rollups         []htmlRollup
	ControlsN       int
	Findings        []htmlFinding
	SeverityOptions []htmlOption
	StatusOptions   []htmlOption
	SeveritySummary []htmlRollup
	Warnings        []string
	Limitations     []string
	StatusLegend    []htmlLegend
	GroupLegend     []htmlRollup
	DecisionLegend  []htmlLegend
	Disclaimer      string
}

// maxHeroReasons bounds the decision reasons shown in the header band.
const maxHeroReasons = 4

type htmlKV struct{ Key, Value string }

type htmlMetric struct {
	Label   string
	Value   string
	Percent int
	Note    string
}

type htmlOption struct{ Value, Label string }

type htmlLegend struct{ Key, Label, Meaning string }

type htmlRollup struct {
	Key     string
	Label   string
	Count   int
	Meaning string
}

type htmlPriority struct {
	Label       string
	LabelKey    string
	ControlID   string
	Title       string
	Anchor      string
	Group       string
	StatusLabel string
	Plain       string
	Agent       string
	Found       string
	Where       string
	Steps       []string
	Severity    string
	SeverityKey string
	Mandatory   bool
}

type htmlAgent struct {
	Name         string
	ID           string
	Root         string
	Framework    string
	Language     string
	Detection    string
	Entrypoint   string
	Owner        string
	RiskTier     string
	Capabilities []string
	Tools        []htmlTool
	MCP          []htmlMCP
	Sensitive    int
	Assessed     bool
	OutcomeKey   string
	DecisionName string
	ScoreText    string
	Domains      []htmlDomain
}

type htmlTool struct {
	Name      string
	Kind      string
	Where     string
	Sensitive bool
	Why       string
	Declared  bool
}

type htmlMCP struct {
	Name      string
	Transport string
	Target    string
	Pinned    bool
	Version   string
	Where     string
}

type htmlDomain struct {
	Name     string
	Counts   []htmlRollup
	Controls []htmlControl
}

type htmlControl struct {
	ID            string
	Anchor        string
	Title         string
	Group         string
	StatusLabel   string
	StatusMeaning string
	Maturity      int
	MaturityText  string
	MaturityLong  string
	Pips          [4]bool
	Mandatory     bool
	MinMaturity   int
	Plain         string
	Reason        string
	Applicability string
	MaxStatic     int
	Severity      string
	NextAction    string
	Remediation   []string
	Limitations   []string
	Evidence      []htmlEvidence
	Findings      []htmlFindingRef
}

type htmlEvidence struct {
	Summary     string
	Source      string
	Validity    string
	ValidityOK  bool
	ValidityWhy string
	Integrity   string
	Result      string
	Observed    string
	ValidUntil  string
	Where       string
	Collector   string
	Limitations []string
}

type htmlFindingRef struct {
	Title    string
	Where    string
	Severity string
}

type htmlFinding struct {
	Severity     string
	SeverityKey  string
	ControlID    string
	ControlTitle string
	Domain       string
	Agent        string
	Title        string
	Description  string
	Why          string
	Remediation  []string
	Reproduction string
	Where        string
	RuleID       string
	Confidence   string
	Group        string
	StatusLabel  string
	Mappings     []htmlMapping
}

type htmlMapping struct {
	Text string
	URL  string // empty unless the mapping carries an https URL
}

func renderHTML(buf *bytes.Buffer, raw *model.ScanResult) error {
	v, err := buildView(raw)
	if err != nil {
		return err
	}
	return htmlTmpl.Execute(buf, buildHTMLPage(v))
}

func buildHTMLPage(v *view) *htmlPage {
	res := v.res
	p := &htmlPage{
		CSP:             htmlCSP,
		ToolName:        v.toolName,
		ToolVersion:     v.toolVersion,
		OutcomeKey:      outcomeKey(v.outcome),
		DecisionName:    DecisionName(v.outcome),
		DecisionExplain: DecisionExplanation(v.outcome),
		HasAgents:       v.hasAgents,
		NoAgent:         v.noAgent,
		HasScore:        v.hasScore,
		ScoreText:       v.scoreText,
		ScoreValue:      v.scoreValue,
		ScoreNote:       ScoreNote,
		NoAgentTitle:    noAgentTitle,
		NoAgentLines:    noAgentLines,
		MultiAgent:      v.multiAgent,
		ControlsN:       v.controlsN,
		Warnings:        res.Warnings,
		Limitations:     res.Limitations,
		Disclaimer:      Disclaimer,
	}
	const circumference = 339.292 // 2 * pi * 54
	p.DialDash = fmt.Sprintf("%.2f %.2f", circumference*float64(v.scoreValue)/100, circumference)

	p.Meta = []htmlKV{
		{"Target", v.target},
		{"Commit", v.commit},
		{"Profile", fmt.Sprintf("%s (%s)", v.profile, v.profileHow)},
		{"Policy", v.policy},
		{"Offline scan", v.offline},
		{"Configuration file", orDefault(res.Scan.ConfigPath, "none found")},
		{"Scan finished", formatTime(res.Scan.FinishedAt)},
		{"Files scanned", fmt.Sprintf("%d (%d skipped)", res.Stats.FilesScanned, res.Stats.FilesSkipped)},
		{"Scan ID", orDefault(res.Scan.ScanID, model.Unknown)},
	}

	for i, r := range res.Decision.Reasons {
		if i == maxHeroReasons {
			p.MoreReasons = len(res.Decision.Reasons) - i
			break
		}
		p.Reasons = append(p.Reasons, reasonText(r))
	}

	if v.hasAgents {
		s := res.Score
		p.Metrics = []htmlMetric{
			{Label: "Evidence coverage", Value: fmt.Sprintf("%d of %d", s.ControlsWithEvidence, s.ApplicableControls),
				Percent: clamp(s.CoveragePercent, 0, 100), Note: "applicable controls have evidence"},
			{Label: "Verified by tests", Value: fmt.Sprintf("%d%%", clamp(s.TestedPercent, 0, 100)),
				Percent: clamp(s.TestedPercent, 0, 100), Note: "of applicable controls"},
			{Label: "Verified in operation", Value: fmt.Sprintf("%d%%", clamp(s.OperationalPercent, 0, 100)),
				Percent: clamp(s.OperationalPercent, 0, 100), Note: "of applicable controls"},
		}
	}

	agentIndex := map[string]int{}
	for i, av := range v.agents {
		agentIndex[av.Agent.ID] = i
	}
	top := v.topPriority()
	p.MorePriority = len(v.priority) - len(top)
	for _, it := range top {
		hp := htmlPriority{
			Label:       it.Label,
			LabelKey:    strings.ToLower(it.Label),
			ControlID:   it.Control.ControlID,
			Title:       it.Control.Title,
			Anchor:      controlAnchor(agentIndex[it.AgentID], it.Control.ControlID),
			Group:       RollupOf(it.Control.Status).key(),
			StatusLabel: StatusLabel(it.Control.Status),
			Plain:       it.Control.PlainLanguage,
			Found:       it.Found,
			Where:       it.Where,
			Steps:       it.Steps,
			Severity:    severityLabel(it.Severity),
			SeverityKey: severityKey(it.Severity),
			Mandatory:   it.Control.Mandatory,
		}
		if v.multiAgent {
			hp.Agent = it.AgentName
		}
		p.Priority = append(p.Priority, hp)
	}

	for i, av := range v.agents {
		p.Agents = append(p.Agents, buildHTMLAgent(v, i, av))
	}

	for _, r := range Rollups() {
		row := htmlRollup{Key: r.key(), Label: r.Label(), Count: v.totals[r], Meaning: r.Meaning()}
		p.Rollups = append(p.Rollups, row)
		p.GroupLegend = append(p.GroupLegend, row)
	}

	statusSeen := map[model.Status]bool{}
	for i := range v.findings {
		f := &v.findings[i]
		hf := htmlFinding{
			Severity:     severityLabel(f.Severity),
			SeverityKey:  severityKey(f.Severity),
			ControlID:    f.ControlID,
			Title:        orDefault(f.Title, f.RuleID),
			Description:  f.Description,
			Why:          f.WhyItMatters,
			Remediation:  f.Remediation,
			Reproduction: f.Reproduction,
			Where:        locationText(f.Location),
			RuleID:       f.RuleID,
			Confidence:   confidenceLabel(f.Confidence),
			Group:        "none",
			StatusLabel:  "Not assessed",
		}
		if f.AgentID != "" && f.AgentID != model.AllAgents {
			hf.Agent = orDefault(v.agentNames[f.AgentID], f.AgentID)
		}
		if st, ok := v.controlStatus(f); ok {
			hf.Group = RollupOf(st).key()
			hf.StatusLabel = StatusLabel(st)
			statusSeen[st] = true
		}
		for _, as := range res.Assessments {
			if c, ok := v.controlByID[as.AgentID+"\x00"+f.ControlID]; ok {
				hf.ControlTitle, hf.Domain = c.Title, c.Domain
				break
			}
		}
		for _, m := range f.Mappings {
			text := strings.TrimSpace(strings.Join([]string{m.Standard, m.Version, m.RequirementID}, " "))
			if text == "" {
				continue
			}
			hf.Mappings = append(hf.Mappings, htmlMapping{Text: text, URL: safeHTTPSURL(m.URL)})
		}
		p.Findings = append(p.Findings, hf)
	}
	for _, sc := range v.sevCounts {
		p.SeveritySummary = append(p.SeveritySummary, htmlRollup{Key: string(sc.Severity), Label: severityLabel(sc.Severity), Count: sc.Count})
		if sc.Count > 0 {
			p.SeverityOptions = append(p.SeverityOptions, htmlOption{string(sc.Severity), severityLabel(sc.Severity)})
		}
	}
	// The status filter offers each distinct label once.
	labelSeen := map[string]bool{}
	for _, st := range AllStatuses() {
		if statusSeen[st] && !labelSeen[StatusLabel(st)] {
			labelSeen[StatusLabel(st)] = true
			p.StatusOptions = append(p.StatusOptions, htmlOption{StatusLabel(st), StatusLabel(st)})
		}
	}

	for _, st := range AllStatuses() {
		p.StatusLegend = append(p.StatusLegend, htmlLegend{Key: RollupOf(st).key(), Label: StatusLabel(st), Meaning: StatusMeaning(st)})
	}
	if v.hasAgents {
		for _, o := range []model.Outcome{model.OutcomeAllow, model.OutcomeReviewRequired, model.OutcomeBlock} {
			p.DecisionLegend = append(p.DecisionLegend, htmlLegend{Key: outcomeKey(o), Label: DecisionName(o), Meaning: DecisionExplanation(o)})
		}
	}
	return p
}

func buildHTMLAgent(v *view, index int, av agentView) htmlAgent {
	a := av.Agent
	fw := orDefault(a.Framework, model.Unknown)
	if a.FrameworkVersion != "" && a.FrameworkVersion != model.Unknown {
		fw += " " + a.FrameworkVersion
	}
	ha := htmlAgent{
		Name:         orDefault(a.Name, a.ID),
		ID:           a.ID,
		Root:         orDefault(a.Root, model.Unknown),
		Framework:    fw,
		Language:     orDefault(a.Language, model.Unknown),
		Detection:    fmt.Sprintf("%s (%s)", detectionLabel(a.Detection), confidenceLabel(a.Confidence)),
		Entrypoint:   orDefault(a.Entrypoint, model.Unknown),
		Owner:        orDefault(a.Owner, model.Unknown),
		RiskTier:     riskTierText(a),
		Capabilities: a.Capabilities,
		Sensitive:    av.Sensitive,
	}
	for _, t := range a.Tools {
		ha.Tools = append(ha.Tools, htmlTool{
			Name: t.Name, Kind: orDefault(t.Kind, model.Unknown), Where: locationText(&t.Location),
			Sensitive: t.Sensitive, Why: t.SensitiveWhy, Declared: t.Declared,
		})
	}
	for _, m := range a.MCPConnections {
		ha.MCP = append(ha.MCP, htmlMCP{
			Name: m.Name, Transport: orDefault(m.Transport, model.Unknown), Target: m.Target,
			Pinned: m.Pinned, Version: m.Version, Where: locationText(&m.Location),
		})
	}
	if av.Assessment == nil {
		return ha
	}
	ha.Assessed = true
	ha.OutcomeKey = outcomeKey(av.Assessment.Decision.Outcome)
	ha.DecisionName = DecisionName(av.Assessment.Decision.Outcome)
	ha.ScoreText = "insufficient evidence"
	if av.Assessment.Score.Value != nil {
		ha.ScoreText = fmt.Sprintf("%d/100", clamp(*av.Assessment.Score.Value, 0, 100))
	}
	for _, d := range av.Domains {
		hd := htmlDomain{Name: d.Name}
		var counts [5]int
		for i := range d.Controls {
			c := &d.Controls[i]
			counts[RollupOf(c.Status)]++
			hd.Controls = append(hd.Controls, buildHTMLControl(v, index, av.Assessment.AgentID, c))
		}
		for _, r := range Rollups() {
			if counts[r] > 0 {
				hd.Counts = append(hd.Counts, htmlRollup{Key: r.key(), Label: r.Label(), Count: counts[r]})
			}
		}
		ha.Domains = append(ha.Domains, hd)
	}
	return ha
}

func buildHTMLControl(v *view, agentIdx int, agentID string, c *model.ControlResult) htmlControl {
	m := clamp(c.Maturity, 0, 4)
	hc := htmlControl{
		ID:            c.ControlID,
		Anchor:        controlAnchor(agentIdx, c.ControlID),
		Title:         c.Title,
		Group:         RollupOf(c.Status).key(),
		StatusLabel:   StatusLabel(c.Status),
		StatusMeaning: StatusMeaning(c.Status),
		Maturity:      m,
		MaturityText:  fmt.Sprintf("Maturity %d/4", m),
		MaturityLong:  fmt.Sprintf("%d of 4", m),
		Mandatory:     c.Mandatory,
		MinMaturity:   clamp(c.MinMaturity, 0, 4),
		Plain:         c.PlainLanguage,
		Reason:        c.StatusReason,
		Applicability: applicabilityText(c),
		MaxStatic:     clamp(c.MaxStaticMaturity, 0, 4),
		Severity:      severityLabel(c.Severity),
		NextAction:    c.NextAction,
		Remediation:   c.Remediation,
		Limitations:   c.Limitations,
	}
	if c.Status == model.StatusNotApplicable {
		hc.MaturityText, hc.MaturityLong = "Not scored", "Not scored"
	}
	for i := 0; i < m; i++ {
		hc.Pips[i] = true
	}
	for _, e := range v.evidenceFor(c) {
		where := locationText(e.Location)
		if where == "" {
			where = e.SourceLocation
		}
		until := "No expiry stated"
		if e.ValidUntil != nil {
			until = formatTime(*e.ValidUntil)
		}
		hc.Evidence = append(hc.Evidence, htmlEvidence{
			Summary:     orDefault(e.Summary, "No summary recorded"),
			Source:      sourceTypeLabel(e.SourceType),
			Validity:    validityLabel(e.Validity),
			ValidityOK:  e.Validity == model.ValidityValid,
			ValidityWhy: e.ValidityReason,
			Integrity:   integrityLabel(e.Integrity),
			Result:      resultLabel(e.Result),
			Observed:    formatTime(e.ObservedAt),
			ValidUntil:  until,
			Where:       where,
			Collector:   e.Collector,
			Limitations: e.Limitations,
		})
	}
	for _, f := range v.findingsFor(agentID, c) {
		hc.Findings = append(hc.Findings, htmlFindingRef{
			Title: orDefault(f.Title, f.RuleID), Where: locationText(f.Location), Severity: severityLabel(f.Severity),
		})
	}
	return hc
}

func applicabilityText(c *model.ControlResult) string {
	basis := ""
	switch c.ApplicabilityBasis {
	case model.BasisAlways:
		basis = "Applies to every agent."
	case model.BasisDetected:
		basis = "Applies because a triggering capability was detected."
	case model.BasisDeclared:
		basis = "Applies because the configuration declares the capability."
	case model.BasisInferred:
		basis = "Treated as not applicable because no triggering capability was detected. This is an inference, not an approval."
	case model.BasisApproved:
		basis = "Not applicable by an approved exception recorded in the configuration."
	default:
		if c.Applicable {
			basis = "Applies to this agent."
		} else {
			basis = "Does not apply to this agent."
		}
	}
	// A recorded reason is more specific than the general sentence.
	if c.ApplicabilityReason != "" {
		if c.ApplicabilityBasis == model.BasisInferred {
			return c.ApplicabilityReason + " This is an inference, not an approval."
		}
		return c.ApplicabilityReason
	}
	return basis
}

func resultLabel(r model.Result) string {
	switch r {
	case model.ResultPass:
		return "Pass"
	case model.ResultFail:
		return "Fail"
	case model.ResultInconclusive:
		return "Inconclusive"
	default:
		return "Unknown"
	}
}

// controlAnchor builds a fragment identifier from a fixed character set.
func controlAnchor(agentIdx int, controlID string) string {
	var b strings.Builder
	for _, r := range strings.ToLower(controlID) {
		if r >= 'a' && r <= 'z' || r >= '0' && r <= '9' || r == '-' {
			b.WriteRune(r)
		}
	}
	return fmt.Sprintf("c-%d-%s", agentIdx, b.String())
}

// safeHTTPSURL returns raw only when it is an absolute https URL with a host
// and no credentials. Every other value, including javascript: and data:
// URLs, yields "" and is not linked.
func safeHTTPSURL(raw string) string {
	u, err := url.Parse(strings.TrimSpace(raw))
	if err != nil || u.Scheme != "https" || u.Host == "" || u.User != nil {
		return ""
	}
	return u.String()
}

func formatTime(t time.Time) string {
	if t.IsZero() {
		return "not recorded"
	}
	return t.UTC().Format("2006-01-02 15:04 UTC")
}
