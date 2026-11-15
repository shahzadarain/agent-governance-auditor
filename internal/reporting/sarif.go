// SPDX-License-Identifier: Apache-2.0

package reporting

import (
	"bytes"
	"fmt"
	"net/url"
	"sort"
	"strings"
	"unicode"

	"github.com/shahzadarain/agent-governance-auditor/internal/model"
)

const (
	sarifSchemaURI = "https://json.schemastore.org/sarif-2.1.0.json"
	sarifVersion   = "2.1.0"
	// sarifFingerprintKey names the stable fingerprint used for alert
	// tracking across scans.
	sarifFingerprintKey = "agentgovFingerprint/v1"
	sarifSrcRoot        = "%SRCROOT%"
)

type sarifLog struct {
	Schema  string     `json:"$schema"`
	Version string     `json:"version"`
	Runs    []sarifRun `json:"runs"`
}

type sarifRun struct {
	Tool              sarifTool         `json:"tool"`
	AutomationDetails sarifAutomation   `json:"automationDetails"`
	Results           []sarifResult     `json:"results"`
	Properties        sarifRunProperies `json:"properties"`
}

type sarifRunProperies struct {
	FindingsWithoutLocation int    `json:"findingsWithoutLocation"`
	Profile                 string `json:"profile"`
	PolicyPack              string `json:"policyPack"`
	PolicyVersion           string `json:"policyVersion"`
	ReleaseDecision         string `json:"releaseDecision"`
}

type sarifAutomation struct {
	ID string `json:"id"`
}

type sarifTool struct {
	Driver sarifDriver `json:"driver"`
}

type sarifDriver struct {
	Name           string      `json:"name"`
	Version        string      `json:"version,omitempty"`
	InformationURI string      `json:"informationUri,omitempty"`
	Rules          []sarifRule `json:"rules"`
}

type sarifText struct {
	Text string `json:"text"`
}

type sarifHelp struct {
	Text     string `json:"text"`
	Markdown string `json:"markdown"`
}

type sarifRule struct {
	ID                   string              `json:"id"`
	Name                 string              `json:"name"`
	ShortDescription     sarifText           `json:"shortDescription"`
	FullDescription      sarifText           `json:"fullDescription"`
	Help                 sarifHelp           `json:"help"`
	DefaultConfiguration sarifConfiguration  `json:"defaultConfiguration"`
	Properties           sarifRuleProperties `json:"properties"`
}

type sarifConfiguration struct {
	Level string `json:"level"`
}

type sarifRuleProperties struct {
	Tags             []string `json:"tags"`
	SecuritySeverity string   `json:"security-severity"`
}

type sarifResult struct {
	RuleID              string                `json:"ruleId"`
	RuleIndex           int                   `json:"ruleIndex"`
	Level               string                `json:"level"`
	Message             sarifText             `json:"message"`
	Locations           []sarifLocation       `json:"locations"`
	PartialFingerprints map[string]string     `json:"partialFingerprints"`
	Properties          sarifResultProperties `json:"properties"`
}

type sarifResultProperties struct {
	ControlID  string `json:"controlId"`
	AgentID    string `json:"agentId"`
	Severity   string `json:"severity"`
	Confidence string `json:"confidence"`
}

type sarifLocation struct {
	PhysicalLocation sarifPhysicalLocation `json:"physicalLocation"`
}

type sarifPhysicalLocation struct {
	ArtifactLocation sarifArtifactLocation `json:"artifactLocation"`
	Region           *sarifRegion          `json:"region,omitempty"`
}

type sarifArtifactLocation struct {
	URI       string `json:"uri"`
	URIBaseID string `json:"uriBaseId"`
}

type sarifRegion struct {
	StartLine int `json:"startLine"`
	EndLine   int `json:"endLine,omitempty"`
}

func sarifLevel(s model.Severity) string {
	switch s {
	case model.SeverityCritical, model.SeverityHigh:
		return "error"
	case model.SeverityMedium:
		return "warning"
	default:
		return "note"
	}
}

func sarifSecuritySeverity(s model.Severity) string {
	switch s {
	case model.SeverityCritical:
		return "9.5"
	case model.SeverityHigh:
		return "8.0"
	case model.SeverityMedium:
		return "5.5"
	case model.SeverityLow:
		return "3.0"
	default:
		return "0.0"
	}
}

// renderSARIF writes a SARIF 2.1.0 log. Only findings with a real file
// location become results; governance statuses without a code location stay
// in the JSON, Markdown, and HTML reports.
func renderSARIF(buf *bytes.Buffer, raw *model.ScanResult, opts Options) error {
	v, err := buildView(raw)
	if err != nil {
		return err
	}

	// Group findings by rule. v.findings is sorted most serious first, so the
	// first finding of each rule sets the rule's default level and text.
	byRule := map[string][]model.Finding{}
	var ruleIDs []string
	for _, f := range v.findings {
		id := sarifRuleID(f)
		if _, ok := byRule[id]; !ok {
			ruleIDs = append(ruleIDs, id)
		}
		byRule[id] = append(byRule[id], f)
	}
	sort.Strings(ruleIDs)

	rules := make([]sarifRule, 0, len(ruleIDs))
	ruleIndex := map[string]int{}
	for i, id := range ruleIDs {
		ruleIndex[id] = i
		rules = append(rules, sarifRuleFor(id, byRule[id][0]))
	}

	type located struct {
		f    model.Finding
		uri  string
		line int
	}
	var withLocation []located
	without := 0
	for _, f := range v.findings {
		uri, ok := sarifURI(f.Location)
		if !ok {
			without++
			continue
		}
		withLocation = append(withLocation, located{f, uri, f.Location.Line})
	}
	sort.SliceStable(withLocation, func(i, j int) bool {
		a, b := withLocation[i], withLocation[j]
		if a.uri != b.uri {
			return a.uri < b.uri
		}
		if a.line != b.line {
			return a.line < b.line
		}
		if ra, rb := sarifRuleID(a.f), sarifRuleID(b.f); ra != rb {
			return ra < rb
		}
		return a.f.Fingerprint < b.f.Fingerprint
	})

	results := make([]sarifResult, 0, len(withLocation))
	for _, l := range withLocation {
		f := l.f
		id := sarifRuleID(f)
		res := sarifResult{
			RuleID:    id,
			RuleIndex: ruleIndex[id],
			Level:     sarifLevel(f.Severity),
			Message:   sarifText{Text: sarifMessage(f)},
			Locations: []sarifLocation{{PhysicalLocation: sarifPhysicalLocation{
				ArtifactLocation: sarifArtifactLocation{URI: l.uri, URIBaseID: sarifSrcRoot},
			}}},
			PartialFingerprints: map[string]string{sarifFingerprintKey: orDefault(f.Fingerprint, f.FindingID)},
			Properties: sarifResultProperties{
				ControlID:  f.ControlID,
				AgentID:    f.AgentID,
				Severity:   severityKey(f.Severity),
				Confidence: string(f.Confidence),
			},
		}
		if f.Location.Line >= 1 {
			region := &sarifRegion{StartLine: f.Location.Line}
			if f.Location.EndLine > f.Location.Line {
				region.EndLine = f.Location.EndLine
			}
			res.Locations[0].PhysicalLocation.Region = region
		}
		results = append(results, res)
	}

	log := sarifLog{
		Schema:  sarifSchemaURI,
		Version: sarifVersion,
		Runs: []sarifRun{{
			Tool: sarifTool{Driver: sarifDriver{
				Name:           v.toolName,
				Version:        v.res.Tool.Version,
				InformationURI: opts.InformationURI,
				Rules:          rules,
			}},
			AutomationDetails: sarifAutomation{ID: "agentgov/" + sarifSlug(v.profile)},
			Results:           results,
			Properties: sarifRunProperies{
				FindingsWithoutLocation: without,
				Profile:                 v.profile,
				PolicyPack:              v.res.Scan.PolicyPack,
				PolicyVersion:           v.res.Scan.PolicyVersion,
				ReleaseDecision:         string(v.outcome),
			},
		}},
	}
	return writeJSON(buf, log)
}

func sarifRuleID(f model.Finding) string {
	if id := strings.TrimSpace(f.RuleID); id != "" {
		return id
	}
	if f.ControlID != "" {
		return f.ControlID + ".unspecified"
	}
	return "agentgov.unspecified"
}

func sarifRuleFor(id string, f model.Finding) sarifRule {
	short := orDefault(f.Title, id)
	full := orDefault(f.WhyItMatters, orDefault(f.Description, short))
	var text, markdown strings.Builder
	if f.WhyItMatters != "" {
		text.WriteString(f.WhyItMatters + "\n\n")
		markdown.WriteString(md(f.WhyItMatters) + "\n\n")
	}
	if len(f.Remediation) > 0 {
		text.WriteString("How to fix:\n")
		markdown.WriteString("**How to fix**\n\n")
		for i, step := range f.Remediation {
			fmt.Fprintf(&text, "%d. %s\n", i+1, step)
			fmt.Fprintf(&markdown, "%d. %s\n", i+1, md(step))
		}
	} else {
		text.WriteString("No remediation steps were recorded for this rule.\n")
		markdown.WriteString("No remediation steps were recorded for this rule.\n")
	}
	tags := []string{"security", "ai-agent-governance"}
	if f.ControlID != "" {
		tags = append(tags, f.ControlID)
	}
	return sarifRule{
		ID:                   id,
		Name:                 sarifRuleName(id),
		ShortDescription:     sarifText{Text: short},
		FullDescription:      sarifText{Text: full},
		Help:                 sarifHelp{Text: strings.TrimRight(text.String(), "\n"), Markdown: strings.TrimRight(markdown.String(), "\n")},
		DefaultConfiguration: sarifConfiguration{Level: sarifLevel(f.Severity)},
		Properties: sarifRuleProperties{
			Tags:             tags,
			SecuritySeverity: sarifSecuritySeverity(f.Severity),
		},
	}
}

// sarifRuleName turns "AGC-008.hardcoded-secret" into "HardcodedSecret".
func sarifRuleName(id string) string {
	name := id
	if i := strings.LastIndex(id, "."); i >= 0 && i+1 < len(id) {
		name = id[i+1:]
	}
	var b strings.Builder
	upper := true
	for _, r := range name {
		if !unicode.IsLetter(r) && !unicode.IsDigit(r) {
			upper = true
			continue
		}
		if upper {
			b.WriteRune(unicode.ToUpper(r))
			upper = false
		} else {
			b.WriteRune(r)
		}
	}
	if b.Len() == 0 {
		return "Unspecified"
	}
	return b.String()
}

func sarifMessage(f model.Finding) string {
	title := strings.TrimSpace(f.Title)
	desc := strings.TrimSpace(f.Description)
	switch {
	case title == "" && desc == "":
		return "Finding reported by rule " + sarifRuleID(f) + "."
	case title == "":
		return desc
	case desc == "" || desc == title:
		return title
	default:
		return strings.TrimRight(title, ".") + ". " + desc
	}
}

// sarifURI converts a repository-relative location to a percent-encoded
// relative URI with forward slashes. It reports false when the finding has no
// usable file location: no path, an absolute path, or a path that leaves the
// repository.
func sarifURI(l *model.Location) (string, bool) {
	if l == nil {
		return "", false
	}
	p := strings.ReplaceAll(strings.TrimSpace(l.Path), "\\", "/")
	if p == "" || strings.HasPrefix(p, "/") {
		return "", false
	}
	if len(p) >= 2 && p[1] == ':' { // drive letter
		return "", false
	}
	var segs []string
	for _, s := range strings.Split(p, "/") {
		switch s {
		case "", ".":
			continue
		case "..":
			return "", false
		}
		segs = append(segs, strings.ReplaceAll(url.PathEscape(s), ":", "%3A"))
	}
	if len(segs) == 0 {
		return "", false
	}
	return strings.Join(segs, "/"), true
}

// sarifSlug keeps the automation ID to a safe character set.
func sarifSlug(s string) string {
	var b strings.Builder
	for _, r := range strings.ToLower(s) {
		switch {
		case r >= 'a' && r <= 'z', r >= '0' && r <= '9', r == '-', r == '_', r == '.':
			b.WriteRune(r)
		default:
			b.WriteByte('-')
		}
	}
	if b.Len() == 0 {
		return model.Unknown
	}
	return b.String()
}
