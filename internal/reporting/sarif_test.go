// SPDX-License-Identifier: Apache-2.0

package reporting

import (
	"encoding/json"
	"net/url"
	"regexp"
	"strconv"
	"strings"
	"testing"

	"github.com/shahzadarain/agent-governance-auditor/internal/model"
	"github.com/shahzadarain/agent-governance-auditor/internal/reporting/reportingtest"
)

// The official SARIF schema cannot be fetched during offline tests, so this
// validator checks the structure that SARIF 2.1.0 requires and the properties
// that GitHub code scanning reads.

func obj(t *testing.T, v any, path string) map[string]any {
	t.Helper()
	m, ok := v.(map[string]any)
	if !ok {
		t.Fatalf("%s: want an object, got %T", path, v)
	}
	return m
}

func arr(t *testing.T, v any, path string) []any {
	t.Helper()
	a, ok := v.([]any)
	if !ok {
		t.Fatalf("%s: want an array, got %T", path, v)
	}
	return a
}

func str(t *testing.T, v any, path string) string {
	t.Helper()
	s, ok := v.(string)
	if !ok || s == "" {
		t.Fatalf("%s: want a non-empty string, got %#v", path, v)
	}
	return s
}

var sarifLevels = map[string]bool{"error": true, "warning": true, "note": true}

// validateSARIF checks one rendered log and returns its single run.
func validateSARIF(t *testing.T, out string) map[string]any {
	t.Helper()
	var doc any
	if err := json.Unmarshal([]byte(out), &doc); err != nil {
		t.Fatalf("SARIF is not valid JSON: %v", err)
	}
	root := obj(t, doc, "$")
	if got := str(t, root["$schema"], "$schema"); got != "https://json.schemastore.org/sarif-2.1.0.json" {
		t.Errorf("$schema = %q", got)
	}
	if got := str(t, root["version"], "version"); got != "2.1.0" {
		t.Errorf("version = %q", got)
	}
	runs := arr(t, root["runs"], "runs")
	if len(runs) != 1 {
		t.Fatalf("runs has %d entries, want 1", len(runs))
	}
	run := obj(t, runs[0], "runs[0]")
	driver := obj(t, obj(t, run["tool"], "tool")["driver"], "tool.driver")
	str(t, driver["name"], "tool.driver.name")

	rules := arr(t, driver["rules"], "tool.driver.rules")
	ruleIDs := make([]string, len(rules))
	seen := map[string]bool{}
	for i, r := range rules {
		p := "rules[" + strconv.Itoa(i) + "]"
		rule := obj(t, r, p)
		id := str(t, rule["id"], p+".id")
		if seen[id] {
			t.Errorf("%s: duplicate rule id %q", p, id)
		}
		seen[id] = true
		ruleIDs[i] = id
		if i > 0 && ruleIDs[i-1] >= id {
			t.Errorf("%s: rules are not sorted by id", p)
		}
		if name := str(t, rule["name"], p+".name"); !regexp.MustCompile(`^[A-Za-z0-9]+$`).MatchString(name) {
			t.Errorf("%s.name = %q, want letters and digits only", p, name)
		}
		str(t, obj(t, rule["shortDescription"], p+".shortDescription")["text"], p+".shortDescription.text")
		str(t, obj(t, rule["fullDescription"], p+".fullDescription")["text"], p+".fullDescription.text")
		help := obj(t, rule["help"], p+".help")
		str(t, help["text"], p+".help.text")
		str(t, help["markdown"], p+".help.markdown")
		if level := str(t, obj(t, rule["defaultConfiguration"], p+".defaultConfiguration")["level"], p+".level"); !sarifLevels[level] {
			t.Errorf("%s: invalid level %q", p, level)
		}
		props := obj(t, rule["properties"], p+".properties")
		hasSecurity, hasControl := false, false
		for _, tag := range arr(t, props["tags"], p+".properties.tags") {
			switch s := tag.(string); {
			case s == "security":
				hasSecurity = true
			case strings.HasPrefix(s, "AGC-"):
				hasControl = true
			}
		}
		if !hasSecurity || !hasControl {
			t.Errorf("%s: tags must include \"security\" and the control ID", p)
		}
		sev := str(t, props["security-severity"], p+".properties.security-severity")
		if f, err := strconv.ParseFloat(sev, 64); err != nil || f < 0 || f > 10 {
			t.Errorf("%s: security-severity %q is not a number from 0 to 10", p, sev)
		}
	}

	results := arr(t, run["results"], "results")
	for i, r := range results {
		p := "results[" + strconv.Itoa(i) + "]"
		res := obj(t, r, p)
		id := str(t, res["ruleId"], p+".ruleId")
		idx, ok := res["ruleIndex"].(float64)
		if !ok || int(idx) < 0 || int(idx) >= len(ruleIDs) || ruleIDs[int(idx)] != id {
			t.Errorf("%s: ruleIndex %v does not point at rule %q", p, res["ruleIndex"], id)
		}
		if level := str(t, res["level"], p+".level"); !sarifLevels[level] {
			t.Errorf("%s: invalid level %q", p, level)
		}
		str(t, obj(t, res["message"], p+".message")["text"], p+".message.text")
		locs := arr(t, res["locations"], p+".locations")
		if len(locs) != 1 {
			t.Fatalf("%s: %d locations, want 1", p, len(locs))
		}
		phys := obj(t, obj(t, locs[0], p+".locations[0]")["physicalLocation"], p+".physicalLocation")
		art := obj(t, phys["artifactLocation"], p+".artifactLocation")
		uri := str(t, art["uri"], p+".artifactLocation.uri")
		checkRelativeURI(t, p, uri)
		if base := str(t, art["uriBaseId"], p+".uriBaseId"); base != "%SRCROOT%" {
			t.Errorf("%s: uriBaseId = %q", p, base)
		}
		if region, ok := phys["region"]; ok {
			start, ok := obj(t, region, p+".region")["startLine"].(float64)
			if !ok || start < 1 {
				t.Errorf("%s: region.startLine = %v, want 1 or more", p, obj(t, region, p)["startLine"])
			}
		}
		fps := obj(t, res["partialFingerprints"], p+".partialFingerprints")
		str(t, fps["agentgovFingerprint/v1"], p+".partialFingerprints[agentgovFingerprint/v1]")
	}
	return run
}

func checkRelativeURI(t *testing.T, p, uri string) {
	t.Helper()
	u, err := url.Parse(uri)
	if err != nil {
		t.Errorf("%s: uri %q does not parse: %v", p, uri, err)
		return
	}
	if u.Scheme != "" || u.Host != "" || strings.HasPrefix(uri, "/") {
		t.Errorf("%s: uri %q is not repository-relative", p, uri)
	}
	if !regexp.MustCompile(`^[A-Za-z0-9\-._~!$&'()*+,;=@/%]+$`).MatchString(uri) {
		t.Errorf("%s: uri %q contains characters that must be percent-encoded", p, uri)
	}
	for _, seg := range strings.Split(uri, "/") {
		if seg == ".." || seg == "." || seg == "" {
			t.Errorf("%s: uri %q has an empty, dot, or parent segment", p, uri)
		}
	}
}

func TestSARIFStructure(t *testing.T) {
	for _, s := range samples {
		t.Run(s.name, func(t *testing.T) {
			res := s.make()
			run := validateSARIF(t, render(t, res, FormatSARIF, Options{}))
			with, without := 0, 0
			for _, f := range res.Findings {
				if f.Location != nil && f.Location.Path != "" {
					with++
				} else {
					without++
				}
			}
			if got := len(arr(t, run["results"], "results")); got != with {
				t.Errorf("results = %d, want %d (findings with a file location)", got, with)
			}
			props := obj(t, run["properties"], "run.properties")
			if got := props["findingsWithoutLocation"]; got != float64(without) {
				t.Errorf("findingsWithoutLocation = %v, want %d", got, without)
			}
			id := str(t, obj(t, run["automationDetails"], "automationDetails")["id"], "automationDetails.id")
			if !regexp.MustCompile(`^agentgov/[a-z0-9._-]+$`).MatchString(id) {
				t.Errorf("automationDetails.id = %q", id)
			}
		})
	}
}

func TestSARIFBlockedDetails(t *testing.T) {
	out := render(t, reportingtest.Blocked(), FormatSARIF, Options{})
	run := validateSARIF(t, out)
	driver := obj(t, obj(t, run["tool"], "tool")["driver"], "driver")
	if driver["name"] != "AgentGov Auditor" || driver["version"] != "0.1.0" {
		t.Errorf("driver = %v %v", driver["name"], driver["version"])
	}
	if _, ok := driver["informationUri"]; ok {
		t.Error("informationUri must be left out unless it is given in the options")
	}
	if id := obj(t, run["automationDetails"], "automationDetails")["id"]; id != "agentgov/high-risk" {
		t.Errorf("automationDetails.id = %v", id)
	}
	rules := arr(t, driver["rules"], "rules")
	if len(rules) != 8 {
		t.Errorf("rules = %d, want 8 distinct rule IDs", len(rules))
	}
	results := arr(t, run["results"], "results")
	if len(results) != 6 {
		t.Fatalf("results = %d, want 6", len(results))
	}
	wantSeverity := map[string][2]string{
		"AGC-010.approval-bypass":      {"error", "9.5"},
		"AGC-004.shared-account":       {"error", "8.0"},
		"AGC-005.undeclared-tool":      {"warning", "5.5"},
		"AGC-023.plain-logs-only":      {"note", "3.0"},
		"AGC-014.unpinned-mcp-server":  {"warning", "5.5"},
		"AGC-009.no-enforcement-point": {"error", "8.0"},
	}
	for _, r := range rules {
		rule := obj(t, r, "rule")
		id := rule["id"].(string)
		want, ok := wantSeverity[id]
		if !ok {
			continue
		}
		level := obj(t, rule["defaultConfiguration"], "cfg")["level"]
		sev := obj(t, rule["properties"], "props")["security-severity"]
		if level != want[0] || sev != want[1] {
			t.Errorf("rule %s: level %v, security-severity %v; want %s, %s", id, level, sev, want[0], want[1])
		}
	}
	var approval map[string]any
	for _, r := range results {
		if res := obj(t, r, "result"); res["ruleId"] == "AGC-010.approval-bypass" {
			approval = res
		}
	}
	if approval == nil {
		t.Fatal("no result for AGC-010.approval-bypass")
	}
	phys := obj(t, obj(t, arr(t, approval["locations"], "locations")[0], "loc")["physicalLocation"], "phys")
	if uri := obj(t, phys["artifactLocation"], "art")["uri"]; uri != "src/actions.py" {
		t.Errorf("uri = %v", uri)
	}
	if line := obj(t, phys["region"], "region")["startLine"]; line != float64(86) {
		t.Errorf("startLine = %v", line)
	}
	if fp := obj(t, approval["partialFingerprints"], "fp")["agentgovFingerprint/v1"]; fp != "1f0a9c3e5b7d2a4c6e8f0b1d3a5c7e9f" {
		t.Errorf("fingerprint = %v", fp)
	}
	if approval["level"] != "error" {
		t.Errorf("level = %v", approval["level"])
	}

	withURI := render(t, reportingtest.Blocked(), FormatSARIF, Options{InformationURI: "https://example.org/agentgov"})
	if !strings.Contains(withURI, `"informationUri": "https://example.org/agentgov"`) {
		t.Error("informationUri from the options is missing")
	}
}

func TestSARIFLocations(t *testing.T) {
	res := reportingtest.Blocked()
	set := func(i int, path string, line int) { res.Findings[i].Location = &model.Location{Path: path, Line: line} }
	set(0, "src\\win dir\\a b#c?.py", 0)    // backslashes, spaces, reserved characters, no line
	set(1, "./docs/r\u00e9sum\u00e9.md", 3) // leading ./ and non-ASCII
	set(2, "../outside/secret.py", 1)       // leaves the repository
	set(3, "/etc/passwd", 1)                // absolute
	set(5, "C:\\Users\\x\\file.py", 1)      // drive letter
	set(6, "weird:name/file.py", 2)         // colon in the first segment
	out := render(t, res, FormatSARIF, Options{})
	run := validateSARIF(t, out)
	results := arr(t, run["results"], "results")
	uris := map[string]map[string]any{}
	for _, r := range results {
		phys := obj(t, obj(t, arr(t, obj(t, r, "r")["locations"], "l")[0], "l0")["physicalLocation"], "p")
		uris[obj(t, phys["artifactLocation"], "a")["uri"].(string)] = phys
	}
	for _, want := range []string{"src/win%20dir/a%20b%23c%3F.py", "docs/r%C3%A9sum%C3%A9.md", "weird%3Aname/file.py"} {
		if _, ok := uris[want]; !ok {
			t.Errorf("expected a result with uri %q; got %v", want, keys(uris))
		}
	}
	if phys := uris["src/win%20dir/a%20b%23c%3F.py"]; phys != nil {
		if _, ok := phys["region"]; ok {
			t.Error("a finding with line 0 must not have a region")
		}
	}
	if len(results) != 3 {
		t.Errorf("results = %d, want 3: paths outside the repository must be left out", len(results))
	}
	if got := obj(t, run["properties"], "props")["findingsWithoutLocation"]; got != float64(5) {
		t.Errorf("findingsWithoutLocation = %v, want 5", got)
	}
}

func keys(m map[string]map[string]any) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	return out
}

func TestSARIFHostile(t *testing.T) {
	for name, res := range hostileResults() {
		out := render(t, res, FormatSARIF, Options{})
		validateSARIF(t, out)
		for _, raw := range []string{"<script>", "\x1b", "\\u001b", "\\r"} {
			if strings.Contains(out, raw) {
				t.Errorf("%s: SARIF contains %q", name, raw)
			}
		}
	}
}

func TestSARIFNoFindings(t *testing.T) {
	out := render(t, reportingtest.NoAgent(), FormatSARIF, Options{})
	run := validateSARIF(t, out)
	if !strings.Contains(out, `"rules": []`) || !strings.Contains(out, `"results": []`) {
		t.Error("an empty SARIF log must carry empty rules and results arrays, not null")
	}
	if len(arr(t, run["results"], "results")) != 0 {
		t.Error("expected no results")
	}
}
