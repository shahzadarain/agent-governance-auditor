// SPDX-License-Identifier: Apache-2.0

package reporting

import (
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"html"
	"regexp"
	"strings"
	"testing"

	"github.com/shahzadarain/agent-governance-auditor/internal/reporting/reportingtest"
)

var (
	styleBlock  = regexp.MustCompile(`(?s)<style>(.*?)</style>`)
	scriptBlock = regexp.MustCompile(`(?s)<script>(.*?)</script>`)
	tagPattern  = regexp.MustCompile(`<(/?)([a-zA-Z][a-zA-Z0-9]*)((?:[^>"']|"[^"]*"|'[^']*')*)>`)
	attrPattern = regexp.MustCompile(`([a-zA-Z_:][-a-zA-Z0-9_:.]*)(?:\s*=\s*(?:"([^"]*)"|'([^']*)'|([^\s"'>]+)))?`)
)

var voidElements = map[string]bool{
	"meta": true, "br": true, "input": true, "hr": true, "img": true, "link": true,
}

// markup returns the page without the contents of its style and script
// blocks, so that tag checks look only at HTML.
func markup(page string) string {
	page = styleBlock.ReplaceAllString(page, "<style></style>")
	return scriptBlock.ReplaceAllString(page, "<script></script>")
}

// checkBalanced verifies that every element is closed in order. Because all
// scan data is escaped, any imbalance means that data broke the markup or
// that the template is wrong.
func checkBalanced(t *testing.T, page string) {
	t.Helper()
	var stack []string
	for _, m := range tagPattern.FindAllStringSubmatch(markup(page), -1) {
		closing, name, rest := m[1] == "/", strings.ToLower(m[2]), m[3]
		if voidElements[name] || strings.HasSuffix(strings.TrimSpace(rest), "/") {
			continue
		}
		if !closing {
			stack = append(stack, name)
			continue
		}
		if len(stack) == 0 || stack[len(stack)-1] != name {
			t.Fatalf("unbalanced markup: closing </%s> with open elements %v", name, stack)
		}
		stack = stack[:len(stack)-1]
	}
	if len(stack) != 0 {
		t.Fatalf("unbalanced markup: unclosed elements %v", stack)
	}
}

// allowedElements is every element the template writes. Scan data must never
// add another one.
var allowedElements = map[string]bool{
	"html": true, "head": true, "meta": true, "title": true, "style": true, "body": true, "a": true,
	"svg": true, "symbol": true, "circle": true, "path": true, "rect": true, "use": true, "text": true,
	"header": true, "main": true, "footer": true, "section": true, "article": true, "div": true,
	"span": true, "p": true, "strong": true, "b": true, "i": true, "br": true,
	"h1": true, "h2": true, "h3": true, "h4": true, "ul": true, "ol": true, "li": true,
	"dl": true, "dt": true, "dd": true, "details": true, "summary": true,
	"table": true, "thead": true, "tbody": true, "tr": true, "th": true, "td": true,
	"label": true, "input": true, "select": true, "option": true, "button": true, "script": true,
}

// checkNoInjection asserts the structural security properties of a page.
func checkNoInjection(t *testing.T, name, page string) {
	t.Helper()
	body := markup(page)
	if n := strings.Count(page, "<script"); n != 1 {
		t.Errorf("%s: page has %d script elements, want exactly 1", name, n)
	}
	if n := strings.Count(page, "<style"); n != 1 {
		t.Errorf("%s: page has %d style elements, want exactly 1", name, n)
	}
	for _, raw := range []string{
		"<script>alert(1)</script>", `" onmouseover="`, "<img", "<iframe", "<object", "<embed", "<form", "<base", "<link",
		"<!--", "url(", "@import", "srcdoc", "innerHTML", "document.write", "eval(",
	} {
		if strings.Contains(page, raw) {
			t.Errorf("%s: page contains %q", name, raw)
		}
	}
	for _, m := range tagPattern.FindAllStringSubmatch(body, -1) {
		tag := strings.ToLower(m[2])
		if !allowedElements[tag] {
			t.Errorf("%s: unexpected element <%s>", name, tag)
		}
		if m[1] == "/" {
			continue
		}
		for _, a := range attrPattern.FindAllStringSubmatch(m[3], -1) {
			attr := strings.ToLower(a[1])
			value := html.UnescapeString(a[2] + a[3] + a[4])
			switch {
			case strings.HasPrefix(attr, "on"):
				t.Errorf("%s: event handler attribute %s on <%s>", name, attr, tag)
			case attr == "style":
				t.Errorf("%s: inline style attribute on <%s>; the policy pins styles by hash", name, tag)
			case attr == "src" || attr == "srcset" || attr == "action" || attr == "formaction" || attr == "data" || attr == "poster":
				t.Errorf("%s: attribute %s on <%s> could load a resource", name, attr, tag)
			case attr == "href" || attr == "xlink:href":
				if strings.HasPrefix(value, "#") {
					continue
				}
				// Only anchors may point away, only to https, and only
				// with rel="noopener noreferrer".
				if tag != "a" || !strings.HasPrefix(value, "https://") || !strings.Contains(m[3], `rel="noopener noreferrer"`) {
					t.Errorf("%s: disallowed link target %q on <%s>", name, value, tag)
				}
			}
		}
	}
	checkBalanced(t, page)
}

func TestHTMLIsSelfContained(t *testing.T) {
	for _, s := range samples {
		page := render(t, s.make(), FormatHTML, Options{})
		checkNoInjection(t, s.name, page)
		if !strings.HasPrefix(page, "<!DOCTYPE html>\n<html lang=\"en\">") {
			t.Errorf("%s: page does not start with a doctype and lang=en", s.name)
		}
	}
}

func TestHTMLContentSecurityPolicyPinsInlineBlocks(t *testing.T) {
	page := render(t, reportingtest.Hostile(), FormatHTML, Options{})
	m := regexp.MustCompile(`<meta http-equiv="Content-Security-Policy" content="([^"]*)">`).FindStringSubmatch(page)
	if m == nil {
		t.Fatal("no Content-Security-Policy meta element")
	}
	csp := html.UnescapeString(m[1])
	for _, want := range []string{"default-src 'none'", "img-src data:", "base-uri 'none'", "form-action 'none'"} {
		if !strings.Contains(csp, want) {
			t.Errorf("policy %q is missing %q", csp, want)
		}
	}
	for _, banned := range []string{"unsafe-eval", "unsafe-inline", "http:", "https:", "*"} {
		if strings.Contains(csp, banned) {
			t.Errorf("policy %q contains %q", csp, banned)
		}
	}
	hash := func(s string) string {
		sum := sha256.Sum256([]byte(s))
		return "'sha256-" + base64.StdEncoding.EncodeToString(sum[:]) + "'"
	}
	// The hashes must match the bytes that are actually in the page, or the
	// browser would refuse to apply the style and run the script.
	style := styleBlock.FindStringSubmatch(page)
	script := scriptBlock.FindStringSubmatch(page)
	if style == nil || script == nil {
		t.Fatal("style or script block not found")
	}
	if want := "style-src " + hash(style[1]); !strings.Contains(csp, want) {
		t.Errorf("policy does not pin the emitted style block: want %s in %s", want, csp)
	}
	if want := "script-src " + hash(script[1]); !strings.Contains(csp, want) {
		t.Errorf("policy does not pin the emitted script block: want %s in %s", want, csp)
	}
	if strings.Index(page, "Content-Security-Policy") > strings.Index(page, "<style>") {
		t.Error("the policy must come before the style block")
	}
}

func TestHTMLEscapesHostileContent(t *testing.T) {
	for name, res := range hostileResults() {
		page := render(t, res, FormatHTML, Options{})
		checkNoInjection(t, name, page)
		// The payloads are present as inert, escaped text.
		for _, escaped := range []string{"&lt;script&gt;alert(1)&lt;/script&gt;", "&#34; onmouseover=&#34;alert(1)"} {
			if !strings.Contains(page, escaped) {
				t.Errorf("%s: expected the escaped payload %q in the page", name, escaped)
			}
		}
		if strings.Contains(page, "ZgotmplZ") {
			t.Errorf("%s: the template engine had to block a value; hostile data reached an unsafe context", name)
		}
	}
	// A javascript: mapping URL is shown as text only; an https URL is linked.
	hostile := render(t, reportingtest.Hostile(), FormatHTML, Options{})
	if strings.Contains(hostile, `rel="noopener noreferrer"`) {
		t.Error("the hostile sample has no https mapping URL, so no external link is expected")
	}
	blocked := render(t, reportingtest.Blocked(), FormatHTML, Options{})
	if !strings.Contains(blocked, `<a href="https://genai.owasp.org/llmrisk/llm062025-excessive-agency/" rel="noopener noreferrer">`) {
		t.Error("an https mapping URL should be linked with rel=noopener noreferrer")
	}
}

func TestSafeHTTPSURL(t *testing.T) {
	cases := map[string]string{
		"https://example.org/a?b=c":      "https://example.org/a?b=c",
		"http://example.org/":            "",
		"javascript:alert(1)":            "",
		"JaVaScRiPt:alert(1)":            "",
		"data:text/html,<script>":        "",
		"//example.org/x":                "",
		"https://user:pw@example.org/":   "",
		"https:///nohost":                "",
		" https://example.org ":          "https://example.org",
		"vbscript:msgbox":                "",
		"":                               "",
		"https://example.org/\x00broken": "",
	}
	for in, want := range cases {
		if got := safeHTTPSURL(in); got != want {
			t.Errorf("safeHTTPSURL(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestHTMLStructure(t *testing.T) {
	page := render(t, reportingtest.Blocked(), FormatHTML, Options{})
	for _, want := range []string{
		`<meta charset="utf-8">`,
		`<meta name="viewport" content="width=device-width, initial-scale=1">`,
		`<title>AgentGov Auditor report: BLOCK</title>`,
		`<a class="skip" href="#main">Skip to main content</a>`,
		`<main id="main"`,
		`<p class="decision-name">BLOCK</p>`,
		`Do not release until the listed controls are fixed.`,
		`<use href="#i-block"/>`,
		`aria-label="Assessment maturity `,
		`illustrative only`,
		`Evidence coverage`, `Verified by tests`, `Verified in operation`,
		`What to fix first`, `Agents found`, `Controls`, `Findings`,
		`Warnings and limits of this scan`, `How to read this report`,
		`id="f-search"`, `id="f-severity"`, `id="f-status"`, `id="f-reset"`, `id="c-group"`,
		`role="status" aria-live="polite"`,
		`<label class="field" for="f-search">`,
		`<th scope="col">Severity</th>`, `<th scope="row"`,
		`prefers-color-scheme:dark`, `prefers-reduced-motion:reduce`, `@media print`, `:focus-visible`,
		`max-width:720px`,
		`#0B1220`, `#3B82F6`, `#06B6D4`, `#F8FAFC`, `#FFFFFF`, `#10B981`, `#F59E0B`, `#EF4444`,
		`Source type`, `Validity`, `Integrity`, `Observed`, `Valid until`, `2026-01-01 00:00 UTC`,
		`The evidence expired on 2026-01-01.`, `Limits of this evidence`,
		`This is an evidence-based assessment, not a certification.`,
	} {
		if !strings.Contains(page, want) {
			t.Errorf("page is missing %q", want)
		}
	}
	if n := strings.Count(page, `<details class="tile`); n != 24 {
		t.Errorf("page has %d control tiles, want 24", n)
	}
	for _, domain := range []string{"A: Accountability", "B: Identity and Access", "C: Action Controls", "D: Trust Boundaries", "E: Containment and Recovery", "F: Assurance and Visibility"} {
		if n := strings.Count(page, "<h3>"+domain+"</h3>"); n != 1 {
			t.Errorf("domain heading %q appears %d times, want 1", domain, n)
		}
	}
	if n := strings.Count(page, "<tr data-finding "); n != 8 {
		t.Errorf("page has %d finding rows, want 8", n)
	}
	if n := strings.Count(page, `<article class="card fix `); n != maxPriority {
		t.Errorf("page has %d priority cards, want %d", n, maxPriority)
	}
	if n := strings.Count(page, "<h1"); n != 1 {
		t.Errorf("page has %d h1 elements, want 1", n)
	}
	// Every table header cell has a scope, and every control tile has a
	// status label in text, so status never depends on color alone.
	for _, th := range regexp.MustCompile(`<th[ >][^>]*>?`).FindAllString(page, -1) {
		if !strings.Contains(th, "scope=") {
			t.Errorf("table header without scope: %s", th)
		}
	}
	tiles := regexp.MustCompile(`(?s)<details class="tile.*?</summary>`).FindAllString(page, -1)
	for _, tile := range tiles {
		labelled := false
		for _, st := range AllStatuses() {
			if strings.Contains(tile, StatusLabel(st)) {
				labelled = true
			}
		}
		if !labelled || !regexp.MustCompile(`Maturity [0-4]/4|Not scored`).MatchString(tile) {
			t.Errorf("control tile lacks a text status label or maturity: %s", tile)
		}
	}
	// Each finding row carries the filter attributes the script reads.
	rows := regexp.MustCompile(`<tr data-finding data-severity="(critical|high|medium|low|info|unrated)" data-status="[^"]+">`).FindAllString(page, -1)
	if len(rows) != 8 {
		t.Errorf("%d finding rows carry filter attributes, want 8", len(rows))
	}
	// Anchors from the priority cards resolve to control tiles.
	for _, m := range regexp.MustCompile(`<a href="#(c-[^"]+)">`).FindAllStringSubmatch(page, -1) {
		if !strings.Contains(page, fmt.Sprintf(`id="%s"`, m[1])) {
			t.Errorf("anchor #%s has no target", m[1])
		}
	}
	ids := map[string]bool{}
	for _, m := range regexp.MustCompile(` id="([^"]+)"`).FindAllStringSubmatch(markup(page), -1) {
		if ids[m[1]] {
			t.Errorf("duplicate id %q", m[1])
		}
		ids[m[1]] = true
	}
	for _, m := range regexp.MustCompile(`aria-labelledby="([^"]+)"`).FindAllStringSubmatch(page, -1) {
		if !ids[m[1]] {
			t.Errorf("aria-labelledby points at missing id %q", m[1])
		}
	}
	for _, m := range regexp.MustCompile(`<label class="field" for="([^"]+)">`).FindAllStringSubmatch(page, -1) {
		if !ids[m[1]] {
			t.Errorf("label points at missing control %q", m[1])
		}
	}
	for _, m := range regexp.MustCompile(`<use href="#([^"]+)"/>`).FindAllStringSubmatch(page, -1) {
		if !ids[m[1]] {
			t.Errorf("icon reference points at missing symbol %q", m[1])
		}
	}
}

func TestHTMLScriptOnlyTogglesVisibility(t *testing.T) {
	for _, banned := range []string{"innerHTML", "outerHTML", "insertAdjacentHTML", "document.write", "eval(", "Function(", "fetch(", "XMLHttpRequest", "import(", "localStorage", "cookie", "//", "/*", "`"} {
		if strings.Contains(htmlJS, banned) {
			t.Errorf("the report script contains %q", banned)
		}
	}
	for _, banned := range []string{"url(", "@import", "http", "/*", "expression("} {
		if strings.Contains(htmlCSS, banned) {
			t.Errorf("the report stylesheet contains %q", banned)
		}
	}
}

func TestHTMLNoAgentPage(t *testing.T) {
	page := render(t, reportingtest.NoAgent(), FormatHTML, Options{})
	for _, want := range []string{"No AI agent was detected", "Insufficient evidence", "REVIEW REQUIRED", "This is not a pass."} {
		if !strings.Contains(page, want) {
			t.Errorf("no-agent page is missing %q", want)
		}
	}
	if strings.Contains(page, `<details class="tile`) || strings.Contains(page, `class="dial"`) {
		t.Error("no-agent page shows control tiles or a score dial")
	}
}
