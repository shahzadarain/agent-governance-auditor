// SPDX-License-Identifier: Apache-2.0

package reporting

import (
	"reflect"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/shahzadarain/agent-governance-auditor/internal/model"
	"github.com/shahzadarain/agent-governance-auditor/internal/reporting/reportingtest"
)

// poison is appended to every plain string of a scan result by poisonAll.
const poison = "\x1b[2J\r<script>alert(1)</script>\" onmouseover=\"alert(1)\x07 ](javascript:alert(1)) <!-- | ``` ‮\x9b31m"

// poisonAll returns the blocked sample with the poison string appended to
// every field of plain string type, including identifiers, references, and
// map keys. Typed enumerations are left alone. Because the same suffix is
// added everywhere, references between records still resolve.
func poisonAll() *model.ScanResult {
	res := reportingtest.Blocked()
	var visit func(v reflect.Value)
	plain := reflect.TypeOf("")
	visit = func(v reflect.Value) {
		switch v.Kind() {
		case reflect.String:
			if v.Type() == plain && v.CanSet() {
				v.SetString(v.String() + poison)
			}
		case reflect.Pointer:
			if !v.IsNil() {
				visit(v.Elem())
			}
		case reflect.Struct:
			if v.Type() == reflect.TypeOf(time.Time{}) {
				return
			}
			for i := 0; i < v.NumField(); i++ {
				visit(v.Field(i))
			}
		case reflect.Slice:
			for i := 0; i < v.Len(); i++ {
				visit(v.Index(i))
			}
		case reflect.Map:
			rebuilt := reflect.MakeMap(v.Type())
			iter := v.MapRange()
			for iter.Next() {
				rebuilt.SetMapIndex(reflect.ValueOf(iter.Key().String()+poison), iter.Value())
			}
			v.Set(rebuilt)
		}
	}
	visit(reflect.ValueOf(res).Elem())
	return res
}

func hostileResults() map[string]*model.ScanResult {
	return map[string]*model.ScanResult{
		"hostile":  reportingtest.Hostile(),
		"poisoned": poisonAll(),
	}
}

func TestClean(t *testing.T) {
	cases := map[string]string{
		"plain text":                      "plain text",
		"src/\x1b[2Jevil\r.py":            "src/evil.py",
		"\x1b[31mred\x1b[0m":              "red",
		"a\x1b]0;window title\x07b":       "ab",
		"a\x1b]8;;https://evil\x1b\\link": "alink",
		"line one\nline two\tend":         "line one line two end",
		"safe text\roverwritten":          "safe textoverwritten",
		"bell\x07 null\x00 del\x7f":       "bell null del",
		"c1 \u009b31m csi":                "c1  csi",
		"rtl ‮override‬ ⁦iso":             "rtl override iso",
		"café 日本":                         "café 日本",
		"bad utf8 \xff\xfe":               "bad utf8 �",
		"trailing escape \x1b":            "trailing escape ",
		"\x1b(B charset":                  " charset",
	}
	for in, want := range cases {
		if got := clean(in); got != want {
			t.Errorf("clean(%q) = %q, want %q", in, got, want)
		}
	}
}

func hasControl(s string) (rune, bool) {
	for _, r := range s {
		if r != '\n' && (r < 0x20 || r == 0x7f || (r >= 0x80 && r <= 0x9f)) {
			return r, true
		}
		if isBidiControl(r) {
			return r, true
		}
	}
	return 0, false
}

func TestTerminalStripsEscapesAndControlCharacters(t *testing.T) {
	for name, res := range hostileResults() {
		for _, o := range []Options{{}, {Full: true}, {SummaryOnly: true}, {Full: true, Width: 60}} {
			out := render(t, res, FormatTerminal, o)
			if r, bad := hasControl(out); bad {
				t.Errorf("%s: terminal output contains control character %U", name, r)
			}
			if strings.Contains(out, "\x1b[2J") || strings.Contains(out, "\r") {
				t.Errorf("%s: terminal output contains a raw escape or carriage return", name)
			}
		}
		colored := render(t, res, FormatTerminal, Options{Color: true, Full: true})
		if strings.ContainsRune(sgr.ReplaceAllString(colored, ""), 0x1b) {
			t.Errorf("%s: colored output contains an injected escape sequence", name)
		}
		if strings.Contains(colored, "\r") || strings.Contains(colored, "\x07") {
			t.Errorf("%s: colored output contains a carriage return or bell", name)
		}
	}
	// The literal payload from the task description.
	res := reportingtest.Blocked()
	res.Findings[0].Location.Path = "src/\x1b[2Jevil\r.py"
	out := render(t, res, FormatTerminal, Options{})
	if !strings.Contains(out, "Where: src/evil.py:86") {
		t.Errorf("the hostile path was not reduced to its printable text:\n%s", out)
	}
}

func TestNoHumanFormatCarriesControlCharacters(t *testing.T) {
	for name, res := range hostileResults() {
		for _, f := range []string{FormatMarkdown, FormatHTML, FormatSARIF} {
			out := render(t, res, f, Options{})
			if r, bad := hasControl(out); bad {
				t.Errorf("%s/%s: output contains control character %U", name, f, r)
			}
		}
	}
}

func TestMarkdownEscape(t *testing.T) {
	cases := map[string]string{
		"plain":                       "plain",
		"<script>alert(1)</script>":   `&lt;script&gt;alert\(1\)&lt;/script&gt;`,
		"a | b":                       `a \| b`,
		"](javascript:alert(1))":      `\]\(javascript:alert\(1\)\)`,
		"<!-- x":                      `&lt;\!-- x`,
		"```":                         "\\`\\`\\`",
		"[t](u) *b* _i_ ~s~ # h":      `\[t\]\(u\) \*b\* \_i\_ \~s\~ \# h`,
		`back\slash`:                  `back\\slash`,
		"R&D @team":                   `R&amp;D &#64;team`,
		"![img](x)":                   `\!\[img\]\(x\)`,
		"src/my_file.py:10":           `src/my\_file.py:10`,
		"AGC-010 Human Approval 1.0.": "AGC-010 Human Approval 1.0.",
	}
	for in, want := range cases {
		if got := md(in); got != want {
			t.Errorf("md(%q) = %q, want %q", in, got, want)
		}
	}
}

var unescapedPipe = regexp.MustCompile(`(^|[^\\])\|`)

func TestMarkdownNeutralizesHostileContent(t *testing.T) {
	for name, res := range hostileResults() {
		out := render(t, res, FormatMarkdown, Options{})
		for _, raw := range []string{
			"<script", "</script", "<img", "<!--", "```", "](javascript:", "](",
		} {
			if strings.Contains(out, raw) {
				t.Errorf("%s: markdown contains raw %q", name, raw)
			}
		}
		// The only HTML tags are the ones the renderer writes itself.
		tags := regexp.MustCompile(`<[^>\n]*>`).FindAllString(out, -1)
		for _, tag := range tags {
			switch tag {
			case "<details>", "</details>", "<summary>", "</summary>":
			default:
				t.Errorf("%s: markdown contains unexpected tag %q", name, tag)
			}
		}
		if strings.Count(out, "<details>") != 1 || strings.Count(out, "</details>") != 1 {
			t.Errorf("%s: markdown must contain exactly one details block", name)
		}
		inTable, columns := false, 0
		for i, line := range strings.Split(out, "\n") {
			// Injected line breaks must not start a new block.
			if strings.HasPrefix(line, "# ") || strings.HasPrefix(line, "#### ") {
				t.Errorf("%s: line %d is an injected heading: %q", name, i+1, line)
			}
			if !strings.HasPrefix(line, "|") {
				inTable = false
				continue
			}
			n := len(unescapedPipe.FindAllString(line, -1))
			if !inTable {
				inTable, columns = true, n
				continue
			}
			if n != columns {
				t.Errorf("%s: table row at line %d has %d cell separators, want %d: %q", name, i+1, n, columns, line)
			}
		}
	}
}

func TestMarkdownContent(t *testing.T) {
	out := render(t, reportingtest.Blocked(), FormatMarkdown, Options{})
	for _, want := range []string{
		"## AgentGov Auditor report",
		"**Release decision: BLOCK.** Do not release until the listed controls are fixed.",
		"(illustrative only)",
		"| Target | Profile | Commit | Policy | Offline |",
		"| Group | Controls | Meaning |",
		"| Verified | 3 |",
		"| Failed | 8 |",
		"| Not applicable | 2 |",
		"### Top findings",
		"| Critical | AGC-010 | Refunds run without an enforced approval | src/actions.py:86 |",
		"No file location",
		"### Unresolved mandatory controls",
		"- **AGC-010 Human Approval Gates** (Failed). Next action:",
		"<details>\n<summary>All 24 control results</summary>",
		"Generated by AgentGov Auditor 0.1.0. This is an evidence-based assessment, not a certification.",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("markdown is missing %q", want)
		}
	}
	for _, banned := range []string{"![", "shields.io", "badge"} {
		if strings.Contains(out, banned) {
			t.Errorf("markdown contains %q; badges are not allowed", banned)
		}
	}
	if n := strings.Count(out, "\n| AGC-0"); n != 24 {
		t.Errorf("control table has %d rows, want 24", n)
	}
}

// bannedWords are marketing words and contractions that the style rules for
// user-facing text forbid.
var bannedWords = regexp.MustCompile(`(?i)\b(leverage|unlock|elevate|delve|navigate|realm|stellar|cutting[- ]edge|don't|doesn't|can't|won't|isn't|aren't|wasn't|couldn't|shouldn't|it's|compliance|compliant)\b`)

func TestStyleRules(t *testing.T) {
	for _, s := range samples[:3] {
		for _, f := range []string{FormatTerminal, FormatMarkdown, FormatHTML} {
			out := render(t, s.make(), f, Options{Full: true})
			if f == FormatHTML {
				// Only visible text is checked, not the script.
				out = regexp.MustCompile(`(?s)<script>.*?</script>|<style>.*?</style>`).ReplaceAllString(out, "")
			}
			if m := bannedWords.FindString(out); m != "" {
				t.Errorf("%s/%s: output uses %q", s.name, f, m)
			}
			for _, r := range out {
				if r >= 0x1F300 && r <= 0x1FAFF || r >= 0x2600 && r <= 0x27BF {
					t.Errorf("%s/%s: output contains an emoji or pictograph %U", s.name, f, r)
					break
				}
			}
		}
	}
}
