// SPDX-License-Identifier: Apache-2.0

package rules

import (
	"path"
	"regexp"
	"strings"

	"github.com/shahzadarain/agent-governance-auditor/internal/adapters"
)

type hit struct {
	src  *adapters.Source
	line int
	text string
}

// grepCode finds matches in the code view of the non-test sources.
func (c *Context) grepCode(re *regexp.Regexp) []hit {
	var out []hit
	for _, s := range c.sources() {
		for _, m := range re.FindAllStringIndex(s.Code, -1) {
			out = append(out, hit{s, s.LineOf(m[0]), s.Code[m[0]:m[1]]})
		}
	}
	return out
}

// grepText finds matches in the text view (strings kept, comments and
// docstrings blanked) of the non-test sources.
func (c *Context) grepText(re *regexp.Regexp) []hit {
	var out []hit
	for _, s := range c.sources() {
		for _, m := range re.FindAllStringIndex(s.Text, -1) {
			out = append(out, hit{s, s.LineOf(m[0]), s.Text[m[0]:m[1]]})
		}
	}
	return out
}

type fn struct {
	src *adapters.Source
	f   *adapters.Func
}

func (x fn) code() string { return x.src.BodyCode(x.f) }
func (x fn) text() string { return x.src.BodyText(x.f) }

// line returns the line of the first match of re in the function's code
// view, or the function's first line.
func (x fn) lineOf(re *regexp.Regexp, view string) int {
	if m := re.FindStringIndex(view); m != nil {
		return x.src.LineOf(x.f.Start + m[0])
	}
	return x.f.Line
}

// funcs returns every function in the non-test sources.
func (c *Context) funcs() []fn {
	if v, ok := c.cache["funcs"]; ok {
		return v.([]fn)
	}
	var out []fn
	for _, s := range c.sources() {
		for i := range s.Funcs {
			out = append(out, fn{s, &s.Funcs[i]})
		}
	}
	c.memo("funcs", out)
	return out
}

// calls iterates over every call in the non-test sources.
func (c *Context) calls(visit func(s *adapters.Source, call adapters.Call)) {
	for _, s := range c.sources() {
		for _, call := range s.Calls {
			visit(s, call)
		}
	}
}

// callsIn returns the calls inside a function.
func callsIn(x fn) []adapters.Call {
	var out []adapters.Call
	for _, call := range x.src.Calls {
		if call.Line >= x.f.Line && call.Line <= x.f.EndLine {
			out = append(out, call)
		}
	}
	return out
}

var (
	registryLookupRe = regexp.MustCompile(`(?i)\b[A-Za-z_]*(tools?|registry|handlers?|functions|actions|commands)[A-Za-z_]*\s*(\[[^\]\n]+\]|\.get\s*\()`)
	dynamicLookupRe  = regexp.MustCompile(`\b(globals|locals)\s*\(\s*\)\s*(\[|\.get\s*\()|\bgetattr\s*\(`)
	dispatchNameRe   = regexp.MustCompile(`(?i)^_?(dispatch|execute_?tool|call_?tool|run_?tool|handle_?tool|invoke_?tool|execute_?action|handle_?tool_?calls?|execute_?tool_?calls?)`)
	loopRe           = regexp.MustCompile(`\bwhile\b|\bfor\b[^\n]*\brange\s*\(|\bfor\s*\(`)
	whileTrueRe      = regexp.MustCompile(`\bwhile\s*\(?\s*(True|true|1)\s*\)?\s*[:{]`)
	modelCallRe      = regexp.MustCompile(`\.\s*(create|generate_content|generateContent|complete|chat|generateText|streamText|invoke|converse|send_message|completion|next_action|plan|step)\s*\(`)
)

// dispatchFuncs returns the functions that execute a tool chosen by name at
// run time.
func (c *Context) dispatchFuncs() []fn {
	if v, ok := c.cache["dispatch"]; ok {
		return v.([]fn)
	}
	var out []fn
	for _, x := range c.funcs() {
		code := x.code()
		if dispatchNameRe.MatchString(x.f.Name) || registryLookupRe.MatchString(code) || dynamicLookupRe.MatchString(code) {
			out = append(out, x)
		}
	}
	c.memo("dispatch", out)
	return out
}

// loopFuncs returns the functions that look like an agent loop: a loop that
// calls a model or dispatches tools.
func (c *Context) loopFuncs() []fn {
	if v, ok := c.cache["loops"]; ok {
		return v.([]fn)
	}
	dispatchNames := map[string]bool{}
	for _, d := range c.dispatchFuncs() {
		dispatchNames[d.f.Name] = true
	}
	var out []fn
	for _, x := range c.funcs() {
		code := x.code()
		if !loopRe.MatchString(code) {
			continue
		}
		agentish := modelCallRe.MatchString(code)
		for _, call := range callsIn(x) {
			if dispatchNames[call.Last()] && call.Last() != x.f.Name {
				agentish = true
			}
			if call.HasKwarg("tools") {
				agentish = true
			}
		}
		if agentish {
			out = append(out, x)
		}
	}
	c.memo("loops", out)
	return out
}

// sensitiveToolFuncs returns the functions that implement sensitive tools.
func (c *Context) sensitiveToolFuncs() []fn {
	var out []fn
	for i, t := range c.Agent.Agent.Tools {
		if t.Sensitive && c.Agent.Tools[i].Fn != nil {
			out = append(out, fn{c.Agent.Tools[i].Src, c.Agent.Tools[i].Fn})
		}
	}
	return out
}

// callees returns the project functions called from x (one hop).
func (c *Context) callees(x fn) []fn {
	var out []fn
	seen := map[*adapters.Func]bool{x.f: true}
	for _, call := range callsIn(x) {
		if s, f := c.Agent.ResolveFunc(x.src, call); f != nil && !seen[f] && !c.Agent.IsTest(s.Path) {
			seen[f] = true
			out = append(out, fn{s, f})
		}
	}
	return out
}

// withCallees returns the functions plus what they call, following hops
// levels of project calls, without duplicates.
func (c *Context) withCallees(list []fn, hops int) []fn {
	seen := map[*adapters.Func]bool{}
	var out []fn
	frontier := list
	for depth := 0; depth <= hops; depth++ {
		var next []fn
		for _, x := range frontier {
			if seen[x.f] {
				continue
			}
			seen[x.f] = true
			out = append(out, x)
			if depth < hops {
				next = append(next, c.callees(x)...)
			}
		}
		frontier = next
	}
	return out
}

// hasImport reports whether any non-test source imports one of the modules.
func (c *Context) hasImport(mods ...string) (*adapters.Source, int, bool) {
	for _, s := range c.sources() {
		for _, im := range s.Imports {
			for _, m := range mods {
				if im.Module == m || strings.HasPrefix(im.Module, m+".") || strings.HasPrefix(im.Module, m+"/") {
					return s, im.Line, true
				}
			}
		}
	}
	return nil, 0, false
}

// fileText returns the content of an inventoried, readable file in scope.
func (c *Context) fileText(p string) (string, bool) {
	f, ok := c.Repo.Inv.Get(p)
	if !ok || f.Skipped != "" || !c.Agent.InScope(p) {
		return "", false
	}
	return string(f.Content), true
}

// rejectAfter reports whether the lines that follow a condition at
// byte offset off (in the function's code view) contain a reject path:
// raise, return, throw, or a deny call.
var rejectRe = regexp.MustCompile(`\b(raise|return|throw|continue|break)\b|\bdeny\w*\s*\(|\babort\s*\(|\bsys\.exit\s*\(`)

func rejectAfter(code string, off int) bool {
	end := off
	lines := 0
	for end < len(code) && lines < 6 {
		if code[end] == '\n' {
			lines++
		}
		end++
	}
	return rejectRe.MatchString(code[off:end])
}

// ---------------------------------------------------------------------------
// CI workflows
// ---------------------------------------------------------------------------

type ciWorkflow struct {
	doc      *adapters.Doc
	kind     string // github | gitlab | azure | circleci
	onChange bool   // runs on push or pull request
	runs     []adapters.Entry
	uses     []adapters.Entry
}

var (
	ghRunRe     = regexp.MustCompile(`^jobs\.[^.]+\.steps\[\d+\]\.run$`)
	ghUsesRe    = regexp.MustCompile(`^jobs\.[^.]+\.steps\[\d+\]\.uses$`)
	ghOnRe      = regexp.MustCompile(`^(on|true)(\.(push|pull_request|pull_request_target|merge_group)|\[\d+\])?$`)
	scriptRe    = regexp.MustCompile(`(^|\.)(script|before_script|bash|pwsh|powershell)(\[\d+\])?$|steps\[\d+\]\.(script|bash|run)$`)
	testCmdRe   = regexp.MustCompile(`(?i)\b(pytest|unittest|go\s+test|npm\s+(run\s+)?test|pnpm\s+(run\s+)?test|yarn\s+(run\s+)?test|bun\s+test|tox|nox|make\s+(test|check)|agentgov|jest|vitest|cargo\s+test|run_governance_tests|promptfoo|garak)\b`)
	agentgovRe  = regexp.MustCompile(`(?i)agentgov|agent-governance-auditor`)
	workflowDir = "/.github/workflows/"
)

// ciWorkflows returns the CI workflow documents in scope.
func (c *Context) ciWorkflows() []ciWorkflow {
	if v, ok := c.cache["ci"]; ok {
		return v.([]ciWorkflow)
	}
	var out []ciWorkflow
	for _, d := range c.Agent.Docs() {
		if d.Format != "yaml" {
			continue
		}
		base := path.Base(d.Path)
		w := ciWorkflow{doc: d}
		switch {
		case strings.Contains("/"+d.Path, workflowDir):
			w.kind = "github"
			for _, e := range d.Entries {
				switch {
				case ghRunRe.MatchString(e.Path):
					w.runs = append(w.runs, e)
				case ghUsesRe.MatchString(e.Path):
					w.uses = append(w.uses, e)
				case ghOnRe.MatchString(e.Path):
					v := e.Path + " " + e.Value
					if strings.Contains(v, "push") || strings.Contains(v, "pull_request") || strings.Contains(v, "merge_group") {
						w.onChange = true
					}
				}
			}
		case base == ".gitlab-ci.yml" || base == ".gitlab-ci.yaml":
			w.kind, w.onChange = "gitlab", true
		case base == "azure-pipelines.yml" || base == "azure-pipelines.yaml":
			w.kind = "azure"
			w.onChange = d.Has("trigger") || d.Has("pr") || true // Azure runs on push by default
		case strings.HasSuffix(d.Path, ".circleci/config.yml"):
			w.kind, w.onChange = "circleci", true
		default:
			continue
		}
		if w.kind != "github" {
			for _, e := range d.Entries {
				if e.Kind == 's' && (scriptRe.MatchString(e.Path) || strings.HasSuffix(e.Path, ".command") || strings.HasSuffix(e.Path, ".run")) {
					w.runs = append(w.runs, e)
				}
			}
		}
		out = append(out, w)
	}
	c.memo("ci", out)
	return out
}

// ciTestRun returns the first CI step that runs tests or the auditor in a
// workflow triggered by changes.
func (c *Context) ciTestRun() (ciWorkflow, adapters.Entry, bool) {
	for _, w := range c.ciWorkflows() {
		if !w.onChange {
			continue
		}
		for _, e := range w.runs {
			if testCmdRe.MatchString(e.Value) {
				return w, e, true
			}
		}
		for _, e := range w.uses {
			if agentgovRe.MatchString(e.Value) {
				return w, e, true
			}
		}
	}
	return ciWorkflow{}, adapters.Entry{}, false
}

// malformedInScope reports whether a malformed file matching the predicate
// is in scope. Detectors use it to stay silent instead of reporting absent.
func (c *Context) malformedInScope(match func(p string) bool) bool {
	for p := range c.Repo.Malformed {
		if c.Agent.InScope(p) && match(p) {
			return true
		}
	}
	return false
}

func joinMax(items []string, n int) string {
	if len(items) > n {
		return strings.Join(items[:n], ", ") + ", and more"
	}
	return strings.Join(items, ", ")
}
