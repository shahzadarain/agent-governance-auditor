// SPDX-License-Identifier: Apache-2.0

package adapters

import (
	"fmt"
	"path"
	"regexp"
	"sort"
	"strings"

	"github.com/shahzadarain/agent-governance-auditor/internal/config"
	"github.com/shahzadarain/agent-governance-auditor/internal/model"
)

var (
	toolDecoNames = map[string]bool{"tool": true, "function_tool": true, "tool_plain": true, "register_for_llm": true, "register_for_execution": true}
	registryRe    = regexp.MustCompile(`(?m)^[ \t]*([A-Za-z_][A-Za-z0-9_]*)\s*(?::[^=\n]+)?=\s*\{`)
	registryName  = regexp.MustCompile(`(?i)tool|registry|handler|function|action|dispatch|command`)
	registryItem  = regexp.MustCompile(`["']([A-Za-z0-9_.\-]+)["']\s*:\s*([A-Za-z_][A-Za-z0-9_.]*)\s*(?:,|$)`)
	schemaNameRe  = regexp.MustCompile(`["']?name["']?\s*:\s*["']([A-Za-z0-9_.\-]+)["']`)
	schemaHintRe  = regexp.MustCompile(`parameters|input_schema|inputSchema`)
	identRe       = regexp.MustCompile(`[A-Za-z_$][A-Za-z0-9_$.]*`)
	firstStrRe    = regexp.MustCompile(`^\s*["'` + "`" + `]([A-Za-z0-9_.\-]+)["'` + "`" + `]`)
	assignBefore  = regexp.MustCompile(`([A-Za-z_$][A-Za-z0-9_$]*)\s*(?::[^=:,;(){}]+)?[:=]\s*(?:await\s+)?$`)
	camelRe       = regexp.MustCompile(`([a-z0-9])([A-Z])`)
	credAssignRe  = regexp.MustCompile(`(?i)\b\w*(api_?key|secret|token|password|passwd)\w*\s*=\s*[fbr]?["']`)
	memoryNameRe  = regexp.MustCompile(`(?i)((save|store|write|add|put|append|update)_?\w*memor|memor\w*_?(save|store|write|add|put|append|update)|^remember)`)
	secretFnRe    = regexp.MustCompile(`(?i)^(get|load|read|fetch)_?(secret|credential|api_?key|token)s?$`)
	mainGuardRe   = regexp.MustCompile(`if\s+__name__\s*==`)
	memoryClassRe = regexp.MustCompile(`(?i)memory|mem0`)
	multiAgentRe  = []string{"Crew", "GroupChat", "GroupChatManager", "RoundRobinGroupChat", "SelectorGroupChat", "Swarm", "create_supervisor", "create_swarm", "handoff"}
)

// SensitiveVerbs are name tokens that mark a tool as a sensitive action.
var SensitiveVerbs = map[string]string{
	"delete": "deletes", "remove": "removes", "transfer": "transfers value", "pay": "pays", "payment": "pays", "refund": "refunds",
	"send": "sends", "execute": "executes", "exec": "executes", "write": "writes", "update": "updates", "drop": "drops",
	"deploy": "deploys", "wire": "transfers value", "purchase": "purchases", "charge": "charges", "withdraw": "withdraws",
	"shell": "runs shell commands", "email": "sends email", "publish": "publishes", "grant": "grants access",
	"revoke": "revokes access", "terminate": "terminates", "close": "changes record state", "cancel": "cancels", "adjust": "adjusts records",
}

var mutatingVerbs = map[string]bool{"create": true, "insert": true, "set": true, "add": true, "save": true, "store": true, "put": true,
	"post": true, "modify": true, "edit": true, "patch": true, "upsert": true, "append": true, "reset": true}

// NameTokens splits an identifier into lower-case word tokens.
func NameTokens(name string) []string {
	n := camelRe.ReplaceAllString(name, "${1}_${2}")
	return strings.FieldsFunc(strings.ToLower(n), func(r rune) bool {
		return !(r >= 'a' && r <= 'z' || r >= '0' && r <= '9')
	})
}

func normName(n string) string { return strings.Join(NameTokens(n), "_") }

func (a *AgentScope) addTool(name string, src *Source, fn *Func, from, to int) {
	for i := range a.Tools {
		if a.Tools[i].Name == name || (fn != nil && a.Tools[i].Fn == fn) {
			if a.Tools[i].Src == nil && src != nil {
				a.Tools[i].Src, a.Tools[i].Fn, a.Tools[i].FromLine, a.Tools[i].ToLine = src, fn, from, to
			}
			return
		}
	}
	a.Tools = append(a.Tools, ToolRef{Name: name, Src: src, Fn: fn, FromLine: from, ToLine: to})
}

func (a *AgentScope) addFuncTool(name string, src *Source, fn *Func) {
	a.addTool(name, src, fn, fn.Line, fn.EndLine)
}

// lookupFunc finds a project function by a possibly dotted identifier used
// in src.
func (a *AgentScope) lookupFunc(src *Source, ident string) (*Source, *Func) {
	first, last := ident, ident
	if i := strings.Index(ident, "."); i >= 0 {
		first = ident[:i]
		last = ident[strings.LastIndex(ident, ".")+1:]
	}
	if b, ok := src.Aliases[first]; ok {
		sym := b.Name
		if first != ident {
			sym = strings.TrimPrefix(b.Name+"."+ident[len(first)+1:], ".")
		}
		if ls := resolveLocal(a.repo, src, b.Module, sym); ls != nil {
			if fn := ls.FuncByName(last); fn != nil {
				return ls, fn
			}
		}
		return nil, nil
	}
	if first == ident {
		if fn := src.FuncByName(ident); fn != nil {
			return src, fn
		}
	}
	return nil, nil
}

func (a *AgentScope) findTools(cfg *config.Config) {
	for _, s := range a.Sources {
		if a.IsTest(s.Path) {
			continue
		}
		importsAnyFramework := false
		for _, im := range s.Imports {
			for i := range Frameworks {
				if Frameworks[i].matchesModule(s.Lang, im.Module) {
					importsAnyFramework = true
				}
			}
		}
		// Decorated functions.
		for i := range s.Funcs {
			fn := &s.Funcs[i]
			for _, d := range fn.Decorators {
				name := decoratorName(d)
				last := name[strings.LastIndex(name, ".")+1:]
				if b, ok := s.Aliases[name]; ok && b.Name != "" {
					last = b.Name[strings.LastIndex(b.Name, ".")+1:] // "from x import tool as lc_tool"
				}
				if !toolDecoNames[last] {
					continue
				}
				mod := decoratorModule(s, d)
				known := false
				for k := range Frameworks {
					if mod != "" && Frameworks[k].matchesModule(s.Lang, mod) {
						known = true
					}
				}
				if known || (strings.Contains(name, ".") && importsAnyFramework) {
					a.addFuncTool(fn.Name, s, fn)
				}
			}
		}
		for _, c := range s.Calls {
			// tools=[a, b] lists and tools: { a, b } objects.
			for _, kw := range []string{"tools", "functions"} {
				if !c.HasKwarg(kw) {
					continue
				}
				val, ok := s.kwargCode(c, kw)
				if !ok {
					continue
				}
				for _, id := range identRe.FindAllString(val, -1) {
					if ts, fn := a.lookupFunc(s, id); fn != nil {
						a.addFuncTool(fn.Name, ts, fn)
					}
				}
			}
			if s.Lang == LangPython {
				continue
			}
			// JS tool definitions.
			last := c.Last()
			isToolCall := (last == "tool" && (c.Module != "" || strings.Contains(c.Name, "."))) || last == "registerTool" ||
				(c.New && (last == "DynamicStructuredTool" || last == "DynamicTool" || last == "FunctionTool"))
			if !isToolCall || !importsAnyFramework {
				continue
			}
			name := ""
			if m := firstStrRe.FindStringSubmatch(s.ArgsText(c)); m != nil {
				name = m[1]
			} else if v, ok := s.KwargText(c, "name"); ok {
				name = strings.Trim(v, "\"'`")
			} else {
				callStart := c.ArgsStart - 1 - len(c.Name)
				before := s.Code[max(0, callStart-80):max(0, callStart)]
				before = strings.TrimSuffix(strings.TrimRight(before, " \t"), "new")
				if m := assignBefore.FindStringSubmatch(strings.TrimRight(before, " \t")); m != nil {
					name = m[1]
				}
			}
			if name == "" || !regexp.MustCompile(`^[A-Za-z0-9_.\-$]+$`).MatchString(name) {
				name = fmt.Sprintf("tool@%s:%d", path.Base(s.Path), c.Line)
			}
			a.addTool(name, s, nil, c.Line, s.LineOf(c.ArgsEnd))
		}
		if s.Lang == LangPython {
			// Registry dictionaries: TOOLS = {"name": function, ...}.
			for _, m := range registryRe.FindAllStringSubmatchIndex(s.Code, -1) {
				if !registryName.MatchString(s.Code[m[2]:m[3]]) {
					continue
				}
				open := m[1] - 1
				end := matchParen(s.Code, open)
				if end < 0 {
					continue
				}
				for _, r := range SplitArgs(s.Code[open+1 : end]) {
					item := strings.TrimSpace(s.Text[open+1+r[0] : open+1+r[1]])
					if im := registryItem.FindStringSubmatch(item); im != nil {
						if ts, fn := a.lookupFunc(s, im[2]); fn != nil {
							a.addFuncTool(im[1], ts, fn)
						}
					}
				}
			}
		}
		// Tool schemas: {"name": "x", ... "parameters" | "input_schema": ...}.
		for _, m := range schemaNameRe.FindAllStringSubmatchIndex(s.Text, -1) {
			if s.Lang != LangPython && !importsAnyFramework {
				continue
			}
			window := s.Text[m[1]:min(len(s.Text), m[1]+600)]
			if !schemaHintRe.MatchString(window) {
				continue
			}
			name := s.Text[m[2]:m[3]]
			if ts, fn := a.lookupFunc(s, name); fn != nil {
				a.addFuncTool(name, ts, fn)
			} else if refs := a.fnIndex[name]; len(refs) == 1 {
				a.addFuncTool(name, refs[0].src, refs[0].fn)
			} else if importsAnyFramework || s.Lang == LangPython && a.Agent.Framework == "generic-tool-calling" {
				a.addTool(name, s, nil, s.LineOf(m[0]), s.LineOf(m[0]))
			}
		}
	}
	_ = cfg
}

// kwargCode returns the code-view value of a keyword argument or object key.
func (s *Source) kwargCode(c Call, name string) (string, bool) {
	code := s.ArgsCode(c)
	if s.Lang != LangPython {
		if i := strings.Index(code, "{"); i >= 0 {
			if j := matchParen(code, i); j > i {
				code = code[i+1 : j]
			}
		}
	}
	for _, r := range SplitArgs(code) {
		part := strings.TrimSpace(code[r[0]:r[1]])
		if !strings.HasPrefix(part, name) {
			continue
		}
		rest := strings.TrimLeft(part[len(name):], " \t")
		if rest == "" {
			return name, true // JS shorthand property
		}
		if rest[0] == '=' || rest[0] == ':' {
			return rest[1:], true
		}
	}
	return "", false
}

// finish fills tools, capabilities, risk tier, and the remaining agent fields.
func (a *AgentScope) finish(cfg *config.Config) {
	ag := &a.Agent
	declared := map[string]bool{}
	sensitiveCfg := map[string]bool{}
	if cfg != nil && a.ConfigAgent != nil {
		for _, t := range cfg.Capabilities.DeclaredTools {
			declared[normName(t)] = true
			ag.PermissionsDeclared = append(ag.PermissionsDeclared, t)
		}
		for _, t := range cfg.Capabilities.SensitiveActions {
			sensitiveCfg[normName(t)] = true
		}
	}
	sort.Strings(ag.PermissionsDeclared)
	caps := map[string]bool{}
	dataPaths := map[string]bool{}
	sort.SliceStable(a.Tools, func(i, j int) bool { return a.Tools[i].Name < a.Tools[j].Name })
	for i := range a.Tools {
		tr := &a.Tools[i]
		t := model.Tool{Name: tr.Name, Kind: "unknown", Capabilities: []string{}, Declared: declared[normName(tr.Name)]}
		if tr.Src != nil {
			t.Location = model.Location{Path: tr.Src.Path, Line: tr.FromLine, EndLine: tr.ToLine}
			tr.Traits = a.TraitsDeep(tr.Src, tr.FromLine, tr.ToLine, 2)
			t.Kind = "function"
		}
		tc := map[string]bool{}
		var why []string
		tokens := NameTokens(tr.Name)
		if a.declared {
			tokens = nil // a declared-only tool is judged by its declaration, not by its name
		}
		mutating := false
		for _, tok := range tokens {
			if w, ok := SensitiveVerbs[tok]; ok {
				why = append(why, fmt.Sprintf("the name says it %s", w))
				mutating = mutating || (tok != "shell" && tok != "execute" && tok != "exec")
				break
			}
		}
		for _, tok := range tokens {
			if mutatingVerbs[tok] {
				mutating = true
			}
			if tok == "memory" || tok == "remember" || tok == "memorize" {
				tc[model.CapMemory] = true
			}
		}
		tt := tr.Traits
		if tt.Shell {
			t.Kind = "shell"
			tc[model.CapShellExec] = true
			why = append(why, "it runs shell commands")
		}
		if tt.CodeExec {
			if t.Kind == "function" {
				t.Kind = "code"
			}
			tc[model.CapCodeExec] = true
			why = append(why, "it evaluates code")
		}
		if tt.HTTP {
			if t.Kind == "function" {
				t.Kind = "http"
			}
			tc[model.CapNetwork] = true
		}
		if tt.HTTPMutate {
			mutating = true
			why = append(why, "it sends state-changing HTTP requests")
		}
		if tt.Browser {
			if t.Kind == "function" {
				t.Kind = "browser"
			}
			tc[model.CapBrowser] = true
		}
		if tt.DB || tt.Vector {
			if t.Kind == "function" {
				t.Kind = "database"
			}
			tc[model.CapDataAccess] = true
			dataPaths[tr.Src.Path] = true
		}
		if tt.DBWrite {
			mutating = true
			why = append(why, "it writes to a database")
		}
		if tt.VectorWrite {
			mutating = true
			tc[model.CapMemory] = true
		}
		if tt.FSRead || tt.FSWrite {
			if t.Kind == "function" {
				t.Kind = "filesystem"
			}
			tc[model.CapFilesystem] = true
		}
		if tt.FSWrite {
			mutating = true
		}
		if sensitiveCfg[normName(tr.Name)] {
			why = append(why, "the configuration lists it as a sensitive action")
		}
		if mutating {
			tc[model.CapMutatingActions] = true
		}
		if len(why) > 0 {
			t.Sensitive = true
			t.SensitiveWhy = strings.Join(why, "; ")
			tc[model.CapSensitiveActions] = true
		}
		for c := range tc {
			t.Capabilities = append(t.Capabilities, c)
			caps[c] = true
		}
		sort.Strings(t.Capabilities)
		ag.Tools = append(ag.Tools, t)
	}
	if len(ag.Tools) > 0 {
		caps[model.CapTools] = true
	}
	mainEntry := ""
	if a.declared && cfg != nil && len(cfg.Capabilities.SensitiveActions) > 0 {
		caps[model.CapSensitiveActions] = true
	}
	// Agent-level signals from non-test sources. A declared-only agent gets
	// its capabilities from declarations alone.
	for _, s := range a.Sources {
		if a.declared {
			break
		}
		if a.IsTest(s.Path) {
			continue
		}
		ft := s.FileTraits()
		if len(ag.Tools) == 0 && a.Agent.Detection == model.Detected {
			if ft.Shell {
				caps[model.CapShellExec] = true
			}
			if ft.CodeExec {
				caps[model.CapCodeExec] = true
			}
			if ft.HTTP {
				caps[model.CapNetwork] = true
			}
			if ft.DB || ft.Vector {
				caps[model.CapDataAccess] = true
				dataPaths[s.Path] = true
			}
			if ft.DBWrite || ft.HTTPMutate {
				caps[model.CapMutatingActions] = true
			}
		}
		if ft.VectorWrite {
			caps[model.CapMemory] = true
		}
		if ft.EnvSecret || credAssignRe.MatchString(s.Code) {
			caps[model.CapCredentials] = true
		}
		for i := range s.Funcs {
			if memoryNameRe.MatchString(s.Funcs[i].Name) {
				caps[model.CapMemory] = true
			}
			if secretFnRe.MatchString(s.Funcs[i].Name) {
				caps[model.CapCredentials] = true
			}
		}
		for _, c := range s.Classes {
			if memoryClassRe.MatchString(c.Name) {
				caps[model.CapMemory] = true
			}
		}
		for _, c := range s.Calls {
			if c.HasKwarg("handoffs") || (c.Module != "" && inList(multiAgentRe, c.Last())) {
				caps[model.CapMultiAgent] = true
			}
			if c.Module != "" && memoryClassRe.MatchString(c.Last()) && !strings.Contains(c.Last(), "MemorySaver") {
				caps[model.CapMemory] = true
			}
		}
		for _, im := range s.Imports {
			if moduleHasPrefix(im.Module, "a2a") || moduleHasPrefix(im.Module, "@a2a-js/sdk") {
				caps[model.CapMultiAgent] = true
			}
			if (FrameworkByID("mcp")).matchesModule(s.Lang, im.Module) && resolveLocal(a.repo, s, im.Module, im.Name) == nil {
				caps[model.CapMCP] = true
			}
		}
		if s.Lang == LangPython && mainGuardRe.MatchString(s.Code) {
			hasFacts := false
			for _, f := range ag.Facts {
				if f.Location.Path == s.Path {
					hasFacts = true
					break
				}
			}
			if hasFacts && (ag.Entrypoint == model.Unknown || mainEntry != "") {
				ag.Entrypoint, mainEntry = s.Path, ""
			} else if ag.Entrypoint == model.Unknown && path.Base(s.Path) == "__main__.py" {
				ag.Entrypoint, mainEntry = s.Path, s.Path
			}
		}
	}
	if ag.Framework == "mcp" {
		caps[model.CapMCP] = true
	}
	for _, m := range a.MCP() {
		if a.declared {
			break
		}
		caps[model.CapMCP] = true
		ag.MCPConnections = append(ag.MCPConnections, model.MCPConnection{Name: m.Name, Transport: m.Transport, Target: m.Target,
			Pinned: m.Pinned, Version: m.Version, Location: model.Location{Path: m.Path, Line: m.Line}})
		ag.Facts = append(ag.Facts, fact("mcp-server", "MCP client configuration lists server "+m.Name+".", m.Path, m.Line, model.ConfidenceHigh, "config.mcp"))
	}
	for _, p := range a.Paths() {
		base := path.Base(p)
		if IsDockerfileName(base) && !a.declared {
			caps[model.CapContainer] = true
		}
	}
	for _, d := range a.Docs() {
		if (IsComposeDoc(d) || IsK8sWorkload(d)) && !a.declared {
			caps[model.CapContainer] = true
		}
	}
	if ag.Entrypoint == model.Unknown && ag.Language != LangPython && !a.declared {
		for _, d := range a.repo.DocsAt(path.Join(a.Root, "package.json")) {
			if mainFile, ok := d.Get("main"); ok {
				cand := path.Join(a.Root, mainFile)
				if a.repo.Inv.Has(cand) {
					ag.Entrypoint = cand
				}
			}
		}
	}
	for c := range caps {
		ag.Capabilities = append(ag.Capabilities, c)
	}
	sort.Strings(ag.Capabilities)
	for p := range dataPaths {
		ag.DataAccessPaths = append(ag.DataAccessPaths, p)
	}
	sort.Strings(ag.DataAccessPaths)
	switch {
	case caps[model.CapShellExec] || caps[model.CapCodeExec] ||
		(caps[model.CapSensitiveActions] && (caps[model.CapCredentials] || caps[model.CapDataAccess])):
		ag.InferredRiskTier = "high"
	case caps[model.CapMutatingActions] || caps[model.CapNetwork] || caps[model.CapDataAccess] || caps[model.CapSensitiveActions] ||
		caps[model.CapFilesystem] || caps[model.CapBrowser] || caps[model.CapMemory] || caps[model.CapMultiAgent]:
		ag.InferredRiskTier = "medium"
	default:
		ag.InferredRiskTier = "low"
	}
	if ag.Detection != model.Detected {
		ag.InferredRiskTier = model.Unknown
	}
	sort.SliceStable(ag.Facts, func(i, j int) bool {
		x, y := ag.Facts[i], ag.Facts[j]
		if x.Location.Path != y.Location.Path {
			return x.Location.Path < y.Location.Path
		}
		if x.Location.Line != y.Location.Line {
			return x.Location.Line < y.Location.Line
		}
		if x.Kind != y.Kind {
			return x.Kind < y.Kind
		}
		return x.Detail < y.Detail
	})
	if len(ag.Facts) > 200 {
		ag.Facts = ag.Facts[:200]
	}
	if ag.Tools == nil {
		ag.Tools = []model.Tool{}
	}
	if ag.PermissionsDeclared == nil {
		ag.PermissionsDeclared = []string{}
	}
	if ag.DataAccessPaths == nil {
		ag.DataAccessPaths = []string{}
	}
	if ag.MCPConnections == nil {
		ag.MCPConnections = []model.MCPConnection{}
	}
	if ag.Capabilities == nil {
		ag.Capabilities = []string{}
	}
	if ag.Facts == nil {
		ag.Facts = []model.Fact{}
	}
}

var composeNameRe = regexp.MustCompile(`(?i)^(docker-)?compose[\w.-]*\.ya?ml$`)

// IsComposeDoc reports whether a document is a Compose file.
func IsComposeDoc(d *Doc) bool {
	return d.Format == "yaml" && d.Has("services") && (composeNameRe.MatchString(path.Base(d.Path)) || len(d.Match(composeImageRe)) > 0)
}

var composeImageRe = regexp.MustCompile(`^services\.[^.]+\.(image|build)$`)

// IsK8sWorkload reports whether a document is a Kubernetes workload manifest.
func IsK8sWorkload(d *Doc) bool {
	if d.Format != "yaml" || !d.Has("apiVersion") {
		return false
	}
	kind, _ := d.Get("kind")
	switch kind {
	case "Pod", "Deployment", "StatefulSet", "DaemonSet", "Job", "CronJob", "ReplicaSet":
		return true
	}
	return false
}
