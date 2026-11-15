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

// ToolRef links a discovered tool to the code that implements it.
type ToolRef struct {
	Name     string
	Src      *Source // nil when only a schema or declaration was found
	Fn       *Func   // nil when the tool body is not a named function
	FromLine int
	ToLine   int
	Traits   Traits
}

// AgentScope is one discovered agent plus the files a detector may inspect
// for it.
type AgentScope struct {
	Agent       model.Agent
	Root        string
	Sources     []*Source // sources under Root, without deeper agent roots
	Tools       []ToolRef // parallel to Agent.Tools
	ConfigAgent *config.Agent
	repo        *Repo
	declared    bool            // created from the configuration; no agent code was recognized
	otherRoots  []string        // deeper agent roots, excluded from this scope
	allRoots    []string        // every agent root
	projRoots   map[string]bool // every project root (directories with a manifest, plus ".")
	fnIndex     map[string][]fnRef
}

type fnRef struct {
	src *Source
	fn  *Func
}

// Discovery is the result of agent discovery.
type Discovery struct {
	Agents      []*AgentScope
	Limitations []string
	Warnings    []string
}

var agentIDRe = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$`)

func under(p, root string) bool {
	return root == "." || p == root || strings.HasPrefix(p, root+"/")
}

// IsTest reports whether a path inside the agent looks like test code. The
// check is relative to the agent root, so an agent that itself lives under a
// directory named "tests" is not treated as test code.
func (a *AgentScope) IsTest(p string) bool {
	if a.Root != "." && strings.HasPrefix(p, a.Root+"/") {
		p = p[len(a.Root)+1:]
	}
	return IsTestPath(p)
}

// InScope reports whether a repo path belongs to this agent: it is under the
// agent root and not under a deeper agent root, or it is a shared
// non-source file (CI, deployment, documentation) that sits outside every
// agent root and whose nearest project root is an ancestor of the agent.
func (a *AgentScope) InScope(p string) bool {
	if under(p, a.Root) {
		for _, o := range a.otherRoots {
			if under(p, o) {
				return false
			}
		}
		return true
	}
	for _, r := range a.allRoots {
		if under(p, r) {
			return false
		}
	}
	ext := strings.ToLower(path.Ext(p))
	if ext == ".py" || hasExt(ext, JSAnalyzer{}.Extensions()) {
		return false
	}
	for d := path.Dir(p); ; d = path.Dir(d) {
		if a.projRoots[d] {
			return under(a.Root, d)
		}
		if d == "." || d == "/" {
			return true
		}
	}
}

// Repo returns the analyzed repository.
func (a *AgentScope) Repo() *Repo { return a.repo }

// Docs returns the structured documents in scope.
func (a *AgentScope) Docs() []*Doc {
	var out []*Doc
	for _, d := range a.repo.Docs {
		if a.InScope(d.Path) {
			out = append(out, d)
		}
	}
	return out
}

// Dockerfiles returns the Dockerfiles in scope.
func (a *AgentScope) Dockerfiles() []*Dockerfile {
	var out []*Dockerfile
	for _, d := range a.repo.Dockerfiles {
		if a.InScope(d.Path) {
			out = append(out, d)
		}
	}
	return out
}

// Deps returns the declared dependencies in scope.
func (a *AgentScope) Deps() []Dependency {
	var out []Dependency
	for _, d := range a.repo.Deps {
		if a.InScope(d.Path) {
			out = append(out, d)
		}
	}
	return out
}

// MCP returns the MCP server entries in scope.
func (a *AgentScope) MCP() []MCPServer {
	var out []MCPServer
	for _, m := range a.repo.MCP {
		if a.InScope(m.Path) {
			out = append(out, m)
		}
	}
	return out
}

// Paths returns every inventory path in scope, sorted.
func (a *AgentScope) Paths() []string {
	var out []string
	for i := range a.repo.Inv.Files {
		if p := a.repo.Inv.Files[i].Path; a.InScope(p) {
			out = append(out, p)
		}
	}
	return out
}

// ResolveFunc finds the project function a call refers to, or nil.
func (a *AgentScope) ResolveFunc(src *Source, c Call) (*Source, *Func) {
	name := c.Name
	for _, pre := range []string{"self.", "cls.", "this."} {
		name = strings.TrimPrefix(name, pre)
	}
	if c.Module != "" {
		if target := resolveLocal(a.repo, src, c.Module, c.Symbol); target != nil {
			last := c.Symbol[strings.LastIndex(c.Symbol, ".")+1:]
			if fn := target.FuncByName(last); fn != nil {
				return target, fn
			}
		}
		return nil, nil
	}
	if !strings.Contains(name, ".") {
		if fn := src.FuncByName(name); fn != nil {
			return src, fn
		}
	}
	last := name[strings.LastIndex(name, ".")+1:]
	if refs := a.fnIndex[last]; len(refs) == 1 && len(last) >= 4 {
		return refs[0].src, refs[0].fn
	}
	return nil, nil
}

// FuncsNamed returns the project functions that have the given name.
func (a *AgentScope) FuncsNamed(name string) []*Func {
	var out []*Func
	for _, r := range a.fnIndex[name] {
		out = append(out, r.fn)
	}
	return out
}

// ImportsAgentFramework reports whether the file imports a supported agent
// framework (a model client SDK alone does not count).
func ImportsAgentFramework(s *Source) bool {
	for _, im := range s.Imports {
		for i := range Frameworks {
			if !Frameworks[i].Generic && Frameworks[i].matchesModule(s.Lang, im.Module) {
				return true
			}
		}
	}
	return false
}

// TraitsDeep computes the traits of a code region and of the project
// functions it calls, following at most depth hops.
func (a *AgentScope) TraitsDeep(src *Source, from, to, depth int) Traits {
	return a.traitsDeep(src, from, to, depth, map[string]bool{})
}

func (a *AgentScope) traitsDeep(src *Source, from, to, depth int, seen map[string]bool) Traits {
	t := src.TraitsIn(from, to)
	if depth <= 0 {
		return t
	}
	for _, c := range src.Calls {
		if c.Line < from || c.Line > to {
			continue
		}
		ts, fn := a.ResolveFunc(src, c)
		if fn == nil {
			continue
		}
		key := fmt.Sprintf("%s:%d", ts.Path, fn.Line)
		if seen[key] || (ts == src && fn.Line >= from && fn.EndLine <= to) {
			continue
		}
		seen[key] = true
		t.merge(a.traitsDeep(ts, fn.Line, fn.EndLine, depth-1, seen))
	}
	return t
}

// resolveLocal maps an import module to a source file of the repository, or
// nil when the module is not local.
func resolveLocal(r *Repo, src *Source, module, symbol string) *Source {
	dir := path.Dir(src.Path)
	if src.Lang != LangPython {
		if !strings.HasPrefix(module, ".") {
			return nil
		}
		base := path.Join(dir, module)
		for _, cand := range []string{base, base + ".ts", base + ".tsx", base + ".js", base + ".mjs", base + ".cjs", base + "/index.ts", base + "/index.js",
			strings.TrimSuffix(base, ".js") + ".ts"} {
			if s := r.srcByPath[cand]; s != nil {
				return s
			}
		}
		return nil
	}
	first := ""
	if symbol != "" {
		first = strings.Split(symbol, ".")[0]
	}
	try := func(base, mod string) *Source {
		rel := strings.ReplaceAll(mod, ".", "/")
		var cands []string
		if first != "" {
			cands = append(cands, path.Join(base, rel, first+".py"))
		}
		if rel != "" {
			cands = append(cands, path.Join(base, rel+".py"), path.Join(base, rel, "__init__.py"))
		}
		for _, cand := range cands {
			if s := r.srcByPath[cand]; s != nil && s != src {
				return s
			}
		}
		return nil
	}
	if strings.HasPrefix(module, ".") {
		dots := len(module) - len(strings.TrimLeft(module, "."))
		base := dir
		for i := 1; i < dots; i++ {
			base = path.Dir(base)
		}
		return try(base, strings.TrimLeft(module, "."))
	}
	for base := dir; ; base = path.Dir(base) {
		if s := try(base, module); s != nil {
			return s
		}
		if base == "." || base == "/" {
			break
		}
	}
	return nil
}

var slugRe = regexp.MustCompile(`[^a-z0-9]+`)

// Slug returns a stable identifier form of a name.
func Slug(s string) string {
	out := strings.Trim(slugRe.ReplaceAllString(strings.ToLower(s), "-"), "-")
	if out == "" {
		return "agent"
	}
	return out
}

func cleanRoot(r string) string {
	r = strings.ReplaceAll(strings.TrimSpace(r), "\\", "/")
	r = path.Clean(strings.TrimPrefix(r, "./"))
	if r == "" || r == "/" || strings.HasPrefix(r, "..") || strings.HasPrefix(r, "/") {
		return "."
	}
	return r
}

type fwState struct {
	fw      *Framework
	imports []model.Fact
	usage   []model.Fact
	deps    []model.Fact
	lang    map[string]int
}

func fact(kind, detail, file string, line int, conf model.Confidence, collector string) model.Fact {
	return model.Fact{Kind: kind, Detail: detail, Location: model.Location{Path: file, Line: line}, Confidence: conf,
		Collector: collector, ParserVersion: ParserVersion}
}

func collectorID(lang, fw string) string {
	if lang == LangPython {
		return "python." + fw
	}
	if lang == "" {
		return "manifest." + fw
	}
	return "js." + fw
}

var genericCallNames = []string{"create", "generate_content", "generateContent", "chat", "complete", "generateText", "streamText",
	"generateObject", "stream", "converse", "completion", "acompletion", "send_message", "sendMessage", "parse", "responses"}

// Discover groups facts into agents by nearest project root.
func Discover(repo *Repo, cfg *config.Config, rootName string) *Discovery {
	disc := &Discovery{}
	roots := map[string]bool{".": true}
	for i := range repo.Inv.Files {
		p := repo.Inv.Files[i].Path
		base := path.Base(p)
		if base == "pyproject.toml" || base == "package.json" || base == "setup.py" || base == "Pipfile" || isRequirementsName(base) {
			roots[path.Dir(p)] = true
		}
	}
	var cfgAgents []config.Agent
	if cfg != nil {
		if cfg.Agent.ID != "" || cfg.Agent.Owner != "" || cfg.Agent.RiskTier != "" || cfg.Agent.Description != "" {
			cfgAgents = append(cfgAgents, cfg.Agent)
		}
		cfgAgents = append(cfgAgents, cfg.Agents...)
		for i := range cfgAgents {
			cfgAgents[i].Root = cleanRoot(cfgAgents[i].Root)
			roots[cfgAgents[i].Root] = true
		}
	}
	nearest := func(p string) string {
		for d := path.Dir(p); ; d = path.Dir(d) {
			if roots[d] {
				return d
			}
			if d == "." || d == "/" {
				return "."
			}
		}
	}
	byRoot := map[string][]*Source{}
	for _, s := range repo.Sources {
		r := nearest(s.Path)
		byRoot[r] = append(byRoot[r], s)
	}
	depsByRoot := map[string][]Dependency{}
	for _, d := range repo.Deps {
		r := nearest(d.Path)
		depsByRoot[r] = append(depsByRoot[r], d)
	}
	rootList := make([]string, 0, len(roots))
	for r := range roots {
		rootList = append(rootList, r)
	}
	sort.Strings(rootList)

	clientOnly := false
	for _, root := range rootList {
		srcs := byRoot[root]
		states := map[string]*fwState{}
		st := func(fw *Framework) *fwState {
			if states[fw.ID] == nil {
				states[fw.ID] = &fwState{fw: fw, lang: map[string]int{}}
			}
			return states[fw.ID]
		}
		hasDep := func(fw *Framework) bool {
			for _, d := range depsByRoot[root] {
				if (d.Eco == "pypi" && inList(fw.PyPkgs, d.Name)) || (d.Eco == "npm" && inList(fw.NPMPkgs, d.Name)) {
					return true
				}
			}
			return false
		}
		for i := range Frameworks {
			fw := &Frameworks[i]
			for _, d := range depsByRoot[root] {
				if (d.Eco == "pypi" && inList(fw.PyPkgs, d.Name)) || (d.Eco == "npm" && inList(fw.NPMPkgs, d.Name)) {
					st(fw).deps = append(st(fw).deps, fact("dependency", "Manifest declares "+d.Name+".", d.Path, d.Line, model.ConfidenceLow, collectorID("", fw.ID)))
				}
			}
		}
		projectHasClient := false
		for _, s := range srcs {
			for i := range Frameworks {
				fw := &Frameworks[i]
				imported := false
				for _, im := range s.Imports {
					if !fw.matchesModule(s.Lang, im.Module) {
						continue
					}
					if fw.ID == "openai-agents" && s.Lang == LangPython && !hasDep(fw) && resolveLocal(repo, s, im.Module, im.Name) != nil {
						continue // a local package named "agents", not the SDK
					}
					if fw.ID == "mcp" && s.Lang == LangPython && resolveLocal(repo, s, im.Module, im.Name) != nil && !hasDep(fw) {
						continue
					}
					imported = true
					kind := "framework-import"
					if fw.Generic {
						kind = "model-client"
						projectHasClient = true
					}
					st(fw).imports = append(st(fw).imports, fact(kind, "Imports "+im.Module+".", s.Path, im.Line, model.ConfidenceHigh, collectorID(s.Lang, fw.ID)))
					st(fw).lang[s.Lang]++
				}
				if !imported {
					// One hop: a local module that imports the framework.
					for _, im := range s.Imports {
						if local := resolveLocal(repo, s, im.Module, im.Name); local != nil {
							for _, lim := range local.Imports {
								if fw.matchesModule(local.Lang, lim.Module) && !fw.Generic {
									st(fw).imports = append(st(fw).imports, fact("framework-import",
										"Imports "+fw.ID+" through the local module "+local.Path+".", s.Path, im.Line, model.ConfidenceMedium, collectorID(s.Lang, fw.ID)))
									st(fw).lang[s.Lang]++
									imported = true
									break
								}
							}
						}
						if imported {
							break
						}
					}
				}
				if !imported || fw.Generic {
					continue
				}
				for _, c := range s.Calls {
					if fw.matchesModule(s.Lang, c.Module) && fw.symbolHasCtor(c.Symbol) {
						st(fw).usage = append(st(fw).usage, fact("agent-construction", "Calls "+c.Name+".", s.Path, c.Line, model.ConfidenceHigh, collectorID(s.Lang, fw.ID)))
					} else if inList(fw.Methods, c.Last()) && strings.Contains(c.Name, ".") {
						st(fw).usage = append(st(fw).usage, fact("agent-construction", "Calls "+c.Last()+" on a model object.", s.Path, c.Line, model.ConfidenceMedium, collectorID(s.Lang, fw.ID)))
					} else if c.Module != "" && !fw.matchesModule(s.Lang, c.Module) {
						// A wrapper from a local module that itself constructs the framework object.
						if ls := resolveLocal(repo, s, c.Module, c.Symbol); ls != nil {
							if fn := ls.FuncByName(c.Symbol[strings.LastIndex(c.Symbol, ".")+1:]); fn != nil {
								for _, lc := range ls.Calls {
									if lc.Line >= fn.Line && lc.Line <= fn.EndLine && fw.matchesModule(ls.Lang, lc.Module) && fw.symbolHasCtor(lc.Symbol) {
										st(fw).usage = append(st(fw).usage, fact("agent-construction",
											"Calls "+c.Name+", a local wrapper that constructs a "+fw.ID+" object.", s.Path, c.Line, model.ConfidenceMedium, collectorID(s.Lang, fw.ID)))
										break
									}
								}
							}
						}
					}
				}
				for fi := range s.Funcs {
					for _, d := range s.Funcs[fi].Decorators {
						if fw.matchesModule(s.Lang, decoratorModule(s, d)) {
							st(fw).usage = append(st(fw).usage, fact("tool-definition", "Decorator @"+decoratorName(d)+" registers "+s.Funcs[fi].Name+" as a tool.",
								s.Path, s.Funcs[fi].Line, model.ConfidenceHigh, collectorID(s.Lang, fw.ID)))
						}
					}
				}
			}
		}
		// Generic tool calling: a model client import plus a tools argument or
		// a tool schema anywhere in the same project.
		if projectHasClient {
			g := st(FrameworkByID("generic-tool-calling"))
			for _, s := range srcs {
				for _, c := range s.Calls {
					if (c.HasKwarg("tools") || c.HasKwarg("functions")) && (inList(genericCallNames, c.Last()) || c.Module != "") {
						g.usage = append(g.usage, fact("tool-calling", "Passes a tools argument to "+c.Last()+".", s.Path, c.Line, model.ConfidenceHigh, collectorID(s.Lang, g.fw.ID)))
					} else if s.Lang != LangPython && c.Last() == "tool" && g.fw.matchesModule(s.Lang, c.Module) {
						g.usage = append(g.usage, fact("tool-definition", "Defines a tool with "+c.Name+".", s.Path, c.Line, model.ConfidenceHigh, collectorID(s.Lang, g.fw.ID)))
					}
				}
			}
		}
		// Pick the framework.
		var best *fwState
		detected := false
		for i := range Frameworks {
			s := states[Frameworks[i].ID]
			if s == nil {
				continue
			}
			if len(s.imports) > 0 && len(s.usage) > 0 {
				best, detected = s, true
				break
			}
		}
		if best == nil {
			for pass := 0; pass < 2 && best == nil; pass++ {
				for i := range Frameworks {
					s := states[Frameworks[i].ID]
					if s == nil || s.fw.Generic {
						continue
					}
					if (pass == 0 && len(s.imports) > 0) || (pass == 1 && len(s.deps) > 0) {
						best = s
						break
					}
				}
			}
		}
		if best == nil {
			if g := states["generic-tool-calling"]; g != nil && (len(g.imports) > 0 || len(g.deps) > 0) {
				clientOnly = true
			}
			continue
		}
		ag := &AgentScope{Root: root, repo: repo}
		a := &ag.Agent
		a.Root = root
		a.Framework = best.fw.ID
		a.FrameworkVersion, a.Entrypoint, a.Owner, a.RiskTier, a.Language = model.Unknown, model.Unknown, model.Unknown, model.Unknown, model.Unknown
		switch {
		case detected:
			a.Detection, a.Confidence = model.Detected, model.ConfidenceHigh
		case len(best.imports) > 0:
			a.Detection, a.Confidence = model.Suspected, model.ConfidenceMedium
		default:
			a.Detection, a.Confidence = model.Suspected, model.ConfidenceLow
		}
		bestLang, bestN := "", 0
		for _, l := range []string{LangPython, LangTypeScript, LangJavaScript} {
			if best.lang[l] > bestN {
				bestLang, bestN = l, best.lang[l]
			}
		}
		if bestLang != "" {
			a.Language = bestLang
		} else {
			for _, d := range depsByRoot[root] {
				if inList(best.fw.PyPkgs, d.Name) && d.Eco == "pypi" {
					a.Language = LangPython
				}
			}
		}
		a.Facts = append(a.Facts, best.imports...)
		a.Facts = append(a.Facts, best.usage...)
		a.Facts = append(a.Facts, best.deps...)
		// Framework version from a pinned manifest entry or a lockfile of the
		// agent's own language ecosystem.
		for _, d := range depsByRoot[root] {
			isPy := a.Language == LangPython
			if !((isPy && d.Eco == "pypi" && inList(best.fw.PyPkgs, d.Name)) || (!isPy && d.Eco == "npm" && inList(best.fw.NPMPkgs, d.Name))) {
				continue
			}
			if d.Pinned {
				a.FrameworkVersion = strings.TrimSpace(strings.TrimLeft(d.Spec, "=v "))
				break
			}
			if v, ok := repo.LockVersion[path.Dir(d.Path)+"|"+d.Name]; ok {
				a.FrameworkVersion = v
				break
			}
		}
		disc.Agents = append(disc.Agents, ag)
	}

	// Agents that are declared in the configuration but were not recognized
	// in code are still assessed, from declarations and external evidence.
	discovered := map[string]bool{}
	for _, ag := range disc.Agents {
		discovered[ag.Root] = true
	}
	lenient := len(disc.Agents) == 1 && len(cfgAgents) == 1 && cfgAgents[0].Root == "."
	declaredRoots := map[string]bool{}
	for i := range cfgAgents {
		ca := &cfgAgents[i]
		isSingle := i == 0 && len(cfgAgents) > len(cfg.Agents)
		if (isSingle && ca.ID == "") || discovered[ca.Root] || declaredRoots[ca.Root] || lenient {
			continue
		}
		declaredRoots[ca.Root] = true
		ag := &AgentScope{Root: ca.Root, repo: repo, declared: true}
		a := &ag.Agent
		a.Root = ca.Root
		a.Detection, a.Confidence = model.Suspected, model.ConfidenceLow
		a.Framework, a.FrameworkVersion, a.Language, a.Entrypoint = model.Unknown, model.Unknown, model.Unknown, model.Unknown
		a.Owner, a.RiskTier = model.Unknown, model.Unknown
		cfgPath := config.FileName
		if cfg.Path != "" {
			cfgPath = cfg.Path
		}
		a.Facts = append(a.Facts, fact("declared-agent", "The configuration declares this agent. No agent code was recognized.", cfgPath, 0, model.ConfidenceLow, "config.agentgov"))
		disc.Agents = append(disc.Agents, ag)
	}

	// Finalize scopes now that every agent root is known.
	var all []string
	for _, ag := range disc.Agents {
		all = append(all, ag.Root)
	}
	usedIDs := map[string]bool{}
	for _, ag := range disc.Agents {
		ag.allRoots = all
		ag.projRoots = roots
		for _, o := range all {
			if o != ag.Root && under(o, ag.Root) {
				ag.otherRoots = append(ag.otherRoots, o)
			}
		}
		for _, s := range repo.Sources {
			if under(s.Path, ag.Root) && ag.InScope(s.Path) {
				ag.Sources = append(ag.Sources, s)
			}
		}
		ag.fnIndex = map[string][]fnRef{}
		for _, s := range ag.Sources {
			for i := range s.Funcs {
				ag.fnIndex[s.Funcs[i].Name] = append(ag.fnIndex[s.Funcs[i].Name], fnRef{s, &s.Funcs[i]})
			}
		}
		// Configuration match.
		for i := range cfgAgents {
			if cfgAgents[i].Root == ag.Root {
				ag.ConfigAgent = &cfgAgents[i]
				break
			}
		}
		if ag.ConfigAgent == nil && len(disc.Agents) == 1 && len(cfgAgents) == 1 && cfgAgents[0].Root == "." {
			ag.ConfigAgent = &cfgAgents[0]
		}
		a := &ag.Agent
		name := path.Base(ag.Root)
		if ag.Root == "." {
			name = rootName
		}
		a.Name = name
		a.ID = Slug(name)
		if ca := ag.ConfigAgent; ca != nil {
			if ca.ID != "" {
				if agentIDRe.MatchString(ca.ID) {
					a.ID, a.Name = ca.ID, ca.ID
				} else {
					disc.Warnings = append(disc.Warnings, "the declared agent id for root "+ag.Root+
						" is not a valid identifier (letters, digits, dot, dash, underscore; at most 128 characters); a derived id was used")
				}
			}
			if ca.Owner != "" {
				a.Owner = ca.Owner
			}
			if ca.RiskTier != "" {
				a.RiskTier = strings.ToLower(ca.RiskTier)
			}
		}
		if usedIDs[a.ID] {
			a.ID = Slug(ag.Root)
			for n := 2; usedIDs[a.ID]; n++ {
				a.ID = fmt.Sprintf("%s-%d", Slug(ag.Root), n)
			}
		}
		usedIDs[a.ID] = true
		if ag.declared {
			for _, name := range cfg.Capabilities.DeclaredTools {
				if strings.TrimSpace(name) != "" {
					ag.addTool(strings.TrimSpace(name), nil, nil, 0, 0)
				}
			}
			disc.Limitations = append(disc.Limitations, "Agent "+a.ID+" is declared in .agentgov.yaml, but no agent code was recognized. "+
				"Controls are assessed from declarations and external evidence only.")
		} else {
			ag.findTools(cfg)
		}
		ag.finish(cfg)
	}
	sort.Slice(disc.Agents, func(i, j int) bool { return disc.Agents[i].Agent.ID < disc.Agents[j].Agent.ID })
	if len(disc.Agents) == 0 {
		disc.Limitations = append(disc.Limitations,
			"No AI agent was detected. Discovery looks for an import of a supported framework (LangChain, LangGraph, OpenAI Agents SDK, CrewAI, AutoGen, PydanticAI, MCP) "+
				"or a model client SDK used with a tools argument, in Python, TypeScript, or JavaScript code. Framework names in comments, documentation, or strings do not count.")
		if clientOnly {
			disc.Limitations = append(disc.Limitations,
				"A model client SDK is referenced, but no tools argument or tool schema was found, so the code was not treated as an agent.")
		}
	}
	return disc
}

func decoratorName(d string) string {
	if i := strings.Index(d, "("); i >= 0 {
		d = d[:i]
	}
	return strings.TrimSpace(d)
}

// decoratorModule returns the import module behind a decorator, or "".
func decoratorModule(s *Source, d string) string {
	name := decoratorName(d)
	first := name
	if i := strings.Index(name, "."); i >= 0 {
		first = name[:i]
	}
	return s.Aliases[first].Module
}
