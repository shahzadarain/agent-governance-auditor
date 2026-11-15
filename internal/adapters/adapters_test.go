// SPDX-License-Identifier: Apache-2.0

package adapters

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/shahzadarain/agent-governance-auditor/internal/config"
	"github.com/shahzadarain/agent-governance-auditor/internal/discovery"
	"github.com/shahzadarain/agent-governance-auditor/internal/model"
)

func analyzeTree(t *testing.T, files map[string]string) *Repo {
	t.Helper()
	root := t.TempDir()
	for rel, content := range files {
		p := filepath.Join(root, filepath.FromSlash(rel))
		if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p, []byte(content), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	inv, err := discovery.Walk(context.Background(), discovery.Options{Root: root})
	if err != nil {
		t.Fatal(err)
	}
	return Analyze(context.Background(), inv)
}

func py(src string) *Source { return PythonAnalyzer{}.Analyze("t.py", []byte(src)) }
func js(src string) *Source { return JSAnalyzer{}.Analyze("t.ts", []byte(src)) }

func TestPythonLexerBlanksCommentsAndStrings(t *testing.T) {
	src := "import os  # import langgraph\n" +
		"\"\"\"Module docstring: from crewai import Agent\"\"\"\n" +
		"x = 'subprocess.run(cmd)'  # eval(x)\n" +
		"y = r'C:\\new\\table' + \"it's\"\n" +
		"z = f\"hello {user.name!r} and {{literal}} {call(a, b)}\"\n" +
		"def f():\n    '''Docstring with eval(x)'''\n    return b\"bytes # not a comment\"\n"
	s := py(src)
	if len(s.Code) != len(src) || len(s.Text) != len(src) {
		t.Fatalf("views must keep byte offsets: raw=%d code=%d text=%d", len(src), len(s.Code), len(s.Text))
	}
	if strings.Count(s.Code, "\n") != strings.Count(src, "\n") {
		t.Fatal("line count changed")
	}
	for _, gone := range []string{"langgraph", "crewai", "subprocess", "eval", "new", "it's", "hello", "literal", "Docstring", "not a comment"} {
		if strings.Contains(s.Code, gone) {
			t.Errorf("code view still contains %q", gone)
		}
	}
	for _, kept := range []string{"import os", "user.name", "call(a, b)", "def f():", "return b"} {
		if !strings.Contains(s.Code, kept) {
			t.Errorf("code view lost %q:\n%s", kept, s.Code)
		}
	}
	// The text view keeps ordinary strings but not comments or docstrings.
	if !strings.Contains(s.Text, "subprocess.run(cmd)") || !strings.Contains(s.Text, "not a comment") {
		t.Errorf("text view should keep string contents:\n%s", s.Text)
	}
	for _, gone := range []string{"langgraph", "crewai", "Docstring with", "# eval"} {
		if strings.Contains(s.Text, gone) {
			t.Errorf("text view still contains %q", gone)
		}
	}
	docs := 0
	for _, l := range s.Strings {
		if l.Doc {
			docs++
		}
	}
	if docs != 2 {
		t.Errorf("expected 2 docstrings, got %d", docs)
	}
}

func TestPythonMultiLineStringsDoNotBreakStructure(t *testing.T) {
	s := py("def a():\n    q = \"\"\"\nSELECT 1\ndef fake(): pass\n\"\"\"\n    return q\n\ndef b():\n    return 2\n")
	if len(s.Funcs) != 2 || s.Funcs[0].Name != "a" || s.Funcs[0].EndLine != 6 || s.Funcs[1].Name != "b" {
		t.Fatalf("functions: %+v", s.Funcs)
	}
}

func TestJSLexer(t *testing.T) {
	src := "// import { Agent } from '@openai/agents'\n" +
		"/* require('child_process').exec(cmd)\n   eval(x) */\n" +
		"const a = 'eval(1)'; const b = \"fetch('/x')\";\n" +
		"const c = `total ${count + fn(1)} items and eval(2)`;\n" +
		"const re = /eval\\(['\"]x/g; const d = a / 2;\n" +
		"call(a);\n"
	s := js(src)
	if len(s.Code) != len(src) {
		t.Fatalf("offsets changed")
	}
	for _, gone := range []string{"Agent", "child_process", "eval", "fetch", "total", "items"} {
		if strings.Contains(s.Code, gone) {
			t.Errorf("code view still contains %q:\n%s", gone, s.Code)
		}
	}
	for _, kept := range []string{"count + fn(1)", "const d = a / 2", "call(a)"} {
		if !strings.Contains(s.Code, kept) {
			t.Errorf("code view lost %q:\n%s", kept, s.Code)
		}
	}
	if len(s.Imports) != 0 {
		t.Errorf("imports inside comments must not count: %+v", s.Imports)
	}
}

func TestPythonImportsAndAliases(t *testing.T) {
	s := py("import os, sys as system\nimport langgraph.graph as lg\nimport a.b.c\n" +
		"from langgraph.prebuilt import (\n    create_react_agent as cra,\n    ToolNode,\n)\n" +
		"from . import data\nfrom ..pkg.mod import thing as t2\nfrom x import *\n" +
		"def f():\n    import subprocess as sp\n    sp.run('x')\n    lg.StateGraph(S)\n    cra(model, tools=[a], interrupt_before=['tools'])\n    a.b.c.go()\n")
	want := map[string]Binding{
		"os": {Module: "os"}, "system": {Module: "sys"}, "lg": {Module: "langgraph.graph"}, "a": {Module: "a"},
		"cra": {Module: "langgraph.prebuilt", Name: "create_react_agent"}, "ToolNode": {Module: "langgraph.prebuilt", Name: "ToolNode"},
		"data": {Module: ".", Name: "data"}, "t2": {Module: "..pkg.mod", Name: "thing"}, "sp": {Module: "subprocess"},
	}
	for k, v := range want {
		if s.Aliases[k] != v {
			t.Errorf("alias %q = %+v, want %+v", k, s.Aliases[k], v)
		}
	}
	find := func(name string) *Call {
		for i := range s.Calls {
			if s.Calls[i].Name == name {
				return &s.Calls[i]
			}
		}
		t.Fatalf("call %q not found in %+v", name, s.Calls)
		return nil
	}
	if c := find("lg.StateGraph"); c.Module != "langgraph.graph" || c.Symbol != "StateGraph" {
		t.Errorf("lg.StateGraph resolved to %q %q", c.Module, c.Symbol)
	}
	c := find("cra")
	if c.Module != "langgraph.prebuilt" || c.Symbol != "create_react_agent" || !c.HasKwarg("tools") || !c.HasKwarg("interrupt_before") || c.Line != 15 {
		t.Errorf("cra call: %+v", c)
	}
	if v, ok := s.KwargText(*c, "interrupt_before"); !ok || v != "['tools']" {
		t.Errorf("KwargText = %q, %v", v, ok)
	}
	if c := find("sp.run"); c.Module != "subprocess" {
		t.Errorf("sp.run module = %q", c.Module)
	}
	if c := find("a.b.c.go"); c.Module != "a" || c.Symbol != "b.c.go" {
		t.Errorf("a.b.c.go resolved to %q %q", c.Module, c.Symbol)
	}
	if !s.ImportsModule("langgraph") || s.ImportsModule("lang") {
		t.Error("ImportsModule must match whole module segments")
	}
}

func TestPythonStructure(t *testing.T) {
	s := py("@mcp.tool()\nasync def fetch(url: str, timeout: int = 30) -> str:\n    return url\n\n" +
		"class Store(Base, metaclass=M):\n    @staticmethod\n    def put(self, key, value=None, *args, **kw):\n        if key:\n            return 1\n        return 2\n\n" +
		"@tool\n@other(1,\n       2)\ndef last(a, approved=True): pass\n")
	if len(s.Funcs) != 3 {
		t.Fatalf("funcs: %+v", s.Funcs)
	}
	f := s.Funcs[0]
	if f.Name != "fetch" || len(f.Decorators) != 1 || f.Decorators[0] != "mcp.tool()" || len(f.Params) != 2 || f.Params[1].Name != "timeout" || f.Params[1].Default != "30" || f.Line != 2 || f.EndLine != 3 {
		t.Errorf("fetch: %+v", f)
	}
	p := s.Funcs[1]
	if p.Name != "put" || p.Class != "Store" || p.EndLine != 10 || len(p.Params) != 5 || p.Params[2].Default != "None" || p.Params[3].Name != "args" {
		t.Errorf("put: %+v", p)
	}
	l := s.Funcs[2]
	if l.Name != "last" || len(l.Decorators) != 2 || l.Decorators[0] != "tool" || l.Params[1].Default != "True" {
		t.Errorf("last: %+v", l)
	}
	if len(s.Classes) != 1 || s.Classes[0].Name != "Store" || len(s.Classes[0].Bases) != 1 || s.Classes[0].Bases[0] != "Base" || s.Classes[0].EndLine != 10 {
		t.Errorf("classes: %+v", s.Classes)
	}
	if got := s.FuncAt(9); got == nil || got.Name != "put" {
		t.Errorf("FuncAt(9) = %+v", got)
	}
}

func TestPythonInvalidSyntaxAndInvalidUTF8(t *testing.T) {
	for _, src := range []string{
		"def broken(a, b:\n    return (a + b\nclass Nope\n    x = \"\"\"never closed\ndef after():\n    return {1, 2\n",
		"x = 'unterminated\ny = \"also\nimport openai\n",
		"\xff\xfe\x00bad bytes \xc3\x28 def f(:\n",
		strings.Repeat("(", 5000),
		"",
	} {
		s := py(src) // must not panic
		if len(s.Code) != len(src) {
			t.Errorf("offsets changed for malformed input")
		}
		_ = js(src)
	}
	s := py("caf\u00e9 = '\u65e5\u672c\u8a9e'  # \u00fcber\nimport openai\n")
	if !s.ImportsModule("openai") || strings.Contains(s.Code, "\u65e5") {
		t.Errorf("unicode source mishandled: %q", s.Code)
	}
	bad := PythonAnalyzer{}.Analyze("b.py", []byte("x = 1\n\xff\xfe\n"))
	if len(bad.Warnings) == 0 {
		t.Error("invalid UTF-8 should produce a warning")
	}
}

func TestJSImportsAndCalls(t *testing.T) {
	s := js("import OpenAI from 'openai';\nimport { Agent, run as go, type Tool } from \"@openai/agents\";\nimport * as mcp from '@modelcontextprotocol/sdk/server/mcp.js';\n" +
		"import 'dotenv/config';\nconst cp = require('node:child_process');\nconst { exec, spawn: sp } = require('child_process');\n" +
		"async function main() {\n  const z = await import('zod');\n  const a = new Agent({ name: 'x', tools: [t], 'quoted-key': 1 });\n  exec('ls');\n  go(a, 'hi', { maxTurns: 3 });\n  const s = new mcp.McpServer({ name: 'srv' });\n}\n")
	want := map[string]Binding{
		"OpenAI": {Module: "openai"}, "Agent": {Module: "@openai/agents", Name: "Agent"}, "go": {Module: "@openai/agents", Name: "run"},
		"mcp": {Module: "@modelcontextprotocol/sdk/server/mcp.js"}, "cp": {Module: "node:child_process"},
		"exec": {Module: "child_process", Name: "exec"}, "sp": {Module: "child_process", Name: "spawn"},
	}
	for k, v := range want {
		if s.Aliases[k] != v {
			t.Errorf("alias %q = %+v, want %+v", k, s.Aliases[k], v)
		}
	}
	for _, m := range []string{"dotenv/config", "zod"} {
		if !s.ImportsModule(m) {
			t.Errorf("import of %q not recorded: %+v", m, s.Imports)
		}
	}
	var agent, mcpCall *Call
	for i := range s.Calls {
		switch s.Calls[i].Name {
		case "Agent":
			agent = &s.Calls[i]
		case "mcp.McpServer":
			mcpCall = &s.Calls[i]
		}
	}
	if agent == nil || !agent.New || agent.Module != "@openai/agents" || !agent.HasKwarg("tools") || !agent.HasKwarg("quoted-key") {
		t.Errorf("Agent call: %+v", agent)
	}
	if mcpCall == nil || mcpCall.Symbol != "McpServer" || !mcpCall.New {
		t.Errorf("McpServer call: %+v", mcpCall)
	}
	if f := s.FuncByName("main"); f == nil || f.Line != 7 || f.EndLine != 13 {
		t.Errorf("main func: %+v", f)
	}
	tr := s.FileTraits()
	if !tr.Shell {
		t.Error("exec from child_process should be a shell trait")
	}
}

func TestTraits(t *testing.T) {
	s := py("import subprocess as sp, sqlite3, requests, os\n" +
		"def a(c): sp.run(c, shell=True)\n" +
		"def b(c): eval(c)\n" +
		"def c1(u): return requests.get(u)\n" +
		"def d(u): return requests.post(u, json={})\n" +
		"def e(p): open(p, 'w').write('x')\n" +
		"def f(p): return open(p).read()\n" +
		"def g(db, v): db.execute('INSERT INTO t VALUES (?)', (v,))\n" +
		"def h(db): return db.execute('SELECT a FROM t').fetchall()\n" +
		"def i(): return os.environ['OPENAI_API_KEY']\n" +
		"def j(): return 'subprocess.run(x); eval(y)'  # os.system(z)\n")
	check := func(name string, ok func(Traits) bool) {
		t.Helper()
		f := s.FuncByName(name)
		if f == nil {
			t.Fatalf("func %s missing", name)
		}
		if tr := s.TraitsIn(f.Line, f.EndLine); !ok(tr) {
			t.Errorf("traits of %s: %+v", name, tr)
		}
	}
	check("a", func(t Traits) bool { return t.Shell && !t.CodeExec })
	check("b", func(t Traits) bool { return t.CodeExec && !t.Shell })
	check("c1", func(t Traits) bool { return t.HTTP && !t.HTTPMutate })
	check("d", func(t Traits) bool { return t.HTTP && t.HTTPMutate })
	check("e", func(t Traits) bool { return t.FSWrite })
	check("f", func(t Traits) bool { return t.FSRead && !t.FSWrite })
	check("g", func(t Traits) bool { return t.DB && t.DBWrite })
	check("h", func(t Traits) bool { return t.DB && !t.DBWrite })
	check("i", func(t Traits) bool { return t.EnvSecret })
	check("j", func(t Traits) bool { return t == Traits{} })
}

func TestTOMLReader(t *testing.T) {
	d, err := ParseTOML("pyproject.toml", []byte("# comment\n[project]\nname = \"demo\"  # trailing\nversion = '1.0'\n"+
		"dependencies = [\n  \"openai>=1.0\",  # why\n  'langgraph==0.2.60',\n]\nrequires-python = \">=3.10\"\n\n"+
		"[project.optional-dependencies]\ndev = [\"pytest\"]\n\n[tool.poetry.dependencies]\npython = \"^3.10\"\ncrewai = \"0.80.0\"\n"+
		"httpx = { version = \"^0.27\", extras = [\"http2\"] }\n\n[[tool.x.items]]\nid = 1\n[[tool.x.items]]\nid = 2\nflag = true\n"))
	if err != nil {
		t.Fatal(err)
	}
	want := map[string]string{
		"project.name": "demo", "project.version": "1.0", "project.dependencies[0]": "openai>=1.0",
		"project.dependencies[1]": "langgraph==0.2.60", "project.optional-dependencies.dev[0]": "pytest",
		"tool.poetry.dependencies.crewai": "0.80.0", "tool.poetry.dependencies.httpx.version": "^0.27",
		"tool.x.items[0].id": "1", "tool.x.items[1].id": "2", "tool.x.items[1].flag": "true",
	}
	for k, v := range want {
		if got, ok := d.Get(k); !ok || got != v {
			t.Errorf("%s = %q (%v), want %q", k, got, ok, v)
		}
	}
	if d.Line("project.dependencies[0]") != 5 {
		t.Errorf("line of dependencies = %d", d.Line("project.dependencies[0]"))
	}
	deps := pyprojectDeps(d)
	byName := map[string]Dependency{}
	for _, dep := range deps {
		byName[dep.Name] = dep
	}
	if byName["openai"].Pinned || !byName["langgraph"].Pinned || !byName["crewai"].Pinned || byName["httpx"].Pinned || !byName["pytest"].Dev {
		t.Errorf("pyproject deps: %+v", deps)
	}
	if _, ok := byName["python"]; ok {
		t.Error("python itself is not a dependency")
	}
	for _, bad := range []string{"[project\nname = 1\n", "x = [1, 2\n", "this is not toml\n", "a = \"unterminated\nb = 1 2 = 3\n"} {
		if _, err := ParseTOML("x.toml", []byte(bad)); err == nil {
			t.Errorf("malformed TOML accepted: %q", bad)
		}
	}
}

func TestManifestsAndLockfiles(t *testing.T) {
	r := analyzeTree(t, map[string]string{
		"requirements.txt": "# comment\nopenai==1.58.1 \\\n    --hash=sha256:abc\nLangGraph>=0.2\nrequests[socks] ~= 2.31 ; python_version > '3.8'\n-r other.txt\n" +
			"pkg @ git+https://example.com/x.git@0123456789abcdef0123456789abcdef01234567\nfuzzy==1.*\n",
		"package.json":      `{"name":"x","dependencies":{"ai":"4.0.20","zod":"^3.24.1","@openai/agents":"latest"},"devDependencies":{"tsx":"4.19.0"}}`,
		"package-lock.json": `{"packages":{"node_modules/zod":{"version":"3.24.1"},"node_modules/a/node_modules/zod":{"version":"1.0.0"}}}`,
		"poetry.lock":       "[[package]]\nname = \"LangGraph\"\nversion = \"0.2.60\"\n\n[[package]]\nname = \"openai\"\nversion = \"1.58.1\"\n",
		"sub/yarn.lock":     "# yarn lockfile v1\n",
	})
	byName := map[string]Dependency{}
	for _, d := range r.Deps {
		byName[d.Eco+":"+d.Name] = d
	}
	if d := byName["pypi:openai"]; !d.Pinned || !d.Hashed || d.Line != 2 {
		t.Errorf("openai: %+v", d)
	}
	if byName["pypi:langgraph"].Pinned || byName["pypi:requests"].Pinned || !byName["pypi:pkg"].Pinned || byName["pypi:fuzzy"].Pinned {
		t.Errorf("pinning wrong: %+v", r.Deps)
	}
	if !byName["npm:ai"].Pinned || byName["npm:zod"].Pinned || byName["npm:@openai/agents"].Pinned || !byName["npm:tsx"].Dev {
		t.Errorf("npm deps: %+v", r.Deps)
	}
	if got := strings.Join(r.Lockfiles, ","); got != "package-lock.json,poetry.lock,sub/yarn.lock" {
		t.Errorf("lockfiles: %s", got)
	}
	if r.LockVersion[".|langgraph"] != "0.2.60" || r.LockVersion[".|zod"] != "3.24.1" {
		t.Errorf("lock versions: %+v", r.LockVersion)
	}
}

func TestMCPConfigNeverKeepsArgsOrEnv(t *testing.T) {
	const secretArg = "ghp_argTokenValueThatMustNeverAppear000000"
	const secretEnv = "env-secret-value-that-must-never-appear"
	r := analyzeTree(t, map[string]string{
		".mcp.json": `{"mcpServers":{
  "pinned":{"command":"npx","args":["-y","@scope/server-files@1.2.3","/private/path","--token","` + secretArg + `"],"env":{"API_KEY":"` + secretEnv + `"}},
  "floating":{"command":"npx","args":["-y","some-mcp-server"]},
  "latest":{"command":"npx","args":["some-mcp-server@latest"]},
  "py":{"command":"uvx","args":["mcp-server-git==0.6.2","--repository","/repo"]},
  "pyfloat":{"command":"uvx","args":["mcp-server-time"]},
  "local":{"command":"C:\\tools\\python.exe","args":["server.py","--password","` + secretArg + `"]},
  "remote":{"type":"sse","url":"https://user:` + secretArg + `@mcp.example.com/sse?key=` + secretArg + `"},
  "img":{"command":"docker","args":["run","-i","--rm","-e","TOKEN=` + secretArg + `","ghcr.io/acme/mcp:1.4.0"]},
  "imgfloat":{"command":"docker","args":["run","-i","acme/mcp"]},
  "scoped":{"command":"node","args":["s.js"],"allowedTools":["read"]}
}}`,
		".cursor/mcp.json": `{"mcpServers":{"c":{"command":"npx","args":["-y","cursor-server@0.1.0"]}}}`,
		".vscode/mcp.json": `{"servers":{"v":{"command":"npx","args":["-y","vscode-server"]}}}`,
		"other.json":       `{"mcpServers":{"ignored":{"command":"npx","args":["x"]}}}`,
	})
	by := map[string]MCPServer{}
	for _, m := range r.MCP {
		by[m.Name] = m
		for _, field := range []string{m.Name, m.Target, m.Package, m.Version, m.Transport} {
			if strings.Contains(field, secretArg) || strings.Contains(field, secretEnv) || strings.Contains(field, "/private/path") || strings.Contains(field, "password") {
				t.Fatalf("MCP server %q leaked an argument or environment value: %+v", m.Name, m)
			}
		}
	}
	type want struct {
		pinned, registry bool
		version, target  string
	}
	cases := map[string]want{
		"pinned": {true, true, "1.2.3", "npx @scope/server-files"}, "floating": {false, true, "", "npx some-mcp-server"},
		"latest": {false, true, "", "npx some-mcp-server"}, "py": {true, true, "0.6.2", "uvx mcp-server-git"},
		"pyfloat": {false, true, "", "uvx mcp-server-time"}, "local": {true, false, "", "python"},
		"remote": {false, false, "", "mcp.example.com"}, "img": {true, true, "1.4.0", "docker ghcr.io/acme/mcp"},
		"imgfloat": {false, true, "", "docker acme/mcp"}, "c": {true, true, "0.1.0", "npx cursor-server"}, "v": {false, true, "", "npx vscode-server"},
	}
	for name, w := range cases {
		m, ok := by[name]
		if !ok {
			t.Errorf("server %q not found", name)
			continue
		}
		if m.Pinned != w.pinned || m.Registry != w.registry || m.Version != w.version || m.Target != w.target {
			t.Errorf("%s: got pinned=%v registry=%v version=%q target=%q, want %+v", name, m.Pinned, m.Registry, m.Version, m.Target, w)
		}
	}
	if by["remote"].Transport != "sse" || by["pinned"].Transport != "stdio" || !by["scoped"].Allowed {
		t.Errorf("transport or allowlist wrong: %+v %+v", by["remote"], by["scoped"])
	}
	if _, ok := by["ignored"]; ok {
		t.Error("only known MCP configuration file names are read")
	}
}

func TestDockerfileAndMalformedDocs(t *testing.T) {
	r := analyzeTree(t, map[string]string{
		"Dockerfile":      "# c\nFROM --platform=linux/amd64 python:3.12 AS build\nRUN pip install \\\n  x\nFROM python@sha256:" + strings.Repeat("a", 64) + "\nUSER 1000:1000\nENV A=b\n",
		"api.Dockerfile":  "FROM node\nUSER root\n",
		"bad.yaml":        "a:\n  b: [1, 2\n c: x\n",
		"bad.json":        `{"a": [1, 2,}`,
		"bad.toml":        "[x\n",
		"ok.yaml":         "a:\n  - b: 1\n    c: [x, y]\n---\nkind: Pod\n",
		"empty.yaml":      "",
		"anchors.yaml":    "a: &a [1, 2]\nb: *a\nc: *a\n",
		"deep.json":       strings.Repeat("[", 200) + strings.Repeat("]", 200),
		"weird.py":        "\x01\x02def f(:\n",
		"notes/readme.md": "from langgraph import x\n",
	})
	if len(r.Dockerfiles) != 2 {
		t.Fatalf("dockerfiles: %d", len(r.Dockerfiles))
	}
	df := r.Dockerfiles[0]
	if len(df.Froms) != 2 || df.Froms[0].Tag != "3.12" || df.Froms[0].Digest || !df.Froms[1].Digest || df.User != "1000:1000" || df.Froms[1].Line != 5 {
		t.Errorf("Dockerfile: %+v", df)
	}
	if r.Dockerfiles[1].Froms[0].Tag != "" || r.Dockerfiles[1].User != "root" {
		t.Errorf("api.Dockerfile: %+v", r.Dockerfiles[1])
	}
	for _, p := range []string{"bad.yaml", "bad.json", "bad.toml"} {
		if r.Malformed[p] == "" {
			t.Errorf("%s should be recorded as malformed", p)
		}
		if len(r.DocsAt(p)) != 0 {
			t.Errorf("%s must not produce a document", p)
		}
	}
	if len(r.Warnings) < 3 {
		t.Errorf("expected warnings for malformed files, got %v", r.Warnings)
	}
	docs := r.DocsAt("ok.yaml")
	if len(docs) != 2 {
		t.Fatalf("ok.yaml docs: %d", len(docs))
	}
	if v, _ := docs[0].Get("a[0].c[1]"); v != "y" {
		t.Errorf("a[0].c[1] = %q", v)
	}
	if v, _ := docs[1].Get("kind"); v != "Pod" || docs[1].Line("kind") != 5 {
		t.Errorf("second doc: %q line %d", v, docs[1].Line("kind"))
	}
	if len(r.DocsAt("anchors.yaml")) != 1 || len(r.DocsAt("anchors.yaml")[0].Entries) > 10 {
		t.Errorf("aliases must not be expanded")
	}
}

func discover(t *testing.T, files map[string]string, cfg *config.Config) *Discovery {
	t.Helper()
	return Discover(analyzeTree(t, files), cfg, "fixture")
}

func TestDiscoveryStates(t *testing.T) {
	t.Run("detected needs import and usage", func(t *testing.T) {
		d := discover(t, map[string]string{"a.py": "from crewai import Agent, Crew\nagent = Agent(role='x')\ncrew = Crew(agents=[agent])\n",
			"requirements.txt": "crewai==0.80.0\n"}, nil)
		if len(d.Agents) != 1 {
			t.Fatalf("agents: %d", len(d.Agents))
		}
		a := d.Agents[0].Agent
		if a.Detection != model.Detected || a.Framework != "crewai" || a.FrameworkVersion != "0.80.0" || a.Language != "python" || a.ID != "fixture" || a.Root != "." {
			t.Errorf("agent: %+v", a)
		}
		if a.Owner != model.Unknown || a.RiskTier != model.Unknown || a.Entrypoint != model.Unknown {
			t.Errorf("unknown fields must stay unknown: %+v", a)
		}
		for _, f := range a.Facts {
			if f.Location.Path == "" || f.Collector == "" || f.ParserVersion == "" || f.Confidence == "" || f.Detail == "" {
				t.Errorf("incomplete fact: %+v", f)
			}
		}
	})
	t.Run("import only is suspected", func(t *testing.T) {
		d := discover(t, map[string]string{"a.py": "import pydantic_ai\n"}, nil)
		if len(d.Agents) != 1 || d.Agents[0].Agent.Detection != model.Suspected || d.Agents[0].Agent.Confidence != model.ConfidenceMedium ||
			d.Agents[0].Agent.FrameworkVersion != model.Unknown || d.Agents[0].Agent.InferredRiskTier != model.Unknown {
			t.Fatalf("agents: %+v", d.Agents)
		}
	})
	t.Run("manifest only is suspected with low confidence", func(t *testing.T) {
		d := discover(t, map[string]string{"pyproject.toml": "[project]\ndependencies = [\"langgraph>=0.2\"]\n", "main.py": "print('hi')\n"}, nil)
		if len(d.Agents) != 1 || d.Agents[0].Agent.Detection != model.Suspected || d.Agents[0].Agent.Confidence != model.ConfidenceLow || d.Agents[0].Agent.Language != "python" {
			t.Fatalf("agents: %+v", d.Agents)
		}
	})
	t.Run("model client without tools is not an agent", func(t *testing.T) {
		d := discover(t, map[string]string{"a.py": "import openai\nc = openai.OpenAI()\nc.chat.completions.create(model='m', messages=[])\n"}, nil)
		if len(d.Agents) != 0 || len(d.Limitations) != 2 {
			t.Fatalf("agents=%d limitations=%v", len(d.Agents), d.Limitations)
		}
	})
	t.Run("names in comments and strings yield nothing", func(t *testing.T) {
		d := discover(t, map[string]string{
			"a.py":      "# import langgraph\n\"\"\"from crewai import Agent\nAgent()\"\"\"\nx = 'from agents import Agent, Runner'\n",
			"b.js":      "// import { Agent } from '@openai/agents'\nconst s = \"require('openai')\";\n",
			"README.md": "Built with LangGraph and CrewAI. `create_react_agent(model, tools=[x])`\n",
		}, nil)
		if len(d.Agents) != 0 || len(d.Limitations) == 0 {
			t.Fatalf("agents: %+v", d.Agents)
		}
	})
	t.Run("local package named agents is not the SDK", func(t *testing.T) {
		d := discover(t, map[string]string{"agents/__init__.py": "class Agent: pass\n", "main.py": "from agents import Agent\nAgent()\n"}, nil)
		if len(d.Agents) != 0 {
			t.Fatalf("a local 'agents' package was treated as the OpenAI Agents SDK: %+v", d.Agents[0].Agent)
		}
	})
}

func TestDiscoveryAliasedAndWrappedImports(t *testing.T) {
	d := discover(t, map[string]string{
		"app/__init__.py": "",
		"app/llm.py":      "from langgraph.prebuilt import (\n    create_react_agent as make_react,\n)\n\ndef make_agent(model, tools):\n    return make_react(model, tools=tools)\n",
		"app/main.py":     "from langchain_core.tools import tool as lc_tool\nfrom .llm import make_agent\n\n@lc_tool\ndef send_report(to: str) -> str:\n    return to\n\nagent = make_agent(None, [send_report])\n",
		"app/graph.py":    "import langgraph.graph as lg\n\ndef build():\n    return lg.StateGraph(dict)\n",
	}, nil)
	if len(d.Agents) != 1 {
		t.Fatalf("agents: %d", len(d.Agents))
	}
	a := d.Agents[0].Agent
	if a.Framework != "langgraph" || a.Detection != model.Detected {
		t.Fatalf("agent: %+v", a)
	}
	var direct, alias, indirect, wrapper bool
	for _, f := range a.Facts {
		switch {
		case f.Location.Path == "app/graph.py" && f.Kind == "agent-construction" && strings.Contains(f.Detail, "lg.StateGraph"):
			alias = true
		case f.Location.Path == "app/llm.py" && f.Kind == "agent-construction" && strings.Contains(f.Detail, "make_react"):
			direct = true
		case f.Location.Path == "app/main.py" && f.Kind == "framework-import" && strings.Contains(f.Detail, "through the local module app/llm.py"):
			indirect = true
		case f.Location.Path == "app/main.py" && f.Kind == "agent-construction" && strings.Contains(f.Detail, "local wrapper"):
			wrapper = true
		}
	}
	if !direct || !alias || !indirect || !wrapper {
		t.Errorf("facts missing: direct=%v alias=%v indirect=%v wrapper=%v\n%+v", direct, alias, indirect, wrapper, a.Facts)
	}
	if len(a.Tools) != 1 || a.Tools[0].Name != "send_report" || !a.Tools[0].Sensitive {
		t.Errorf("aliased @tool decorator not resolved: %+v", a.Tools)
	}
}

func TestDiscoveryMonorepoAndConfig(t *testing.T) {
	files := map[string]string{
		"services/billing/requirements.txt": "openai-agents==0.0.17\n",
		"services/billing/main.py":          "from agents import Agent, Runner, function_tool\n\n@function_tool\ndef issue_refund(account: str) -> str:\n    return 'ok'\n\na = Agent(name='b', tools=[issue_refund])\n",
		"services/bot/package.json":         `{"main":"src/index.ts","dependencies":{"@openai/agents":"0.1.3"}}`,
		"services/bot/src/index.ts":         "import { Agent, tool } from '@openai/agents';\nconst getStatus = tool({ name: 'get_status', execute: async () => 'ok' });\nexport const agent = new Agent({ name: 'x', tools: [getStatus] });\n",
		"web/package.json":                  `{"dependencies":{"left-pad":"1.3.0"}}`,
		"web/index.js":                      "export const x = 1;\n",
		"Dockerfile":                        "FROM python:3.12\n",
	}
	cfg := &config.Config{Agents: []config.Agent{{ID: "billing-prod", Root: "./services/billing/", Owner: "billing-team", RiskTier: "High"}}}
	cfg.Capabilities.DeclaredTools = []string{"issue-refund"}
	cfg.Capabilities.SensitiveActions = []string{"issue_refund"}
	d := discover(t, files, cfg)
	if len(d.Agents) != 2 {
		t.Fatalf("expected 2 agents, got %d", len(d.Agents))
	}
	b, s := d.Agents[1], d.Agents[0]
	if b.Agent.ID != "billing-prod" {
		b, s = s, b
	}
	if b.Agent.ID != "billing-prod" || b.Agent.Owner != "billing-team" || b.Agent.RiskTier != "high" || b.Agent.Root != "services/billing" || b.Agent.Framework != "openai-agents" {
		t.Errorf("billing: %+v", b.Agent)
	}
	if len(b.Agent.Tools) != 1 || !b.Agent.Tools[0].Declared || !b.Agent.Tools[0].Sensitive || !strings.Contains(b.Agent.Tools[0].SensitiveWhy, "configuration") {
		t.Errorf("billing tools: %+v", b.Agent.Tools)
	}
	if s.Agent.ID != "bot" || s.Agent.Language != "typescript" || s.Agent.Entrypoint != "services/bot/src/index.ts" || s.Agent.FrameworkVersion != "0.1.3" ||
		len(s.Agent.Tools) != 1 || s.Agent.Tools[0].Name != "get_status" || s.Agent.Owner != model.Unknown {
		t.Errorf("bot: %+v", s.Agent)
	}
	if b.InScope("services/bot/src/index.ts") || s.InScope("services/billing/main.py") || b.InScope("web/index.js") {
		t.Error("an agent scope must not include another agent's sources or unrelated source code")
	}
	if !b.InScope("Dockerfile") || !s.InScope("Dockerfile") || !b.InScope("services/billing/requirements.txt") {
		t.Error("shared infrastructure files and own files must be in scope")
	}
}

func TestDiscoveryRejectsHostileDeclaredID(t *testing.T) {
	cfg := &config.Config{Agent: config.Agent{ID: "<script>alert(1)</script>", Owner: "x"}}
	d := discover(t, map[string]string{"a.py": "import openai\nopenai.OpenAI().chat.completions.create(model='m', messages=[], tools=[])\n"}, cfg)
	if len(d.Agents) != 1 || d.Agents[0].Agent.ID != "fixture" || len(d.Warnings) != 1 {
		t.Fatalf("agents=%+v warnings=%v", d.Agents, d.Warnings)
	}
}

func TestToolSensitivityAndRiskTier(t *testing.T) {
	d := discover(t, map[string]string{"a.py": "import subprocess, sqlite3, os\nimport anthropic\n\n" +
		"def payload_size(x):\n    return len(x)\n\n" +
		"def run_report(db, name):\n    return db.execute('SELECT * FROM r WHERE n = ?', (name,)).fetchall()\n\n" +
		"def deletePayment(db, pid):\n    db.execute('DELETE FROM payments WHERE id = ?', (pid,))\n\n" +
		"def diagnostics(cmd):\n    return helper(cmd)\n\n" +
		"def helper(cmd):\n    return subprocess.check_output(cmd, shell=True)\n\n" +
		"TOOL_REGISTRY = {\n    'payload_size': payload_size,\n    'run_report': run_report,\n    'delete_payment': deletePayment,\n    'diagnostics': diagnostics,\n}\n" +
		"KEY = os.environ['ANTHROPIC_API_KEY']\n" +
		"def go(c, m):\n    return c.messages.create(model='x', max_tokens=5, messages=m, tools=[])\n"}, nil)
	if len(d.Agents) != 1 {
		t.Fatalf("agents: %d", len(d.Agents))
	}
	a := d.Agents[0].Agent
	tools := map[string]model.Tool{}
	for _, tl := range a.Tools {
		tools[tl.Name] = tl
	}
	if tools["payload_size"].Sensitive {
		t.Error("'payload' must not match the verb 'pay'")
	}
	if tl := tools["run_report"]; tl.Sensitive || tl.Kind != "database" || strings.Join(tl.Capabilities, ",") != "data-access" {
		t.Errorf("run_report: %+v", tl)
	}
	if tl := tools["delete_payment"]; !tl.Sensitive || !strings.Contains(tl.SensitiveWhy, "deletes") || !strings.Contains(tl.SensitiveWhy, "writes to a database") {
		t.Errorf("delete_payment: %+v", tl)
	}
	if tl := tools["diagnostics"]; !tl.Sensitive || tl.Kind != "shell" {
		t.Errorf("a tool that reaches subprocess through a helper must be a shell tool: %+v", tl)
	}
	if a.InferredRiskTier != "high" {
		t.Errorf("inferred tier = %s", a.InferredRiskTier)
	}
	want := "credentials,data-access,mutating-actions,sensitive-actions,shell-exec,tools"
	if got := strings.Join(a.Capabilities, ","); got != want {
		t.Errorf("capabilities = %s, want %s", got, want)
	}
}

func TestAgentUnderATestsDirectoryIsNotTreatedAsTestCode(t *testing.T) {
	d := discover(t, map[string]string{
		"tests/fixtures/demo/requirements.txt": "openai==1.58.1\n",
		"tests/fixtures/demo/agent.py":         "import openai, subprocess\n\ndef run_it(cmd):\n    return subprocess.run(cmd, shell=True)\n\nTOOLS = {\"run_it\": run_it}\n\ndef ask(c, m):\n    return c.chat.completions.create(model=\"m\", messages=m, tools=[])\n",
		"tests/fixtures/demo/tests/test_a.py":  "def test_x():\n    assert True\n",
		"infra/Dockerfile":                     "FROM python:3.12\n",
		"other/package.json":                   "{\"dependencies\":{\"left-pad\":\"1.3.0\"}}",
		"other/Dockerfile":                     "FROM node:22\n",
	}, nil)
	if len(d.Agents) != 1 {
		t.Fatalf("agents: %d", len(d.Agents))
	}
	ag := d.Agents[0]
	if len(ag.Agent.Tools) != 1 || ag.Agent.Tools[0].Kind != "shell" {
		t.Fatalf("tools of an agent rooted under tests/: %+v", ag.Agent.Tools)
	}
	if ag.IsTest("tests/fixtures/demo/agent.py") || !ag.IsTest("tests/fixtures/demo/tests/test_a.py") {
		t.Error("test detection must be relative to the agent root")
	}
	if !ag.InScope("infra/Dockerfile") {
		t.Error("shared infrastructure under the repository root must be in scope")
	}
	if ag.InScope("other/Dockerfile") {
		t.Error("files of an unrelated project must not be in scope")
	}
}

func TestDeclaredAgentWithoutRecognizedCode(t *testing.T) {
	files := map[string]string{"app.py": "import sqlite3\nfrom flask import Flask\napp = Flask(__name__)\n", "requirements.txt": "flask==3.0.3\n", "Dockerfile": "FROM python:3.12\n"}
	cfg := &config.Config{Agent: config.Agent{ID: "inventory-agent", Owner: "ops-team", RiskTier: "Medium"}}
	cfg.Capabilities.DeclaredTools = []string{"lookup_item", "adjust_stock"}
	cfg.Capabilities.SensitiveActions = []string{"adjust_stock"}
	cfg.Path = ".agentgov.yaml"
	d := discover(t, files, cfg)
	if len(d.Agents) != 1 {
		t.Fatalf("expected exactly one declared agent, got %d", len(d.Agents))
	}
	a := d.Agents[0].Agent
	if a.ID != "inventory-agent" || a.Detection != model.Suspected || a.Confidence != model.ConfidenceLow || a.Owner != "ops-team" || a.RiskTier != "medium" ||
		a.Framework != model.Unknown || a.Language != model.Unknown || a.Entrypoint != model.Unknown || a.FrameworkVersion != model.Unknown || a.InferredRiskTier != model.Unknown {
		t.Errorf("declared agent: %+v", a)
	}
	if got := strings.Join(a.Capabilities, ","); got != "sensitive-actions,tools" {
		t.Errorf("capabilities must come from declarations only, got %s", got)
	}
	if len(a.Tools) != 2 || a.Tools[0].Name != "adjust_stock" || !a.Tools[0].Sensitive || !a.Tools[0].Declared || a.Tools[0].Kind != "unknown" ||
		a.Tools[1].Name != "lookup_item" || a.Tools[1].Sensitive || !a.Tools[1].Declared {
		t.Errorf("declared tools: %+v", a.Tools)
	}
	if len(a.Facts) != 1 || a.Facts[0].Kind != "declared-agent" || a.Facts[0].Location.Path != ".agentgov.yaml" {
		t.Errorf("facts: %+v", a.Facts)
	}
	want := "Agent inventory-agent is declared in .agentgov.yaml, but no agent code was recognized. Controls are assessed from declarations and external evidence only."
	if len(d.Limitations) != 1 || d.Limitations[0] != want {
		t.Errorf("limitations: %v", d.Limitations)
	}
	// No configuration: still zero agents.
	if none := discover(t, files, nil); len(none.Agents) != 0 {
		t.Errorf("without a declaration there must be no agent: %+v", none.Agents)
	}
	// A configuration with no agent id declares nothing.
	if none := discover(t, files, &config.Config{Agent: config.Agent{Owner: "ops-team"}}); len(none.Agents) != 0 {
		t.Errorf("an agent entry without an id must not create an agent")
	}
	// A discovered agent at the declared root is unchanged.
	files["agent.py"] = "import openai\nopenai.OpenAI().chat.completions.create(model=\"m\", messages=[], tools=[])\n"
	found := discover(t, files, cfg)
	if len(found.Agents) != 1 || found.Agents[0].Agent.Detection != model.Detected || found.Agents[0].Agent.ID != "inventory-agent" || len(found.Limitations) != 0 {
		t.Errorf("discovered agent with a declaration: %+v %v", found.Agents[0].Agent, found.Limitations)
	}
	// Monorepo entries: one discovered, one declared only.
	multi := &config.Config{Agents: []config.Agent{{ID: "found", Root: "."}, {ID: "planned", Root: "services/planned"}}}
	both := discover(t, files, multi)
	if len(both.Agents) != 2 || both.Agents[0].Agent.ID != "found" || both.Agents[1].Agent.ID != "planned" || both.Agents[1].Agent.Detection != model.Suspected {
		t.Errorf("monorepo declarations: %d agents", len(both.Agents))
	}
}
