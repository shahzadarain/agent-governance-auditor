// SPDX-License-Identifier: Apache-2.0

package adapters

import (
	"regexp"
	"strings"
)

// Framework describes how one agent framework is recognized. Detection needs
// an import of one of Modules in code plus a construction or usage site.
type Framework struct {
	ID       string
	Priority int      // lower wins when several frameworks are detected in one project
	PyMods   []string // Python import roots
	JSMods   []string // JS/TS import roots
	Ctors    []string // symbol names whose call is a construction or usage site
	Methods  []string // method names that count as usage in a file that imports the framework
	PyPkgs   []string // PyPI distribution names
	NPMPkgs  []string // npm package names
	Generic  bool     // model client SDK: usage needs a tools argument or tool schema
}

// Frameworks is the maintained adapter table.
var Frameworks = []Framework{
	{ID: "langgraph", Priority: 1, PyMods: []string{"langgraph"}, JSMods: []string{"@langchain/langgraph"},
		Ctors:  []string{"StateGraph", "MessageGraph", "create_react_agent", "createReactAgent", "create_supervisor", "create_swarm", "ToolNode"},
		PyPkgs: []string{"langgraph"}, NPMPkgs: []string{"@langchain/langgraph"}},
	{ID: "langchain", Priority: 2,
		PyMods: []string{"langchain", "langchain_core", "langchain_openai", "langchain_anthropic", "langchain_community", "langchain_google_genai", "langchain_aws"},
		JSMods: []string{"langchain", "@langchain/core", "@langchain/openai", "@langchain/anthropic", "@langchain/community"},
		Ctors: []string{"AgentExecutor", "create_tool_calling_agent", "create_openai_tools_agent", "create_openai_functions_agent",
			"create_react_agent", "create_structured_chat_agent", "initialize_agent", "create_agent", "createToolCallingAgent",
			"createOpenAIToolsAgent", "createReactAgent", "createAgent", "DynamicStructuredTool", "StructuredTool", "Tool"},
		Methods: []string{"bind_tools", "bindTools"},
		PyPkgs:  []string{"langchain", "langchain-core", "langchain-openai", "langchain-anthropic", "langchain-community"},
		NPMPkgs: []string{"langchain", "@langchain/core", "@langchain/openai", "@langchain/anthropic"}},
	{ID: "openai-agents", Priority: 3, PyMods: []string{"agents"}, JSMods: []string{"@openai/agents"},
		Ctors:  []string{"Agent", "Runner", "run"},
		PyPkgs: []string{"openai-agents"}, NPMPkgs: []string{"@openai/agents"}},
	{ID: "crewai", Priority: 4, PyMods: []string{"crewai"},
		Ctors: []string{"Agent", "Crew", "Task"}, PyPkgs: []string{"crewai"}},
	{ID: "autogen", Priority: 5, PyMods: []string{"autogen", "autogen_agentchat", "autogen_core", "autogen_ext"},
		Ctors: []string{"AssistantAgent", "UserProxyAgent", "ConversableAgent", "GroupChat", "GroupChatManager",
			"RoundRobinGroupChat", "SelectorGroupChat", "Swarm"},
		PyPkgs: []string{"pyautogen", "autogen", "ag2", "autogen-agentchat", "autogen-core"}},
	{ID: "pydantic-ai", Priority: 6, PyMods: []string{"pydantic_ai"},
		Ctors: []string{"Agent"}, PyPkgs: []string{"pydantic-ai", "pydantic-ai-slim"}},
	{ID: "mcp", Priority: 7, PyMods: []string{"mcp", "fastmcp"}, JSMods: []string{"@modelcontextprotocol/sdk"},
		Ctors: []string{"FastMCP", "Server", "McpServer", "Client", "ClientSession", "stdio_client", "sse_client",
			"streamablehttp_client", "StdioServerTransport", "StdioClientTransport"},
		PyPkgs: []string{"mcp", "fastmcp"}, NPMPkgs: []string{"@modelcontextprotocol/sdk"}},
	{ID: "generic-tool-calling", Priority: 8, Generic: true,
		PyMods:  []string{"openai", "anthropic", "google.generativeai", "google.genai", "mistralai", "cohere", "groq", "litellm", "ollama"},
		JSMods:  []string{"openai", "@anthropic-ai/sdk", "ai", "@ai-sdk", "@google/generative-ai", "@google/genai", "@mistralai/mistralai", "ollama"},
		PyPkgs:  []string{"openai", "anthropic", "google-generativeai", "google-genai", "mistralai", "cohere", "groq", "litellm", "ollama"},
		NPMPkgs: []string{"openai", "@anthropic-ai/sdk", "ai", "@google/generative-ai", "@google/genai"}},
}

// FrameworkByID returns the adapter entry for an ID.
func FrameworkByID(id string) *Framework {
	for i := range Frameworks {
		if Frameworks[i].ID == id {
			return &Frameworks[i]
		}
	}
	return nil
}

func (f *Framework) mods(lang string) []string {
	if lang == LangPython {
		return f.PyMods
	}
	return f.JSMods
}

// matchesModule reports whether an import module belongs to the framework.
func (f *Framework) matchesModule(lang, module string) bool {
	for _, m := range f.mods(lang) {
		if moduleHasPrefix(module, m) {
			return true
		}
	}
	return false
}

func inList(list []string, v string) bool {
	for _, x := range list {
		if x == v {
			return true
		}
	}
	return false
}

// symbolHasCtor reports whether any dotted part of the symbol is a
// constructor name of the framework.
func (f *Framework) symbolHasCtor(symbol string) bool {
	for _, part := range strings.Split(symbol, ".") {
		if inList(f.Ctors, part) {
			return true
		}
	}
	return false
}

// Traits are the security-relevant behaviors observed in a code region.
type Traits struct {
	Shell, CodeExec                bool
	HTTP, HTTPMutate               bool
	FSRead, FSWrite                bool
	DB, DBWrite                    bool
	Vector, VectorWrite            bool
	Browser, EnvSecret             bool
	ShellLine, CodeLine, HTTPLine  int
	FSLine, DBLine, VectorLine     int
	DBWriteLine, HTTPMutateLine    int
	FSWriteLine, EnvLine, BrowLine int
}

func (t *Traits) merge(o Traits) {
	t.Shell = t.Shell || o.Shell
	t.CodeExec = t.CodeExec || o.CodeExec
	t.HTTP = t.HTTP || o.HTTP
	t.HTTPMutate = t.HTTPMutate || o.HTTPMutate
	t.FSRead = t.FSRead || o.FSRead
	t.FSWrite = t.FSWrite || o.FSWrite
	t.DB = t.DB || o.DB
	t.DBWrite = t.DBWrite || o.DBWrite
	t.Vector = t.Vector || o.Vector
	t.VectorWrite = t.VectorWrite || o.VectorWrite
	t.Browser = t.Browser || o.Browser
	t.EnvSecret = t.EnvSecret || o.EnvSecret
}

var (
	pyDBMods     = []string{"sqlite3", "psycopg", "psycopg2", "sqlalchemy", "pymysql", "asyncpg", "pymongo", "redis", "aiosqlite", "mysql", "duckdb"}
	pyHTTPMods   = []string{"requests", "httpx", "urllib", "urllib3", "aiohttp", "http.client"}
	vectorMods   = []string{"chromadb", "pinecone", "qdrant_client", "weaviate", "faiss", "pymilvus", "lancedb", "mem0", "@pinecone-database/pinecone", "@qdrant/js-client-rest", "weaviate-client"}
	jsDBMods     = []string{"pg", "mysql2", "better-sqlite3", "sqlite3", "mongodb", "@prisma/client", "knex", "drizzle-orm", "node:sqlite"}
	jsHTTPMods   = []string{"axios", "node-fetch", "got", "undici", "node:http", "node:https", "http", "https"}
	sqlWriteRe   = regexp.MustCompile(`(?i)\b(INSERT\s+(OR\s+\w+\s+)?INTO|UPDATE\s+[\w."]+\s+SET|DELETE\s+FROM|DROP\s+TABLE|ALTER\s+TABLE|TRUNCATE\s+TABLE|REPLACE\s+INTO)\b`)
	sqlAnyRe     = regexp.MustCompile(`(?i)\b(SELECT\s+.+?\s+FROM|INSERT\s+(OR\s+\w+\s+)?INTO|UPDATE\s+[\w."]+\s+SET|DELETE\s+FROM)\b`)
	httpMethodRe = regexp.MustCompile(`(?i)method\s*[:=]\s*["'](POST|PUT|PATCH|DELETE)["']`)
	openWriteRe  = regexp.MustCompile(`["'][rb]*[wax+][rb+t]*["']`)
	envKeyRe     = regexp.MustCompile(`(?i)(key|token|secret|password|passwd|credential)`)
	pyEnvRe      = regexp.MustCompile(`\bos\s*\.\s*(environ|getenv)\b|\bgetenv\s*\(`)
	jsEnvRe      = regexp.MustCompile(`\bprocess\s*\.\s*env\b`)
)

func modIn(module string, mods []string) bool {
	for _, m := range mods {
		if moduleHasPrefix(module, m) {
			return true
		}
	}
	return false
}

// TraitsIn computes the traits of the calls between two lines (inclusive).
func (s *Source) TraitsIn(fromLine, toLine int) Traits {
	var t Traits
	set := func(flag *bool, line *int, at int) {
		if !*flag {
			*flag = true
			*line = at
		}
	}
	fileVector := false
	fileDB := false
	for _, im := range s.Imports {
		if modIn(im.Module, vectorMods) || strings.Contains(im.Module, "vectorstores") {
			fileVector = true
		}
		if modIn(im.Module, pyDBMods) || modIn(im.Module, jsDBMods) {
			fileDB = true
		}
	}
	for _, c := range s.Calls {
		if c.Line < fromLine || c.Line > toLine {
			continue
		}
		last := c.Last()
		mod := strings.TrimPrefix(c.Module, "node:")
		args := ""
		if c.ArgsEnd > c.ArgsStart {
			args = s.Text[c.ArgsStart:c.ArgsEnd]
		}
		if s.Lang == LangPython {
			switch {
			case mod == "subprocess" || mod == "pty" || (mod == "os" && (last == "system" || last == "popen" || strings.HasPrefix(last, "exec") || strings.HasPrefix(last, "spawn"))) ||
				mod == "asyncio" && strings.HasPrefix(last, "create_subprocess"):
				set(&t.Shell, &t.ShellLine, c.Line)
			case c.Name == "eval" || c.Name == "exec":
				set(&t.CodeExec, &t.CodeLine, c.Line)
			case modIn(mod, pyHTTPMods):
				set(&t.HTTP, &t.HTTPLine, c.Line)
				if inList([]string{"post", "put", "patch", "delete"}, last) || httpMethodRe.MatchString(args) ||
					(last == "request" && regexp.MustCompile(`(?i)["'](POST|PUT|PATCH|DELETE)["']`).MatchString(args)) {
					set(&t.HTTPMutate, &t.HTTPMutateLine, c.Line)
				}
			case c.Name == "open" || (mod == "io" && last == "open"):
				parts := SplitArgs(s.Code[c.ArgsStart:c.ArgsEnd])
				mode := ""
				if len(parts) >= 2 {
					mode = args[parts[1][0]:parts[1][1]]
				}
				if v, ok := s.KwargText(c, "mode"); ok {
					mode = v
				}
				if openWriteRe.MatchString(mode) {
					set(&t.FSWrite, &t.FSWriteLine, c.Line)
				}
				set(&t.FSRead, &t.FSLine, c.Line)
			case last == "write_text" || last == "write_bytes" || (mod == "os" && inList([]string{"remove", "unlink", "rmdir", "rename", "replace", "makedirs"}, last)) || mod == "shutil":
				set(&t.FSWrite, &t.FSWriteLine, c.Line)
				set(&t.FSRead, &t.FSLine, c.Line)
			case last == "read_text" || last == "read_bytes":
				set(&t.FSRead, &t.FSLine, c.Line)
			case modIn(mod, pyDBMods) || inList([]string{"execute", "executemany", "executescript"}, last) && strings.Contains(c.Name, "."):
				set(&t.DB, &t.DBLine, c.Line)
				if sqlWriteRe.MatchString(args) {
					set(&t.DBWrite, &t.DBWriteLine, c.Line)
				}
			case modIn(mod, vectorMods) || strings.Contains(mod, "vectorstores") ||
				inList([]string{"similarity_search", "similarity_search_with_score", "as_retriever", "get_relevant_documents"}, last):
				set(&t.Vector, &t.VectorLine, c.Line)
			case fileVector && inList([]string{"add_texts", "add_documents", "upsert", "add"}, last) && strings.Contains(c.Name, "."):
				set(&t.Vector, &t.VectorLine, c.Line)
				set(&t.VectorWrite, &t.VectorLine, c.Line)
			case fileVector && inList([]string{"query", "search"}, last) && strings.Contains(c.Name, "."):
				set(&t.Vector, &t.VectorLine, c.Line)
			case modIn(mod, []string{"playwright", "selenium", "pyppeteer", "browser_use"}):
				set(&t.Browser, &t.BrowLine, c.Line)
			}
			continue
		}
		switch {
		case mod == "child_process" || (inList([]string{"execSync", "spawnSync", "execFileSync"}, last)):
			set(&t.Shell, &t.ShellLine, c.Line)
		case c.Name == "eval" || (c.New && c.Name == "Function") || mod == "vm":
			set(&t.CodeExec, &t.CodeLine, c.Line)
		case c.Name == "fetch" || modIn(mod, jsHTTPMods):
			set(&t.HTTP, &t.HTTPLine, c.Line)
			if httpMethodRe.MatchString(args) || inList([]string{"post", "put", "patch", "delete"}, last) {
				set(&t.HTTPMutate, &t.HTTPMutateLine, c.Line)
			}
		case mod == "fs" || mod == "fs/promises" || mod == "fs-extra":
			set(&t.FSRead, &t.FSLine, c.Line)
			if regexp.MustCompile(`(?i)^(write|append|unlink|rm|mkdir|rename|copy)`).MatchString(last) {
				set(&t.FSWrite, &t.FSWriteLine, c.Line)
			}
		case modIn(mod, jsDBMods) || fileDB && inList([]string{"query", "execute", "prepare", "run", "all"}, last) && strings.Contains(c.Name, "."):
			set(&t.DB, &t.DBLine, c.Line)
			if sqlWriteRe.MatchString(args) {
				set(&t.DBWrite, &t.DBWriteLine, c.Line)
			}
		case modIn(mod, vectorMods):
			set(&t.Vector, &t.VectorLine, c.Line)
			if last == "upsert" {
				t.VectorWrite = true
			}
		case modIn(mod, []string{"playwright", "puppeteer", "selenium-webdriver", "@playwright/test"}):
			set(&t.Browser, &t.BrowLine, c.Line)
		}
	}
	// Environment reads of secret-looking names.
	envRe := pyEnvRe
	if s.Lang != LangPython {
		envRe = jsEnvRe
	}
	for ln := max(1, fromLine); ln <= toLine && ln <= s.Lines(); ln++ {
		code := s.CodeLine(ln)
		if envRe.MatchString(code) && envKeyRe.MatchString(s.TextLine(ln)) {
			set(&t.EnvSecret, &t.EnvLine, ln)
			break
		}
	}
	return t
}

// FileTraits computes the traits of the whole file.
func (s *Source) FileTraits() Traits { return s.TraitsIn(1, s.Lines()) }

// IsTestPath reports whether a path looks like test code.
func IsTestPath(p string) bool {
	l := strings.ToLower(p)
	base := l[strings.LastIndex(l, "/")+1:]
	return strings.Contains("/"+l, "/tests/") || strings.Contains("/"+l, "/test/") || strings.Contains("/"+l, "/__tests__/") ||
		strings.HasPrefix(base, "test_") || strings.HasSuffix(base, "_test.py") || strings.Contains(base, ".test.") ||
		strings.Contains(base, ".spec.") || base == "conftest.py"
}
