// SPDX-License-Identifier: Apache-2.0

package adapters

import (
	"sort"
	"strings"
	"unicode/utf8"
)

// Languages handled by the source analyzers.
const (
	LangPython     = "python"
	LangJavaScript = "javascript"
	LangTypeScript = "typescript"
)

// Analyzer is the versioned interface a language adapter implements. The
// built-in analyzers are lexical; a full parser can replace one by
// implementing the same interface.
type Analyzer interface {
	Language() string
	Version() string
	Extensions() []string
	Analyze(path string, content []byte) *Source
}

// Binding is what a local name refers to after import resolution.
type Binding struct {
	Module string // imported module, e.g. "langgraph.graph" or "@openai/agents"
	Name   string // imported symbol; "" when the name is the module itself
}

// Import is one import statement binding.
type Import struct {
	Module string // module as written; relative Python imports keep leading dots
	Name   string // imported symbol, "" for a whole-module import
	Alias  string // local name bound, "" for side-effect or dynamic imports
	Line   int
}

// Param is one function parameter.
type Param struct {
	Name    string
	Default string // code-view text of the default; "" when none
}

// Func is one function or method definition.
type Func struct {
	Name       string
	Class      string   // enclosing class for Python methods, else ""
	Decorators []string // code-view text after "@", e.g. "mcp.tool()"
	Params     []Param
	Line       int // line of the "def" or "function"
	EndLine    int
	Start, End int // byte range of the whole definition including the body
	Indent     int
}

// Class is one class definition.
type Class struct {
	Name          string
	Bases         []string
	Line, EndLine int
}

// Call is one call site.
type Call struct {
	Name      string   // as written, e.g. "lg.StateGraph"
	Module    string   // resolved import module of the first name segment, "" when not imported
	Symbol    string   // resolved symbol path within Module, or Name when not imported
	Line      int      //
	Kwargs    []string // keyword-argument names (Python) or object-literal keys of the first argument (JS)
	ArgsStart int      // byte offset after "("
	ArgsEnd   int      // byte offset of the matching ")"
	New       bool     // JS "new X(...)"
}

// Last returns the final dotted component of the call name.
func (c Call) Last() string {
	if i := strings.LastIndex(c.Name, "."); i >= 0 {
		return c.Name[i+1:]
	}
	return c.Name
}

// Source is the analyzed form of one source file. Raw, Code, and Text have
// the same length and the same byte offsets.
type Source struct {
	Path     string
	Lang     string
	Raw      string
	Code     string
	Text     string
	Strings  []StringLit
	Imports  []Import
	Aliases  map[string]Binding
	Funcs    []Func
	Classes  []Class
	Calls    []Call
	Warnings []string
	lineOff  []int
	inString []bool
}

func newSource(path, lang string, content []byte, lr lexResult) *Source {
	s := &Source{
		Path: path, Lang: lang, Raw: string(content), Code: string(lr.code), Text: string(lr.text),
		Strings: lr.strings, Aliases: map[string]Binding{}, inString: lr.inString,
	}
	s.lineOff = []int{0}
	for i := 0; i < len(content); i++ {
		if content[i] == '\n' {
			s.lineOff = append(s.lineOff, i+1)
		}
	}
	if !utf8.Valid(content) {
		s.Warnings = append(s.Warnings, path+": file is not valid UTF-8; analysis is best-effort")
	}
	return s
}

// Lines returns the number of lines.
func (s *Source) Lines() int { return len(s.lineOff) }

// LineOf returns the 1-based line for a byte offset.
func (s *Source) LineOf(off int) int {
	return sort.Search(len(s.lineOff), func(i int) bool { return s.lineOff[i] > off })
}

// lineSpan returns the byte range of a 1-based line without its newline.
func (s *Source) lineSpan(line int) (int, int) {
	if line < 1 || line > len(s.lineOff) {
		return 0, 0
	}
	start := s.lineOff[line-1]
	end := len(s.Raw)
	if line < len(s.lineOff) {
		end = s.lineOff[line] - 1
	}
	if end > start && s.Raw[end-1] == '\r' {
		end--
	}
	return start, end
}

// CodeLine returns the code view of a line.
func (s *Source) CodeLine(line int) string {
	a, b := s.lineSpan(line)
	return s.Code[a:b]
}

// TextLine returns the text view of a line.
func (s *Source) TextLine(line int) string {
	a, b := s.lineSpan(line)
	return s.Text[a:b]
}

// FuncAt returns the innermost function that contains the line, or nil.
func (s *Source) FuncAt(line int) *Func {
	var best *Func
	for i := range s.Funcs {
		f := &s.Funcs[i]
		if line >= f.Line && line <= f.EndLine {
			if best == nil || f.Line >= best.Line {
				best = f
			}
		}
	}
	return best
}

// FuncByName returns the first function with the given name, or nil.
func (s *Source) FuncByName(name string) *Func {
	for i := range s.Funcs {
		if s.Funcs[i].Name == name {
			return &s.Funcs[i]
		}
	}
	return nil
}

// BodyCode returns the code view of a function including its signature.
func (s *Source) BodyCode(f *Func) string { return s.Code[f.Start:f.End] }

// BodyText returns the text view of a function including its signature.
func (s *Source) BodyText(f *Func) string { return s.Text[f.Start:f.End] }

// ArgsCode returns the code view of a call's argument list.
func (s *Source) ArgsCode(c Call) string { return s.Code[c.ArgsStart:c.ArgsEnd] }

// ArgsText returns the text view of a call's argument list.
func (s *Source) ArgsText(c Call) string { return s.Text[c.ArgsStart:c.ArgsEnd] }

// ImportsModule reports whether the file imports the module or a submodule.
func (s *Source) ImportsModule(mod string) bool {
	for _, im := range s.Imports {
		if moduleHasPrefix(im.Module, mod) {
			return true
		}
	}
	return false
}

func moduleHasPrefix(module, prefix string) bool {
	if module == prefix {
		return true
	}
	if !strings.HasPrefix(module, prefix) {
		return false
	}
	c := module[len(prefix)]
	return c == '.' || c == '/'
}

// resolve fills Module and Symbol on a call from the alias map.
func (s *Source) resolve(c *Call) {
	first, rest := c.Name, ""
	if i := strings.Index(c.Name, "."); i >= 0 {
		first, rest = c.Name[:i], c.Name[i+1:]
	}
	b, ok := s.Aliases[first]
	if !ok {
		c.Symbol = c.Name
		return
	}
	c.Module = b.Module
	parts := []string{}
	if b.Name != "" {
		parts = append(parts, b.Name)
	}
	if rest != "" {
		parts = append(parts, rest)
	}
	c.Symbol = strings.Join(parts, ".")
}

// matchParen returns the offset of the bracket that closes the one at open.
// It works on the code view, where string contents are blanked.
func matchParen(code string, open int) int {
	depth := 0
	limit := open + 200000
	for i := open; i < len(code) && i < limit; i++ {
		switch code[i] {
		case '(', '[', '{':
			depth++
		case ')', ']', '}':
			depth--
			if depth == 0 {
				return i
			}
		}
	}
	return -1
}

// splitTop splits s on commas that are not nested in brackets.
func splitTop(s string) []string {
	var out []string
	depth, last := 0, 0
	for i := 0; i < len(s); i++ {
		switch s[i] {
		case '(', '[', '{':
			depth++
		case ')', ']', '}':
			depth--
		case ',':
			if depth == 0 {
				out = append(out, s[last:i])
				last = i + 1
			}
		}
	}
	if strings.TrimSpace(s[last:]) != "" {
		out = append(out, s[last:])
	}
	return out
}

// SplitArgs splits an argument list at top-level commas and returns the byte
// range of each argument relative to the start of args.
func SplitArgs(args string) [][2]int {
	var out [][2]int
	depth, last := 0, 0
	for i := 0; i < len(args); i++ {
		switch args[i] {
		case '(', '[', '{':
			depth++
		case ')', ']', '}':
			depth--
		case ',':
			if depth == 0 {
				out = append(out, [2]int{last, i})
				last = i + 1
			}
		}
	}
	if strings.TrimSpace(args[last:]) != "" {
		out = append(out, [2]int{last, len(args)})
	}
	return out
}

// KwargText returns the text-view value of a keyword argument (Python
// "name=value") or object key (JS "name: value") of a call, and whether it
// was found.
func (s *Source) KwargText(c Call, name string) (string, bool) {
	code := s.ArgsCode(c)
	text := s.ArgsText(c)
	if s.Lang != LangPython {
		// Look inside the first object-literal argument.
		if i := strings.Index(code, "{"); i >= 0 {
			if j := matchParen(code, i); j > i {
				code, text = code[i+1:j], text[i+1:j]
			}
		}
	}
	for _, r := range SplitArgs(code) {
		part := code[r[0]:r[1]]
		trim := strings.TrimLeft(part, " \t\r\n")
		lead := len(part) - len(trim)
		if !strings.HasPrefix(trim, name) {
			continue
		}
		rest := strings.TrimLeft(trim[len(name):], " \t")
		sep := byte('=')
		if s.Lang != LangPython {
			sep = ':'
		}
		if rest == "" || rest[0] != sep || (sep == '=' && len(rest) > 1 && rest[1] == '=') {
			continue
		}
		valStart := r[0] + lead + len(name) + (len(trim[len(name):]) - len(rest)) + 1
		return strings.TrimSpace(text[valStart:r[1]]), true
	}
	return "", false
}

// HasKwarg reports whether the call passes the named keyword argument.
func (c Call) HasKwarg(name string) bool {
	for _, k := range c.Kwargs {
		if k == name {
			return true
		}
	}
	return false
}

// LineStart returns the byte offset where a 1-based line starts.
func (s *Source) LineStart(line int) int {
	a, _ := s.lineSpan(line)
	return a
}

// LitName returns the variable, keyword-argument, or dictionary-key name a
// string literal is assigned to, or "" when there is none.
func (s *Source) LitName(idx int) string {
	lit := s.Strings[idx]
	qs := lit.Start
	for qs > 0 && (s.Raw[qs-1] == '"' || s.Raw[qs-1] == '\'' || s.Raw[qs-1] == '`') && lit.Start-qs < 3 {
		qs--
	}
	qs -= len(lit.Prefix)
	if lit.Prefix == "`" {
		qs++
	}
	ls := s.LineStart(lit.Line)
	if qs < ls || qs > len(s.Code) {
		return ""
	}
	before := strings.TrimRight(s.Code[ls:qs], " \t")
	if strings.HasSuffix(before, "=") && !strings.HasSuffix(before, "==") && !strings.HasSuffix(before, "!=") {
		b := strings.TrimRight(before[:len(before)-1], " \t+")
		// Drop a type annotation: name: str = "..."
		if i := strings.LastIndex(b, ":"); i >= 0 && !strings.ContainsAny(b[i:], "({[") {
			if id := trailingIdent(strings.TrimRight(b[:i], " \t")); id != "" {
				return id
			}
		}
		return trailingIdent(b)
	}
	if strings.HasSuffix(before, ":") {
		b := strings.TrimRight(before[:len(before)-1], " \t")
		if b != "" && (b[len(b)-1] == '"' || b[len(b)-1] == '\'') && idx > 0 && s.Strings[idx-1].Line == lit.Line {
			return s.Strings[idx-1].Value
		}
		return trailingIdent(b)
	}
	return ""
}

func trailingIdent(b string) string {
	end := len(b)
	i := end
	for i > 0 && (isIdentByte(b[i-1]) || b[i-1] == '.') {
		i--
	}
	id := b[i:end]
	if j := strings.LastIndex(id, "."); j >= 0 {
		id = id[j+1:]
	}
	return id
}
