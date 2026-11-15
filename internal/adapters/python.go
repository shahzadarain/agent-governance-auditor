// SPDX-License-Identifier: Apache-2.0

package adapters

import (
	"regexp"
	"strings"
)

// PythonAnalyzer is the lexical Python adapter.
type PythonAnalyzer struct{}

// Language implements Analyzer.
func (PythonAnalyzer) Language() string { return LangPython }

// Version implements Analyzer.
func (PythonAnalyzer) Version() string { return ParserVersion }

// Extensions implements Analyzer.
func (PythonAnalyzer) Extensions() []string { return []string{".py", ".pyi"} }

var (
	pyCallRe    = regexp.MustCompile(`[A-Za-z_][A-Za-z0-9_]*(?:\s*\.\s*[A-Za-z_][A-Za-z0-9_]*)*\s*\(`)
	pyKwargRe   = regexp.MustCompile(`^\s*([A-Za-z_][A-Za-z0-9_]*)\s*=(?:[^=]|$)`)
	pyDefRe     = regexp.MustCompile(`^(?:async\s+)?def\s+([A-Za-z_][A-Za-z0-9_]*)\s*\(`)
	pyClassRe   = regexp.MustCompile(`^class\s+([A-Za-z_][A-Za-z0-9_]*)\s*([(:])`)
	pyImportRe  = regexp.MustCompile(`^import\s+(.+)$`)
	pyFromRe    = regexp.MustCompile(`^from\s+(\.*[A-Za-z0-9_.]*)\s+import\s+(.+)$`)
	pyModNameRe = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_.]*$`)
	spaceRe     = regexp.MustCompile(`\s+`)
)

var pyKeywords = map[string]bool{
	"if": true, "elif": true, "while": true, "for": true, "return": true, "and": true, "or": true,
	"not": true, "in": true, "is": true, "lambda": true, "yield": true, "await": true, "assert": true,
	"del": true, "raise": true, "with": true, "except": true, "def": true, "class": true, "else": true,
	"from": true, "import": true, "as": true, "pass": true, "try": true, "finally": true, "async": true,
	"global": true, "nonlocal": true, "match": true, "case": true,
}

type openBlock struct {
	indent int
	fn     int // index into Funcs, or -1
	cl     int // index into Classes, or -1
}

// Analyze implements Analyzer.
func (PythonAnalyzer) Analyze(path string, content []byte) *Source {
	s := newSource(path, LangPython, content, lexPython(content))
	n := s.Lines()
	var stack []openBlock
	var pendingDecos []string
	pendingStart := -1
	lastEnd := 0
	closeTo := func(indent int) {
		for len(stack) > 0 && stack[len(stack)-1].indent >= indent {
			top := stack[len(stack)-1]
			stack = stack[:len(stack)-1]
			_, endOff := s.lineSpan(lastEnd)
			if top.fn >= 0 {
				s.Funcs[top.fn].EndLine = lastEnd
				s.Funcs[top.fn].End = endOff
			}
			if top.cl >= 0 {
				s.Classes[top.cl].EndLine = lastEnd
			}
		}
	}
	for ln := 1; ln <= n; ln++ {
		start := ln
		depth := 0
		for {
			line := s.CodeLine(ln)
			for i := 0; i < len(line); i++ {
				switch line[i] {
				case '(', '[', '{':
					depth++
				case ')', ']', '}':
					if depth > 0 {
						depth--
					}
				}
			}
			cont := depth > 0 || strings.HasSuffix(strings.TrimRight(line, " \t"), "\\") || (ln < n && s.inString[ln])
			if !cont || ln >= n {
				break
			}
			if ln-start > 400 {
				// Unbalanced brackets: give up on joining and resume line by line.
				ln = start
				break
			}
			ln++
		}
		a, _ := s.lineSpan(start)
		_, b := s.lineSpan(ln)
		logical := s.Code[a:b]
		trimmed := strings.TrimLeft(logical, " \t")
		if strings.TrimSpace(trimmed) == "" {
			continue
		}
		indent := 0
		for _, c := range logical[:len(logical)-len(trimmed)] {
			if c == '\t' {
				indent += 8
			} else {
				indent++
			}
		}
		closeTo(indent)
		lastEnd = ln
		switch {
		case strings.HasPrefix(trimmed, "@"):
			if pendingStart < 0 {
				pendingStart = a
			}
			pendingDecos = append(pendingDecos, spaceRe.ReplaceAllString(strings.TrimSpace(trimmed[1:]), " "))
			continue
		case pyDefRe.MatchString(trimmed):
			m := pyDefRe.FindStringSubmatchIndex(trimmed)
			f := Func{Name: trimmed[m[2]:m[3]], Line: start, EndLine: ln, Start: a, End: b, Indent: indent, Decorators: pendingDecos}
			if pendingStart >= 0 {
				f.Start = pendingStart
			}
			open := m[1] - 1
			if cl := matchParen(trimmed, open); cl > open {
				f.Params = parsePyParams(trimmed[open+1 : cl])
			}
			for i := len(stack) - 1; i >= 0; i-- {
				if stack[i].cl >= 0 {
					f.Class = s.Classes[stack[i].cl].Name
					break
				}
				if stack[i].fn >= 0 {
					break
				}
			}
			s.Funcs = append(s.Funcs, f)
			stack = append(stack, openBlock{indent: indent, fn: len(s.Funcs) - 1, cl: -1})
		case pyClassRe.MatchString(trimmed):
			m := pyClassRe.FindStringSubmatchIndex(trimmed)
			c := Class{Name: trimmed[m[2]:m[3]], Line: start, EndLine: ln}
			if trimmed[m[4]] == '(' {
				if cl := matchParen(trimmed, m[4]); cl > m[4] {
					for _, base := range splitTop(trimmed[m[4]+1 : cl]) {
						base = strings.TrimSpace(base)
						if base != "" && !strings.Contains(base, "=") {
							c.Bases = append(c.Bases, base)
						}
					}
				}
			}
			s.Classes = append(s.Classes, c)
			stack = append(stack, openBlock{indent: indent, fn: -1, cl: len(s.Classes) - 1})
		case strings.HasPrefix(trimmed, "import ") || strings.HasPrefix(trimmed, "from "):
			s.parsePyImport(trimmed, start)
		}
		pendingDecos = nil
		pendingStart = -1
	}
	closeTo(-1)
	s.findCalls(pyCallRe, pyKeywords)
	return s
}

func parsePyParams(code string) []Param {
	var out []Param
	for _, part := range splitTop(code) {
		part = strings.TrimSpace(part)
		part = strings.TrimLeft(part, "*")
		if part == "" || part == "/" {
			continue
		}
		def := ""
		if i := topLevelIndex(part, '='); i >= 0 {
			def = strings.TrimSpace(part[i+1:])
			part = part[:i]
		}
		if i := strings.Index(part, ":"); i >= 0 {
			part = part[:i]
		}
		name := strings.TrimSpace(part)
		if name != "" {
			out = append(out, Param{Name: name, Default: def})
		}
	}
	return out
}

func topLevelIndex(s string, c byte) int {
	depth := 0
	for i := 0; i < len(s); i++ {
		switch s[i] {
		case '(', '[', '{':
			depth++
		case ')', ']', '}':
			depth--
		default:
			if s[i] == c && depth == 0 {
				return i
			}
		}
	}
	return -1
}

func (s *Source) parsePyImport(stmt string, line int) {
	// A one-line "import a; import b" is rare; handle the first statement.
	if i := strings.Index(stmt, ";"); i >= 0 {
		stmt = stmt[:i]
	}
	flat := strings.NewReplacer("(", " ", ")", " ", "\\", " ", "\n", " ", "\r", " ").Replace(stmt)
	flat = strings.TrimSpace(spaceRe.ReplaceAllString(flat, " "))
	if m := pyFromRe.FindStringSubmatch(flat); m != nil {
		mod := m[1]
		for _, item := range strings.Split(m[2], ",") {
			fields := strings.Fields(item)
			if len(fields) == 0 || fields[0] == "*" {
				if len(fields) > 0 {
					s.Imports = append(s.Imports, Import{Module: mod, Name: "*", Line: line})
				}
				continue
			}
			name, alias := fields[0], fields[0]
			if len(fields) == 3 && fields[1] == "as" {
				alias = fields[2]
			}
			if !pyModNameRe.MatchString(name) {
				continue
			}
			s.Imports = append(s.Imports, Import{Module: mod, Name: name, Alias: alias, Line: line})
			s.Aliases[alias] = Binding{Module: mod, Name: name}
		}
		return
	}
	if m := pyImportRe.FindStringSubmatch(flat); m != nil {
		for _, item := range strings.Split(m[1], ",") {
			fields := strings.Fields(item)
			if len(fields) == 0 || !pyModNameRe.MatchString(fields[0]) {
				continue
			}
			mod := fields[0]
			if len(fields) == 3 && fields[1] == "as" {
				s.Imports = append(s.Imports, Import{Module: mod, Alias: fields[2], Line: line})
				s.Aliases[fields[2]] = Binding{Module: mod}
				continue
			}
			first := mod
			if i := strings.Index(mod, "."); i >= 0 {
				first = mod[:i]
			}
			s.Imports = append(s.Imports, Import{Module: mod, Alias: first, Line: line})
			if _, exists := s.Aliases[first]; !exists {
				s.Aliases[first] = Binding{Module: first}
			}
		}
	}
}

// findCalls records call sites from the code view.
func (s *Source) findCalls(re *regexp.Regexp, keywords map[string]bool) {
	code := s.Code
	for _, m := range re.FindAllStringIndex(code, -1) {
		open := m[1] - 1
		name := spaceRe.ReplaceAllString(strings.TrimSpace(code[m[0]:open]), "")
		first := name
		if i := strings.Index(name, "."); i >= 0 {
			first = name[:i]
		}
		if keywords[first] && first == name {
			continue
		}
		if keywords[first] {
			// "return foo.bar(" style: drop the keyword-led match.
			continue
		}
		before := strings.TrimRight(code[max(0, m[0]-12):m[0]], " \t")
		isNew := false
		if s.Lang == LangPython {
			if strings.HasSuffix(before, "def") || strings.HasSuffix(before, "class") {
				continue
			}
		} else {
			if strings.HasSuffix(before, "function") || strings.HasSuffix(before, "function*") {
				continue
			}
			isNew = strings.HasSuffix(before, "new")
		}
		end := matchParen(code, open)
		if end < 0 {
			continue
		}
		c := Call{Name: name, Line: s.LineOf(m[0]), ArgsStart: open + 1, ArgsEnd: end, New: isNew}
		args := code[open+1 : end]
		if s.Lang == LangPython {
			for _, part := range splitTop(args) {
				if km := pyKwargRe.FindStringSubmatch(part); km != nil {
					c.Kwargs = append(c.Kwargs, km[1])
				}
			}
		} else {
			c.Kwargs = jsObjectKeys(args, s.Text[open+1:end])
		}
		s.resolve(&c)
		s.Calls = append(s.Calls, c)
	}
}
