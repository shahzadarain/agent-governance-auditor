// SPDX-License-Identifier: Apache-2.0

package adapters

import (
	"regexp"
	"strings"
)

// JSAnalyzer is the lexical JavaScript and TypeScript adapter.
type JSAnalyzer struct{}

// Language implements Analyzer.
func (JSAnalyzer) Language() string { return LangJavaScript }

// Version implements Analyzer.
func (JSAnalyzer) Version() string { return ParserVersion }

// Extensions implements Analyzer.
func (JSAnalyzer) Extensions() []string {
	return []string{".js", ".mjs", ".cjs", ".jsx", ".ts", ".mts", ".cts", ".tsx"}
}

var (
	jsCallRe = regexp.MustCompile(`[A-Za-z_$][A-Za-z0-9_$]*(?:\s*\??\.\s*[A-Za-z_$][A-Za-z0-9_$]*)*\s*\(`)
	// import defaultName, { a as b } from 'mod'   /   import * as ns from 'mod'   /   import 'mod'
	jsImportRe  = regexp.MustCompile(`(?s)\bimport\s+(?:type\s+)?([^'"` + "`" + `;()]*?)\s*(?:from\s*)?['"]([^'"\n]+)['"]`)
	jsRequireRe = regexp.MustCompile(`(?:(?:const|let|var)\s+([A-Za-z_$][\w$]*|\{[^}]*\})\s*(?::[^=]+)?=\s*(?:await\s+)?)?\b(require|import)\s*\(\s*['"]([^'"\n]+)['"]\s*\)`)
	jsFuncRes   = []*regexp.Regexp{
		regexp.MustCompile(`\bfunction\s*\*?\s*([A-Za-z_$][\w$]*)\s*(?:<[^>(]*>)?\s*\(`),
		regexp.MustCompile(`\b(?:const|let|var)\s+([A-Za-z_$][\w$]*)\s*(?::[^=;]+)?=\s*(?:async\s+)?(?:function\b\s*\*?\s*[\w$]*\s*)?\(`),
		regexp.MustCompile(`(?m)^[ \t]*(?:(?:public|private|protected|static|async|override|readonly)\s+)*([A-Za-z_$][\w$]*)\s*(?:<[^>(]*>)?\s*\(`),
		regexp.MustCompile(`\b([A-Za-z_$][\w$]*)\s*:\s*(?:async\s+)?(?:function\b\s*\*?\s*[\w$]*\s*)?\(`),
	}
	jsKeyRe = regexp.MustCompile(`^\s*(?:['"]([^'"]*)['"]|([A-Za-z_$][\w$]*))\s*(?::|\(|$)`)
)

var jsKeywords = map[string]bool{
	"if": true, "while": true, "for": true, "switch": true, "catch": true, "return": true, "typeof": true,
	"function": true, "await": true, "new": true, "delete": true, "void": true, "throw": true, "else": true,
	"do": true, "in": true, "of": true, "yield": true, "super": true, "import": true, "with": true,
	"case": true, "class": true, "const": true, "let": true, "var": true, "export": true, "async": true,
}

// Analyze implements Analyzer.
func (JSAnalyzer) Analyze(path string, content []byte) *Source {
	lang := LangJavaScript
	lower := strings.ToLower(path)
	if strings.HasSuffix(lower, ".ts") || strings.HasSuffix(lower, ".tsx") || strings.HasSuffix(lower, ".mts") || strings.HasSuffix(lower, ".cts") {
		lang = LangTypeScript
	}
	s := newSource(path, lang, content, lexJS(content))
	s.parseJSImports()
	s.parseJSFuncs()
	s.findCalls(jsCallRe, jsKeywords)
	return s
}

// codeIntact reports whether the keyword at off is real code, not text
// inside a string or comment.
func (s *Source) codeIntact(off int, word string) bool {
	return off >= 0 && off+len(word) <= len(s.Code) && s.Code[off:off+len(word)] == word
}

func (s *Source) parseJSImports() {
	for _, m := range jsImportRe.FindAllStringSubmatchIndex(s.Text, -1) {
		kw := strings.Index(s.Text[m[0]:m[1]], "import") + m[0]
		if !s.codeIntact(kw, "import") {
			continue
		}
		// The module string must be a real string literal, and the clause
		// must not contain code that shows this is not an import statement.
		clause := s.Text[m[2]:m[3]]
		mod := s.Text[m[4]:m[5]]
		if strings.ContainsAny(clause, "=\n") && !strings.Contains(clause, "{") {
			continue
		}
		line := s.LineOf(kw)
		clause = strings.TrimSpace(strings.TrimSuffix(strings.TrimSpace(clause), "from"))
		if clause == "" {
			s.Imports = append(s.Imports, Import{Module: mod, Line: line})
			continue
		}
		named := ""
		if i := strings.Index(clause, "{"); i >= 0 {
			if j := strings.Index(clause, "}"); j > i {
				named = clause[i+1 : j]
				clause = clause[:i] + clause[j+1:]
			}
		}
		for _, part := range strings.Split(clause, ",") {
			fields := strings.Fields(part)
			switch {
			case len(fields) == 3 && fields[0] == "*" && fields[1] == "as":
				s.addJSImport(mod, "", fields[2], line)
			case len(fields) == 1:
				s.addJSImport(mod, "default", fields[0], line)
			}
		}
		for _, part := range strings.Split(named, ",") {
			fields := strings.Fields(part)
			if len(fields) > 0 && fields[0] == "type" && len(fields) > 1 {
				fields = fields[1:]
			}
			switch {
			case len(fields) == 3 && fields[1] == "as":
				s.addJSImport(mod, fields[0], fields[2], line)
			case len(fields) == 1:
				s.addJSImport(mod, fields[0], fields[0], line)
			}
		}
	}
	for _, m := range jsRequireRe.FindAllStringSubmatchIndex(s.Text, -1) {
		if !s.codeIntact(m[4], s.Text[m[4]:m[5]]) {
			continue
		}
		mod := s.Text[m[6]:m[7]]
		line := s.LineOf(m[4])
		if m[2] < 0 {
			s.Imports = append(s.Imports, Import{Module: mod, Line: line})
			continue
		}
		target := s.Text[m[2]:m[3]]
		if !strings.HasPrefix(target, "{") {
			s.addJSImport(mod, "", target, line)
			continue
		}
		for _, part := range strings.Split(strings.Trim(target, "{}"), ",") {
			kv := strings.SplitN(part, ":", 2)
			name := strings.TrimSpace(kv[0])
			alias := name
			if len(kv) == 2 {
				alias = strings.TrimSpace(kv[1])
			}
			if name != "" && alias != "" {
				s.addJSImport(mod, name, alias, line)
			}
		}
	}
}

func (s *Source) addJSImport(mod, name, alias string, line int) {
	s.Imports = append(s.Imports, Import{Module: mod, Name: name, Alias: alias, Line: line})
	if name == "default" {
		name = ""
	}
	s.Aliases[alias] = Binding{Module: mod, Name: name}
}

func (s *Source) parseJSFuncs() {
	code := s.Code
	seen := map[int]bool{}
	for _, re := range jsFuncRes {
		for _, m := range re.FindAllStringSubmatchIndex(code, -1) {
			name := code[m[2]:m[3]]
			if jsKeywords[name] || seen[m[2]] {
				continue
			}
			open := m[1] - 1
			closeP := matchParen(code, open)
			if closeP < 0 {
				continue
			}
			// After the parameter list: optional return type, then "{" or "=>".
			k := closeP + 1
			limit := min(len(code), k+200)
			body := -1
			arrow := false
			for k < limit {
				if code[k] == '{' {
					body = k
					break
				}
				if code[k] == '=' && k+1 < len(code) && code[k+1] == '>' {
					arrow = true
					k += 2
					for k < limit && (code[k] == ' ' || code[k] == '\t' || code[k] == '\n' || code[k] == '\r') {
						k++
					}
					if k < len(code) && code[k] == '{' {
						body = k
					}
					break
				}
				if code[k] == ';' || code[k] == ')' || code[k] == ',' {
					break
				}
				k++
			}
			end := -1
			if body >= 0 {
				end = matchParen(code, body)
			} else if arrow {
				end = strings.IndexByte(code[k:], '\n')
				if end < 0 {
					end = len(code) - 1
				} else {
					end += k
				}
			}
			if end < 0 {
				continue
			}
			seen[m[2]] = true
			f := Func{Name: name, Line: s.LineOf(m[0]), EndLine: s.LineOf(end), Start: m[0], End: min(end+1, len(code))}
			for _, p := range splitTop(code[open+1 : closeP]) {
				p = strings.TrimSpace(strings.TrimLeft(strings.TrimSpace(p), "."))
				def := ""
				if i := topLevelIndex(p, '='); i >= 0 {
					def = strings.TrimSpace(p[i+1:])
					p = p[:i]
				}
				if i := strings.Index(p, ":"); i >= 0 {
					p = p[:i]
				}
				p = strings.TrimSpace(strings.TrimSuffix(strings.TrimSpace(p), "?"))
				if p != "" {
					f.Params = append(f.Params, Param{Name: p, Default: def})
				}
			}
			s.Funcs = append(s.Funcs, f)
		}
	}
}

// jsObjectKeys returns the keys of the first object-literal argument.
func jsObjectKeys(code, text string) []string {
	i := strings.Index(code, "{")
	if i < 0 || strings.TrimSpace(code[:i]) != "" && !strings.HasSuffix(strings.TrimSpace(code[:i]), ",") {
		return nil
	}
	j := matchParen(code, i)
	if j < 0 {
		return nil
	}
	var keys []string
	inner := code[i+1 : j]
	for _, r := range SplitArgs(inner) {
		part := text[i+1+r[0] : i+1+r[1]]
		if m := jsKeyRe.FindStringSubmatch(part); m != nil {
			if m[1] != "" {
				keys = append(keys, m[1])
			} else {
				keys = append(keys, m[2])
			}
		}
	}
	return keys
}
