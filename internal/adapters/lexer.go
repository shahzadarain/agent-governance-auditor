// SPDX-License-Identifier: Apache-2.0

// Package adapters turns inventoried files into normalized facts. Python and
// JavaScript/TypeScript sources go through purpose-built lexers that produce
// two views of each file with identical byte offsets:
//
//   - Code: comments and the contents of string literals are blanked. The
//     expressions inside f-string braces and template-literal ${...} parts
//     are kept. All identifier matching runs on this view, so text in
//     comments, docstrings, and documentation never triggers a detection.
//   - Text: comments and docstrings are blanked, other string contents are
//     kept. It is used when a check needs a literal value (a file mode, an
//     SQL keyword).
//
// The lexers are lexical, not full parsers. They sit behind the Analyzer
// interface so a complete parser can replace them later.
package adapters

// ParserVersion identifies the lexical analyzers in this package. It is
// recorded on every fact.
const ParserVersion = "lex-1"

// StringLit is one string literal found by a lexer.
type StringLit struct {
	Start, End int    // byte offsets of the content (without quotes)
	Line       int    // 1-based line of the opening quote
	Value      string // raw content, escapes not processed
	Prefix     string // Python prefix letters, lower case; "`" for JS templates
	Doc        bool   // statement-level string (docstring)
}

type lexResult struct {
	code    []byte
	text    []byte
	strings []StringLit
	// inString[i] is true when line i+1 starts inside a multi-line string.
	inString []bool
}

func blank(dst []byte, from, to int) {
	for i := from; i < to && i < len(dst); i++ {
		if dst[i] != '\n' {
			dst[i] = ' '
		}
	}
}

func isIdentByte(c byte) bool {
	return c == '_' || c == '$' || (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') || c >= 0x80
}

// lexPython produces the views for a Python source file.
func lexPython(src []byte) lexResult {
	n := len(src)
	code := append([]byte(nil), src...)
	text := append([]byte(nil), src...)
	var lits []StringLit
	lines := 1
	for _, c := range src {
		if c == '\n' {
			lines++
		}
	}
	inString := make([]bool, lines)
	line := 1
	depth := 0
	lineStart := 0
	i := 0
	for i < n {
		c := src[i]
		switch {
		case c == '\n':
			line++
			i++
			lineStart = i
		case c == '#':
			j := i
			for j < n && src[j] != '\n' {
				j++
			}
			blank(code, i, j)
			blank(text, i, j)
			i = j
		case c == '"' || c == '\'':
			// Find prefix letters directly before the quote.
			p := i
			for p > 0 && i-p < 3 && isPyPrefixByte(src[p-1]) {
				p--
			}
			if p > 0 && isIdentByte(src[p-1]) {
				p = i // the letters belong to an identifier
			}
			prefix := toLowerASCII(string(src[p:i]))
			triple := i+2 < n && src[i+1] == c && src[i+2] == c
			qlen := 1
			if triple {
				qlen = 3
			}
			start := i + qlen
			j := start
			startLine := line
			closed := false
			for j < n {
				if src[j] == '\\' && j+1 < n {
					if src[j+1] == '\n' {
						line++
						if line-1 < len(inString) {
							inString[line-1] = true
						}
					}
					j += 2
					continue
				}
				if src[j] == '\n' {
					if !triple {
						break // unterminated single-line string
					}
					line++
					if line-1 < len(inString) {
						inString[line-1] = true
					}
					j++
					continue
				}
				if src[j] == c {
					if !triple {
						closed = true
						break
					}
					if j+2 < n && src[j+1] == c && src[j+2] == c {
						closed = true
						break
					}
				}
				j++
			}
			end := j
			isF := containsByte(prefix, 'f')
			// Statement-level string: nothing but whitespace before it on its
			// line, bracket depth zero, and nothing but whitespace or a
			// comment after it.
			doc := false
			if onlySpace(src[lineStart:p]) && depth == 0 && !isF {
				k := end
				if closed {
					k += qlen
				}
				for k < n && (src[k] == ' ' || src[k] == '\t' || src[k] == '\r') {
					k++
				}
				doc = k >= n || src[k] == '\n' || src[k] == '#'
			}
			lits = append(lits, StringLit{Start: start, End: end, Line: startLine, Value: string(src[start:end]), Prefix: prefix, Doc: doc})
			if isF {
				blankKeepingBraces(code, src, start, end, '{', false)
			} else {
				blank(code, start, end)
			}
			if doc {
				blank(text, start, end)
			}
			i = end
			if closed {
				i += qlen
			}
			if ls := lastNewline(src, i); ls > lineStart {
				lineStart = ls
			}
		default:
			if c == '(' || c == '[' || c == '{' {
				depth++
			} else if (c == ')' || c == ']' || c == '}') && depth > 0 {
				depth--
			}
			i++
		}
	}
	return lexResult{code: code, text: text, strings: lits, inString: inString}
}

func onlySpace(b []byte) bool {
	for _, c := range b {
		if c != ' ' && c != '\t' && c != '\r' {
			return false
		}
	}
	return true
}

// lastNewline returns the offset just after the last newline before pos.
func lastNewline(src []byte, pos int) int {
	for k := pos - 1; k >= 0; k-- {
		if src[k] == '\n' {
			return k + 1
		}
	}
	return 0
}

func isPyPrefixByte(c byte) bool {
	switch c {
	case 'r', 'R', 'b', 'B', 'u', 'U', 'f', 'F':
		return true
	}
	return false
}

func toLowerASCII(s string) string {
	b := []byte(s)
	for i, c := range b {
		if c >= 'A' && c <= 'Z' {
			b[i] = c + 32
		}
	}
	return string(b)
}

func containsByte(s string, c byte) bool {
	for i := 0; i < len(s); i++ {
		if s[i] == c {
			return true
		}
	}
	return false
}

// blankKeepingBraces blanks string content between from and to in dst but
// keeps interpolated expressions: "{expr}" for Python f-strings and
// "${expr}" for JS templates (dollar is true).
func blankKeepingBraces(dst, src []byte, from, to int, open byte, dollar bool) {
	i := from
	for i < to {
		c := src[i]
		if c == '\\' && i+1 < to {
			blank(dst, i, i+2)
			i += 2
			continue
		}
		isOpen := c == open
		if dollar {
			isOpen = c == '$' && i+1 < to && src[i+1] == '{'
		} else if isOpen && i+1 < to && src[i+1] == '{' {
			blank(dst, i, i+2) // escaped "{{"
			i += 2
			continue
		}
		if !isOpen {
			blank(dst, i, i+1)
			i++
			continue
		}
		if dollar {
			i++ // keep "$"
		}
		d := 0
		for i < to {
			if src[i] == '{' {
				d++
			} else if src[i] == '}' {
				d--
				if d == 0 {
					i++
					break
				}
			}
			i++
		}
	}
}

// lexJS produces the views for a JavaScript or TypeScript source file.
func lexJS(src []byte) lexResult {
	n := len(src)
	code := append([]byte(nil), src...)
	text := append([]byte(nil), src...)
	var lits []StringLit
	lines := 1
	for _, c := range src {
		if c == '\n' {
			lines++
		}
	}
	inString := make([]bool, lines)
	line := 1
	var prev byte // previous significant code byte
	prevWord := ""
	i := 0
	for i < n {
		c := src[i]
		switch {
		case c == '\n':
			line++
			i++
		case c == '/' && i+1 < n && src[i+1] == '/':
			j := i
			for j < n && src[j] != '\n' {
				j++
			}
			blank(code, i, j)
			blank(text, i, j)
			i = j
		case c == '/' && i+1 < n && src[i+1] == '*':
			j := i + 2
			for j < n && !(src[j] == '*' && j+1 < n && src[j+1] == '/') {
				if src[j] == '\n' {
					line++
				}
				j++
			}
			if j < n {
				j += 2
			}
			blank(code, i, j)
			blank(text, i, j)
			i = j
		case c == '"' || c == '\'' || c == '`':
			start := i + 1
			j := start
			startLine := line
			closed := false
			tmplDepth := 0
			for j < n {
				if src[j] == '\\' && j+1 < n {
					if src[j+1] == '\n' {
						line++
					}
					j += 2
					continue
				}
				if src[j] == '\n' {
					if c != '`' {
						break
					}
					line++
					if line-1 < len(inString) {
						inString[line-1] = true
					}
					j++
					continue
				}
				if c == '`' {
					if src[j] == '$' && j+1 < n && src[j+1] == '{' {
						tmplDepth++
						j += 2
						continue
					}
					if tmplDepth > 0 {
						if src[j] == '{' {
							tmplDepth++
						} else if src[j] == '}' {
							tmplDepth--
						}
						j++
						continue
					}
				}
				if src[j] == c {
					closed = true
					break
				}
				j++
			}
			end := j
			prefix := ""
			if c == '`' {
				prefix = "`"
				blankKeepingBraces(code, src, start, end, '{', true)
			} else {
				blank(code, start, end)
			}
			lits = append(lits, StringLit{Start: start, End: end, Line: startLine, Value: string(src[start:end]), Prefix: prefix})
			prev = c
			prevWord = ""
			i = end
			if closed {
				i++
			}
		case c == '/' && regexAllowed(prev, prevWord):
			j := i + 1
			inClass := false
			ok := false
			for j < n && src[j] != '\n' {
				if src[j] == '\\' && j+1 < n {
					j += 2
					continue
				}
				if src[j] == '[' {
					inClass = true
				} else if src[j] == ']' {
					inClass = false
				} else if src[j] == '/' && !inClass {
					ok = true
					break
				}
				j++
			}
			if ok {
				blank(code, i+1, j)
				blank(text, i+1, j)
				i = j + 1
				prev = '/'
				prevWord = ""
			} else {
				prev = c
				i++
			}
		default:
			if isIdentByte(c) {
				j := i
				for j < n && isIdentByte(src[j]) {
					j++
				}
				prevWord = string(src[i:j])
				prev = 'a'
				i = j
				continue
			}
			if c != ' ' && c != '\t' && c != '\r' {
				prev = c
				prevWord = ""
			}
			i++
		}
	}
	return lexResult{code: code, text: text, strings: lits, inString: inString}
}

// regexAllowed decides whether a "/" starts a regular-expression literal,
// based on the previous significant token.
func regexAllowed(prev byte, prevWord string) bool {
	if prev == 0 {
		return true
	}
	if prev == 'a' {
		switch prevWord {
		case "return", "typeof", "case", "in", "of", "void", "delete", "throw", "new", "do", "else", "yield", "await":
			return true
		}
		return false
	}
	switch prev {
	case '(', ',', '=', ':', '[', '!', '&', '|', '?', '{', '}', ';', '+', '-', '*', '%', '<', '>', '~', '^':
		return true
	}
	return false
}
