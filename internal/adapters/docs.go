// SPDX-License-Identifier: Apache-2.0

package adapters

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"regexp"
	"strconv"
	"strings"

	"gopkg.in/yaml.v3"
)

// Entry is one node of a structured document, addressed by a dotted path
// such as "jobs.test.steps[0].run".
type Entry struct {
	Path  string
	Value string // scalar value; "" for maps and lists
	Line  int
	Kind  byte // 's' scalar, 'm' map, 'l' list
}

// Doc is a flattened JSON, YAML, or TOML document.
type Doc struct {
	Path    string // file path
	Format  string // json | yaml | toml
	Index   int    // document index within a multi-document YAML file
	Entries []Entry
	byPath  map[string]int
}

const (
	maxDocEntries = 50000
	maxDocDepth   = 64
)

func (d *Doc) add(path, value string, line int, kind byte) bool {
	if len(d.Entries) >= maxDocEntries {
		return false
	}
	if d.byPath == nil {
		d.byPath = map[string]int{}
	}
	if _, dup := d.byPath[path]; !dup {
		d.byPath[path] = len(d.Entries)
	}
	d.Entries = append(d.Entries, Entry{Path: path, Value: value, Line: line, Kind: kind})
	return true
}

// Get returns the scalar value at the exact path.
func (d *Doc) Get(path string) (string, bool) {
	i, ok := d.byPath[path]
	if !ok || d.Entries[i].Kind != 's' {
		return "", false
	}
	return d.Entries[i].Value, true
}

// Has reports whether any node exists at the exact path.
func (d *Doc) Has(path string) bool {
	_, ok := d.byPath[path]
	return ok
}

// Line returns the line of the node at path, or 0.
func (d *Doc) Line(path string) int {
	if i, ok := d.byPath[path]; ok {
		return d.Entries[i].Line
	}
	return 0
}

// Match returns the entries whose path matches the regular expression.
func (d *Doc) Match(re *regexp.Regexp) []Entry {
	var out []Entry
	for _, e := range d.Entries {
		if re.MatchString(e.Path) {
			out = append(out, e)
		}
	}
	return out
}

// Keys returns the direct child keys of the map at path ("" for the root),
// in document order.
func (d *Doc) Keys(path string) []string {
	prefix := path
	if prefix != "" {
		prefix += "."
	}
	var out []string
	seen := map[string]bool{}
	for _, e := range d.Entries {
		if !strings.HasPrefix(e.Path, prefix) || e.Path == path {
			continue
		}
		rest := e.Path[len(prefix):]
		if i := strings.IndexAny(rest, ".["); i >= 0 {
			rest = rest[:i]
		}
		if rest != "" && !seen[rest] {
			seen[rest] = true
			out = append(out, rest)
		}
	}
	return out
}

// List returns the scalar items of the list at path.
func (d *Doc) List(path string) []Entry {
	var out []Entry
	for i := 0; ; i++ {
		idx, ok := d.byPath[path+"["+strconv.Itoa(i)+"]"]
		if !ok {
			break
		}
		out = append(out, d.Entries[idx])
	}
	return out
}

func flattenYAML(d *Doc, n *yaml.Node, path string, depth int) {
	if depth > maxDocDepth || n == nil {
		return
	}
	switch n.Kind {
	case yaml.DocumentNode:
		for _, c := range n.Content {
			flattenYAML(d, c, path, depth+1)
		}
	case yaml.MappingNode:
		if path != "" {
			d.add(path, "", n.Line, 'm')
		}
		for i := 0; i+1 < len(n.Content); i += 2 {
			key := n.Content[i].Value
			p := key
			if path != "" {
				p = path + "." + key
			}
			flattenYAML(d, n.Content[i+1], p, depth+1)
		}
	case yaml.SequenceNode:
		d.add(path, "", n.Line, 'l')
		for i, c := range n.Content {
			flattenYAML(d, c, path+"["+strconv.Itoa(i)+"]", depth+1)
		}
	case yaml.ScalarNode:
		d.add(path, n.Value, n.Line, 's')
	case yaml.AliasNode:
		// Aliases are never expanded; that keeps anchor bombs inert.
		d.add(path, "", n.Line, 's')
	}
}

// ParseYAML parses every document in a YAML file.
func ParseYAML(path string, content []byte) ([]*Doc, error) {
	dec := yaml.NewDecoder(bytes.NewReader(content))
	var docs []*Doc
	for i := 0; i < 200; i++ {
		var n yaml.Node
		err := dec.Decode(&n)
		if err == io.EOF {
			break
		}
		if err != nil {
			return nil, fmt.Errorf("malformed YAML")
		}
		d := &Doc{Path: path, Format: "yaml", Index: i, byPath: map[string]int{}}
		flattenYAML(d, &n, "", 0)
		docs = append(docs, d)
	}
	return docs, nil
}

// ParseJSON parses a JSON file. Line numbers come from a YAML pass over the
// same bytes when that succeeds; otherwise they are 0.
func ParseJSON(path string, content []byte) (*Doc, error) {
	content = bytes.TrimPrefix(content, []byte("\xef\xbb\xbf"))
	if !json.Valid(content) {
		return nil, fmt.Errorf("malformed JSON")
	}
	if docs, err := ParseYAML(path, content); err == nil && len(docs) == 1 {
		docs[0].Format = "json"
		return docs[0], nil
	}
	var v any
	dec := json.NewDecoder(bytes.NewReader(content))
	dec.UseNumber()
	if err := dec.Decode(&v); err != nil {
		return nil, fmt.Errorf("malformed JSON")
	}
	d := &Doc{Path: path, Format: "json", byPath: map[string]int{}}
	flattenAny(d, v, "", 0)
	return d, nil
}

func flattenAny(d *Doc, v any, path string, depth int) {
	if depth > maxDocDepth {
		return
	}
	switch t := v.(type) {
	case map[string]any:
		if path != "" {
			d.add(path, "", 0, 'm')
		}
		keys := make([]string, 0, len(t))
		for k := range t {
			keys = append(keys, k)
		}
		sortStrings(keys)
		for _, k := range keys {
			p := k
			if path != "" {
				p = path + "." + k
			}
			flattenAny(d, t[k], p, depth+1)
		}
	case []any:
		d.add(path, "", 0, 'l')
		for i, c := range t {
			flattenAny(d, c, path+"["+strconv.Itoa(i)+"]", depth+1)
		}
	case nil:
		d.add(path, "", 0, 's')
	default:
		d.add(path, fmt.Sprint(t), 0, 's')
	}
}

// ---------------------------------------------------------------------------
// Minimal TOML reader. It covers what dependency manifests and lockfiles
// use: tables, arrays of tables, strings, numbers, booleans, arrays, and
// inline tables. It is not a complete TOML implementation.
// ---------------------------------------------------------------------------

var (
	tomlTableRe = regexp.MustCompile(`^\[\s*([^\[\]]+?)\s*\]$`)
	tomlArrayRe = regexp.MustCompile(`^\[\[\s*([^\[\]]+?)\s*\]\]$`)
	tomlKeyRe   = regexp.MustCompile(`^((?:[A-Za-z0-9_-]+|"[^"]*"|'[^']*')(?:\s*\.\s*(?:[A-Za-z0-9_-]+|"[^"]*"|'[^']*'))*)\s*=\s*(.*)$`)
)

// ParseTOML parses a TOML file with the minimal reader.
func ParseTOML(path string, content []byte) (*Doc, error) {
	d := &Doc{Path: path, Format: "toml", byPath: map[string]int{}}
	lines := strings.Split(strings.ReplaceAll(string(content), "\r\n", "\n"), "\n")
	table := ""
	arrayCount := map[string]int{}
	for i := 0; i < len(lines); i++ {
		line := strings.TrimSpace(tomlStripComment(lines[i]))
		if line == "" {
			continue
		}
		lineNo := i + 1
		if m := tomlArrayRe.FindStringSubmatch(line); m != nil {
			name := tomlKeyPath(m[1])
			idx := arrayCount[name]
			arrayCount[name] = idx + 1
			table = name + "[" + strconv.Itoa(idx) + "]"
			d.add(table, "", lineNo, 'm')
			continue
		}
		if m := tomlTableRe.FindStringSubmatch(line); m != nil {
			table = tomlKeyPath(m[1])
			d.add(table, "", lineNo, 'm')
			continue
		}
		m := tomlKeyRe.FindStringSubmatch(line)
		if m == nil {
			return nil, fmt.Errorf("malformed TOML at line %d", lineNo)
		}
		key := tomlKeyPath(m[1])
		if table != "" {
			key = table + "." + key
		}
		val := m[2]
		// Multi-line strings and arrays: join lines until the value closes.
		for !tomlValueComplete(val) {
			i++
			if i >= len(lines) || i-lineNo > 5000 {
				return nil, fmt.Errorf("malformed TOML: value starting at line %d is not closed", lineNo)
			}
			val += "\n" + tomlStripComment(lines[i])
		}
		if err := tomlAddValue(d, key, strings.TrimSpace(val), lineNo, 0); err != nil {
			return nil, fmt.Errorf("malformed TOML at line %d", lineNo)
		}
	}
	return d, nil
}

func tomlKeyPath(k string) string {
	var parts []string
	for _, p := range splitTOMLKey(k) {
		parts = append(parts, strings.Trim(strings.TrimSpace(p), `"'`))
	}
	return strings.Join(parts, ".")
}

func splitTOMLKey(k string) []string {
	var out []string
	var quote byte
	last := 0
	for i := 0; i < len(k); i++ {
		c := k[i]
		if quote != 0 {
			if c == quote {
				quote = 0
			}
			continue
		}
		if c == '"' || c == '\'' {
			quote = c
		} else if c == '.' {
			out = append(out, k[last:i])
			last = i + 1
		}
	}
	return append(out, k[last:])
}

// tomlStripComment removes a trailing comment that is outside any string.
func tomlStripComment(line string) string {
	var quote byte
	for i := 0; i < len(line); i++ {
		c := line[i]
		if quote != 0 {
			if c == '\\' && quote == '"' {
				i++
			} else if c == quote {
				quote = 0
			}
			continue
		}
		if c == '"' || c == '\'' {
			quote = c
		} else if c == '#' {
			return line[:i]
		}
	}
	return line
}

func tomlValueComplete(v string) bool {
	t := strings.TrimSpace(v)
	for _, q := range []string{`"""`, `'''`} {
		if strings.HasPrefix(t, q) {
			return len(t) >= 6 && strings.HasSuffix(t, q)
		}
	}
	depth := 0
	var quote byte
	for i := 0; i < len(t); i++ {
		c := t[i]
		if quote != 0 {
			if c == '\\' && quote == '"' {
				i++
			} else if c == quote {
				quote = 0
			}
			continue
		}
		switch c {
		case '"', '\'':
			quote = c
		case '[', '{':
			depth++
		case ']', '}':
			depth--
		}
	}
	return depth <= 0
}

func tomlUnquote(v string) (string, bool) {
	for _, q := range []string{`"""`, `'''`} {
		if strings.HasPrefix(v, q) && strings.HasSuffix(v, q) && len(v) >= 6 {
			return strings.TrimPrefix(v[3:len(v)-3], "\n"), true
		}
	}
	if len(v) >= 2 && (v[0] == '"' || v[0] == '\'') && v[len(v)-1] == v[0] {
		inner := v[1 : len(v)-1]
		if v[0] == '"' {
			inner = strings.NewReplacer(`\"`, `"`, `\\`, `\`, `\n`, "\n", `\t`, "\t").Replace(inner)
		}
		return inner, true
	}
	return "", false
}

func tomlSplit(s string) []string {
	var out []string
	depth, last := 0, 0
	var quote byte
	for i := 0; i < len(s); i++ {
		c := s[i]
		if quote != 0 {
			if c == '\\' && quote == '"' {
				i++
			} else if c == quote {
				quote = 0
			}
			continue
		}
		switch c {
		case '"', '\'':
			quote = c
		case '[', '{':
			depth++
		case ']', '}':
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

func tomlAddValue(d *Doc, key, v string, line, depth int) error {
	if depth > 16 || v == "" {
		return fmt.Errorf("bad value")
	}
	if s, ok := tomlUnquote(v); ok {
		d.add(key, s, line, 's')
		return nil
	}
	switch v[0] {
	case '[':
		if v[len(v)-1] != ']' {
			return fmt.Errorf("bad array")
		}
		d.add(key, "", line, 'l')
		for i, item := range tomlSplit(v[1 : len(v)-1]) {
			if err := tomlAddValue(d, key+"["+strconv.Itoa(i)+"]", strings.TrimSpace(item), line, depth+1); err != nil {
				return err
			}
		}
		return nil
	case '{':
		if v[len(v)-1] != '}' {
			return fmt.Errorf("bad inline table")
		}
		d.add(key, "", line, 'm')
		for _, item := range tomlSplit(v[1 : len(v)-1]) {
			m := tomlKeyRe.FindStringSubmatch(strings.TrimSpace(item))
			if m == nil {
				return fmt.Errorf("bad inline table")
			}
			if err := tomlAddValue(d, key+"."+tomlKeyPath(m[1]), strings.TrimSpace(m[2]), line, depth+1); err != nil {
				return err
			}
		}
		return nil
	}
	if strings.ContainsAny(v, "\"'= \t") {
		return fmt.Errorf("bad scalar")
	}
	d.add(key, v, line, 's')
	return nil
}

func sortStrings(s []string) {
	for i := 1; i < len(s); i++ {
		for j := i; j > 0 && s[j] < s[j-1]; j-- {
			s[j], s[j-1] = s[j-1], s[j]
		}
	}
}
