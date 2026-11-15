// SPDX-License-Identifier: Apache-2.0

// Package policies embeds the versioned policy data of AgentGov Auditor: the
// control catalog, the default risk profiles, and the JSON Schemas. It also
// offers small helpers to validate a document against an embedded schema.
//
// Everything in this package is data that ships inside the binary. Nothing
// here reads the scanned repository.
package policies

import (
	"bytes"
	"embed"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"sort"
	"strings"
	"sync"

	"github.com/santhosh-tekuri/jsonschema/v6"
	"gopkg.in/yaml.v3"
)

// FS holds the embedded policy data. Paths use forward slashes:
// "controls/v1/AGC-001.yaml", "profiles/baseline.yaml",
// "schema/control.schema.json".
//
//go:embed controls/v1/*.yaml profiles/*.yaml schema/*.json
var FS embed.FS

// Directories and file names inside FS.
const (
	ControlsDir   = "controls/v1"
	ProfilesDir   = "profiles"
	SchemaDir     = "schema"
	PackFile      = "controls/v1/pack.yaml"
	ControlSchema = "control.schema.json"
	ProfileSchema = "profile.schema.json"
	ConfigSchema  = "agentgov-config.schema.json"
)

var (
	schemaMu    sync.Mutex
	schemaCache = map[string]*jsonschema.Schema{}
)

// Schema compiles the embedded JSON Schema with the given file name (for
// example "control.schema.json"). Compiled schemas are cached.
func Schema(name string) (*jsonschema.Schema, error) {
	schemaMu.Lock()
	defer schemaMu.Unlock()
	if s, ok := schemaCache[name]; ok {
		return s, nil
	}
	if strings.ContainsAny(name, `/\`) {
		return nil, fmt.Errorf("schema name %q must be a plain file name", name)
	}
	raw, err := FS.ReadFile(SchemaDir + "/" + name)
	if err != nil {
		return nil, fmt.Errorf("read embedded schema %s: %w", name, err)
	}
	doc, err := jsonschema.UnmarshalJSON(bytes.NewReader(raw))
	if err != nil {
		return nil, fmt.Errorf("parse embedded schema %s: %w", name, err)
	}
	c := jsonschema.NewCompiler()
	url := "https://agentgov.invalid/schema/" + name
	if err := c.AddResource(url, doc); err != nil {
		return nil, fmt.Errorf("add embedded schema %s: %w", name, err)
	}
	s, err := c.Compile(url)
	if err != nil {
		return nil, fmt.Errorf("compile embedded schema %s: %w", name, err)
	}
	schemaCache[name] = s
	return s, nil
}

// ValidateYAML checks one YAML document against the named embedded schema.
// It returns human-readable diagnostics, each starting with a field path such
// as "policy.min_maturity: ...". An empty result means the document is valid.
// The error return is for problems with the schema itself, not the document.
func ValidateYAML(schemaName string, data []byte) ([]string, error) {
	v, problem := DecodeYAML(data)
	if problem != "" {
		return []string{problem}, nil
	}
	return ValidateValue(schemaName, v)
}

// maxYAMLNodes bounds the size of a decoded document, so that a small file
// with nested aliases cannot expand into a very large value.
const maxYAMLNodes = 50000

// DecodeYAML parses exactly one YAML document into plain values (maps with
// string keys, slices, strings, numbers, booleans, nil). Dates stay strings,
// so an unquoted "2026-12-31" validates as a date string. A non-empty problem
// string describes why the input was rejected.
func DecodeYAML(data []byte) (v any, problem string) {
	dec := yaml.NewDecoder(bytes.NewReader(data))
	var doc yaml.Node
	if err := dec.Decode(&doc); err != nil {
		if errors.Is(err, io.EOF) {
			return nil, ""
		}
		return nil, "malformed YAML: " + cleanYAMLError(err)
	}
	var extra yaml.Node
	if err := dec.Decode(&extra); err == nil {
		return nil, "malformed YAML: the file holds more than one document; use a single document"
	} else if !errors.Is(err, io.EOF) {
		return nil, "malformed YAML: " + cleanYAMLError(err)
	}
	budget := maxYAMLNodes
	out, err := nodeValue(&doc, &budget)
	if err != nil {
		return nil, "malformed YAML: " + err.Error()
	}
	return out, ""
}

func nodeValue(n *yaml.Node, budget *int) (any, error) {
	*budget--
	if *budget < 0 {
		return nil, errors.New("the document is too large or expands too many aliases")
	}
	switch n.Kind {
	case yaml.DocumentNode:
		if len(n.Content) == 0 {
			return nil, nil
		}
		return nodeValue(n.Content[0], budget)
	case yaml.AliasNode:
		if n.Alias == nil {
			return nil, errors.New("unresolved alias")
		}
		return nodeValue(n.Alias, budget)
	case yaml.MappingNode:
		m := make(map[string]any, len(n.Content)/2)
		for i := 0; i+1 < len(n.Content); i += 2 {
			k := n.Content[i]
			if k.Kind != yaml.ScalarNode {
				return nil, fmt.Errorf("line %d: mapping keys must be plain strings", k.Line)
			}
			if _, dup := m[k.Value]; dup {
				return nil, fmt.Errorf("line %d: duplicate key %q", k.Line, k.Value)
			}
			val, err := nodeValue(n.Content[i+1], budget)
			if err != nil {
				return nil, err
			}
			m[k.Value] = val
		}
		return m, nil
	case yaml.SequenceNode:
		s := make([]any, 0, len(n.Content))
		for _, c := range n.Content {
			val, err := nodeValue(c, budget)
			if err != nil {
				return nil, err
			}
			s = append(s, val)
		}
		return s, nil
	case yaml.ScalarNode:
		if n.ShortTag() == "!!timestamp" {
			return n.Value, nil
		}
		var v any
		if err := n.Decode(&v); err != nil {
			return nil, fmt.Errorf("line %d: %s", n.Line, cleanYAMLError(err))
		}
		return v, nil
	}
	return nil, fmt.Errorf("line %d: unsupported YAML node", n.Line)
}

// ValidateValue checks an already decoded YAML or JSON value against the
// named embedded schema. See ValidateYAML for the result format.
func ValidateValue(schemaName string, v any) ([]string, error) {
	s, err := Schema(schemaName)
	if err != nil {
		return nil, err
	}
	inst, err := toJSONValue(v)
	if err != nil {
		return []string{"document cannot be represented as JSON: " + err.Error()}, nil
	}
	return Diagnostics(s.Validate(inst)), nil
}

// Diagnostics flattens a schema validation error into sorted, de-duplicated
// lines of the form "field.path: message". A nil error gives nil.
func Diagnostics(err error) []string {
	if err == nil {
		return nil
	}
	ve, ok := err.(*jsonschema.ValidationError)
	if !ok {
		return []string{err.Error()}
	}
	seen := map[string]bool{}
	var out []string
	var walk func(u jsonschema.OutputUnit)
	walk = func(u jsonschema.OutputUnit) {
		if u.Error != nil && len(u.Errors) == 0 {
			line := fieldPath(u.InstanceLocation) + ": " + u.Error.String()
			if !seen[line] {
				seen[line] = true
				out = append(out, line)
			}
		}
		for _, c := range u.Errors {
			walk(c)
		}
	}
	walk(*ve.DetailedOutput())
	if len(out) == 0 {
		out = []string{ve.Error()}
	}
	sort.Strings(out)
	return out
}

// fieldPath turns a JSON pointer ("/policy/not_applicable/0/control") into a
// dotted path ("policy.not_applicable[0].control").
func fieldPath(ptr string) string {
	if ptr == "" || ptr == "/" {
		return "(document)"
	}
	var b strings.Builder
	for _, tok := range strings.Split(strings.TrimPrefix(ptr, "/"), "/") {
		tok = strings.ReplaceAll(strings.ReplaceAll(tok, "~1", "/"), "~0", "~")
		if isDigits(tok) {
			b.WriteString("[" + tok + "]")
			continue
		}
		if b.Len() > 0 {
			b.WriteString(".")
		}
		b.WriteString(tok)
	}
	return b.String()
}

func isDigits(s string) bool {
	if s == "" {
		return false
	}
	for _, r := range s {
		if r < '0' || r > '9' {
			return false
		}
	}
	return true
}

// toJSONValue converts a YAML-decoded value into the value types the schema
// validator expects, by a JSON round trip.
func toJSONValue(v any) (any, error) {
	raw, err := json.Marshal(v)
	if err != nil {
		return nil, err
	}
	return jsonschema.UnmarshalJSON(bytes.NewReader(raw))
}

func cleanYAMLError(err error) string {
	return strings.TrimPrefix(err.Error(), "yaml: ")
}
