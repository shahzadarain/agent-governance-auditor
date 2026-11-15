// SPDX-License-Identifier: Apache-2.0

package policies

import (
	"io/fs"
	"strings"
	"testing"
)

func TestEmbeddedFilesArePresent(t *testing.T) {
	for dir, want := range map[string]int{ControlsDir: 25, ProfilesDir: 3} {
		entries, err := fs.ReadDir(FS, dir)
		if err != nil {
			t.Fatalf("%s: %v", dir, err)
		}
		if len(entries) != want {
			t.Errorf("%s: %d files, want %d", dir, len(entries), want)
		}
	}
	for _, name := range []string{ControlSchema, ProfileSchema, ConfigSchema} {
		if _, err := Schema(name); err != nil {
			t.Errorf("schema %s must compile: %v", name, err)
		}
		raw, err := FS.ReadFile(SchemaDir + "/" + name)
		if err != nil {
			t.Fatal(err)
		}
		if !strings.Contains(string(raw), `"https://json-schema.org/draft/2020-12/schema"`) {
			t.Errorf("schema %s must declare draft 2020-12", name)
		}
	}
	if _, err := Schema("missing.schema.json"); err == nil {
		t.Error("an unknown schema name must fail")
	}
	if _, err := Schema("../embed.go"); err == nil {
		t.Error("a schema name with a path must fail")
	}
}

func TestDecodeYAML(t *testing.T) {
	v, problem := DecodeYAML([]byte("a: 1\nb: [x, 2026-12-31]\nc: {d: true, e: null}\n"))
	if problem != "" {
		t.Fatal(problem)
	}
	m := v.(map[string]any)
	if m["b"].([]any)[1] != "2026-12-31" {
		t.Errorf("an unquoted date must stay a string, got %#v", m["b"])
	}
	if m["c"].(map[string]any)["d"] != true {
		t.Errorf("booleans must decode")
	}
	if v, problem := DecodeYAML(nil); v != nil || problem != "" {
		t.Errorf("empty input is a nil document: %v %q", v, problem)
	}
	for name, doc := range map[string]string{
		"syntax":        "a: [1\n",
		"two documents": "a: 1\n---\nb: 2\n",
		"duplicate key": "a: 1\na: 2\n",
		"complex key":   "? [a, b]\n: 1\n",
	} {
		if _, problem := DecodeYAML([]byte(doc)); !strings.HasPrefix(problem, "malformed YAML: ") {
			t.Errorf("%s: want a malformed YAML problem, got %q", name, problem)
		}
	}
}

func TestValidateYAMLGivesFieldPaths(t *testing.T) {
	doc := "name: org\nversion: \"1\"\ndescription: A valid description here.\nmandatory_controls: [AGC-001, AGC-030]\nmin_maturity: 9\n"
	diags, err := ValidateYAML(ProfileSchema, []byte(doc))
	if err != nil {
		t.Fatal(err)
	}
	joined := strings.Join(diags, "\n")
	if len(diags) != 2 || !strings.Contains(joined, "mandatory_controls[1]: ") || !strings.Contains(joined, "min_maturity: ") {
		t.Fatalf("diagnostics:\n%s", joined)
	}
	ok := strings.Replace(strings.Replace(doc, "AGC-030", "AGC-024", 1), "9", "4", 1)
	if diags, _ := ValidateYAML(ProfileSchema, []byte(ok)); len(diags) != 0 {
		t.Fatalf("valid profile rejected: %v", diags)
	}
	if got := Diagnostics(nil); got != nil {
		t.Errorf("no error gives no diagnostics")
	}
}
