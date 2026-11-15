// SPDX-License-Identifier: Apache-2.0

package reporting

import (
	"bytes"
	"encoding/json"
	"os"
	"reflect"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/santhosh-tekuri/jsonschema/v6"

	"github.com/shahzadarain/agent-governance-auditor/internal/model"
	"github.com/shahzadarain/agent-governance-auditor/internal/reporting/reportingtest"
)

const (
	schemaPath = "../../policies/schema/scan-result.schema.json"
	schemaID   = "https://github.com/shahzadarain/agent-governance-auditor/policies/schema/scan-result.schema.json"
)

// schemaEnums lists the allowed values of every typed enumeration in the
// model. A new constant in the model must be added here; the schema file is
// then regenerated with `go test ./internal/reporting -run Schema -update`.
var schemaEnums = map[reflect.Type][]string{
	reflect.TypeOf(model.Status("")): {
		string(model.StatusVerifiedOperational), string(model.StatusVerifiedTested), string(model.StatusVerifiedImplementation),
		string(model.StatusDeclaredOnly), string(model.StatusMissing), string(model.StatusFailed), string(model.StatusUnknown),
		string(model.StatusNotApplicable), string(model.StatusAcceptedRisk), string(model.StatusError),
	},
	reflect.TypeOf(model.Severity("")): {
		string(model.SeverityCritical), string(model.SeverityHigh), string(model.SeverityMedium), string(model.SeverityLow), string(model.SeverityInfo),
	},
	reflect.TypeOf(model.Confidence("")): {
		string(model.ConfidenceHigh), string(model.ConfidenceMedium), string(model.ConfidenceLow),
	},
	reflect.TypeOf(model.DetectionState("")): {
		string(model.Detected), string(model.Suspected), string(model.NotDetected),
	},
	reflect.TypeOf(model.SourceType("")): {
		string(model.SourceStatic), string(model.SourceConfiguration), string(model.SourceTest), string(model.SourceRuntime),
		string(model.SourceAttestation), string(model.SourceManualReview),
	},
	reflect.TypeOf(model.Integrity("")): {
		string(model.IntegrityVerified), string(model.IntegrityUnsigned), string(model.IntegrityInvalid), string(model.IntegrityNotAvailable),
	},
	reflect.TypeOf(model.Result("")): {
		string(model.ResultPass), string(model.ResultFail), string(model.ResultInconclusive),
	},
	reflect.TypeOf(model.Signal("")): {
		string(model.SignalPresent), string(model.SignalAbsent), string(model.SignalViolation), string(model.SignalDeclared), string(model.SignalError),
	},
	reflect.TypeOf(model.Strength("")): {
		string(model.StrengthDeclared), string(model.StrengthImplementation), string(model.StrengthTested), string(model.StrengthOperational),
	},
	reflect.TypeOf(model.Validity("")): {
		string(model.ValidityValid), string(model.ValidityExpired), string(model.ValidityCommitMismatch), string(model.ValidityDigestMismatch),
		string(model.ValidityUnbound), string(model.ValidityInvalidSignature), string(model.ValidityMalformed),
	},
	reflect.TypeOf(model.Outcome("")): {
		string(model.OutcomeAllow), string(model.OutcomeBlock), string(model.OutcomeReviewRequired),
	},
}

var capabilityEnum = []string{
	model.CapTools, model.CapSensitiveActions, model.CapMutatingActions, model.CapShellExec, model.CapCodeExec, model.CapFilesystem,
	model.CapNetwork, model.CapBrowser, model.CapDataAccess, model.CapMemory, model.CapMultiAgent, model.CapMCP, model.CapCredentials,
	model.CapContainer,
}

var basisEnum = []string{model.BasisAlways, model.BasisDetected, model.BasisDeclared, model.BasisInferred, model.BasisApproved}

func anyList(values []string) []any {
	out := make([]any, len(values))
	for i, v := range values {
		out[i] = v
	}
	return out
}

func capabilityItems() map[string]any {
	return map[string]any{"type": "array", "items": map[string]any{"type": "string", "enum": anyList(capabilityEnum)}}
}

func bounded(lo, hi int) map[string]any {
	return map[string]any{"type": "integer", "minimum": lo, "maximum": hi}
}

// schemaOverrides replaces the generated schema of single fields, keyed by
// "GoType.json_name". These carry constraints that the Go types cannot.
var schemaOverrides = map[string]map[string]any{
	"ScanResult.schema_version":         {"type": "string", "const": model.SchemaVersion},
	"Agent.capabilities":                capabilityItems(),
	"Tool.capabilities":                 capabilityItems(),
	"ControlResult.applicability_basis": {"type": "string", "enum": anyList(basisEnum)},
	"ControlResult.maturity":            bounded(0, 4),
	"ControlResult.max_static_maturity": bounded(0, 4),
	"ControlResult.min_maturity":        bounded(0, 4),
	"Score.value":                       {"type": []any{"integer", "null"}, "minimum": 0, "maximum": 100},
	"Score.coverage_percent":            bounded(0, 100),
	"Score.tested_percent":              bounded(0, 100),
	"Score.operational_percent":         bounded(0, 100),
}

var schemaDescriptions = map[string]string{
	"ScanResult":      "The normalized scan output. All report formats render from this one value.",
	"ToolInfo":        "The scanner build.",
	"ScanMeta":        "Scan-level metadata.",
	"Agent":           "One detected or suspected AI agent.",
	"Tool":            "A tool or action an agent can invoke.",
	"MCPConnection":   "A configured MCP server or client connection.",
	"Fact":            "One normalized observation made by a discovery adapter.",
	"Location":        "A place in the scanned repository. Paths are repository-relative with forward slashes.",
	"AgentAssessment": "The complete assessment of one agent.",
	"ControlResult":   "The assessment of one control for one agent.",
	"Evidence":        "One typed evidence item for one control.",
	"Subject":         "Binds external evidence to exact file content.",
	"Finding":         "One actionable issue.",
	"Mapping":         "A link from a finding to a published external standard. Informative only.",
	"Score":           "The illustrative maturity score and its companion measures. It is not a certification or a probability of safety.",
	"Decision":        "The definitive policy decision.",
	"Reason":          "One machine-readable reason behind a decision.",
	"Stats":           "The work a scan performed.",
}

type schemaGen struct{ defs map[string]any }

func (g *schemaGen) ref(name string) map[string]any {
	return map[string]any{"$ref": "#/$defs/" + name}
}

// jsonField returns the JSON name of a struct field and whether it is
// omitted when empty. ok is false for fields that are not serialized.
func jsonField(f reflect.StructField) (name string, omitempty, ok bool) {
	tag := f.Tag.Get("json")
	if tag == "-" || !f.IsExported() {
		return "", false, false
	}
	parts := strings.Split(tag, ",")
	name = parts[0]
	if name == "" {
		name = f.Name
	}
	for _, p := range parts[1:] {
		if p == "omitempty" {
			omitempty = true
		}
	}
	return name, omitempty, true
}

func (g *schemaGen) schemaFor(t reflect.Type) map[string]any {
	if t == reflect.TypeOf(time.Time{}) {
		return map[string]any{"type": "string", "format": "date-time"}
	}
	if values, ok := schemaEnums[t]; ok {
		if _, done := g.defs[t.Name()]; !done {
			g.defs[t.Name()] = map[string]any{"type": "string", "enum": anyList(values)}
		}
		return g.ref(t.Name())
	}
	switch t.Kind() {
	case reflect.String:
		return map[string]any{"type": "string"}
	case reflect.Bool:
		return map[string]any{"type": "boolean"}
	case reflect.Int, reflect.Int64:
		return map[string]any{"type": "integer", "minimum": 0}
	case reflect.Slice:
		return map[string]any{"type": "array", "items": g.schemaFor(t.Elem())}
	case reflect.Map:
		return map[string]any{"type": "object", "additionalProperties": g.schemaFor(t.Elem())}
	case reflect.Pointer:
		return g.schemaFor(t.Elem())
	case reflect.Struct:
		if _, done := g.defs[t.Name()]; done {
			return g.ref(t.Name())
		}
		def := map[string]any{"type": "object", "additionalProperties": false}
		g.defs[t.Name()] = def // set first, so recursive types terminate
		props := map[string]any{}
		required := []any{}
		for i := 0; i < t.NumField(); i++ {
			f := t.Field(i)
			name, omitempty, ok := jsonField(f)
			if !ok {
				continue
			}
			var s map[string]any
			if o, has := schemaOverrides[t.Name()+"."+name]; has {
				s = o
			} else {
				s = g.schemaFor(f.Type)
				// A pointer that is always written may be null.
				if f.Type.Kind() == reflect.Pointer && !omitempty {
					s = map[string]any{"anyOf": []any{s, map[string]any{"type": "null"}}}
				}
			}
			props[name] = s
			if !omitempty {
				required = append(required, name)
			}
		}
		def["properties"] = props
		def["required"] = required
		if d := schemaDescriptions[t.Name()]; d != "" {
			def["description"] = d
		}
		return g.ref(t.Name())
	}
	panic("schema generator: unsupported type " + t.String())
}

func generateSchema(t *testing.T) []byte {
	t.Helper()
	g := &schemaGen{defs: map[string]any{}}
	root := g.schemaFor(reflect.TypeOf(model.ScanResult{}))
	doc := map[string]any{
		"$schema":     "https://json-schema.org/draft/2020-12/schema",
		"$id":         schemaID,
		"title":       "AgentGov Auditor scan result",
		"description": "The JSON document written by `agentgov scan --format json`. Schema version " + model.SchemaVersion + ". Generated from internal/model; do not edit by hand.",
		"$ref":        root["$ref"],
		"$defs":       g.defs,
	}
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetIndent("", "  ")
	enc.SetEscapeHTML(false)
	if err := enc.Encode(doc); err != nil {
		t.Fatal(err)
	}
	return buf.Bytes()
}

func readSchema(t *testing.T) []byte {
	t.Helper()
	data, err := os.ReadFile(schemaPath)
	if err != nil {
		t.Fatalf("read schema (run the tests with -update to create it): %v", err)
	}
	return bytes.ReplaceAll(data, []byte("\r\n"), []byte("\n"))
}

// TestSchemaFileIsCurrent regenerates the schema from the model and compares
// it with the published file, so any change to the model is caught.
func TestSchemaFileIsCurrent(t *testing.T) {
	want := generateSchema(t)
	if *update {
		if err := os.MkdirAll("../../policies/schema", 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(schemaPath, want, 0o644); err != nil {
			t.Fatal(err)
		}
		return
	}
	if got := readSchema(t); !bytes.Equal(got, want) {
		t.Errorf("%s is out of date with internal/model. Review the change, then run: go test ./internal/reporting -run Schema -update\n%s",
			schemaPath, firstDiff(string(got), string(want)))
	}
}

func compileSchema(t *testing.T) *jsonschema.Schema {
	t.Helper()
	doc, err := jsonschema.UnmarshalJSON(bytes.NewReader(readSchema(t)))
	if err != nil {
		t.Fatalf("schema is not valid JSON: %v", err)
	}
	c := jsonschema.NewCompiler()
	c.DefaultDraft(jsonschema.Draft2020)
	if err := c.AddResource(schemaID, doc); err != nil {
		t.Fatal(err)
	}
	sch, err := c.Compile(schemaID)
	if err != nil {
		t.Fatalf("schema does not compile: %v", err)
	}
	return sch
}

func validateJSON(t *testing.T, sch *jsonschema.Schema, data string) error {
	t.Helper()
	inst, err := jsonschema.UnmarshalJSON(strings.NewReader(data))
	if err != nil {
		t.Fatalf("output is not valid JSON: %v", err)
	}
	return sch.Validate(inst)
}

func TestJSONOutputValidatesAgainstSchema(t *testing.T) {
	sch := compileSchema(t)
	for _, s := range samples {
		if err := validateJSON(t, sch, render(t, s.make(), FormatJSON, Options{})); err != nil {
			t.Errorf("%s: rendered JSON does not validate: %v", s.name, err)
		}
	}
	// A result with nothing set still validates, apart from the enumerated
	// decision and the schema version, which a real scan always sets.
	empty := &model.ScanResult{SchemaVersion: model.SchemaVersion, Decision: model.Decision{Outcome: model.OutcomeReviewRequired}}
	if err := validateJSON(t, sch, render(t, empty, FormatJSON, Options{})); err != nil {
		t.Errorf("minimal result does not validate: %v", err)
	}
}

func TestSchemaRejectsInvalidDocuments(t *testing.T) {
	sch := compileSchema(t)
	mutate := func(name string, fn func(doc map[string]any)) {
		var doc map[string]any
		if err := json.Unmarshal([]byte(render(t, reportingtest.Blocked(), FormatJSON, Options{})), &doc); err != nil {
			t.Fatal(err)
		}
		fn(doc)
		data, _ := json.Marshal(doc)
		if err := validateJSON(t, sch, string(data)); err == nil {
			t.Errorf("%s: the schema accepted an invalid document", name)
		}
	}
	first := func(doc map[string]any, key string) map[string]any {
		return doc[key].([]any)[0].(map[string]any)
	}
	mutate("unknown top-level property", func(d map[string]any) { d["extra"] = true })
	mutate("unknown nested property", func(d map[string]any) { first(d, "findings")["secret_value"] = "x" })
	mutate("missing required property", func(d map[string]any) { delete(d, "decision") })
	mutate("wrong schema version", func(d map[string]any) { d["schema_version"] = "2" })
	mutate("invalid outcome", func(d map[string]any) { d["decision"].(map[string]any)["outcome"] = "PASS" })
	mutate("invalid severity", func(d map[string]any) { first(d, "findings")["severity"] = "urgent" })
	mutate("invalid status", func(d map[string]any) {
		first(first(d, "assessments"), "controls")["status"] = "passed"
	})
	mutate("maturity out of range", func(d map[string]any) {
		first(first(d, "assessments"), "controls")["maturity"] = 5
	})
	mutate("invalid capability", func(d map[string]any) { first(d, "agents")["capabilities"] = []any{"telepathy"} })
	mutate("score above 100", func(d map[string]any) { d["score"].(map[string]any)["value"] = 101 })
	mutate("null array", func(d map[string]any) { d["findings"] = nil })
	mutate("wrong type", func(d map[string]any) { first(d, "evidence")["observed_at"] = 12 })
}

// TestSchemaCoversEveryModelField walks the JSON tags of model.ScanResult and
// fails when a field is missing from the schema file, when the schema lists a
// property the model does not have, or when the required list is wrong. It
// reads the published file directly and does not use the generator.
func TestSchemaCoversEveryModelField(t *testing.T) {
	var root map[string]any
	if err := json.Unmarshal(readSchema(t), &root); err != nil {
		t.Fatal(err)
	}
	if root["$schema"] != "https://json-schema.org/draft/2020-12/schema" {
		t.Errorf("$schema = %v, want draft 2020-12", root["$schema"])
	}
	defs, _ := root["$defs"].(map[string]any)

	var resolve func(node map[string]any) map[string]any
	resolve = func(node map[string]any) map[string]any {
		if ref, ok := node["$ref"].(string); ok {
			target, ok := defs[strings.TrimPrefix(ref, "#/$defs/")].(map[string]any)
			if !ok {
				t.Fatalf("unresolved reference %s", ref)
			}
			return resolve(target)
		}
		if alts, ok := node["anyOf"].([]any); ok {
			for _, a := range alts {
				if m := a.(map[string]any); m["type"] != "null" {
					return resolve(m)
				}
			}
		}
		return node
	}

	visited := map[reflect.Type]bool{}
	fields := 0
	var check func(typ reflect.Type, node map[string]any, path string)
	check = func(typ reflect.Type, node map[string]any, path string) {
		node = resolve(node)
		if typ == reflect.TypeOf(time.Time{}) {
			if node["type"] != "string" || node["format"] != "date-time" {
				t.Errorf("%s: a timestamp must be a date-time string", path)
			}
			return
		}
		if values, ok := schemaEnums[typ]; ok {
			got, _ := node["enum"].([]any)
			if !reflect.DeepEqual(got, anyList(values)) {
				t.Errorf("%s: enum %v does not match the model values %v", path, got, values)
			}
			return
		}
		switch typ.Kind() {
		case reflect.Pointer:
			check(typ.Elem(), node, path)
		case reflect.Slice:
			items, ok := node["items"].(map[string]any)
			if node["type"] != "array" || !ok {
				t.Errorf("%s: want an array schema with items", path)
				return
			}
			check(typ.Elem(), items, path+"[]")
		case reflect.Map:
			extra, ok := node["additionalProperties"].(map[string]any)
			if node["type"] != "object" || !ok {
				t.Errorf("%s: want an object schema with typed additionalProperties", path)
				return
			}
			check(typ.Elem(), extra, path+"{}")
		case reflect.Struct:
			if visited[typ] {
				return
			}
			visited[typ] = true
			if node["type"] != "object" {
				t.Errorf("%s: want an object schema", path)
				return
			}
			if node["additionalProperties"] != false {
				t.Errorf("%s: additionalProperties must be false", path)
			}
			props, _ := node["properties"].(map[string]any)
			required := map[string]bool{}
			for _, r := range node["required"].([]any) {
				required[r.(string)] = true
			}
			want := map[string]bool{}
			for i := 0; i < typ.NumField(); i++ {
				f := typ.Field(i)
				name, omitempty, ok := jsonField(f)
				if !ok {
					continue
				}
				fields++
				want[name] = true
				prop, ok := props[name].(map[string]any)
				if !ok {
					t.Errorf("%s.%s: field %s.%s is missing from the schema", path, name, typ.Name(), f.Name)
					continue
				}
				if required[name] == omitempty {
					t.Errorf("%s.%s: required = %v, but omitempty = %v", path, name, required[name], omitempty)
				}
				check(f.Type, prop, path+"."+name)
			}
			var extra []string
			for name := range props {
				if !want[name] {
					extra = append(extra, name)
				}
			}
			sort.Strings(extra)
			if len(extra) > 0 {
				t.Errorf("%s: the schema lists properties the model does not have: %v", path, extra)
			}
		case reflect.String:
			if node["type"] != "string" {
				t.Errorf("%s: want a string schema, got %v", path, node["type"])
			}
		case reflect.Bool:
			if node["type"] != "boolean" {
				t.Errorf("%s: want a boolean schema, got %v", path, node["type"])
			}
		case reflect.Int, reflect.Int64:
			if ts, ok := node["type"].([]any); ok {
				if len(ts) == 0 || ts[0] != "integer" {
					t.Errorf("%s: want an integer schema, got %v", path, ts)
				}
			} else if node["type"] != "integer" {
				t.Errorf("%s: want an integer schema, got %v", path, node["type"])
			}
		default:
			t.Errorf("%s: unsupported kind %s", path, typ.Kind())
		}
	}
	check(reflect.TypeOf(model.ScanResult{}), root, "$")
	if fields < 150 {
		t.Errorf("walked only %d fields; the walk is not reaching the whole model", fields)
	}
	t.Logf("checked %d model fields in %d struct types", fields, len(visited))
}
