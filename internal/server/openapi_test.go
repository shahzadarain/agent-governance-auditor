// SPDX-License-Identifier: Apache-2.0

package server

import (
	"os"
	"reflect"
	"sort"
	"strings"
	"testing"

	"gopkg.in/yaml.v3"

	"github.com/shahzadarain/agent-governance-auditor/internal/model"
	"github.com/shahzadarain/agent-governance-auditor/internal/storage"
)

func loadOpenAPI(t *testing.T) map[string]any {
	t.Helper()
	data, err := os.ReadFile("../../api/openapi.yaml")
	if err != nil {
		t.Fatalf("read spec: %v", err)
	}
	var doc map[string]any
	if err := yaml.Unmarshal(data, &doc); err != nil {
		t.Fatalf("parse spec: %v", err)
	}
	return doc
}

var httpMethods = map[string]bool{"get": true, "post": true, "put": true, "patch": true, "delete": true, "head": true, "options": true}

// TestOpenAPIMatchesRoutes checks both directions: every registered route is
// in the spec with the same method, and the spec lists no route the server
// does not register.
func TestOpenAPIMatchesRoutes(t *testing.T) {
	doc := loadOpenAPI(t)
	if doc["openapi"] != "3.0.3" {
		t.Fatalf("openapi version = %v", doc["openapi"])
	}
	spec := map[string]map[string]any{} // "METHOD path" -> operation
	opIDs := map[string]bool{}
	for path, item := range doc["paths"].(map[string]any) {
		for method, op := range item.(map[string]any) {
			if !httpMethods[method] {
				continue
			}
			o := op.(map[string]any)
			spec[strings.ToUpper(method)+" "+path] = o
			id, _ := o["operationId"].(string)
			if id == "" || opIDs[id] {
				t.Errorf("%s %s: missing or duplicate operationId %q", method, path, id)
			}
			opIDs[id] = true
			if _, ok := o["responses"].(map[string]any); !ok {
				t.Errorf("%s %s: no responses", method, path)
			}
		}
	}
	registered := map[string]route{}
	for _, rt := range routeTable() {
		registered[rt.Method+" "+rt.Path] = rt
	}
	if len(Routes()) != len(registered) {
		t.Fatalf("Routes() has %d entries, route table has %d distinct routes", len(Routes()), len(registered))
	}
	for key := range registered {
		if _, ok := spec[key]; !ok {
			t.Errorf("route %q is registered but not in api/openapi.yaml", key)
		}
	}
	for key := range spec {
		if _, ok := registered[key]; !ok {
			t.Errorf("api/openapi.yaml documents %q but the server does not register it", key)
		}
	}

	// The documented security of each operation matches the route table.
	defaultSec := doc["security"]
	for key, rt := range registered {
		op, ok := spec[key]
		if !ok {
			continue
		}
		sec, has := op["security"]
		if !has {
			sec = defaultSec
		}
		schemes := map[string]bool{}
		if list, ok := sec.([]any); ok {
			for _, alt := range list {
				for name := range alt.(map[string]any) {
					schemes[name] = true
				}
			}
		}
		switch rt.access {
		case accessSession:
			if !schemes["sessionCookie"] || schemes["bearerToken"] {
				t.Errorf("%s: spec security %v, want sessionCookie only", key, schemes)
			}
			if isMutating(rt.Method) != schemes["csrfToken"] {
				t.Errorf("%s: csrfToken documented = %v, mutating = %v", key, schemes["csrfToken"], isMutating(rt.Method))
			}
		case accessToken:
			if !schemes["bearerToken"] || schemes["sessionCookie"] {
				t.Errorf("%s: spec security %v, want bearerToken only", key, schemes)
			}
		case accessPublic:
			if schemes["sessionCookie"] || schemes["csrfToken"] {
				t.Errorf("%s: public route documents session security %v", key, schemes)
			}
		}
		// Path parameters in the route are declared in the spec.
		for _, seg := range strings.Split(rt.Path, "/") {
			if strings.HasPrefix(seg, "{") && !specDeclaresPathParam(doc, rt.Path, strings.Trim(seg, "{}")) {
				t.Errorf("%s: path parameter %s is not declared", key, seg)
			}
		}
	}

	comps := doc["components"].(map[string]any)
	for _, name := range []string{"sessionCookie", "csrfToken", "bearerToken"} {
		if _, ok := comps["securitySchemes"].(map[string]any)[name]; !ok {
			t.Errorf("security scheme %q missing", name)
		}
	}
}

func specDeclaresPathParam(doc map[string]any, path, name string) bool {
	item := doc["paths"].(map[string]any)[path].(map[string]any)
	params, _ := item["parameters"].([]any)
	for _, p := range params {
		pm := p.(map[string]any)
		if ref, ok := pm["$ref"].(string); ok {
			pm, _ = resolveRef(doc, ref).(map[string]any)
		}
		if pm != nil && pm["name"] == name && pm["in"] == "path" && pm["required"] == true {
			return true
		}
	}
	return false
}

func resolveRef(doc map[string]any, ref string) any {
	if !strings.HasPrefix(ref, "#/") {
		return nil
	}
	var cur any = doc
	for _, part := range strings.Split(strings.TrimPrefix(ref, "#/"), "/") {
		m, ok := cur.(map[string]any)
		if !ok {
			return nil
		}
		cur = m[part]
	}
	return cur
}

// TestOpenAPIRefsResolve walks the whole document and checks every $ref.
func TestOpenAPIRefsResolve(t *testing.T) {
	doc := loadOpenAPI(t)
	count := 0
	var walk func(v any, where string)
	walk = func(v any, where string) {
		switch x := v.(type) {
		case map[string]any:
			if ref, ok := x["$ref"].(string); ok {
				count++
				if resolveRef(doc, ref) == nil {
					t.Errorf("%s: unresolved $ref %q", where, ref)
				}
			}
			for k, sub := range x {
				walk(sub, where+"/"+k)
			}
		case []any:
			for _, sub := range x {
				walk(sub, where)
			}
		}
	}
	walk(doc, "")
	if count < 100 {
		t.Fatalf("only %d $ref found; the walk is broken", count)
	}
}

func jsonFields(typ reflect.Type) []string {
	var out []string
	for i := 0; i < typ.NumField(); i++ {
		f := typ.Field(i)
		if f.Anonymous {
			out = append(out, jsonFields(f.Type)...)
			continue
		}
		name := strings.Split(f.Tag.Get("json"), ",")[0]
		if name == "-" {
			continue
		}
		if name == "" {
			name = f.Name
		}
		out = append(out, name)
	}
	sort.Strings(out)
	return out
}

// TestOpenAPISchemasMatchGoTypes compares the property names of the spec
// schemas with the JSON field names of the Go types the server encodes.
func TestOpenAPISchemasMatchGoTypes(t *testing.T) {
	doc := loadOpenAPI(t)
	schemas := doc["components"].(map[string]any)["schemas"].(map[string]any)
	types := map[string]any{
		"ScanResult": model.ScanResult{}, "ScanMeta": model.ScanMeta{}, "ToolInfo": model.ToolInfo{}, "Stats": model.Stats{},
		"Agent": model.Agent{}, "Tool": model.Tool{}, "Fact": model.Fact{}, "MCPConnection": model.MCPConnection{}, "Location": model.Location{},
		"Evidence": model.Evidence{}, "Subject": model.Subject{}, "Finding": model.Finding{}, "Mapping": model.Mapping{},
		"ControlResult": model.ControlResult{}, "Score": model.Score{}, "Reason": model.Reason{}, "Decision": model.Decision{},
		"AgentAssessment": model.AgentAssessment{}, "Comparison": model.Comparison{}, "ControlChange": model.ControlChange{},
		"Catalog": model.Catalog{}, "Control": model.Control{}, "Profile": model.Profile{}, "Applicability": model.Applicability{},
		"VerificationRules": model.VerificationRules{},
		"User":              storage.User{}, "Project": storage.Project{}, "Member": storage.Member{}, "APIToken": storage.APIToken{},
		"ScanSummary": storage.Scan{}, "AgentSummary": storage.Agent{}, "AgentScan": storage.AgentScan{}, "Overview": storage.Overview{},
		"Version": versionResponse{}, "SetupRequest": setupRequest{}, "LoginRequest": loginRequest{}, "Session": sessionResponse{},
		"CreateUserRequest": createUserRequest{}, "UserResponse": userResponse{}, "CreateProjectRequest": createProjectRequest{},
		"ProjectDetail": projectDetail{}, "OverviewResponse": overviewResponse{}, "SetMemberRequest": setMemberRequest{},
		"CreateTokenRequest": createTokenRequest{}, "CreateTokenResponse": createTokenResponse{}, "UploadResponse": ingestResponse{},
		"ScanDetail": scanDetail{}, "AgentDetail": agentDetail{}, "CompareResponse": compareResponse{}, "AuditEvent": auditEventView{},
		"EvidenceVerifyRequest": evidenceVerifyRequest{}, "EvidenceVerifyResponse": evidenceVerifyResponse{}, "Status": statusBody{},
		"ErrorResponse": errorBody{},
	}
	for name, v := range types {
		schema, ok := schemas[name].(map[string]any)
		if !ok {
			t.Errorf("schema %q is missing from the spec", name)
			continue
		}
		props, _ := schema["properties"].(map[string]any)
		var got []string
		for p := range props {
			got = append(got, p)
		}
		sort.Strings(got)
		want := jsonFields(reflect.TypeOf(v))
		if strings.Join(got, ",") != strings.Join(want, ",") {
			t.Errorf("schema %s properties differ from the Go type:\n spec: %v\n   go: %v", name, got, want)
		}
		for _, req := range toStrings(schema["required"]) {
			if _, ok := props[req]; !ok {
				t.Errorf("schema %s: required property %q is not defined", name, req)
			}
		}
	}
	// The enumerations match the model constants.
	wantEnum := func(schema string, want ...string) {
		got := toStrings(schemas[schema].(map[string]any)["enum"])
		sort.Strings(got)
		sort.Strings(want)
		if strings.Join(got, ",") != strings.Join(want, ",") {
			t.Errorf("enum %s = %v, want %v", schema, got, want)
		}
	}
	var statuses, severities, outcomes []string
	for s := range validStatuses {
		statuses = append(statuses, string(s))
	}
	for s := range validSeverities {
		severities = append(severities, string(s))
	}
	for s := range validOutcomes {
		outcomes = append(outcomes, string(s))
	}
	wantEnum("ControlStatus", statuses...)
	wantEnum("Severity", severities...)
	wantEnum("Outcome", outcomes...)
	if len(statuses) != 10 {
		t.Fatalf("expected ten statuses, got %d", len(statuses))
	}
}

func toStrings(v any) []string {
	list, _ := v.([]any)
	var out []string
	for _, x := range list {
		if s, ok := x.(string); ok {
			out = append(out, s)
		}
	}
	return out
}
