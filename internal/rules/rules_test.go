// SPDX-License-Identifier: Apache-2.0

package rules

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"testing"
	"time"

	"gopkg.in/yaml.v3"

	"github.com/shahzadarain/agent-governance-auditor/internal/adapters"
	"github.com/shahzadarain/agent-governance-auditor/internal/config"
	"github.com/shahzadarain/agent-governance-auditor/internal/discovery"
	"github.com/shahzadarain/agent-governance-auditor/internal/model"
)

// ---------------------------------------------------------------------------
// Harness
// ---------------------------------------------------------------------------

type result struct {
	evidence []model.Evidence
	findings []model.Finding
	agent    model.Agent
}

// run builds a repository from files, discovers the first agent, and runs
// every detector. cfgYAML, when set, is written as .agentgov.yaml and parsed.
func run(t *testing.T, files map[string]string, cfgYAML string) result {
	t.Helper()
	root := t.TempDir()
	all := map[string]string{}
	for k, v := range files {
		all[k] = v
	}
	var cfg *config.Config
	if cfgYAML != "" {
		all[config.FileName] = cfgYAML
		var c config.Config
		if err := yaml.Unmarshal([]byte(cfgYAML), &c); err == nil {
			c.Path = config.FileName
			cfg = &c
		}
	}
	for rel, content := range all {
		p := filepath.Join(root, filepath.FromSlash(rel))
		if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p, []byte(content), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	inv, err := discovery.Walk(context.Background(), discovery.Options{Root: root})
	if err != nil {
		t.Fatal(err)
	}
	repo := adapters.Analyze(context.Background(), inv)
	disc := adapters.Discover(repo, cfg, "fixture")
	if len(disc.Agents) == 0 {
		t.Fatalf("no agent discovered in the test repository")
	}
	c := &Context{Agent: disc.Agents[0], Repo: repo, Config: cfg, Now: time.Date(2026, 11, 15, 0, 0, 0, 0, time.UTC)}
	evs, fs := RunAll(context.Background(), c)
	return result{evs, fs, disc.Agents[0].Agent}
}

func (r result) signals(control string) string {
	set := map[string]bool{}
	for _, e := range r.evidence {
		if e.ControlID == control {
			set[string(e.Signal)] = true
		}
	}
	var out []string
	for s := range set {
		out = append(out, s)
	}
	sort.Strings(out)
	return strings.Join(out, ",")
}

func (r result) rules() string {
	set := map[string]bool{}
	for _, f := range r.findings {
		set[f.RuleID] = true
	}
	var out []string
	for s := range set {
		out = append(out, s)
	}
	sort.Strings(out)
	return strings.Join(out, ",")
}

func (r result) summary(control string) string {
	var out []string
	for _, e := range r.evidence {
		if e.ControlID == control {
			out = append(out, e.Summary+" "+strings.Join(e.Limitations, " "))
		}
	}
	return strings.Join(out, " | ")
}

// with returns base plus extra files.
func with(base map[string]string, extra map[string]string) map[string]string {
	out := map[string]string{}
	for k, v := range base {
		out[k] = v
	}
	for k, v := range extra {
		out[k] = v
	}
	return out
}

// ---------------------------------------------------------------------------
// Building blocks
// ---------------------------------------------------------------------------

const modelCall = "\ndef ask(client, messages):\n    return client.chat.completions.create(model=\"m\", messages=messages, tools=[])\n"

// A harmless agent: one read-only tool, no credentials.
var plain = map[string]string{"agent.py": "import openai\n\ndef get_weather(city):\n    return \"sunny\"\n\nTOOLS = {\"get_weather\": get_weather}\n" + modelCall}

// An agent with one sensitive, mutating tool and a registry dispatch.
const sensitiveHead = "import openai\n\ndef refund_payment(order_id, amount):\n    return \"ok\"\n\nTOOLS = {\"refund_payment\": refund_payment}\n"
const plainDispatch = "\ndef dispatch(name, args):\n    return TOOLS[name](**args)\n"

var sensitive = map[string]string{"agent.py": sensitiveHead + plainDispatch + modelCall}

// An agent with a shell tool.
var shell = map[string]string{"agent.py": "import openai, subprocess\n\ndef run_command(command):\n    return subprocess.run(command, shell=True)\n\nTOOLS = {\"run_command\": run_command}\n" + modelCall}

const fullConfig = "schema_version: \"1\"\nagent:\n  id: demo-agent\n  owner: platform-team\n  description: Demo agent\n  risk_tier: high\n  risk_rationale: Runs commands.\n"

const ciYAML = "name: ci\non:\n  pull_request:\n  push:\n    branches: [main]\njobs:\n  test:\n    runs-on: ubuntu-latest\n    steps:\n      - uses: actions/checkout@v4\n      - run: python -m pytest tests/\n"

type tc struct {
	name     string
	files    map[string]string
	cfg      string
	want     string // exact set of signals for the control, comma-joined and sorted; "" means no evidence
	finding  string // rule ID that must be present ("" for none required)
	absentFn string // rule ID that must not be present
	contains string // text that must appear in the evidence summary or limitations
}

func runCases(t *testing.T, control string, cases []tc) {
	t.Helper()
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			r := run(t, c.files, c.cfg)
			if got := r.signals(control); got != c.want {
				t.Errorf("signals for %s = %q, want %q\nevidence: %s\nfindings: %s", control, got, c.want, r.summary(control), r.rules())
			}
			if c.finding != "" && !strings.Contains(","+r.rules()+",", ","+c.finding+",") {
				t.Errorf("finding %s missing; got %s", c.finding, r.rules())
			}
			if c.absentFn != "" && strings.Contains(","+r.rules()+",", ","+c.absentFn+",") {
				t.Errorf("finding %s must not be reported", c.absentFn)
			}
			if c.contains != "" && !strings.Contains(r.summary(control), c.contains) {
				t.Errorf("evidence text for %s should contain %q; got %q", control, c.contains, r.summary(control))
			}
		})
	}
}

// ---------------------------------------------------------------------------
// Domain A
// ---------------------------------------------------------------------------

func TestAGC001OwnerInventory(t *testing.T) {
	runCases(t, "AGC-001", []tc{
		{name: "complete declaration is declared, never more", files: plain, cfg: fullConfig, want: "declared", contains: "does not prove that the owner exists"},
		{name: "undeclared tool", files: plain, cfg: fullConfig + "capabilities:\n  declared_tools: [other_tool]\n", want: "declared", finding: "AGC-001.undeclared-tool"},
		{name: "declared tool matches", files: plain, cfg: fullConfig + "capabilities:\n  declared_tools: [get_weather]\n", want: "declared", absentFn: "AGC-001.undeclared-tool"},
		{name: "incomplete declaration", files: plain, cfg: "agent:\n  id: demo-agent\n", want: "declared", finding: "AGC-001.incomplete-declaration"},
		{name: "no configuration", files: plain, want: "absent"},
		{name: "malformed configuration is an error, not a pass", files: with(plain, map[string]string{".agentgov.yaml": "agent:\n  id: [unclosed\n"}), want: "error"},
	})
}

func TestAGC002RiskTier(t *testing.T) {
	runCases(t, "AGC-002", []tc{
		{name: "declared lower than detected", files: shell, cfg: "agent:\n  id: a\n  owner: o\n  risk_tier: low\n", want: "violation", finding: "AGC-002.declared-tier-too-low"},
		{name: "declared with rationale", files: shell, cfg: fullConfig, want: "declared", contains: "written rationale", absentFn: "AGC-002.declared-tier-too-low"},
		{name: "declared without rationale", files: plain, cfg: "agent:\n  id: a\n  owner: o\n  risk_tier: medium\n", want: "declared", contains: "without a written rationale"},
		{name: "not declared", files: plain, want: "absent"},
		{name: "malformed configuration", files: with(plain, map[string]string{".agentgov.yaml": "agent: [\n"}), want: ""},
	})
}

func TestAGC003ChangeControl(t *testing.T) {
	runCases(t, "AGC-003", []tc{
		{name: "workflow runs tests on pull request", files: with(plain, map[string]string{".github/workflows/ci.yml": ciYAML}), want: "present", contains: "workflow definition only"},
		{name: "codeowners noted", files: with(plain, map[string]string{".github/workflows/ci.yml": ciYAML, "CODEOWNERS": "# owners\n/prompts/ @sec\n"}), want: "present", contains: "CODEOWNERS"},
		{name: "gitlab pipeline", files: with(plain, map[string]string{".gitlab-ci.yml": "test:\n  script:\n    - pytest -q\n"}), want: "present"},
		{name: "workflow without tests", files: with(plain, map[string]string{".github/workflows/ci.yml": "on: [push]\njobs:\n  lint:\n    steps:\n      - run: echo hello\n"}), want: "absent"},
		{name: "manual-only workflow", files: with(plain, map[string]string{".github/workflows/ci.yml": "on:\n  workflow_dispatch:\njobs:\n  t:\n    steps:\n      - run: pytest\n"}), want: "absent"},
		{name: "no workflow", files: plain, want: "absent"},
		{name: "malformed workflow is unknown", files: with(plain, map[string]string{".github/workflows/ci.yml": "on: [push\njobs:\n  - run: pytest\n bad\n"}), want: ""},
	})
}

// ---------------------------------------------------------------------------
// Domain B
// ---------------------------------------------------------------------------

func TestAGC004Identity(t *testing.T) {
	envCreds := with(plain, map[string]string{"creds.py": "import os\nKEY = os.environ[\"SERVICE_API_KEY\"]\n"})
	runCases(t, "AGC-004", []tc{
		{name: "hardcoded admin account", files: with(plain, map[string]string{"db.py": "DB_USER = \"admin\"\nDB_PASSWORD = \"Tr0ub4dor-and-3\"\n"}), want: "violation", finding: "AGC-004.hardcoded-account-credentials", contains: "administrator"},
		{name: "hardcoded email login in a call", files: with(plain, map[string]string{"db.py": "def connect(lib):\n    return lib.login(username=\"jane.doe@example.com\", password=\"correct-horse-battery\")\n"}), want: "violation", contains: "email-style"},
		{name: "host credentials mounted", files: with(plain, map[string]string{"compose.yaml": "services:\n  agent:\n    image: x:1\n    volumes:\n      - ~/.aws:/root/.aws:ro\n"}), want: "violation", finding: "AGC-004.host-credential-mount"},
		{name: "docker socket mounted", files: with(plain, map[string]string{"docker-compose.yml": "services:\n  agent:\n    image: x:1\n    volumes:\n      - /var/run/docker.sock:/var/run/docker.sock\n"}), want: "violation", finding: "AGC-004.host-credential-mount"},
		{name: "managed identity client", files: with(plain, map[string]string{"auth.py": "from azure.identity import DefaultAzureCredential\ncred = DefaultAzureCredential()\n"}), want: "present", contains: "Operational confirmation needs identity-provider evidence"},
		{name: "oidc federation in ci", files: with(plain, map[string]string{".github/workflows/deploy.yml": "on: [push]\npermissions:\n  id-token: write\njobs:\n  d:\n    steps:\n      - uses: aws-actions/configure-aws-credentials@v4\n        with:\n          role-to-assume: arn:aws:iam::123456789012:role/agent\n"}), want: "present"},
		{name: "kubernetes service account with projected token", files: with(plain, map[string]string{"k8s.yaml": "apiVersion: apps/v1\nkind: Deployment\nspec:\n  template:\n    spec:\n      serviceAccountName: agent\n      volumes:\n        - name: t\n          projected:\n            sources:\n              - serviceAccountToken:\n                  path: token\n"}), want: "present"},
		{name: "placeholders and env lookups are not accounts", files: with(envCreds, map[string]string{"db.py": "import os\nDB_USER = \"<USER>\"\nDB_PASSWORD = \"changeme\"\nuser = os.environ[\"DB_USER\"]\npassword = os.environ[\"DB_PASSWORD\"]\n"}), want: "absent"},
		{name: "credentials with no workload identity", files: envCreds, want: "absent"},
		{name: "no credentials at all", files: plain, want: ""},
		{name: "malformed manifest", files: with(plain, map[string]string{"compose.yaml": "services:\n  a:\n   volumes: [~/.aws\n"}), want: ""},
	})
}

func TestAGC005Allowlist(t *testing.T) {
	head := sensitiveHead
	runCases(t, "AGC-005", []tc{
		{name: "membership test with reject at dispatch", files: map[string]string{"agent.py": head + "ALLOWED_TOOLS = frozenset({\"refund_payment\"})\n\ndef dispatch(name, args):\n    if name not in ALLOWED_TOOLS:\n        raise PermissionError(\"tool not allowed\")\n    return TOOLS[name](**args)\n" + modelCall}, want: "present", contains: "ALLOWED_TOOLS"},
		{name: "membership test with else reject", files: map[string]string{"agent.py": head + "ALLOWED = {\"refund_payment\"}\n\ndef dispatch(tool_name, args):\n    if tool_name in ALLOWED:\n        return TOOLS[tool_name](**args)\n    else:\n        raise PermissionError(\"denied\")\n" + modelCall}, want: "present"},
		{name: "constant named ALLOWLIST alone is not enforcement", files: map[string]string{"agent.py": head + "ALLOWLIST = {\"refund_payment\"}\n" + plainDispatch + modelCall}, want: "absent"},
		{name: "membership test without a reject path", files: map[string]string{"agent.py": head + "ALLOWED_TOOLS = {\"refund_payment\"}\n\ndef dispatch(name, args):\n    if name not in ALLOWED_TOOLS:\n        print(\"hmm\")\n    result = TOOLS[name](**args)\n    result = str(result)\n    result = result.strip()\n    result = result.lower()\n    result = result.title()\n    assert result\n    use(result)\n" + modelCall}, want: "absent"},
		{name: "globals dispatch", files: map[string]string{"agent.py": head + "\ndef dispatch(name, args):\n    return globals()[name](**args)\n" + modelCall}, want: "violation", finding: "AGC-005.unrestricted-dynamic-dispatch"},
		{name: "getattr dispatch through a variable", files: map[string]string{"agent.py": "import toolbox\n" + head + "\ndef dispatch(name, args):\n    fn = getattr(toolbox, name)\n    return fn(**args)\n" + modelCall}, want: "violation", finding: "AGC-005.unrestricted-dynamic-dispatch"},
		{name: "getattr with a literal default is not a call", files: map[string]string{"agent.py": head + "\ndef dispatch(name, args):\n    limit = getattr(args, \"limit\", 5)\n    return TOOLS[name](**args)\n" + modelCall}, want: "absent"},
		{name: "unrestricted shell tool", files: shell, want: "violation", finding: "AGC-005.unrestricted-exec-tool"},
		{name: "framework tool scoping", files: map[string]string{"agent.py": head + "\ndef make(sdk):\n    return sdk.Options(allowed_tools=[\"refund_payment\"])\n" + modelCall}, want: "present"},
		{name: "mcp allowed tools", files: with(sensitive, map[string]string{".mcp.json": `{"mcpServers":{"fs":{"command":"node","args":["s.js"],"allowedTools":["read_file"]}}}`}), want: "present"},
		{name: "tools with no allowlist", files: sensitive, want: "absent"},
		{name: "broken neighbor file does not break detection", files: with(sensitive, map[string]string{"broken.py": "def x(:\n  return (\n\"\"\"\n"}), want: "absent"},
	})
}

func TestAGC006Tokens(t *testing.T) {
	runCases(t, "AGC-006", []tc{
		{name: "token valid for thirty days", files: with(plain, map[string]string{"auth.py": "import jwt, datetime\n\ndef issue_token(sub):\n    exp = datetime.datetime.utcnow() + datetime.timedelta(days=30)\n    return jwt.encode({\"sub\": sub, \"exp\": exp}, KEY)\n"}), want: "violation", finding: "AGC-006.long-lived-token"},
		{name: "expiry check disabled", files: with(plain, map[string]string{"auth.py": "import jwt\n\ndef read_token(t):\n    return jwt.decode(t, KEY, options={\"verify_exp\": False})\n"}), want: "violation"},
		{name: "js token without expiry limit", files: with(plain, map[string]string{"auth.ts": "import jwt from 'jsonwebtoken';\nexport function signToken(sub: string) {\n  return jwt.sign({ sub }, KEY, { expiresIn: '90d' });\n}\n"}), want: "violation"},
		{name: "short lived scoped token", files: with(plain, map[string]string{"auth.py": "import jwt, datetime\n\ndef issue_token(sub):\n    exp = datetime.datetime.utcnow() + datetime.timedelta(minutes=15)\n    return jwt.encode({\"sub\": sub, \"exp\": exp, \"aud\": \"tickets-api\", \"scope\": \"tickets:read\"}, KEY)\n"}), want: "present", contains: "cannot prove real token expiry"},
		{name: "short lived but no audience or scope", files: with(plain, map[string]string{"auth.py": "import jwt, datetime\n\ndef issue_token(sub):\n    exp = datetime.datetime.utcnow() + datetime.timedelta(minutes=15)\n    return jwt.encode({\"sub\": sub, \"exp\": exp}, KEY)\n"}), want: ""},
		{name: "no token code", files: plain, want: ""},
	})
}

func TestAGC007DataLayer(t *testing.T) {
	head := "import openai, sqlite3\nDB = sqlite3.connect(\":memory:\")\n"
	reg := "\nTOOLS = {\"get_order\": get_order}\n" + modelCall
	runCases(t, "AGC-007", []tc{
		{name: "identity from context in a parameterized filter", files: map[string]string{"agent.py": head + "\ndef get_order(ctx, order_id):\n    return load_order(ctx.user_id, order_id)\n\ndef load_order(user_id, order_id):\n    return DB.execute(\"SELECT id FROM orders WHERE id = ? AND owner_id = ?\", (order_id, user_id)).fetchone()\n" + reg}, want: "present", contains: "does not prove the identity is authentic"},
		{name: "sql built with an f-string", files: map[string]string{"agent.py": head + "\ndef get_order(ctx, order_id):\n    return DB.execute(f\"SELECT id FROM orders WHERE id = '{order_id}'\").fetchone()\n" + reg}, want: "violation", finding: "AGC-007.sql-built-from-arguments"},
		{name: "sql built by concatenation", files: map[string]string{"agent.py": head + "\ndef get_order(ctx, order_id):\n    q = \"SELECT id FROM orders WHERE id = \" + order_id\n    return DB.execute(q).fetchone()\n" + reg}, want: "violation", finding: "AGC-007.sql-built-from-arguments"},
		{name: "identity supplied by the model through the schema", files: map[string]string{"agent.py": head + "\ndef get_order(user_id, order_id):\n    return DB.execute(\"SELECT id FROM orders WHERE id = ? AND owner_id = ?\", (order_id, user_id)).fetchone()\n\nSCHEMA = {\"name\": \"get_order\", \"parameters\": {\"type\": \"object\", \"properties\": {\"user_id\": {\"type\": \"string\"}, \"order_id\": {\"type\": \"string\"}}}}\n" + reg}, want: "violation", finding: "AGC-007.identity-supplied-by-model"},
		{name: "identity supplied by the model through a decorator", files: map[string]string{"agent.py": "import sqlite3\nfrom agents import Agent, function_tool\nDB = sqlite3.connect(\":memory:\")\n\n@function_tool\ndef get_order(tenant_id: str, order_id: str) -> str:\n    return str(DB.execute(\"SELECT id FROM orders WHERE id = ?\", (order_id,)).fetchone())\n\nagent = Agent(name=\"a\", tools=[get_order])\n", "requirements.txt": "openai-agents==0.0.17\n"}, want: "violation", finding: "AGC-007.identity-supplied-by-model"},
		{name: "parameterized query with no identity filter", files: map[string]string{"agent.py": head + "\ndef get_order(ctx, order_id):\n    return DB.execute(\"SELECT id FROM orders WHERE id = ?\", (order_id,)).fetchone()\n" + reg}, want: "absent"},
		{name: "no data access", files: plain, want: ""},
		{name: "broken sql file next to the agent", files: map[string]string{"agent.py": head + "\ndef get_order(ctx, order_id):\n    return DB.execute(\"SELECT id FROM orders WHERE id = ?\", (order_id,)).fetchone()\n" + reg, "broken.py": "def q(:\n    DB.execute(f\"SELECT {\n"}, want: "absent"},
	})
}

func TestAGC008Secrets(t *testing.T) {
	// Fake values in the shape of real secrets. They are test inputs only.
	const openaiKey = "sk-" + "TESTONLYnotAKeyTESTONLYnotAKey1234"
	const awsKey = "AKIA" + "TESTONLY0NOTREAL"
	const slack = "xoxb-" + "000000000000-TESTONLYNOTREAL"
	const password = "q8Zr-Lm2v_Xt7Kp9w-Bn4"
	cases := []struct {
		name   string
		files  map[string]string
		want   string
		secret string
		kind   string
	}{
		{"openai style key", with(plain, map[string]string{"cfg.py": "OPENAI_API_KEY = \"" + openaiKey + "\"\n"}), "violation", openaiKey, "OpenAI-style API key"},
		{"anthropic style key in a dict", with(plain, map[string]string{"cfg.py": "CONFIG = {\"anthropic\": \"sk-ant-" + "TESTONLYnotAKeyTESTONLY0000" + "\"}\n"}), "violation", "TESTONLYnotAKeyTESTONLY0000", "Anthropic-style API key"},
		{"aws access key id", with(plain, map[string]string{"cfg.py": "aws_access_key_id = \"" + awsKey + "\"\n"}), "violation", awsKey, "AWS access key ID"},
		{"slack token in yaml", with(plain, map[string]string{"deploy/values.yaml": "slack:\n  botToken: " + slack + "\n"}), "violation", slack, "Slack token"},
		{"private key header", with(plain, map[string]string{"cfg.py": "PEM = \"\"\"-----BEGIN RSA PRIVATE KEY-----\nTESTONLYTESTONLY\n-----END RSA PRIVATE KEY-----\"\"\"\n"}), "violation", "TESTONLYTESTONLY", "private key"},
		{"generic high entropy password", with(plain, map[string]string{"cfg.py": "db_password = \"" + password + "\"\n"}), "violation", password, "db_password"},
		{"secret in a keyword argument", with(plain, map[string]string{"cfg.py": "def connect(lib):\n    return lib.connect(host=\"db\", api_key=\"" + password + "\")\n"}), "violation", password, "api_key"},
		{"secret in a dockerfile", with(plain, map[string]string{"Dockerfile": "FROM python:3.12\nUSER 1000\nENV SERVICE_TOKEN=" + password + "\n"}), "violation", password, "SERVICE_TOKEN"},
		{"js secret", with(plain, map[string]string{"cfg.ts": "export const config = { clientSecret: '" + password + "' };\n"}), "violation", password, "clientSecret"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			r := run(t, c.files, "")
			if got := r.signals("AGC-008"); got != c.want {
				t.Fatalf("signals = %q, want %q (%s)", got, c.want, r.summary("AGC-008"))
			}
			if !strings.Contains(","+r.rules()+",", ",AGC-008.hardcoded-secret,") {
				t.Fatalf("finding missing: %s", r.rules())
			}
			if !strings.Contains(r.summary("AGC-008"), c.kind) {
				t.Errorf("summary should name the type %q: %s", c.kind, r.summary("AGC-008"))
			}
			blob, _ := json.Marshal(struct {
				E []model.Evidence
				F []model.Finding
			}{r.evidence, r.findings})
			if strings.Contains(string(blob), c.secret) {
				t.Fatalf("the secret value appears in the output")
			}
		})
	}
	notSecrets := "import os\n" +
		"password = \"changeme\"\napi_key = \"your-key-here\"\nTOKEN = \"<TOKEN>\"\nsecret = \"xxxxxxxxxxxxxxxx\"\n" +
		"API_KEY = os.environ[\"SERVICE_API_KEY\"]\napi_token = os.getenv(\"API_TOKEN\", \"\")\n" +
		"FAKE_API_KEY = \"" + password + "\"\nexample_password = \"" + password + "\"\n" +
		"token_url = \"https://auth.example.com/oauth/token\"\nsecret_name = \"prod/agent/" + password + "\"\n" +
		"max_tokens = \"" + password + "\"\npassword_field = f\"{prefix}-" + password + "\"\n" +
		"OPENAI_API_KEY = \"sk-xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx\"\n" +
		"# password = \"" + password + "\"\n\"\"\"api_key = \"" + password + "\" in a docstring\"\"\"\n" +
		"description = \"" + password + "\"\n"
	runCases(t, "AGC-008", []tc{
		{name: "placeholders, env lookups, fakes, comments", files: with(plain, map[string]string{"cfg.py": notSecrets}), want: "absent", absentFn: "AGC-008.hardcoded-secret"},
		{name: "secret in a test file is not flagged", files: with(plain, map[string]string{"tests/test_auth.py": "API_KEY = \"" + openaiKey + "\"\n", "cfg.py": "import os\nK = os.environ[\"API_KEY\"]\n"}), want: "absent"},
		{name: "vault client", files: with(plain, map[string]string{"sec.py": "import hvac\n\ndef load():\n    return hvac.Client().secrets.kv.read_secret_version(path=\"agent\")\n"}), want: "present", contains: "does not prove every secret is protected"},
		{name: "aws secrets manager", files: with(plain, map[string]string{"sec.py": "import boto3\n\ndef load():\n    return boto3.client(\"secretsmanager\").get_secret_value(SecretId=\"agent\")\n"}), want: "present"},
		{name: "kubernetes secret reference", files: with(plain, map[string]string{"k8s.yaml": "apiVersion: v1\nkind: Pod\nspec:\n  containers:\n    - name: a\n      env:\n        - name: KEY\n          valueFrom:\n            secretKeyRef:\n              name: agent\n              key: api-key\n"}), want: "present"},
		{name: "ci secret context", files: with(plain, map[string]string{".github/workflows/ci.yml": "on: [push]\njobs:\n  t:\n    steps:\n      - run: pytest\n        env:\n          API_KEY: ${{ secrets.API_KEY }}\n"}), want: "present"},
		{name: "local helper named get_secret is not a vault", files: with(plain, map[string]string{"sec.py": "import os\n\ndef get_secret(name):\n    return os.environ[name]\n\nK = get_secret(\"X\")\n"}), want: "absent"},
		{name: "no credentials at all", files: plain, want: ""},
		{name: "malformed yaml next to a real secret", files: with(plain, map[string]string{"cfg.py": "OPENAI_API_KEY = \"" + openaiKey + "\"\n", "values.yaml": "a: [1,\n b\n"}), want: "violation"},
	})
}

func TestSecretFingerprintIsStableAndValueFree(t *testing.T) {
	const a = "sk-" + "TESTONLYnotAKeyTESTONLYnotAKey1234"
	const b = "sk-" + "TESTONLYotherKeyTESTONLYotherKey99"
	fp := func(src string) string {
		r := run(t, with(plain, map[string]string{"cfg.py": src}), "")
		for _, f := range r.findings {
			if f.RuleID == "AGC-008.hardcoded-secret" {
				if f.FindingID != "F-"+f.Fingerprint[:12] || len(f.Fingerprint) != 64 {
					t.Errorf("finding ID must derive from the fingerprint: %s %s", f.FindingID, f.Fingerprint)
				}
				return f.Fingerprint
			}
		}
		t.Fatal("no secret finding")
		return ""
	}
	base := fp("OPENAI_API_KEY = \"" + a + "\"\n")
	if fp("OPENAI_API_KEY = \""+b+"\"\n") != base {
		t.Error("the fingerprint must not depend on the secret value")
	}
	if fp("# moved down\n\n\nOPENAI_API_KEY = \""+a+"\"\n") != base {
		t.Error("the fingerprint must survive a line shift")
	}
	if fp("OTHER_API_KEY = \""+a+"\"\n") == base {
		t.Error("a different variable is a different finding")
	}
}

// ---------------------------------------------------------------------------
// Domain C
// ---------------------------------------------------------------------------

const policyModule = "class Decision:\n    def __init__(self, allowed, reason):\n        self.allowed = allowed\n        self.reason = reason\n\ndef _rules(name, args):\n    return Decision(name == \"refund_payment\" and args.get(\"amount\", 0) < 100, \"rule\")\n\ndef decide(name, args):\n    try:\n        return _rules(name, args)\n    except Exception:\n        return Decision(False, \"policy error\")\n"

func TestAGC009PolicyEngine(t *testing.T) {
	guarded := "from policy import decide\n" + sensitiveHead + "\ndef dispatch(name, args):\n    decision = decide(name, args)\n    if not decision.allowed:\n        raise PermissionError(decision.reason)\n    return TOOLS[name](**args)\n" + modelCall
	failOpen := "from policy import decide\n" + sensitiveHead + "\ndef dispatch(name, args):\n    try:\n        decision = decide(name, args)\n        if not decision.allowed:\n            raise PermissionError(decision.reason)\n    except Exception:\n        pass\n    return TOOLS[name](**args)\n" + modelCall
	unchecked := "from policy import decide\n" + sensitiveHead + "\ndef dispatch(name, args):\n    decide(name, args)\n    return TOOLS[name](**args)\n" + modelCall
	prompt := sensitiveHead + "SYSTEM_PROMPT = \"You are a careful agent. You must never refund more than 100 without approval.\"\n" + plainDispatch + modelCall
	runCases(t, "AGC-009", []tc{
		{name: "local policy module with default deny", files: map[string]string{"agent.py": guarded, "policy.py": policyModule}, want: "present", contains: "An error in the policy check leads to a denial"},
		{name: "fail open on policy error", files: map[string]string{"agent.py": failOpen, "policy.py": policyModule}, want: "violation", finding: "AGC-009.policy-fail-open"},
		{name: "decision never checked", files: map[string]string{"agent.py": unchecked, "policy.py": strings.Replace(policyModule, "try:\n        return _rules(name, args)\n    except Exception:\n        return Decision(False, \"policy error\")", "return _rules(name, args)", 1)}, want: "absent"},
		{name: "opa decision endpoint", files: with(sensitive, map[string]string{"authz.py": "import requests\n\ndef allowed(inp):\n    return requests.post(\"http://opa:8181/v1/data/agent/allow\", json={\"input\": inp}).json()[\"result\"]\n"}), want: "present"},
		{name: "prompt text is not a policy engine", files: map[string]string{"agent.py": prompt}, want: "absent", contains: "system-prompt instruction is not a policy engine"},
		{name: "sensitive actions with no enforcement", files: sensitive, want: "absent", contains: "no policy enforcement point"},
		{name: "no sensitive actions", files: plain, want: ""},
		{name: "opa url only in a comment", files: with(sensitive, map[string]string{"notes.py": "# requests.post(\"http://opa:8181/v1/data/agent/allow\")\nX = 1\n"}), want: "absent"},
	})
}

func TestAGC010ApprovalGate(t *testing.T) {
	bound := "import openai, hmac, hashlib, time, os\nKEY = os.environ[\"APPROVAL_KEY\"].encode()\n\n" +
		"def verify_approval(token, action, digest):\n    expected = hmac.new(KEY, (token.action + token.digest + str(token.expires_at)).encode(), hashlib.sha256).hexdigest()\n" +
		"    if not hmac.compare_digest(expected, token.signature):\n        raise PermissionError(\"approval is not valid\")\n" +
		"    if token.action != action or token.digest != digest:\n        raise PermissionError(\"approval is for another action\")\n" +
		"    if time.time() > token.expires_at:\n        raise PermissionError(\"approval expired\")\n\n" +
		"def refund_payment(order_id, amount, approval=None):\n    verify_approval(approval, \"refund_payment\", str(amount))\n    return \"ok\"\n\nTOOLS = {\"refund_payment\": refund_payment}\n" + plainDispatch + modelCall
	named := "import openai\n\ndef approve(action):\n    return True\n\ndef refund_payment(order_id, amount):\n    if approve(\"refund\"):\n        return \"ok\"\n\nTOOLS = {\"refund_payment\": refund_payment}\n" + plainDispatch + modelCall
	auto := strings.Replace(sensitive["agent.py"], "def refund_payment(order_id, amount):", "def refund_payment(order_id, amount, auto_approve=True):", 1)
	flag := sensitive["agent.py"] + "\nSKIP_APPROVAL = True\n"
	requireOff := strings.Replace(sensitive["agent.py"], "def refund_payment(order_id, amount):", "def refund_payment(order_id, amount, require_approval=False):", 1)
	langgraph := "from langchain_core.tools import tool\nfrom langgraph.prebuilt import create_react_agent\n\n@tool\ndef refund_payment(order_id: str) -> str:\n    \"\"\"Refund.\"\"\"\n    return \"ok\"\n\nagent = create_react_agent(None, tools=[refund_payment], interrupt_before=[\"tools\"])\n"
	langgraphOff := strings.Replace(langgraph, "interrupt_before=[\"tools\"]", "interrupt_before=[]", 1)
	crew := "from crewai import Agent, Task, Crew\nfrom crewai.tools import tool\n\n@tool\ndef send_wire(amount: str) -> str:\n    \"\"\"Wire.\"\"\"\n    return \"ok\"\n\na = Agent(role=\"x\", tools=[send_wire])\nt = Task(description=\"d\", agent=a, human_input=True)\nc = Crew(agents=[a], tasks=[t])\n"
	runCases(t, "AGC-010", []tc{
		{name: "approval bound to action, digest, and expiry", files: map[string]string{"agent.py": bound}, want: "present", contains: "Binding and replay protection need a test to confirm"},
		{name: "a function named approve is not evidence", files: map[string]string{"agent.py": named}, want: "absent", contains: "only named approve is not counted"},
		{name: "auto approve default", files: map[string]string{"agent.py": auto}, want: "violation", finding: "AGC-010.auto-approve"},
		{name: "skip approval flag", files: map[string]string{"agent.py": flag}, want: "violation", finding: "AGC-010.auto-approve"},
		{name: "approval requirement off by default", files: map[string]string{"agent.py": requireOff}, want: "violation", finding: "AGC-010.auto-approve"},
		{name: "langgraph interrupt", files: map[string]string{"agent.py": langgraph, "requirements.txt": "langgraph==0.2.60\n"}, want: "present"},
		{name: "langgraph interrupt list empty", files: map[string]string{"agent.py": langgraphOff, "requirements.txt": "langgraph==0.2.60\n"}, want: "absent"},
		{name: "crewai human input", files: map[string]string{"agent.py": crew}, want: "present"},
		{name: "sensitive tool with no gate", files: sensitive, want: "absent"},
		{name: "no sensitive tools", files: plain, want: ""},
	})
}

func TestAGC011Guardrails(t *testing.T) {
	guard := sensitiveHead + "\ndef validate_tool_arguments(args):\n    if not isinstance(args, dict):\n        raise ValueError(\"bad arguments\")\n    return args\n\ndef dispatch(name, args):\n    return TOOLS[name](**validate_tool_arguments(args))\n" + modelCall
	unused := sensitiveHead + "\ndef validate_tool_arguments(args):\n    raise ValueError(\"never called\")\n" + plainDispatch + modelCall
	inject := sensitive["agent.py"] + "\ndef build(retrieved_docs):\n    system_prompt = f\"You are helpful. Context: {retrieved_docs}\"\n    return system_prompt\n"
	userMsg := sensitive["agent.py"] + "\ndef build(retrieved_docs):\n    user_message = f\"Context: {retrieved_docs}\"\n    return user_message\n"
	runCases(t, "AGC-011", []tc{
		{name: "validation function on the path", files: map[string]string{"agent.py": guard}, want: "present", contains: "Guardrail existence does not guarantee protection"},
		{name: "structured output", files: map[string]string{"agent.py": sensitive["agent.py"] + "\ndef make(sdk, Out):\n    return sdk.Agent(name=\"a\", output_type=Out, input_guardrails=[check])\n"}, want: "present", contains: "input guardrail"},
		{name: "validation function that is never called", files: map[string]string{"agent.py": unused}, want: "absent"},
		{name: "retrieved content in the system prompt", files: map[string]string{"agent.py": inject}, want: "violation", finding: "AGC-011.untrusted-content-in-system-prompt"},
		{name: "retrieved content in a user message is fine", files: map[string]string{"agent.py": userMsg}, want: "absent", absentFn: "AGC-011.untrusted-content-in-system-prompt"},
		{name: "nothing", files: sensitive, want: "absent"},
	})
}

func TestAGC012Limits(t *testing.T) {
	loop := func(body string) map[string]string {
		return map[string]string{"agent.py": sensitive["agent.py"] + "\ndef run(client, messages):\n" + body}
	}
	runCases(t, "AGC-012", []tc{
		{name: "unbounded while true", files: loop("    while True:\n        reply = ask(client, messages)\n        if reply.done:\n            return reply\n        dispatch(reply.name, reply.args)\n"), want: "violation", finding: "AGC-012.unbounded-loop"},
		{name: "bounded for loop", files: loop("    for step in range(MAX_STEPS):\n        reply = ask(client, messages)\n        dispatch(reply.name, reply.args)\n    raise RuntimeError(\"step limit\")\n"), want: "present", contains: "step limit"},
		{name: "while true with a step counter", files: loop("    steps = 0\n    while True:\n        steps += 1\n        if steps > 10:\n            raise RuntimeError(\"too many steps\")\n        dispatch(ask(client, messages).name, {})\n"), want: "present", absentFn: "AGC-012.unbounded-loop"},
		{name: "while true with a deadline", files: loop("    import time\n    deadline = time.monotonic() + 30\n    while True:\n        if time.monotonic() > deadline:\n            break\n        dispatch(ask(client, messages).name, {})\n"), want: "present", contains: "time limit"},
		{name: "framework limit argument", files: map[string]string{"agent.py": sensitive["agent.py"] + "\ndef make(sdk):\n    return sdk.AgentExecutor(agent=None, tools=[], max_iterations=5, max_execution_time=30)\n"}, want: "present"},
		{name: "limit set to none does not count", files: map[string]string{"agent.py": sensitive["agent.py"] + "\ndef make(sdk):\n    return sdk.AgentExecutor(agent=None, tools=[], max_iterations=None)\n"}, want: "absent"},
		{name: "no limits", files: sensitive, want: "absent"},
	})
}

func TestAGC013Sandbox(t *testing.T) {
	hardened := "services:\n  agent:\n    build: .\n    user: \"10001:10001\"\n    read_only: true\n    cap_drop:\n      - ALL\n    security_opt:\n      - no-new-privileges:true\n    mem_limit: 256m\n"
	k8s := "apiVersion: apps/v1\nkind: Deployment\nspec:\n  template:\n    spec:\n      containers:\n        - name: a\n          image: x:1\n          securityContext:\n            runAsNonRoot: true\n            readOnlyRootFilesystem: true\n            allowPrivilegeEscalation: false\n"
	runCases(t, "AGC-013", []tc{
		{name: "hardened compose", files: with(shell, map[string]string{"Dockerfile": "FROM python:3.12\nUSER 10001\n", "compose.yaml": hardened}), want: "present", contains: "not automatically an adequate sandbox"},
		{name: "hardened kubernetes", files: with(shell, map[string]string{"deploy.yaml": k8s}), want: "present", contains: "No CPU, memory, or process limits"},
		{name: "privileged container", files: with(shell, map[string]string{"compose.yaml": hardened + "    privileged: true\n"}), want: "violation", finding: "AGC-013.privileged-container"},
		{name: "docker socket", files: with(plain, map[string]string{"compose.yaml": hardened + "    volumes:\n      - /var/run/docker.sock:/var/run/docker.sock\n"}), want: "violation", finding: "AGC-013.privileged-container"},
		{name: "root image with exec tools", files: with(shell, map[string]string{"Dockerfile": "FROM python:3.12\nCMD [\"python\"]\n"}), want: "violation", finding: "AGC-013.root-container-with-exec-tools"},
		{name: "root image without exec tools", files: with(plain, map[string]string{"Dockerfile": "FROM python:3.12\nUSER root\n"}), want: "absent", contains: "non-root user"},
		{name: "exec tool and no sandbox", files: shell, want: "absent", contains: "no container or sandbox configuration"},
		{name: "no exec and no container", files: plain, want: ""},
		{name: "malformed compose with exec tool", files: with(shell, map[string]string{"compose.yaml": "services:\n  a:\n   read_only: [true\n"}), want: "absent"},
	})
}

// ---------------------------------------------------------------------------
// Domain D
// ---------------------------------------------------------------------------

func TestAGC014SupplyChain(t *testing.T) {
	runCases(t, "AGC-014", []tc{
		{name: "pinned requirements", files: with(plain, map[string]string{"requirements.txt": "openai==1.58.1\n"}), want: "present", contains: "does not show that the version is trustworthy"},
		{name: "unpinned requirements", files: with(plain, map[string]string{"requirements.txt": "openai\nrequests>=2\n"}), want: "violation", finding: "AGC-014.unpinned-dependencies", contains: "Unversioned is not the same as known malicious"},
		{name: "unpinned with a lockfile", files: with(plain, map[string]string{"pyproject.toml": "[project]\ndependencies = [\"openai>=1\"]\n", "uv.lock": "version = 1\n"}), want: "present"},
		{name: "latest image", files: with(plain, map[string]string{"Dockerfile": "FROM python:latest\nUSER 1000\n"}), want: "violation", finding: "AGC-014.unpinned-image"},
		{name: "untagged image", files: with(plain, map[string]string{"Dockerfile": "FROM node\nUSER 1000\n"}), want: "violation", finding: "AGC-014.unpinned-image"},
		{name: "digest pinned image and build stage", files: with(plain, map[string]string{"Dockerfile": "FROM python:3.12@sha256:" + strings.Repeat("a", 64) + " AS build\nFROM build\nUSER 1000\n"}), want: "present", contains: "pinned by digest"},
		{name: "unpinned mcp server", files: with(plain, map[string]string{".mcp.json": `{"mcpServers":{"fs":{"command":"npx","args":["-y","some-server"]}}}`}), want: "violation", finding: "AGC-014.unpinned-mcp-server"},
		{name: "pinned mcp server", files: with(plain, map[string]string{".mcp.json": `{"mcpServers":{"fs":{"command":"npx","args":["-y","some-server@1.2.3"]}}}`}), want: "present"},
		{name: "third-party action by tag", files: with(plain, map[string]string{".github/workflows/ci.yml": "on: [push]\njobs:\n  t:\n    steps:\n      - uses: actions/checkout@v4\n      - uses: someone/deploy-action@v1\n"}), want: "violation", finding: "AGC-014.unpinned-ci-action"},
		{name: "third-party action by sha", files: with(plain, map[string]string{"requirements.txt": "openai==1.58.1\n", ".github/workflows/ci.yml": "on: [push]\njobs:\n  t:\n    steps:\n      - uses: someone/deploy-action@" + strings.Repeat("a", 40) + "\n"}), want: "present", absentFn: "AGC-014.unpinned-ci-action"},
		{name: "nothing to assess", files: plain, want: ""},
		{name: "malformed manifest is never a pass", files: with(plain, map[string]string{"requirements.txt": "openai==1.58.1\n", "pyproject.toml": "[project\ndependencies = [\n"}), want: ""},
		{name: "malformed mcp config is never a pass", files: with(plain, map[string]string{"requirements.txt": "openai==1.58.1\n", ".mcp.json": `{"mcpServers": {`}), want: ""},
	})
}

func TestAGC015Memory(t *testing.T) {
	good := "class MemoryStore:\n    def __init__(self):\n        self.data = {}\n\n    def save_memory(self, user_id, key, value):\n        if len(value) > 500:\n            raise ValueError(\"too long\")\n        self.data.setdefault(user_id, {})[key] = value\n"
	shared := "MEMORY = []\n\ndef save_memory(content):\n    MEMORY.append(content)\n"
	nsOnly := "DATA = {}\n\ndef save_memory(user_id, text):\n    DATA.setdefault(user_id, []).append(text)\n"
	runCases(t, "AGC-015", []tc{
		{name: "namespaced and validated", files: with(plain, map[string]string{"memory.py": good}), want: "present", contains: "keyed by \"user_id\""},
		{name: "raw write to shared memory", files: with(plain, map[string]string{"memory.py": shared}), want: "violation", finding: "AGC-015.shared-memory-write"},
		{name: "namespaced but not validated", files: with(plain, map[string]string{"memory.py": nsOnly}), want: "absent"},
		{name: "no memory", files: plain, want: ""},
	})
}

func TestAGC016InterAgent(t *testing.T) {
	multi := "from agents import Agent, Runner\n\na = Agent(name=\"a\")\nb = Agent(name=\"b\", handoffs=[a])\n"
	signed := "import hmac, hashlib\n\ndef receive_message(envelope, key):\n    expected = hmac.new(key, envelope.body, hashlib.sha256).hexdigest()\n    if not hmac.compare_digest(expected, envelope.signature):\n        raise PermissionError(\"bad signature\")\n    return envelope.body\n"
	req := map[string]string{"requirements.txt": "openai-agents==0.0.17\n"}
	runCases(t, "AGC-016", []tc{
		{name: "signed messages verified on receipt", files: with(req, map[string]string{"main.py": multi, "bus.py": signed}), want: "present"},
		{name: "plain message passing", files: with(req, map[string]string{"main.py": multi}), want: "absent", contains: "Plain message passing does not satisfy this control"},
		{name: "hmac in unrelated code does not count", files: with(req, map[string]string{"main.py": multi, "util.py": "import hmac\n\ndef etag(key, body):\n    return hmac.new(key, body, \"sha256\").hexdigest()\n"}), want: "absent"},
		{name: "single agent", files: plain, want: ""},
	})
}

// ---------------------------------------------------------------------------
// Domain E
// ---------------------------------------------------------------------------

func TestAGC017KillSwitch(t *testing.T) {
	loop := func(pre, check string) map[string]string {
		return map[string]string{"agent.py": sensitive["agent.py"] + pre + "\ndef run(client, messages):\n    while True:\n" + check + "        reply = ask(client, messages)\n        dispatch(reply.name, reply.args)\n"}
	}
	runCases(t, "AGC-017", []tc{
		{name: "external file checked every step", files: loop("import os\n\ndef should_stop():\n    return os.path.exists(\"/var/run/agent/KILL\")\n", "        if should_stop():\n            break\n"), want: "present", contains: "does not prove the agent stops in time"},
		{name: "inline external check", files: loop("import os\n", "        if os.path.exists(KILL_FILE):\n            break\n"), want: "present"},
		{name: "check through a store two hops away", files: loop("\nclass Flags:\n    def read_flag(self):\n        return self.redis.get(\"agent:stop\")\n\ndef kill_requested(flags):\n    return flags.read_flag() == b\"1\"\n", "        if kill_requested(FLAGS):\n            return None\n"), want: "present"},
		{name: "module boolean never re-read", files: loop("\nKILL_SWITCH = False\n", "        if KILL_SWITCH:\n            break\n"), want: "declared", finding: "AGC-017.kill-flag-not-external", contains: "does not prove termination"},
		{name: "local function that only reads a constant", files: loop("\nSTOP_REQUESTED = False\n\ndef should_stop():\n    return STOP_REQUESTED\n", "        if should_stop():\n            break\n"), want: "declared", finding: "AGC-017.kill-flag-not-external"},
		{name: "loop with no check", files: loop("", ""), want: "absent", contains: "no stop signal check"},
		{name: "framework managed loop", files: map[string]string{"agent.py": "from langgraph.prebuilt import create_react_agent\nagent = create_react_agent(None, tools=[])\n"}, want: "absent", contains: "managed by a framework"},
	})
}

func TestAGC018Reversible(t *testing.T) {
	runCases(t, "AGC-018", []tc{
		{name: "idempotency key", files: map[string]string{"agent.py": strings.Replace(sensitive["agent.py"], "def refund_payment(order_id, amount):", "def refund_payment(order_id, amount, idempotency_key):", 1)}, want: "present", contains: "idempotency keys"},
		{name: "transaction with rollback", files: with(sensitive, map[string]string{"db.py": "def write(conn, v):\n    try:\n        conn.execute(\"INSERT INTO t VALUES (?)\", (v,))\n        conn.commit()\n    except Exception:\n        conn.rollback()\n        raise\n"}), want: "present", contains: "transactions with rollback"},
		{name: "compensation handler", files: with(sensitive, map[string]string{"undo.py": "def compensate_refund(order_id):\n    return \"reversed\"\n"}), want: "present", contains: "compensation handler"},
		{name: "mutating tool with nothing", files: sensitive, want: "absent"},
		{name: "idempotency only in a comment", files: with(sensitive, map[string]string{"n.py": "# TODO add idempotency_key and rollback()\nX = 1\n"}), want: "absent"},
		{name: "no mutating tools", files: plain, want: ""},
	})
}

func TestAGC019Runbook(t *testing.T) {
	full := "# Incident runbook\n## Owner\nteam\n## Escalation\npage\n## Containment\nkill switch\n## Revocation\nrevoke tokens\n## Recovery\nrestore\n"
	runCases(t, "AGC-019", []tc{
		{name: "runbook with the expected sections", files: with(plain, map[string]string{"docs/runbooks/incident.md": full}), want: "declared", contains: "File presence is weak evidence; attach exercise results"},
		{name: "top-level incident file", files: with(plain, map[string]string{"INCIDENT_RESPONSE.md": full}), want: "declared"},
		{name: "runbook missing sections", files: with(plain, map[string]string{"RUNBOOK.md": "# Runbook\nCall the owner.\n"}), want: "absent", contains: "escalation, containment, revocation, recovery"},
		{name: "readme mentioning a runbook", files: with(plain, map[string]string{"README.md": full}), want: "absent"},
		{name: "no runbook", files: plain, want: "absent"},
	})
}

// ---------------------------------------------------------------------------
// Domain F
// ---------------------------------------------------------------------------

const denialTest = "import unittest\nfrom agent import dispatch\n\nclass GovernanceTest(unittest.TestCase):\n    def test_unlisted_tool_is_denied(self):\n        with self.assertRaises(PermissionError):\n            dispatch(\"delete_everything\", {})\n"

func TestAGC020RegressionEvals(t *testing.T) {
	runCases(t, "AGC-020", []tc{
		{name: "denial tests and a ci job", files: with(sensitive, map[string]string{"tests/governance/test_tools.py": denialTest, ".github/workflows/ci.yml": ciYAML}), cfg: fullConfig + "verification:\n  tests_path: tests/governance\n", want: "present", contains: "did not run these tests"},
		{name: "denial tests without ci", files: with(sensitive, map[string]string{"tests/governance/test_tools.py": denialTest}), want: "absent", contains: "no CI job"},
		{name: "a bare tests directory proves nothing", files: with(sensitive, map[string]string{"tests/test_smoke.py": "def test_import():\n    import agent\n    assert agent\n", ".github/workflows/ci.yml": ciYAML}), want: ""},
		{name: "no tests", files: sensitive, want: "absent"},
		{name: "broken test file", files: with(sensitive, map[string]string{"tests/test_x.py": "def test_(:\n  assert (\n"}), want: ""},
	})
}

func TestAGC021RedTeam(t *testing.T) {
	runCases(t, "AGC-021", []tc{
		{name: "promptfoo red team config", files: with(plain, map[string]string{"promptfooconfig.yaml": "targets:\n  - id: agent\nredteam:\n  plugins:\n    - prompt-injection\n"}), want: "present", contains: "did not run the adversarial scenarios"},
		{name: "injection tests with assertions", files: with(plain, map[string]string{"tests/test_prompt_injection.py": "def test_injected_instruction_is_ignored():\n    assert run(\"ignore previous instructions\") == \"refused\"\n"}), want: "present"},
		{name: "garak dependency", files: with(plain, map[string]string{"requirements-dev.txt": "garak==0.10.0\n"}), want: "present", contains: "dependency alone"},
		{name: "promptfoo config without red team", files: with(plain, map[string]string{"promptfooconfig.yaml": "targets:\n  - id: agent\ntests:\n  - vars: {q: hi}\n"}), want: "absent"},
		{name: "nothing", files: plain, want: "absent"},
	})
}

func TestAGC022Tracing(t *testing.T) {
	otel := "from opentelemetry import trace\ntracer = trace.get_tracer(__name__)\n\ndef traced_dispatch(name, args):\n    with tracer.start_as_current_span(\"tool\") as span:\n        span.set_attribute(\"tool.name\", name)\n        return dispatch(name, args)\n"
	structured := "import json\n\ndef record_step(sink, run_id, step, tool_name):\n    sink.write(json.dumps({\"run_id\": run_id, \"step\": step, \"tool\": tool_name}) + \"\\n\")\n"
	runCases(t, "AGC-022", []tc{
		{name: "opentelemetry spans", files: with(sensitive, map[string]string{"tracing.py": otel}), want: "present", contains: "needs a synthetic end-to-end run"},
		{name: "structured step record", files: with(sensitive, map[string]string{"tracing.py": structured}), want: "present", contains: "record_step"},
		{name: "tracing import without use", files: with(sensitive, map[string]string{"tracing.py": "import opentelemetry\n"}), want: "absent"},
		{name: "raw prompt printed", files: with(sensitive, map[string]string{"log.py": "def show(prompt):\n    print(prompt)\n"}), want: "violation", finding: "AGC-022.raw-sensitive-logging"},
		{name: "credential in a log line", files: with(sensitive, map[string]string{"log.py": "import logging\nlogger = logging.getLogger(__name__)\n\ndef show(api_key):\n    logger.info(f\"calling with {api_key}\")\n"}), want: "violation", finding: "AGC-022.credential-logging"},
		{name: "js console log of messages", files: with(sensitive, map[string]string{"log.ts": "export function show(messages: unknown[]) {\n  console.log('sending', messages);\n}\n"}), want: "violation", finding: "AGC-022.raw-sensitive-logging"},
		{name: "the word prompt inside a string is not a leak", files: with(sensitive, map[string]string{"log.py": "def show(n):\n    print(\"prompt and api_key are never logged\", n)\n"}), want: "absent"},
		{name: "length and redacted values are fine", files: with(sensitive, map[string]string{"log.py": "def show(prompt, token):\n    print(len(prompt))\n    print(redact(token))\n"}), want: "absent"},
		{name: "nothing", files: sensitive, want: "absent"},
	})
}

func TestAGC023AuditTrail(t *testing.T) {
	chain := "import hashlib, json\n\nclass AuditLog:\n    def __init__(self, f):\n        self.f = f\n        self.last_hash = \"0\" * 64\n\n    def append(self, event):\n        body = {\"event\": event, \"prev_hash\": self.last_hash}\n        digest = hashlib.sha256(json.dumps(body, sort_keys=True).encode()).hexdigest()\n        self.f.write(json.dumps(dict(body, hash=digest)) + \"\\n\")\n        self.last_hash = digest\n"
	runCases(t, "AGC-023", []tc{
		{name: "hash chained log", files: with(plain, map[string]string{"audit.py": chain}), want: "present", contains: "hash of the previous record"},
		{name: "object lock storage", files: with(plain, map[string]string{"infra/bucket.yaml": "Resources:\n  AuditLogBucket:\n    Type: AWS::S3::Bucket\n    Properties:\n      ObjectLockEnabled: true\n"}), want: "present", contains: "object lock"},
		{name: "plain logging only", files: with(plain, map[string]string{"log.py": "import logging\nlogger = logging.getLogger(\"audit\")\n\ndef audit(event):\n    logger.info(\"event %s\", event)\n"}), want: "absent", contains: "Plain application logs are not tamper-evident"},
		{name: "hashing unrelated to a chain", files: with(plain, map[string]string{"audit.py": "import hashlib\n\ndef audit_id(event):\n    return hashlib.sha256(event.encode()).hexdigest()\n"}), want: "absent"},
		{name: "nothing", files: plain, want: "absent"},
	})
}

func TestAGC024Monitoring(t *testing.T) {
	rules := func(expr string) string {
		return "groups:\n  - name: service\n    rules:\n      - alert: HighErrorRate\n        expr: " + expr + "\n"
	}
	runCases(t, "AGC-024", []tc{
		{name: "prometheus rules on agent signals", files: with(plain, map[string]string{"monitoring/alerts.yaml": rules("rate(agent_policy_denied_total[5m]) > 0.2")}), want: "present", contains: "Static rules are not a passing runtime assessment"},
		{name: "cloudwatch alarm on tool errors", files: with(plain, map[string]string{"infra/alarms.yaml": "Resources:\n  ToolErrors:\n    Type: AWS::CloudWatch::Alarm\n    Properties:\n      MetricName: AgentToolErrors\n"}), want: "present"},
		{name: "rules that ignore the agent", files: with(plain, map[string]string{"monitoring/alerts.yaml": rules("rate(http_requests_5xx[5m]) > 1")}), want: "absent", contains: "none refers to agent signals"},
		{name: "no rules", files: plain, want: "absent"},
		{name: "malformed rules file", files: with(plain, map[string]string{"monitoring/alerts.yaml": "groups:\n  - rules: [\n"}), want: "absent"},
	})
}

// ---------------------------------------------------------------------------
// Cross-cutting properties
// ---------------------------------------------------------------------------

type panicking struct{}

func (panicking) ID() string        { return "AGC-099.boom" }
func (panicking) ControlID() string { return "AGC-099" }
func (panicking) Run(context.Context, *Context) ([]model.Evidence, []model.Finding) {
	var m map[string]int
	m["x"] = 1 // nil map write panics
	return nil, nil
}

func TestDetectorPanicBecomesErrorEvidence(t *testing.T) {
	root := t.TempDir()
	os.WriteFile(filepath.Join(root, "agent.py"), []byte(plain["agent.py"]), 0o644)
	inv, _ := discovery.Walk(context.Background(), discovery.Options{Root: root})
	repo := adapters.Analyze(context.Background(), inv)
	disc := adapters.Discover(repo, nil, "fixture")
	c := &Context{Agent: disc.Agents[0], Repo: repo}
	evs, fs := RunDetector(context.Background(), panicking{}, c)
	if len(evs) != 1 || len(fs) != 0 {
		t.Fatalf("expected exactly one evidence item, got %d and %d findings", len(evs), len(fs))
	}
	e := evs[0]
	if e.Signal != model.SignalError || e.ControlID != "AGC-099" || e.Result != model.ResultInconclusive || e.AgentID != "fixture" || e.Collector != "AGC-099.boom" || e.EvidenceID == "" {
		t.Fatalf("panic evidence: %+v", e)
	}
	// With no agent in the context the detector still cannot crash the scan.
	evs, _ = RunDetector(context.Background(), panicking{}, nil)
	if len(evs) != 1 || evs[0].AgentID != model.AllAgents || evs[0].Signal != model.SignalError {
		t.Fatalf("panic evidence without context: %+v", evs)
	}
}

func TestRegistryCoversAllControlsInOrder(t *testing.T) {
	all := All()
	seen := map[string]bool{}
	prev := ""
	idRe := regexp.MustCompile(`^AGC-0\d\d\.[a-z0-9-]+$`)
	for _, d := range all {
		if !idRe.MatchString(d.ID()) || !strings.HasPrefix(d.ID(), d.ControlID()+".") {
			t.Errorf("bad detector ID %q for control %q", d.ID(), d.ControlID())
		}
		if d.ID() <= prev {
			t.Errorf("registry order is not strictly ascending at %s", d.ID())
		}
		prev = d.ID()
		seen[d.ControlID()] = true
	}
	for i := 1; i <= 24; i++ {
		id := "AGC-0" + string(rune('0'+i/10)) + string(rune('0'+i%10))
		if !seen[id] {
			t.Errorf("no detector registered for %s", id)
		}
	}
}

var (
	bannedWords  = regexp.MustCompile(`(?i)\b(leverage|unlock|elevate|delve|navigate|realm|stellar|cutting[- ]edge|game[- ]changer|supercharge|unleash|revolutioni[sz]e)\b`)
	contractions = regexp.MustCompile(`(?i)\b(can't|won't|don't|doesn't|isn't|aren't|wasn't|it's|you're|we're|they're|didn't|couldn't|shouldn't|wouldn't|hasn't|haven't|that's|there's)\b`)
)

// TestOutputQuality runs a deliberately bad repository and checks every
// evidence item and finding for the required fields and writing rules.
func TestOutputQuality(t *testing.T) {
	files := map[string]string{
		"agent.py": "import openai, subprocess, sqlite3, logging\nDB = sqlite3.connect(\":memory:\")\nOPENAI_API_KEY = \"sk-" + "TESTONLYnotAKeyTESTONLYnotAKey1234" + "\"\nDB_USER = \"admin\"\nDB_PASSWORD = \"Tr0ub4dor-and-3-x9\"\nKILL = False\n\n" +
			"def run_shell(command):\n    return subprocess.run(command, shell=True)\n\n" +
			"def lookup(user_id, name):\n    return DB.execute(f\"SELECT * FROM t WHERE name = '{name}'\").fetchall()\n\n" +
			"def refund_payment(order_id, auto_approve=True):\n    DB.execute(\"UPDATE o SET r = 1 WHERE id = ?\", (order_id,))\n\n" +
			"def save_memory(content):\n    DB.execute(\"INSERT INTO m VALUES (?)\", (content,))\n\n" +
			"SCHEMAS = [{\"name\": \"lookup\", \"parameters\": {\"properties\": {\"user_id\": {}}}}, {\"name\": \"run_shell\", \"parameters\": {}}, {\"name\": \"refund_payment\", \"parameters\": {}}]\n\n" +
			"def dispatch(name, args):\n    return globals()[name](**args)\n\n" +
			"def run(client, messages, retrieved_docs):\n    system_prompt = f\"Context: {retrieved_docs}\"\n    while True:\n        logging.info(f\"prompt {messages} {OPENAI_API_KEY}\")\n        print(messages)\n        r = client.chat.completions.create(model=\"m\", messages=messages, tools=SCHEMAS)\n        dispatch(r.name, r.args)\n",
		"requirements.txt": "openai\n", "Dockerfile": "FROM python:latest\n",
		"compose.yaml":            "services:\n  a:\n    build: .\n    privileged: true\n    volumes:\n      - ~/.aws:/root/.aws\n      - /var/run/docker.sock:/var/run/docker.sock\n",
		".mcp.json":               `{"mcpServers":{"x":{"command":"npx","args":["-y","some-server"]}}}`,
		"auth.py":                 "import jwt, datetime\n\ndef issue_token(s):\n    return jwt.encode({\"exp\": datetime.datetime.utcnow() + datetime.timedelta(days=365)}, K)\n",
		".github/workflows/x.yml": "on: [push]\njobs:\n  a:\n    steps:\n      - uses: someone/action@v1\n",
	}
	r := run(t, files, "agent:\n  id: bad-agent\n  risk_tier: low\ncapabilities:\n  declared_tools: [lookup]\n")
	if len(r.findings) < 18 {
		t.Fatalf("expected a broad set of findings, got %d: %s", len(r.findings), r.rules())
	}
	evIDs := map[string]bool{}
	for _, e := range r.evidence {
		if evIDs[e.EvidenceID] {
			t.Errorf("duplicate evidence ID %s", e.EvidenceID)
		}
		evIDs[e.EvidenceID] = true
		if !regexp.MustCompile(`^E-[0-9a-f]{12}$`).MatchString(e.EvidenceID) {
			t.Errorf("bad evidence ID %q", e.EvidenceID)
		}
		if e.Strength == model.StrengthTested || e.Strength == model.StrengthOperational {
			t.Errorf("%s: static evidence must never claim %s", e.Collector, e.Strength)
		}
		if e.SourceType != model.SourceStatic && e.SourceType != model.SourceConfiguration {
			t.Errorf("%s: scanner evidence has source type %s", e.Collector, e.SourceType)
		}
		if e.Integrity != model.IntegrityNotAvailable || e.Validity != model.ValidityValid {
			t.Errorf("%s: integrity=%s validity=%s", e.Collector, e.Integrity, e.Validity)
		}
		wantResult := map[model.Signal]model.Result{model.SignalPresent: model.ResultPass, model.SignalViolation: model.ResultFail}[e.Signal]
		if wantResult == "" {
			wantResult = model.ResultInconclusive
		}
		if e.Result != wantResult || e.Summary == "" || e.Limitations == nil || e.SourceLocation == "" || e.AgentID != "bad-agent" {
			t.Errorf("incomplete evidence: %+v", e)
		}
		if (e.Signal == model.SignalAbsent || e.Signal == model.SignalDeclared) && e.Strength != model.StrengthDeclared {
			t.Errorf("%s: %s evidence must have declared strength", e.Collector, e.Signal)
		}
	}
	fps := map[string]bool{}
	for _, f := range r.findings {
		if fps[f.Fingerprint] {
			t.Errorf("duplicate fingerprint for %s", f.RuleID)
		}
		fps[f.Fingerprint] = true
		if !regexp.MustCompile(`^AGC-0\d\d\.[a-z0-9-]+$`).MatchString(f.RuleID) || !strings.HasPrefix(f.RuleID, f.ControlID+".") {
			t.Errorf("bad rule ID %q", f.RuleID)
		}
		if f.FindingID != "F-"+f.Fingerprint[:12] || f.Severity == "" || f.Confidence == "" || f.Title == "" || f.Description == "" ||
			f.WhyItMatters == "" || len(f.Remediation) < 2 || f.AgentID != "bad-agent" || f.Mappings == nil || len(f.Mappings) != 0 {
			t.Errorf("incomplete finding: %+v", f)
		}
		if len(f.EvidenceRefs) == 0 {
			t.Errorf("%s: a finding must reference evidence", f.RuleID)
		}
		for _, ref := range f.EvidenceRefs {
			if !evIDs[ref] {
				t.Errorf("%s: evidence reference %s does not exist", f.RuleID, ref)
			}
		}
		text := strings.Join(append([]string{f.Title, f.Description, f.WhyItMatters}, f.Remediation...), " ")
		if m := bannedWords.FindString(text); m != "" {
			t.Errorf("%s uses the word %q", f.RuleID, m)
		}
		if m := contractions.FindString(text); m != "" {
			t.Errorf("%s uses the contraction %q", f.RuleID, m)
		}
		for _, sentence := range strings.Split(f.WhyItMatters, ". ") {
			if len(strings.Fields(sentence)) > 32 {
				t.Errorf("%s: why-it-matters sentence is too long: %q", f.RuleID, sentence)
			}
		}
	}
	for _, e := range r.evidence {
		text := e.Summary + " " + strings.Join(e.Limitations, " ")
		if m := bannedWords.FindString(text); m != "" {
			t.Errorf("%s evidence uses the word %q", e.Collector, m)
		}
		if m := contractions.FindString(text); m != "" {
			t.Errorf("%s evidence uses the contraction %q", e.Collector, m)
		}
	}
	blob, _ := json.Marshal(r)
	_ = blob
	out, _ := json.Marshal(struct {
		E []model.Evidence
		F []model.Finding
	}{r.evidence, r.findings})
	for _, secret := range []string{"TESTONLYnotAKey", "Tr0ub4dor"} {
		if strings.Contains(string(out), secret) {
			t.Errorf("secret value %q leaked into the output", secret)
		}
	}
}
