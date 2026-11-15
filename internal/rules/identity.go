// SPDX-License-Identifier: Apache-2.0

package rules

import (
	"math"
	"path"
	"regexp"
	"strconv"
	"strings"

	"github.com/shahzadarain/agent-governance-auditor/internal/adapters"
	"github.com/shahzadarain/agent-governance-auditor/internal/model"
)

func init() {
	register("AGC-004", "workload-identity", runIdentity)
	register("AGC-005", "tool-allowlist", runAllowlist)
	register("AGC-006", "token-lifetime", runTokens)
	register("AGC-008", "secrets", runSecrets)
}

// ---------------------------------------------------------------------------
// Secret detection shared by AGC-004 and AGC-008. Values are inspected in
// memory and never copied into any output.
// ---------------------------------------------------------------------------

type secretHit struct {
	file string
	line int
	kind string // human-readable secret type
	name string // variable or key name; never the value
	rule string
}

var providerPatterns = []struct {
	kind string
	re   *regexp.Regexp
}{
	{"Anthropic-style API key", regexp.MustCompile(`^sk-ant-[A-Za-z0-9_\-]{20,}$`)},
	{"OpenAI-style API key", regexp.MustCompile(`^sk-(proj-|svcacct-)?[A-Za-z0-9_\-]{20,}$`)},
	{"AWS access key ID", regexp.MustCompile(`^(AKIA|ASIA)[0-9A-Z]{16}$`)},
	{"GitHub token", regexp.MustCompile(`^(ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9]{36,}$|^github_pat_[A-Za-z0-9_]{30,}$`)},
	{"Slack token", regexp.MustCompile(`^xox[baprs]-[A-Za-z0-9-]{10,}$`)},
	{"private key", regexp.MustCompile(`-----BEGIN (RSA |EC |OPENSSH |DSA |PGP |ENCRYPTED )?PRIVATE KEY-----`)},
}

var (
	secretNameRe   = regexp.MustCompile(`(?i)(pass(word|wd)?|pwd|secret|token|api[_-]?key|apikey|private[_-]?key|access[_-]?key|auth[_-]?key|client[_-]?secret|credential)`)
	nonSecretName  = regexp.MustCompile(`(?i)(_name|_id|_path|_file|_url|_uri|_header|_env|_var|_field|_prefix|_type|_ttl|_param|_endpoint|name|tokens|max_token|token_count|tokenizer)$`)
	fakeNameRe     = regexp.MustCompile(`(?i)fake|dummy|example|sample|placeholder|mock|test`)
	placeholderRe  = regexp.MustCompile(`(?i)^(changeme|change[-_ ]?me|password|passwd|secret|token|none|null|nil|todo|tbd|test|dummy|example|placeholder|redacted|default|\*+|x+|\.+|-+|your[-_ ].*|<.*>|\$\{.*\}|\{\{.*\}\}|%\(.*\)s|.*your[-_]?(api[-_]?)?(key|token|secret|password).*|.*[-_]here)$`)
	trivialValueRe = regexp.MustCompile(`(?i)x{4,}|\*{3,}|<[^>]*>|changeme|your[-_ ]|\.\.\.`)
	userNameRe     = regexp.MustCompile(`(?i)^(\w*_)?(user(name)?|login|account|email|uid)$`)
	passNameRe     = regexp.MustCompile(`(?i)^(\w*_)?(pass(word|wd)?|pwd)$`)
)

func entropy(s string) float64 {
	if s == "" {
		return 0
	}
	var counts [256]int
	for i := 0; i < len(s); i++ {
		counts[s[i]]++
	}
	e := 0.0
	n := float64(len(s))
	for _, c := range counts {
		if c > 0 {
			p := float64(c) / n
			e -= p * math.Log2(p)
		}
	}
	return e
}

var nameCleanRe = regexp.MustCompile(`[^A-Za-z0-9_.\-]`)

// sanitizeName makes a variable or key name safe to print.
func sanitizeName(n string) string {
	n = nameCleanRe.ReplaceAllString(n, "")
	if len(n) > 60 {
		n = n[:60]
	}
	return n
}

func sameChar(s string) bool {
	for i := 1; i < len(s); i++ {
		if s[i] != s[0] {
			return false
		}
	}
	return true
}

// classifySecret decides whether a literal with the given name is a
// hardcoded secret. It returns the secret type, or "".
func classifySecret(name, value string) (kind, rule string) {
	v := strings.TrimSpace(value)
	if len(v) < 8 || sameChar(v) {
		return "", ""
	}
	for _, p := range providerPatterns {
		if p.re.MatchString(v) {
			if trivialValueRe.MatchString(v) || fakeNameRe.MatchString(name) {
				return "", ""
			}
			return p.kind, "hardcoded-secret"
		}
	}
	if name == "" || !secretNameRe.MatchString(name) || nonSecretName.MatchString(name) || fakeNameRe.MatchString(name) {
		return "", ""
	}
	if len(v) < 12 || strings.ContainsAny(v, " \t\n") || placeholderRe.MatchString(v) || trivialValueRe.MatchString(v) {
		return "", ""
	}
	l := strings.ToLower(v)
	if strings.HasPrefix(l, "http://") || strings.HasPrefix(l, "https://") || strings.HasPrefix(v, "/") || strings.HasPrefix(v, "$") ||
		strings.HasPrefix(l, "env:") || strings.Contains(v, "{") {
		return "", ""
	}
	if entropy(v) < 3.2 {
		return "", ""
	}
	return "secret assigned to " + sanitizeName(name), "hardcoded-secret"
}

var dockerEnvRe = regexp.MustCompile(`([A-Za-z_][A-Za-z0-9_]*)=("[^"]*"|'[^']*'|\S+)`)

// secretHits scans the agent's non-test sources and configuration files.
func (c *Context) secretHits() []secretHit {
	if v, ok := c.cache["secrets"]; ok {
		return v.([]secretHit)
	}
	var hits []secretHit
	for _, s := range c.sources() {
		for i, lit := range s.Strings {
			if lit.Doc || len(lit.Value) < 8 || len(lit.Value) > 8192 {
				continue
			}
			if strings.Contains(lit.Prefix, "f") && strings.Contains(lit.Value, "{") {
				continue
			}
			name := s.LitName(i)
			if kind, rule := classifySecret(name, lit.Value); kind != "" {
				hits = append(hits, secretHit{s.Path, lit.Line, kind, name, rule})
			}
		}
	}
	for _, d := range c.Agent.Docs() {
		base := path.Base(d.Path)
		if strings.Contains(base, "lock") || c.Agent.IsTest(d.Path) || strings.Contains(d.Path, ".agentgov/evidence") {
			continue
		}
		for _, e := range d.Entries {
			if e.Kind != 's' || len(e.Value) < 8 || len(e.Value) > 8192 {
				continue
			}
			name := e.Path
			if i := strings.LastIndex(name, "."); i >= 0 {
				name = name[i+1:]
			}
			if strings.HasSuffix(name, "]") {
				name = "" // a list item has no key of its own; only provider formats apply
			}
			if strings.Contains(e.Value, "${{") || strings.HasPrefix(e.Value, "$") {
				continue
			}
			if kind, rule := classifySecret(name, e.Value); kind != "" {
				hits = append(hits, secretHit{d.Path, e.Line, kind, name, rule})
			}
		}
	}
	for _, df := range c.Agent.Dockerfiles() {
		for _, in := range df.Lines {
			if in.Op != "ENV" && in.Op != "ARG" {
				continue
			}
			for _, m := range dockerEnvRe.FindAllStringSubmatch(in.Args, -1) {
				if kind, rule := classifySecret(m[1], strings.Trim(m[2], `"'`)); kind != "" {
					hits = append(hits, secretHit{df.Path, in.Line, kind, m[1], rule})
				}
			}
		}
	}
	c.memo("secrets", hits)
	return hits
}

// ---------------------------------------------------------------------------
// AGC-008 Vault-Injected Secrets
// ---------------------------------------------------------------------------

var specHardcodedSecret = findingSpec{
	Slug: "hardcoded-secret", Severity: model.SeverityCritical, Confidence: model.ConfidenceHigh,
	Title: "A secret is written directly in a file",
	Why: "Anyone who can read the repository can copy this secret and use it. Old copies stay in the history even after the line is deleted. " +
		"A secret in code also cannot be rotated without a code change.",
	Remediation: []string{
		"Treat the secret as exposed and rotate it now.",
		"Remove the value from the file.",
		"Load the secret at run time from a secret manager or from an environment variable that the platform injects.",
		"Add secret scanning to CI so the next one is caught before it is merged.",
	},
	Repro: "Open the file at the reported line. The report does not repeat the value.",
}

var vaultCallRe = regexp.MustCompile(`\b(get_secret_value|GetSecretValueCommand|get_secret|access_secret_version|accessSecretVersion|read_secret_version|read_secret|SecretClient|SecretManagerServiceClient|getSecret)\b`)

func runSecrets(c *Context, o *out) {
	hits := c.secretHits()
	for _, h := range hits {
		ref := o.violation(h.file, h.line, "A hardcoded secret ("+h.kind+") is present at "+at(h.file, h.line)+". The value is not shown.")
		o.finding(specHardcodedSecret, h.file, h.line, "secret-name:"+h.name+"|"+h.kind,
			"A hardcoded secret of type \""+h.kind+"\" was found at "+at(h.file, h.line)+". The value is withheld from this report.", ref)
	}
	limit := "Presence of a vault SDK does not prove every secret is protected."
	found := false
	vaultMods := []string{"hvac", "azure.keyvault", "google.cloud.secretmanager", "dopplersdk", "infisical_client", "infisical_sdk",
		"@aws-sdk/client-secrets-manager", "@azure/keyvault-secrets", "@google-cloud/secret-manager", "node-vault", "@infisical/sdk", "@dopplerhq/node-sdk"}
	if s, line, ok := c.hasImport(vaultMods...); ok {
		o.present(s.Path, line, "The code imports a secret-manager client.", limit)
		found = true
	}
	if _, _, ok := c.hasImport("boto3", "botocore", "aioboto3", "azure", "google", "@aws-sdk", "@azure", "@google-cloud", "hvac"); ok {
		for _, h := range c.grepCode(vaultCallRe) {
			if len(c.Agent.FuncsNamed(h.text)) > 0 {
				continue // a local helper with a similar name
			}
			o.present(h.src.Path, h.line, "The code retrieves a secret from a secret manager at run time.", limit)
			found = true
			break
		}
	}
	for _, d := range c.Agent.Docs() {
		for _, e := range d.Entries {
			switch {
			case strings.HasSuffix(e.Path, ".secretKeyRef.name") || strings.HasSuffix(e.Path, ".secret.secretName") || strings.HasSuffix(e.Path, ".secretRef.name"):
				o.present(d.Path, e.Line, "A Kubernetes manifest injects a secret by reference.", limit)
				found = true
			case e.Kind == 's' && strings.Contains(e.Value, "${{ secrets.") || e.Kind == 's' && strings.Contains(e.Value, "${{secrets."):
				o.present(d.Path, e.Line, "A CI workflow reads a secret from the platform secret store.", limit)
				found = true
			case adapters.IsComposeDoc(d) && regexp.MustCompile(`^services\.[^.]+\.secrets(\[\d+\])?$`).MatchString(e.Path):
				o.present(d.Path, e.Line, "A Compose service receives a secret through the secrets mechanism.", limit)
				found = true
			}
		}
	}
	if !found && len(hits) == 0 && c.has(model.CapCredentials) {
		o.absent("The agent handles credentials, but no secret-manager retrieval or injected-secret reference was found.",
			"Secrets supplied through plain environment variables cannot be told apart from vault-injected ones by static analysis.")
	}
}

// ---------------------------------------------------------------------------
// AGC-004 Dedicated Non-Human Identity
// ---------------------------------------------------------------------------

var specSharedAccount = findingSpec{
	Slug: "hardcoded-account-credentials", Severity: model.SeverityHigh, Confidence: model.ConfidenceMedium,
	Title: "The agent signs in with a hardcoded user or shared account",
	Why: "The agent acts under a person's or a shared account. Logs cannot tell the agent apart from the person. " +
		"The agent also gets every permission that account has, and the access cannot be removed without locking the person out.",
	Remediation: []string{
		"Create a dedicated service identity for this agent with only the permissions it needs.",
		"Use workload identity (for example OIDC federation or a managed identity) so no password is stored.",
		"Remove the user name and password from the code and rotate the password.",
	},
}

var specHostCredentialMount = findingSpec{
	Slug: "host-credential-mount", Severity: model.SeverityHigh, Confidence: model.ConfidenceHigh,
	Title: "A host credential store is mounted into the agent container",
	Why: "The container can read the credentials of whoever runs it. The agent then acts with a person's cloud or server access " +
		"and not with an identity of its own. A Docker socket mount gives control of the whole host.",
	Remediation: []string{
		"Remove the mount of the host credential directory or Docker socket.",
		"Give the container its own workload identity with narrow permissions.",
	},
}

var (
	hostCredRe    = regexp.MustCompile(`(?i)(~|\$HOME|\$\{HOME\}|/root|/home/[^/:]+|/Users/[^/:]+)/\.(aws|ssh|kube|azure|docker|config/gcloud|gnupg)\b|docker\.sock`)
	workloadIDRe  = regexp.MustCompile(`\b(DefaultAzureCredential|ManagedIdentityCredential|WorkloadIdentityCredential|assume_role_with_web_identity|AssumeRoleWithWebIdentityCommand|fromWebToken|fromTokenFile|IdentityPoolClient|fetch_id_token)\b`)
	wiAnnotations = regexp.MustCompile(`eks\.amazonaws\.com/role-arn|iam\.gke\.io/gcp-service-account|azure\.workload\.identity/client-id`)
)

const identityLimit = "Operational confirmation needs identity-provider evidence."

func runIdentity(c *Context, o *out) {
	violated := false
	// Hardcoded user plus password literals close together.
	for _, s := range c.sources() {
		type named struct {
			line  int
			value string
		}
		var users, passes []named
		for i, lit := range s.Strings {
			if lit.Doc || lit.Value == "" || len(lit.Value) > 256 || (strings.Contains(lit.Prefix, "f") && strings.Contains(lit.Value, "{")) {
				continue
			}
			name := s.LitName(i)
			if name == "" || fakeNameRe.MatchString(name) {
				continue
			}
			v := strings.TrimSpace(lit.Value)
			if placeholderRe.MatchString(v) || trivialValueRe.MatchString(v) || strings.HasPrefix(v, "$") {
				continue
			}
			if userNameRe.MatchString(name) && len(v) >= 2 {
				users = append(users, named{lit.Line, v})
			} else if passNameRe.MatchString(name) && len(v) >= 4 {
				passes = append(passes, named{lit.Line, v})
			}
		}
		for _, p := range passes {
			for _, u := range users {
				if d := p.line - u.line; d >= -6 && d <= 6 {
					kind := "a named account"
					lu := strings.ToLower(u.value)
					switch {
					case strings.Contains(u.value, "@"):
						kind = "an email-style user login"
					case lu == "admin" || lu == "root" || lu == "administrator" || strings.Contains(lu, "admin"):
						kind = "an administrator account"
					}
					ref := o.violation(s.Path, p.line, "The code holds a hardcoded user name and password for "+kind+". The values are not shown.")
					o.finding(specSharedAccount, s.Path, p.line, "",
						"A user name and a password are written as literals near "+at(s.Path, p.line)+". The login looks like "+kind+". The values are withheld.", ref)
					violated = true
					break
				}
			}
		}
	}
	for _, h := range c.secretHits() {
		if h.kind == "AWS access key ID" {
			ref := o.violation(h.file, h.line, "A long-lived AWS access key ID is written in the code. The value is not shown.")
			o.finding(specSharedAccount, h.file, h.line, "aws-key:"+h.name,
				"A long-lived AWS access key ID is hardcoded at "+at(h.file, h.line)+". Static keys are tied to a user or root account, not to this workload.", ref)
			violated = true
		}
	}
	// Host credential stores mounted into containers.
	for _, d := range c.Agent.Docs() {
		if !adapters.IsComposeDoc(d) && !adapters.IsK8sWorkload(d) {
			continue
		}
		for _, e := range d.Entries {
			if e.Kind != 's' || !(strings.Contains(e.Path, "volumes") || strings.Contains(e.Path, "hostPath")) || !hostCredRe.MatchString(e.Value) {
				continue
			}
			what := "a host credential directory"
			if strings.Contains(e.Value, "docker.sock") {
				what = "the Docker socket"
			}
			ref := o.violation(d.Path, e.Line, "A container manifest mounts "+what+" from the host.")
			o.finding(specHostCredentialMount, d.Path, e.Line, "mount:"+hostCredRe.FindString(e.Value),
				"The manifest at "+at(d.Path, e.Line)+" mounts "+what+" into the container.", ref)
			violated = true
		}
	}
	// Workload identity patterns.
	found := false
	for _, w := range c.ciWorkflows() {
		if w.kind != "github" {
			continue
		}
		idToken := 0
		for _, e := range w.doc.Entries {
			if strings.HasSuffix(e.Path, "permissions.id-token") && e.Value == "write" {
				idToken = e.Line
			}
		}
		if idToken == 0 {
			continue
		}
		for _, e := range w.doc.Entries {
			if strings.HasSuffix(e.Path, ".with.role-to-assume") || strings.HasSuffix(e.Path, ".with.workload_identity_provider") ||
				(strings.HasSuffix(e.Path, ".with.client-id") && strings.Contains(w.doc.Path, "workflows")) {
				o.present(w.doc.Path, e.Line, "A CI workflow uses OIDC federation: it requests an identity token and assumes a cloud role without a stored key.", identityLimit)
				found = true
				break
			}
		}
	}
	for _, h := range c.grepCode(workloadIDRe) {
		o.present(h.src.Path, h.line, "The code obtains credentials through a workload or managed identity.", identityLimit)
		found = true
		break
	}
	for _, d := range c.Agent.Docs() {
		if d.Format != "yaml" || !d.Has("apiVersion") {
			continue
		}
		sa, saLine, projected := false, 0, false
		for _, e := range d.Entries {
			if strings.HasSuffix(e.Path, "serviceAccountName") && e.Value != "" && e.Value != "default" {
				sa, saLine = true, e.Line
			}
			if strings.Contains(e.Path, "serviceAccountToken") {
				projected = true
			}
			if wiAnnotations.MatchString(e.Path) {
				o.present(d.Path, e.Line, "A Kubernetes service account is bound to a cloud workload identity.", identityLimit)
				found = true
			}
		}
		if sa && projected {
			o.present(d.Path, saLine, "A Kubernetes workload runs under a named service account with a projected, time-bound token.", identityLimit)
			found = true
		}
	}
	if !found && !violated && c.has(model.CapCredentials) {
		o.absent("The agent handles credentials, but no workload identity pattern was found. The scanner looked for OIDC federation in CI, managed identity clients, and Kubernetes service accounts with projected tokens.",
			identityLimit)
	}
}

// ---------------------------------------------------------------------------
// AGC-005 Allowlisted Tool Access
// ---------------------------------------------------------------------------

var specDynamicDispatch = findingSpec{
	Slug: "unrestricted-dynamic-dispatch", Severity: model.SeverityCritical, Confidence: model.ConfidenceHigh,
	Title: "The model can call any function by name",
	Why: "The code looks up a function from a name the model supplies and runs it. There is no fixed list of permitted tools. " +
		"A crafted prompt can make the agent run functions that were never meant to be tools.",
	Remediation: []string{
		"Keep a fixed set of permitted tool names.",
		"Before running a tool, check that the requested name is in the set. Reject the request when it is not.",
		"Remove lookups through globals(), getattr(), or eval() from the dispatch path.",
	},
	Repro: "Read the dispatch function at the reported line and follow how the tool name selects the function.",
}

var specUnrestrictedExec = findingSpec{
	Slug: "unrestricted-exec-tool", Severity: model.SeverityHigh, Confidence: model.ConfidenceMedium,
	Title: "A shell or code-execution tool is exposed with no restriction",
	Why: "The tool runs whatever command or code the model gives it. A single misleading input can make the agent delete files, " +
		"read secrets, or reach other systems.",
	Remediation: []string{
		"Remove the tool if the agent does not need it.",
		"Otherwise accept only a fixed list of commands and reject everything else.",
		"Run the tool in a disposable sandbox with no credentials and no network.",
	},
}

var (
	notInRe       = regexp.MustCompile(`\bif\s+\(?\s*([A-Za-z_][\w.\[\]"' ]*?)\s+not\s+in\s+([A-Za-z_][\w.]*)\s*\)?\s*:`)
	inElseRe      = regexp.MustCompile(`\bif\s+([A-Za-z_][\w.]*)\s+in\s+([A-Za-z_][\w.]*)\s*:`)
	jsNotInRe     = regexp.MustCompile(`\bif\s*\(\s*!\s*([A-Za-z_$][\w$.]*)\s*\.\s*(has|includes)\s*\(\s*([A-Za-z_$][\w$.]*)\s*\)\s*\)|\bif\s*\(\s*!\s*\(\s*([A-Za-z_$][\w$.]*)\s+in\s+([A-Za-z_$][\w$.]*)\s*\)\s*\)`)
	allowNameRe   = regexp.MustCompile(`(?i)allow|permit|whitelist|approved_tools|enabled_tools|safe_tools|tool`)
	toolVarRe     = regexp.MustCompile(`(?i)tool|name|action|function|fn|command|cmd`)
	dynCallRe     = regexp.MustCompile(`\b(globals|locals)\s*\(\s*\)\s*(\[[^\]\n]+\]|\.get\s*\([^)\n]*\))\s*\(|\bgetattr\s*\(\s*[\w.]+\s*,\s*[A-Za-z_][\w.\[\]"' ]*\)\s*\(`)
	dynAssignRe   = regexp.MustCompile(`=\s*((globals|locals)\s*\(\s*\)\s*(\[[^\]\n]+\]|\.get\s*\([^)\n]*\))|getattr\s*\(\s*[\w.]+\s*,\s*[A-Za-z_][\w.\[\]]*\s*(,[^)\n]*)?\))\s*$`)
	evalNameRe    = regexp.MustCompile(`\beval\s*\(\s*[^)\n]*\b(tool|name|action|function|call)\w*`)
	scopeKwargs   = []string{"allowed_tools", "allowedTools", "tool_filter", "allowed_tool_names", "include_tools", "activeTools", "allowed_function_names", "permitted_tools"}
	collectionDef = `(?m)^[ \t]*(?:self\.)?%s\s*(?::[^=\n]+)?=\s*(\{|\[|\(|frozenset\s*\(|set\s*\(|dict\s*\(|tuple\s*\(|new\s+Set\s*\(|Object\.freeze)`
)

// collectionDefined reports whether name is assigned a literal collection
// somewhere in the agent's sources.
func (c *Context) collectionDefined(name string) bool {
	last := name[strings.LastIndex(name, ".")+1:]
	re, err := regexp.Compile(strings.Replace(collectionDef, "%s", `(?:const\s+|let\s+|var\s+|export\s+const\s+)?`+regexp.QuoteMeta(last), 1))
	if err != nil {
		return false
	}
	return len(c.grepCode(re)) > 0
}

func runAllowlist(c *Context, o *out) {
	tools := c.Agent.Agent.Tools
	found, violated := false, false
	// Membership test plus reject path in one function.
	for _, x := range c.funcs() {
		code := x.code()
		check := func(varName, setName string, off int, needElse bool) {
			if !(toolVarRe.MatchString(varName) || allowNameRe.MatchString(setName)) {
				return
			}
			if !c.collectionDefined(setName) && setName != strings.ToUpper(setName) {
				return
			}
			if needElse {
				rest := code[off:]
				if i := strings.Index(rest, "else"); i < 0 || !rejectAfter(rest, i) {
					return
				}
			} else if !rejectAfter(code, off) {
				return
			}
			line := x.src.LineOf(x.f.Start + off)
			o.present(x.src.Path, line, "The function "+x.f.Name+" checks the requested name against the fixed set "+setName+" and rejects anything else.",
				"The scanner did not run the check. Attach a test that calls a tool outside the allowlist to confirm rejection.")
			found = true
		}
		if x.src.Lang == adapters.LangPython {
			for _, m := range notInRe.FindAllStringSubmatchIndex(code, -1) {
				check(code[m[2]:m[3]], code[m[4]:m[5]], m[1], false)
			}
			for _, m := range inElseRe.FindAllStringSubmatchIndex(code, -1) {
				check(code[m[2]:m[3]], code[m[4]:m[5]], m[1], true)
			}
		} else {
			for _, m := range jsNotInRe.FindAllStringSubmatchIndex(code, -1) {
				if m[2] >= 0 {
					check(code[m[6]:m[7]], code[m[2]:m[3]], m[1], false)
				} else {
					check(code[m[8]:m[9]], code[m[10]:m[11]], m[1], false)
				}
			}
		}
	}
	// Framework-native scoping.
	c.calls(func(s *adapters.Source, call adapters.Call) {
		for _, k := range scopeKwargs {
			if call.HasKwarg(k) {
				o.present(s.Path, call.Line, "The call to "+call.Last()+" restricts tools with "+k+".",
					"The scanner did not confirm the listed tools are the minimum needed.")
				found = true
			}
		}
		if call.HasKwarg("tool_choice") {
			if v, ok := s.KwargText(call, "tool_choice"); ok && (strings.Contains(v, "allowed_tools") || strings.Contains(v, "\"function\"") || strings.Contains(v, "'function'")) {
				o.present(s.Path, call.Line, "The model call restricts tool choice to a named list.", "A restricted tool choice limits one call, not every path to the tools.")
				found = true
			}
		}
	})
	for _, m := range c.Agent.MCP() {
		if m.Allowed {
			o.present(m.Path, m.Line, "The MCP server entry "+m.Name+" lists the tools the client may use.",
				"The scanner did not confirm the MCP client enforces the list.")
			found = true
		}
	}
	// Unrestricted dynamic dispatch.
	for _, x := range c.funcs() {
		code := x.code()
		for _, re := range []*regexp.Regexp{dynCallRe, evalNameRe} {
			for _, m := range re.FindAllStringIndex(code, -1) {
				line := x.src.LineOf(x.f.Start + m[0])
				ref := o.violation(x.src.Path, line, "The function "+x.f.Name+" resolves a function from a run-time name and calls it, with no fixed list of permitted tools.")
				o.finding(specDynamicDispatch, x.src.Path, line, "",
					"At "+at(x.src.Path, line)+" the function "+x.f.Name+" looks up a callable by a name chosen at run time and calls it.", ref)
				violated = true
			}
		}
		// handler = globals()[name] ... handler(...)
		for ln := x.f.Line; ln <= x.f.EndLine; ln++ {
			cl := x.src.CodeLine(ln)
			if !dynAssignRe.MatchString(cl) || dynCallRe.MatchString(cl) {
				continue
			}
			lhs := strings.TrimSpace(cl[:strings.Index(cl, "=")])
			if lhs == "" || strings.ContainsAny(lhs, " ([") {
				continue
			}
			if regexp.MustCompile(`\b` + regexp.QuoteMeta(lhs) + `\s*\(`).MatchString(code) {
				ref := o.violation(x.src.Path, ln, "The function "+x.f.Name+" resolves a function from a run-time name and calls it, with no fixed list of permitted tools.")
				o.finding(specDynamicDispatch, x.src.Path, ln, "",
					"At "+at(x.src.Path, ln)+" the function "+x.f.Name+" looks up a callable by a name chosen at run time and later calls it.", ref)
				violated = true
			}
		}
	}
	// Shell or code-exec tools with no restriction at all.
	if !found {
		for i, t := range tools {
			tr := c.Agent.Tools[i]
			if tr.Fn == nil || !(tr.Traits.Shell || tr.Traits.CodeExec) {
				continue
			}
			body := tr.Src.BodyCode(tr.Fn)
			if notInRe.MatchString(body) || jsNotInRe.MatchString(body) || strings.Contains(body, "shlex") && inElseRe.MatchString(body) {
				continue // the tool restricts its own input
			}
			ref := o.violation(t.Location.Path, t.Location.Line, "The tool "+t.Name+" runs shell commands or code and nothing restricts which tools or commands may run.")
			o.finding(specUnrestrictedExec, t.Location.Path, t.Location.Line, "tool:"+t.Name,
				"The tool \""+t.Name+"\" at "+at(t.Location.Path, t.Location.Line)+" executes commands or code. No allowlist was found for tools or for commands.", ref)
			violated = true
		}
	}
	if !found && !violated && len(tools) > 0 {
		o.absent("The agent exposes tools, but no allowlist check was found. The scanner looked for a membership test with a reject path at the dispatch point and for framework tool scoping.",
			"Frameworks that only run registered tools already limit calls to those tools. That is weaker than an explicit, reviewed allowlist.")
	}
}

// ---------------------------------------------------------------------------
// AGC-006 Short-Lived Scoped Tokens
// ---------------------------------------------------------------------------

var specLongLivedToken = findingSpec{
	Slug: "long-lived-token", Severity: model.SeverityMedium, Confidence: model.ConfidenceMedium,
	Title: "A token is issued with a long lifetime or with no expiry",
	Why: "A token that lasts for days, or never expires, stays useful to anyone who steals it. " +
		"Short-lived tokens limit how long a leak can be abused.",
	Remediation: []string{
		"Issue tokens that expire within one hour.",
		"Set an audience and a narrow scope on each token.",
		"Refresh tokens automatically instead of extending their lifetime.",
	},
}

var (
	jsExpiresRe   = regexp.MustCompile(`expiresIn\s*:\s*(?:["'](\d+)\s*([smhdwy]?)\w*["']|(\d[\d_* ]*))`)
	pyExpiresRe   = regexp.MustCompile(`\b(expires_in|expires_delta|ttl|ttl_seconds|lifetime|max_age|exp_seconds)\s*[=:]\s*(\d[\d_]*)\b`)
	timedeltaRe   = regexp.MustCompile(`timedelta\s*\(\s*(days|hours|minutes|seconds|weeks)\s*=\s*(\d+)`)
	noExpiryRe    = regexp.MustCompile(`\b(expires|expires_in|expires_delta|expires_at|exp|ttl)\s*=\s*None\b|\bexpiresIn\s*:\s*(null|undefined)\b|verify_exp["']?\s*:\s*False`)
	tokenFnRe     = regexp.MustCompile(`(?i)token|jwt|credential|session|sign|issue|mint`)
	audScopeRe    = regexp.MustCompile(`(?i)["']?(aud|audience|scope|scopes)["']?\s*[:=]`)
	jwtEncodeCall = regexp.MustCompile(`\bjwt\s*\.\s*(encode|sign)\s*\(`)
)

func unitSeconds(n int, unit string) int {
	switch unit {
	case "m", "minutes":
		return n * 60
	case "h", "hours":
		return n * 3600
	case "d", "days":
		return n * 86400
	case "w", "weeks":
		return n * 604800
	case "y":
		return n * 31536000
	}
	return n
}

func runTokens(c *Context, o *out) {
	for _, x := range c.funcs() {
		code, text := x.code(), x.text()
		tokenish := tokenFnRe.MatchString(x.f.Name) || jwtEncodeCall.MatchString(code)
		if !tokenish {
			continue
		}
		secs := -1
		line := x.f.Line
		if m := jsExpiresRe.FindStringSubmatchIndex(text); m != nil {
			line = x.src.LineOf(x.f.Start + m[0])
			if m[2] >= 0 {
				n, _ := strconv.Atoi(text[m[2]:m[3]])
				secs = unitSeconds(n, text[m[4]:m[5]])
			} else {
				n, _ := strconv.Atoi(strings.NewReplacer("_", "", " ", "").Replace(strings.Split(text[m[6]:m[7]], "*")[0]))
				secs = n
				if strings.Contains(text[m[6]:m[7]], "*") {
					prod := 1
					for _, part := range strings.Split(text[m[6]:m[7]], "*") {
						v, err := strconv.Atoi(strings.TrimSpace(strings.ReplaceAll(part, "_", "")))
						if err != nil {
							prod = -1
							break
						}
						prod *= v
					}
					if prod > 0 {
						secs = prod
					}
				}
			}
		} else if m := timedeltaRe.FindStringSubmatchIndex(code); m != nil {
			n, _ := strconv.Atoi(code[m[4]:m[5]])
			secs = unitSeconds(n, code[m[2]:m[3]])
			line = x.src.LineOf(x.f.Start + m[0])
		} else if m := pyExpiresRe.FindStringSubmatchIndex(code); m != nil {
			secs, _ = strconv.Atoi(strings.ReplaceAll(code[m[4]:m[5]], "_", ""))
			line = x.src.LineOf(x.f.Start + m[0])
		}
		if m := noExpiryRe.FindStringIndex(text); m != nil {
			ln := x.src.LineOf(x.f.Start + m[0])
			ref := o.violation(x.src.Path, ln, "The function "+x.f.Name+" issues or accepts a token with no expiry.")
			o.finding(specLongLivedToken, x.src.Path, ln, "", "At "+at(x.src.Path, ln)+" a token is created or checked with expiry turned off.", ref)
			continue
		}
		switch {
		case secs > 86400:
			ref := o.violation(x.src.Path, line, "The function "+x.f.Name+" issues a token that is valid for more than 24 hours.")
			o.finding(specLongLivedToken, x.src.Path, line, "", "At "+at(x.src.Path, line)+" a token lifetime longer than 24 hours is configured.", ref)
		case secs > 0 && secs <= 3600 && audScopeRe.MatchString(text):
			o.present(x.src.Path, line, "The function "+x.f.Name+" issues a token that expires within one hour and carries an audience or scope.",
				"Static configuration cannot prove real token expiry. Attach a test with an expired and a wrong-audience token.")
		}
	}
}
