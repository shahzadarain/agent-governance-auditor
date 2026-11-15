// SPDX-License-Identifier: Apache-2.0

package rules

import (
	"path"
	"regexp"
	"strings"

	"github.com/shahzadarain/agent-governance-auditor/internal/adapters"
	"github.com/shahzadarain/agent-governance-auditor/internal/model"
)

func init() {
	register("AGC-013", "sandbox", runSandbox)
	register("AGC-014", "supply-chain", runSupplyChain)
	register("AGC-015", "memory-integrity", runMemory)
	register("AGC-016", "inter-agent-auth", runInterAgent)
	register("AGC-017", "kill-switch", runKillSwitch)
	register("AGC-018", "reversible-actions", runReversible)
	register("AGC-019", "incident-runbook", runRunbook)
	register("AGC-020", "regression-evals", runRegressionEvals)
	register("AGC-021", "red-teaming", runRedTeam)
	register("AGC-022", "step-tracing", runTracing)
	register("AGC-023", "audit-trail", runAuditTrail)
	register("AGC-024", "monitoring", runMonitoring)
}

var sqlAnyRe = regexp.MustCompile(`(?i)\b(SELECT\s+.+?\s+FROM|INSERT\s+(OR\s+\w+\s+)?INTO|UPDATE\s+[\w."]+\s+SET|DELETE\s+FROM)\b`)

// ---------------------------------------------------------------------------
// AGC-013 Disposable Sandbox Environments
// ---------------------------------------------------------------------------

var specPrivileged = findingSpec{
	Slug: "privileged-container", Severity: model.SeverityHigh, Confidence: model.ConfidenceHigh,
	Title: "The agent container has host-level privileges",
	Why: "A privileged container, or one that can reach the Docker socket, can take over the machine it runs on. " +
		"If the agent is tricked into running a bad command, the damage is not limited to the container.",
	Remediation: []string{
		"Remove privileged mode and the Docker socket mount.",
		"Run as a non-root user with a read-only root filesystem.",
		"Drop all Linux capabilities and set no-new-privileges.",
	},
}

var specRootExec = findingSpec{
	Slug: "root-container-with-exec-tools", Severity: model.SeverityHigh, Confidence: model.ConfidenceMedium,
	Title: "The container runs as root and the agent can execute commands",
	Why: "The agent can run shell commands or code, and the container gives those commands full administrator rights. " +
		"One bad command can change or delete anything in the container and makes an escape to the host easier.",
	Remediation: []string{
		"Add a USER instruction with a non-root user to the Dockerfile.",
		"Make the root filesystem read-only and drop all capabilities.",
		"Run command execution in a separate, disposable sandbox.",
	},
}

func runSandbox(c *Context, o *out) {
	exec := c.has(model.CapShellExec) || c.has(model.CapCodeExec)
	dockerfiles := c.Agent.Dockerfiles()
	var manifests []*adapters.Doc
	for _, d := range c.Agent.Docs() {
		if adapters.IsComposeDoc(d) || adapters.IsK8sWorkload(d) {
			manifests = append(manifests, d)
		}
	}
	if len(dockerfiles) == 0 && len(manifests) == 0 {
		if exec {
			o.absent("The agent can execute shell commands or code, but no container or sandbox configuration was found.",
				"A sandbox defined outside this repository is not visible to the scanner.")
		}
		return
	}
	nonRoot, readOnly, capDrop, noNewPriv, limits := false, false, false, false, false
	violated := false
	firstFile, firstLine := "", 0
	mark := func(f string, l int) {
		if firstFile == "" {
			firstFile, firstLine = f, l
		}
	}
	rootDockerfile := ""
	rootLine := 0
	for _, df := range dockerfiles {
		u := strings.ToLower(strings.Split(df.User, ":")[0])
		if u != "" && u != "root" && u != "0" {
			nonRoot = true
			mark(df.Path, df.UserLine)
		} else if len(df.Froms) > 0 {
			rootDockerfile, rootLine = df.Path, df.UserLine
			if rootLine == 0 {
				rootLine = df.Froms[len(df.Froms)-1].Line
			}
		}
	}
	for _, d := range manifests {
		for _, e := range d.Entries {
			p, v := e.Path, strings.ToLower(strings.TrimSpace(e.Value))
			switch {
			case strings.HasSuffix(p, ".privileged") && v == "true":
				ref := o.violation(d.Path, e.Line, "A container manifest sets privileged mode.")
				o.finding(specPrivileged, d.Path, e.Line, "privileged", "The manifest at "+at(d.Path, e.Line)+" runs the container in privileged mode.", ref)
				violated = true
			case e.Kind == 's' && (strings.Contains(p, "volumes") || strings.Contains(p, "hostPath")) && strings.Contains(v, "docker.sock"):
				ref := o.violation(d.Path, e.Line, "A container manifest mounts the Docker socket.")
				o.finding(specPrivileged, d.Path, e.Line, "docker.sock", "The manifest at "+at(d.Path, e.Line)+" mounts the Docker socket into the container.", ref)
				violated = true
			case (strings.HasSuffix(p, ".read_only") || strings.HasSuffix(p, ".readOnlyRootFilesystem")) && v == "true":
				readOnly = true
				mark(d.Path, e.Line)
			case (strings.Contains(p, ".cap_drop[") || strings.Contains(p, ".capabilities.drop[")) && v == "all":
				capDrop = true
			case strings.Contains(p, ".security_opt[") && strings.Contains(v, "no-new-privileges") && !strings.HasSuffix(v, "false"):
				noNewPriv = true
			case strings.HasSuffix(p, ".allowPrivilegeEscalation") && v == "false":
				noNewPriv = true
			case strings.HasSuffix(p, ".runAsNonRoot") && v == "true":
				nonRoot = true
			case regexp.MustCompile(`^services\.[^.]+\.user$`).MatchString(p) && v != "" && v != "root" && v != "0" && !strings.HasPrefix(v, "0:"):
				nonRoot = true
			case strings.Contains(p, ".resources.limits.") || strings.HasSuffix(p, ".mem_limit") || strings.HasSuffix(p, ".pids_limit") || strings.HasSuffix(p, ".cpus"):
				limits = true
			}
		}
	}
	if rootDockerfile != "" && !nonRoot && exec {
		ref := o.violation(rootDockerfile, rootLine, "The Dockerfile runs as root and the agent can execute shell commands or code.")
		o.finding(specRootExec, rootDockerfile, rootLine, "user:root",
			"The image built from "+rootDockerfile+" runs as root. The agent exposes tools that execute commands or code.", ref)
		violated = true
	}
	if violated {
		return
	}
	if nonRoot && readOnly && (capDrop || noNewPriv) {
		summary := "Container configuration runs as a non-root user with a read-only root filesystem and reduced privileges."
		lim := []string{"A container is not automatically an adequate sandbox. Network and mount restrictions need review.",
			"The scanner did not start the container."}
		if limits {
			summary += " Resource limits are set."
		} else {
			lim = append(lim, "No CPU, memory, or process limits were found.")
		}
		o.present(firstFile, firstLine, summary, lim...)
		return
	}
	var missing []string
	if !nonRoot {
		missing = append(missing, "non-root user")
	}
	if !readOnly {
		missing = append(missing, "read-only root filesystem")
	}
	if !capDrop && !noNewPriv {
		missing = append(missing, "dropped capabilities or no-new-privileges")
	}
	o.absent("Container configuration exists, but the core hardening set is incomplete. Missing: " + strings.Join(missing, ", ") + ".")
}

// ---------------------------------------------------------------------------
// AGC-014 Vetted Tool Supply Chain
// ---------------------------------------------------------------------------

var specUnpinnedDeps = findingSpec{
	Slug: "unpinned-dependencies", Severity: model.SeverityMedium, Confidence: model.ConfidenceHigh,
	Title: "Dependencies are not pinned to exact versions",
	Why: "Each install can pull a different version of a package. A new release, good or bad, reaches the agent with no review. " +
		"Unversioned is not the same as known malicious, but nobody can say which code actually runs.",
	Remediation: []string{
		"Pin each dependency to an exact version.",
		"Commit a lockfile with hashes.",
		"Review dependency updates like any other code change.",
	},
}

var specUnpinnedImage = findingSpec{
	Slug: "unpinned-image", Severity: model.SeverityMedium, Confidence: model.ConfidenceHigh,
	Title: "A container image uses the latest tag or no tag",
	Why: "The image behind a floating tag changes over time. Two builds of the same commit can run different software. " +
		"Unversioned is not the same as known malicious, but the build cannot be repeated or reviewed.",
	Remediation: []string{
		"Use a specific version tag.",
		"For stronger assurance, pin the image by its sha256 digest.",
	},
}

var specUnpinnedMCP = findingSpec{
	Slug: "unpinned-mcp-server", Severity: model.SeverityMedium, Confidence: model.ConfidenceHigh,
	Title: "An MCP server package is launched without a pinned version",
	Why: "The launcher downloads whatever version is newest each time it starts. A compromised or changed release would run " +
		"with the agent's access right away. Unversioned is not the same as known malicious, but there is no review step.",
	Remediation: []string{
		"Pin the package to an exact version, for example package@1.2.3.",
		"Review new versions before you update the pin.",
	},
}

var specUnpinnedAction = findingSpec{
	Slug: "unpinned-ci-action", Severity: model.SeverityLow, Confidence: model.ConfidenceHigh,
	Title: "A third-party CI action is not pinned to a commit",
	Why:   "A tag on someone else's action can be moved to different code. That code then runs inside the build with access to its secrets.",
	Remediation: []string{
		"Pin third-party actions to a full commit SHA.",
		"Use an update tool to propose new SHAs for review.",
	},
}

var shaRefRe = regexp.MustCompile(`@[0-9a-f]{40}$`)

func runSupplyChain(c *Context, o *out) {
	assessed := []string{}
	violated := false
	firstFile, firstLine := "", 0
	const note = "Unversioned is not the same as known malicious."
	// Dependencies per manifest.
	type agg struct {
		unpinned []string
		total    int
		line     int
	}
	byManifest := map[string]*agg{}
	var order []string
	for _, d := range c.Agent.Deps() {
		if d.Dev {
			continue
		}
		a := byManifest[d.Path]
		if a == nil {
			a = &agg{}
			byManifest[d.Path] = a
			order = append(order, d.Path)
		}
		a.total++
		if !d.Pinned {
			a.unpinned = append(a.unpinned, d.Name)
			if a.line == 0 {
				a.line = d.Line
			}
		}
	}
	hasLock := func(dir string) bool {
		for _, l := range c.Repo.Lockfiles {
			if path.Dir(l) == dir {
				return true
			}
		}
		return false
	}
	for _, m := range order {
		a := byManifest[m]
		if firstFile == "" {
			firstFile = m
		}
		if len(a.unpinned) > 0 && !hasLock(path.Dir(m)) {
			ref := o.violation(m, a.line, "The manifest lists "+plural(len(a.unpinned), "dependency", "dependencies")+" without an exact version and no lockfile is present. "+note)
			o.finding(specUnpinnedDeps, m, a.line, "manifest:"+path.Base(m),
				"The manifest "+m+" has unpinned entries ("+joinMax(a.unpinned, 5)+") and no lockfile sits next to it.", ref)
			violated = true
		} else {
			assessed = append(assessed, "dependencies in "+m+" are pinned or locked")
		}
	}
	for _, df := range c.Agent.Dockerfiles() {
		stages := map[string]bool{}
		for _, in := range df.Lines {
			if in.Op == "FROM" {
				f := strings.Fields(in.Args)
				for i, w := range f {
					if strings.EqualFold(w, "as") && i+1 < len(f) {
						stages[strings.ToLower(f[i+1])] = true
					}
				}
			}
		}
		for _, from := range df.Froms {
			if from.Image == "" || from.Image == "scratch" || stages[strings.ToLower(from.Image)] || strings.Contains(from.Image, "$") {
				continue
			}
			if firstFile == "" {
				firstFile, firstLine = df.Path, from.Line
			}
			if !from.Digest && (from.Tag == "" || from.Tag == "latest") {
				ref := o.violation(df.Path, from.Line, "A base image uses the latest tag or no tag. "+note)
				o.finding(specUnpinnedImage, df.Path, from.Line, "from:"+strings.Split(from.Image, ":")[0],
					"The base image at "+at(df.Path, from.Line)+" is not pinned to a version or digest.", ref)
				violated = true
			} else if from.Digest {
				assessed = append(assessed, "a base image in "+df.Path+" is pinned by digest")
			} else {
				assessed = append(assessed, "a base image in "+df.Path+" uses a version tag (not a digest)")
			}
		}
	}
	for _, m := range c.Agent.MCP() {
		if !m.Registry {
			continue
		}
		if firstFile == "" {
			firstFile, firstLine = m.Path, m.Line
		}
		if !m.Pinned {
			ref := o.violation(m.Path, m.Line, "The MCP server "+m.Name+" is launched from a package registry without a pinned version. "+note)
			o.finding(specUnpinnedMCP, m.Path, m.Line, "mcp:"+m.Name,
				"The MCP server \""+m.Name+"\" in "+m.Path+" starts through "+m.Target+" with no version pin.", ref)
			violated = true
		} else {
			assessed = append(assessed, "MCP server "+m.Name+" is pinned")
		}
	}
	for _, w := range c.ciWorkflows() {
		for _, e := range w.uses {
			v := strings.TrimSpace(e.Value)
			if strings.HasPrefix(v, "./") || strings.HasPrefix(v, "docker://") || shaRefRe.MatchString(v) {
				continue
			}
			owner := strings.ToLower(strings.Split(v, "/")[0])
			if owner == "actions" || owner == "github" {
				continue
			}
			ref := o.violation(w.doc.Path, e.Line, "A third-party CI action is referenced by tag or branch, not by commit SHA. "+note)
			o.finding(specUnpinnedAction, w.doc.Path, e.Line, "uses:"+strings.Split(v, "@")[0],
				"The workflow step at "+at(w.doc.Path, e.Line)+" uses a third-party action without a commit pin.", ref)
			violated = true
		}
	}
	brokenManifest := c.malformedInScope(func(p string) bool {
		b := path.Base(p)
		return b == "pyproject.toml" || b == "package.json" || b == "package-lock.json" || strings.HasSuffix(b, ".lock") ||
			adapters.IsMCPConfigPath(p) || strings.Contains("/"+p, workflowDir)
	})
	if !violated && len(assessed) > 0 && !brokenManifest {
		o.present(firstFile, firstLine, "Supply-chain pinning was checked: "+joinMax(assessed, 5)+".",
			"Pinning shows a fixed version. It does not show that the version is trustworthy.",
			"No vulnerability or provenance lookup was made. The scan is offline.")
	}
}

func plural(n int, one, many string) string {
	if n == 1 {
		return "1 " + one
	}
	return itoa(n) + " " + many
}

func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	var b []byte
	for n > 0 {
		b = append([]byte{byte('0' + n%10)}, b...)
		n /= 10
	}
	return string(b)
}

// ---------------------------------------------------------------------------
// AGC-015 Context Memory Integrity
// ---------------------------------------------------------------------------

var specSharedMemory = findingSpec{
	Slug: "shared-memory-write", Severity: model.SeverityMedium, Confidence: model.ConfidenceLow,
	Title: "Model or tool output is written to shared memory without a check",
	Why: "Everything the agent remembers is stored in one shared place and nothing checks it first. " +
		"One user's data can surface in another user's session. A planted instruction can also be saved and steer later runs.",
	Remediation: []string{
		"Store memory under a per-user or per-tenant namespace.",
		"Validate content before it is saved.",
		"Record where each memory came from and set a retention period.",
	},
}

var (
	memWriteFnRe = regexp.MustCompile(`(?i)^(save|store|write|add|put|append|update|remember|upsert|set|persist)`)
	memWordRe    = regexp.MustCompile(`(?i)memor|remember|recall`)
	nsParamRe    = regexp.MustCompile(`(?i)^(user_?id|tenant_?id|namespace|session|session_?id|principal|owner|owner_?id|ctx|context|thread_?id|actor)$`)
	validateRe   = regexp.MustCompile(`(?i)\b\w*(validat|sanitiz|verify|screen|is_safe|check_|allowed|reject)\w*\s*\(|\braise\b|\bthrow\b`)
	rawParamRe   = regexp.MustCompile(`(?i)^(output|response|result|content|message|text|value|data|item|entry|fact|memory)$`)
)

func runMemory(c *Context, o *out) {
	if !c.has(model.CapMemory) {
		return
	}
	found, violated := false, false
	seen := 0
	for _, x := range c.funcs() {
		inMemoryCtx := memWordRe.MatchString(x.f.Name) || memWordRe.MatchString(x.f.Class) || memWordRe.MatchString(path.Base(x.src.Path))
		t := x.src.TraitsIn(x.f.Line, x.f.EndLine)
		if !(inMemoryCtx && memWriteFnRe.MatchString(x.f.Name)) && !t.VectorWrite {
			continue
		}
		if x.f.Name == "__init__" {
			continue
		}
		seen++
		code := x.code()
		ns := ""
		for _, p := range x.f.Params {
			if nsParamRe.MatchString(p.Name) && len(regexp.MustCompile(`\b`+regexp.QuoteMeta(p.Name)+`\b`).FindAllStringIndex(code, -1)) >= 2 {
				ns = p.Name
			}
		}
		if ns == "" && regexp.MustCompile(`\bnamespace\s*=`).MatchString(code) {
			ns = "namespace"
		}
		validated := validateRe.MatchString(code)
		switch {
		case ns != "" && validated:
			o.present(x.src.Path, x.f.Line, "The memory write "+x.f.Name+" is keyed by \""+ns+"\" and validates content before it is stored.",
				"The scanner did not test cross-user access or memory poisoning. Attach an isolation test.")
			found = true
		case ns == "":
			raw := false
			for _, p := range x.f.Params {
				if rawParamRe.MatchString(p.Name) {
					raw = true
				}
			}
			if raw && !validated {
				ref := o.violation(x.src.Path, x.f.Line, "The memory write "+x.f.Name+" stores content in a shared namespace with no validation.")
				o.finding(specSharedMemory, x.src.Path, x.f.Line, "fn:"+x.f.Name,
					"The function "+x.f.Name+" at "+at(x.src.Path, x.f.Line)+" writes to memory with no user or tenant key and no validation step.", ref)
				violated = true
			}
		}
	}
	if !found && !violated {
		if seen == 0 {
			return // memory is handled by a framework the scanner cannot see into
		}
		o.absent("Memory writes exist, but none is both namespaced by user or tenant and validated before storage.")
	}
}

// ---------------------------------------------------------------------------
// AGC-016 Authenticated Inter-Agent Messages
// ---------------------------------------------------------------------------

var (
	msgAuthRe = regexp.MustCompile(`\bhmac\s*\.\s*(compare_digest|new)\b|\bjwt\s*\.\s*(decode|verify)\s*\(|\bcreateHmac\s*\(|\btimingSafeEqual\s*\(|\bCERT_REQUIRED\b|\bload_cert_chain\s*\(|\brequestCert\s*:\s*true|\bload_verify_locations\s*\(`)
	msgCtxRe  = regexp.MustCompile(`(?i)message|agent|envelope|a2a|handoff|peer|inbox|receive|verify`)
)

func runInterAgent(c *Context, o *out) {
	if !c.has(model.CapMultiAgent) {
		return
	}
	for _, x := range c.funcs() {
		code := x.code()
		if msgAuthRe.MatchString(code) && (msgCtxRe.MatchString(x.f.Name) || msgCtxRe.MatchString(path.Base(x.src.Path))) {
			o.present(x.src.Path, x.lineOf(msgAuthRe, code), "The function "+x.f.Name+" verifies a signature, token, or peer certificate on inter-agent traffic.",
				"The scanner did not test replay protection or recipient checks. Attach a test with a forged message.")
			return
		}
	}
	for _, d := range c.Agent.Docs() {
		for _, e := range d.Entries {
			if strings.HasSuffix(e.Path, "securitySchemes") || strings.Contains(e.Path, "securitySchemes.") {
				o.present(d.Path, e.Line, "An agent card declares security schemes for agent-to-agent calls.",
					"A declared scheme is configuration. Attach a test with an unauthenticated call.")
				return
			}
		}
	}
	o.absent("The agent exchanges messages with other agents, but no message authentication was found. Plain message passing does not satisfy this control.")
}

// ---------------------------------------------------------------------------
// AGC-017 Instant Agent Kill Switch
// ---------------------------------------------------------------------------

var specBooleanKill = findingSpec{
	Slug: "kill-flag-not-external", Severity: model.SeverityMedium, Confidence: model.ConfidenceMedium,
	Title: "The kill flag does not prove termination",
	Why: "The stop flag lives inside the running program and nothing outside can change it. " +
		"When the agent misbehaves, an operator has no way to flip the flag. The only option left is to kill the whole process by hand.",
	Remediation: []string{
		"Read the stop signal from a place an operator can change: a file, a shared store, or an admin endpoint.",
		"Check it before every model call and every tool call.",
		"Test that the agent stops within a set time after the signal.",
	},
}

var (
	killNameRe      = regexp.MustCompile(`(?i)(kill|halt|stop|shutdown|cancel|abort|emergency|pause)[a-z_]*(switch|flag|signal|requested|event|token)?|should_stop|is_killed|is_halted`)
	killModuleFlag  = regexp.MustCompile(`(?m)^([A-Z_]*(KILL|HALT|STOP|SHUTDOWN|ABORT)[A-Z_]*)\s*(?::[^=\n]+)?=\s*(False|True|false|true)\b`)
	externalSrcRe   = regexp.MustCompile(`\bos\s*\.\s*path\s*\.\s*exists\s*\(|\.exists\s*\(|\.is_file\s*\(|\bopen\s*\(|\.read_text\s*\(|\bos\s*\.\s*(environ|getenv)\b|\.is_set\s*\(|\bredis\b|\.get\s*\(|\bsignal\s*\.\s*signal\s*\(|\.cancelled\s*\(|\.cancel\s*\(|\bCancellationToken|AbortSignal|\.aborted\b|existsSync\s*\(|readFileSync\s*\(|process\.env\b|\.fetchone\s*\(|\bexecute\s*\(`)
	signalHandlerRe = regexp.MustCompile(`\bsignal\s*\.\s*signal\s*\(|\.add_signal_handler\s*\(|AbortController\s*\(`)
	killLimit       = "A check in code does not prove the agent stops in time. Attach a test that sets the signal during a run and measures the result."
)

func runKillSwitch(c *Context, o *out) {
	loops := c.loopFuncs()
	dispatch := c.dispatchFuncs()
	if len(loops) == 0 && len(dispatch) == 0 {
		// Framework-managed loop: look for signal handlers or cancellation only.
		if len(c.grepCode(signalHandlerRe)) > 0 {
			return // a handler exists, but its link to the agent loop cannot be seen: unknown
		}
		if c.Agent.Agent.Detection == model.Detected {
			o.absent("No stop signal check was found. The agent loop is managed by a framework, and no cancellation hook, signal handler, or external stop check was found around it.",
				"The scanner cannot see inside framework run loops.")
		}
		return
	}
	found := false
	// A check inside the loop or dispatch path whose source is external.
	for _, x := range append(append([]fn{}, loops...), dispatch...) {
		for _, call := range callsIn(x) {
			if !killNameRe.MatchString(call.Name) {
				continue
			}
			ts, tf := c.Agent.ResolveFunc(x.src, call)
			if tf == nil {
				continue
			}
			target := fn{ts, tf}
			ext := false
			for _, y := range c.withCallees([]fn{target}, 2) {
				if externalSrcRe.MatchString(y.code()) {
					ext = true
				}
			}
			if ext {
				o.present(x.src.Path, call.Line, "The function "+x.f.Name+" calls "+tf.Name+" before each step. That check reads a stop signal from outside the process ("+ts.Path+").", killLimit,
					"Active tool calls and issued credentials may outlive the stop signal.")
				found = true
			}
		}
		// Inline check: if os.path.exists(KILL_FILE): break
		code := x.code()
		for _, m := range regexp.MustCompile(`\bif\b[^\n]*`).FindAllStringIndex(code, -1) {
			cond := code[m[0]:m[1]]
			if killNameRe.MatchString(cond) && externalSrcRe.MatchString(cond) && rejectAfter(code, m[1]) {
				o.present(x.src.Path, x.src.LineOf(x.f.Start+m[0]), "The function "+x.f.Name+" checks an external stop signal inside its loop and stops when it is set.", killLimit)
				found = true
			}
		}
	}
	if found {
		return
	}
	// A module-level boolean that is never refreshed from outside.
	for _, s := range c.sources() {
		for _, m := range killModuleFlag.FindAllStringSubmatchIndex(s.Code, -1) {
			name := s.Code[m[2]:m[3]]
			line := s.LineOf(m[0])
			ref := o.ev(model.SignalDeclared, model.StrengthDeclared, s.Path, line,
				"A module-level flag named "+name+" exists, but nothing re-reads it from a source an operator can change.",
				"A Boolean flag does not prove termination.")
			o.finding(specBooleanKill, s.Path, line, "flag:"+name,
				"The flag "+name+" at "+at(s.Path, line)+" is a constant inside the process. Flag does not prove termination: no file, store, signal, or endpoint can set it while the agent runs.", ref)
			found = true
		}
	}
	if found {
		return
	}
	if len(loops) > 0 {
		o.absent("An agent loop exists, but it has no stop signal check before model or tool calls.",
			"The scanner looks for a check that reads a file, store, environment value, signal, or cancellation token inside the loop or dispatch path.")
		return
	}
	o.absent("Tools are dispatched, but no stop signal check was found before tool execution.")
}

// ---------------------------------------------------------------------------
// AGC-018 Reversible Action Design
// ---------------------------------------------------------------------------

var (
	idemRe       = regexp.MustCompile(`(?i)\bidempotency_?key\b|\bidem_?key\b|\bdedup(e|lication)?_?key\b`)
	idemTextRe   = regexp.MustCompile(`(?i)Idempotency-Key`)
	rollbackRe   = regexp.MustCompile(`\.\s*rollback\s*\(|\bROLLBACK\b|\btransaction\s*\(|\batomic\s*\(|\.begin\s*\(|\bwith\s+[\w.]*(conn|connection|db|session)[\w.]*\s*:`)
	compensateRe = regexp.MustCompile(`(?i)^(compensate|undo|revert|reverse|rollback)_?\w*`)
)

func runReversible(c *Context, o *out) {
	if !c.has(model.CapMutatingActions) {
		return
	}
	var parts []string
	file, line := "", 0
	note := func(p, f string, l int) {
		parts = append(parts, p)
		if file == "" {
			file, line = f, l
		}
	}
	if hs := c.grepCode(idemRe); len(hs) > 0 {
		note("idempotency keys", hs[0].src.Path, hs[0].line)
	} else if hs := c.grepText(idemTextRe); len(hs) > 0 {
		note("an Idempotency-Key header", hs[0].src.Path, hs[0].line)
	}
	if hs := c.grepCode(rollbackRe); len(hs) > 0 {
		note("transactions with rollback", hs[0].src.Path, hs[0].line)
	}
	for _, x := range c.funcs() {
		if compensateRe.MatchString(x.f.Name) {
			note("a compensation handler ("+x.f.Name+")", x.src.Path, x.f.Line)
			break
		}
	}
	if len(parts) > 0 {
		o.present(file, line, "Reversibility mechanisms were found: "+strings.Join(parts, ", ")+".",
			"The scanner did not confirm that every mutating tool uses them. Attach a compensation or duplicate-request test.")
		return
	}
	o.absent("The agent has mutating tools, but no idempotency key, transaction with rollback, or compensation handler was found.",
		"Actions that cannot be reversed need approval and a recorded risk treatment instead.")
}

// ---------------------------------------------------------------------------
// AGC-019 Dedicated Incident Runbook
// ---------------------------------------------------------------------------

var runbookPathRe = regexp.MustCompile(`(?i)(^|/)(docs/runbooks?/[^/]+\.(md|markdown|rst|txt)|runbooks?/[^/]+\.(md|markdown|rst|txt)|incident[^/]*\.(md|markdown|rst)|runbook[^/]*\.(md|markdown|rst))$`)

func runRunbook(c *Context, o *out) {
	sections := []struct{ name, re string }{
		{"owner", `(?i)\bowner`}, {"escalation", `(?i)escalat`}, {"containment", `(?i)contain`},
		{"revocation", `(?i)revo(ke|cation)`}, {"recovery", `(?i)recover`},
	}
	best, bestMissing := "", []string(nil)
	for _, p := range c.Agent.Paths() {
		if !runbookPathRe.MatchString(p) {
			continue
		}
		txt, ok := c.fileText(p)
		if !ok {
			continue
		}
		var missing []string
		for _, s := range sections {
			if !regexp.MustCompile(s.re).MatchString(txt) {
				missing = append(missing, s.name)
			}
		}
		if best == "" || len(missing) < len(bestMissing) {
			best, bestMissing = p, missing
		}
	}
	switch {
	case best == "":
		o.absent("No incident runbook was found. The scanner looked for docs/runbooks, INCIDENT*.md, and RUNBOOK*.md.")
	case len(bestMissing) <= 1:
		o.declared(best, 0, "An incident runbook exists and covers owner, escalation, containment, revocation, and recovery.",
			"File presence is weak evidence; attach exercise results.",
			"The scanner read section keywords only. It did not judge whether the procedure is current or correct.")
	default:
		o.absent("A runbook file exists at "+best+", but these expected sections were not found: "+strings.Join(bestMissing, ", ")+".",
			"File presence is weak evidence; attach exercise results.")
	}
}

// ---------------------------------------------------------------------------
// AGC-020 Mandatory Regression Evals and AGC-021 Continuous Red Teaming
// ---------------------------------------------------------------------------

var (
	denialAssertRe = regexp.MustCompile(`(?i)(assertRaises|pytest\s*\.\s*raises|assertFalse|assert\s+not\b|assertIn|assertEqual|\.toThrow|\.rejects|expect\s*\()`)
	denialWordRe   = regexp.MustCompile(`(?i)(den(y|ied|ial)|forbid|reject|unauthori[sz]ed|not[_ ]allowed|blocked|PermissionError|Forbidden|refus)`)
	advNameRe      = regexp.MustCompile(`(?i)(injection|jailbreak|adversarial|red_?team|poison)`)
	anyAssertRe    = regexp.MustCompile(`(?i)\bassert\w*\b|\bexpect\s*\(`)
)

func (c *Context) testSources() []*adapters.Source {
	var out []*adapters.Source
	for _, s := range c.Agent.Sources {
		if c.Agent.IsTest(s.Path) {
			out = append(out, s)
		}
	}
	return out
}

func runRegressionEvals(c *Context, o *out) {
	tests := c.testSources()
	testsPath := ""
	if c.Config != nil {
		testsPath = strings.Trim(strings.ReplaceAll(c.Config.Verification.TestsPath, "\\", "/"), "/")
	}
	var gov *adapters.Source
	n := 0
	for _, s := range tests {
		if denialAssertRe.MatchString(s.Code) && (denialWordRe.MatchString(s.Code) || denialWordRe.MatchString(s.Text)) {
			n++
			if gov == nil || (testsPath != "" && strings.Contains("/"+s.Path, "/"+testsPath+"/") && !strings.Contains("/"+gov.Path, "/"+testsPath+"/")) {
				gov = s
			}
		}
	}
	if len(tests) == 0 {
		o.absent("No test files were found for this agent.")
		return
	}
	if gov == nil {
		return // tests exist, but the scanner cannot tell whether they cover forbidden behavior
	}
	if w, e, ok := c.ciTestRun(); ok {
		o.present(gov.Path, 0, plural(n, "test file asserts", "test files assert")+" that forbidden behavior is denied, and the CI workflow "+w.doc.Path+" runs tests (line "+itoa(e.Line)+").",
			"The scanner did not run these tests. Attach test results as evidence to reach tested maturity.")
		return
	}
	o.absent("Governance tests exist ("+gov.Path+"), but no CI job was found that runs them on code changes.",
		"The scanner did not run these tests.")
}

func runRedTeam(c *Context, o *out) {
	limit := "The scanner did not run the adversarial scenarios. Attach their results as evidence."
	for _, d := range c.Agent.Docs() {
		base := strings.ToLower(path.Base(d.Path))
		if strings.HasPrefix(base, "promptfoo") && (d.Has("redteam") || len(d.Match(regexp.MustCompile(`^redteam\b`))) > 0) {
			o.present(d.Path, d.Line("redteam"), "A promptfoo red-team configuration is present.", limit)
			return
		}
		if strings.Contains(base, "garak") || strings.Contains(base, "pyrit") {
			o.present(d.Path, 0, "An adversarial evaluation configuration is present.", limit)
			return
		}
	}
	for _, dep := range c.Agent.Deps() {
		if dep.Name == "garak" || dep.Name == "pyrit" || dep.Name == "giskard" || dep.Name == "promptfoo" || dep.Name == "deepteam" {
			o.present(dep.Path, dep.Line, "The adversarial testing tool "+dep.Name+" is a declared dependency.", limit,
				"A dependency alone does not show which scenarios run.")
			return
		}
	}
	for _, s := range c.testSources() {
		nameHit := advNameRe.MatchString(path.Base(s.Path))
		for i := range s.Funcs {
			if advNameRe.MatchString(s.Funcs[i].Name) {
				nameHit = true
			}
		}
		if nameHit && anyAssertRe.MatchString(s.Code) {
			o.present(s.Path, 0, "Adversarial tests with assertions are present (prompt injection, jailbreak, or poisoning scenarios).", limit)
			return
		}
	}
	if c.Agent.Agent.Detection == model.Detected {
		o.absent("No adversarial evaluation was found. The scanner looked for promptfoo red-team, garak, PyRIT, and giskard configurations and for tests named for injection or jailbreak scenarios.")
	}
}

// ---------------------------------------------------------------------------
// AGC-022 Complete Step Tracing
// ---------------------------------------------------------------------------

var specRawLogging = findingSpec{
	Slug: "raw-sensitive-logging", Severity: model.SeverityMedium, Confidence: model.ConfidenceMedium,
	Title: "Prompts, outputs, or credentials are written to logs without redaction",
	Why: "Prompts and model outputs often contain personal or confidential data, and credentials give access to systems. " +
		"Once they are in a log, everyone who can read the log can read them.",
	Remediation: []string{
		"Remove the raw value from the log statement.",
		"Log an identifier, a length, or a hash instead.",
		"Apply a redaction filter to all agent logs by default.",
	},
}

var specCredLogging = findingSpec{
	Slug: "credential-logging", Severity: model.SeverityHigh, Confidence: model.ConfidenceMedium,
	Title: "A credential is written to logs",
	Why: "The log line includes a key, token, or password. Logs are copied to many systems and kept for a long time. " +
		"Anyone with log access can take the credential and use it.",
	Remediation: []string{
		"Remove the credential from the log statement.",
		"Rotate the credential, because it may already be in stored logs.",
		"Apply a redaction filter to all agent logs by default.",
	},
}

var (
	logCallRe    = regexp.MustCompile(`^(print|pprint|console\.(log|info|debug|warn|error)|(logger|logging|log|LOG|LOGGER|self\.logger|self\.log)\.(info|debug|warning|warn|error|critical|exception|log))$`)
	promptVarRe  = regexp.MustCompile(`\b(prompt|prompts|system_prompt|user_prompt|full_prompt|messages|completion|llm_output|model_output|raw_output)\b`)
	credVarRe    = regexp.MustCompile(`(?i)\b\w*(api_?key|apikey|password|passwd|secret|access_?token|auth_?token|bearer|credentials?|authorization)\w*\b|\btoken\b`)
	tracingMods  = []string{"opentelemetry", "@opentelemetry/api", "@opentelemetry/sdk-node", "@opentelemetry/sdk-trace-node", "langsmith", "langfuse", "openinference", "phoenix", "arize", "logfire", "agentops", "mlflow", "weave", "traceloop"}
	spanCallRe   = regexp.MustCompile(`\b(start_as_current_span|start_span|startActiveSpan|startSpan|get_tracer|getTracer|traceable|observe|CallbackHandler|instrument|set_tracer_provider|LangChainInstrumentor|configure)\b`)
	traceCtxRe   = regexp.MustCompile(`(?i)trac|span|telemetry|record_step`)
	runIDRe      = regexp.MustCompile(`(?i)\b(run_?id|trace_?id|span_?id|correlation_?id)\b`)
	toolKeyRe    = regexp.MustCompile(`(?i)["']tool(_?name)?["']|\btool(_?name)?\s*=`)
	sinkRe       = regexp.MustCompile(`\bjson\s*\.\s*dumps\s*\(|\.write\s*\(|\b(logger|logging|log)\s*\.\s*\w+\s*\(|\.append\s*\(|\bemit\s*\(|JSON\.stringify\s*\(|console\.\w+\s*\(`)
	tracingLimit = "Tracing code exists. A complete trace needs a synthetic end-to-end run that links a step to its tool call."
)

func runTracing(c *Context, o *out) {
	found, violated := false, false
	if _, _, ok := c.hasImport(tracingMods...); ok {
		// Require a usage site, not just the import.
		for _, h := range c.grepCode(spanCallRe) {
			o.present(h.src.Path, h.line, "The code creates trace spans or configures a tracing integration ("+strings.TrimSpace(h.text)+").", tracingLimit)
			found = true
			break
		}
	}
	for pass := 0; pass < 2 && !found; pass++ {
		for _, x := range c.funcs() {
			code, text := x.code(), x.text()
			if pass == 0 && !traceCtxRe.MatchString(x.f.Name+" "+path.Base(x.src.Path)) {
				continue
			}
			if (runIDRe.MatchString(code) || runIDRe.MatchString(text)) && toolKeyRe.MatchString(text) && sinkRe.MatchString(code) {
				o.present(x.src.Path, x.f.Line, "The function "+x.f.Name+" writes a structured step record with a run or trace ID and the tool name.", tracingLimit,
					"The scanner did not confirm that every step and tool call is recorded.")
				found = true
				break
			}
		}
	}
	c.calls(func(s *adapters.Source, call adapters.Call) {
		if !logCallRe.MatchString(call.Name) {
			return
		}
		args := s.ArgsCode(call)
		switch {
		case credVarRe.MatchString(args) && !strings.Contains(args, "redact") && !strings.Contains(args, "mask") && !strings.Contains(args, "len("):
			ref := o.violation(s.Path, call.Line, "A log statement includes a credential variable.")
			o.finding(specCredLogging, s.Path, call.Line, "", "The log statement at "+at(s.Path, call.Line)+" writes a credential variable to the log.", ref)
			violated = true
		case promptVarRe.MatchString(args) && !strings.Contains(args, "redact") && !strings.Contains(args, "len("):
			ref := o.violation(s.Path, call.Line, "A log statement writes a raw prompt or model output.")
			o.finding(specRawLogging, s.Path, call.Line, "", "The log statement at "+at(s.Path, call.Line)+" writes prompt or message content to the log without redaction.", ref)
			violated = true
		}
	})
	if !found && !violated && c.Agent.Agent.Detection == model.Detected {
		o.absent("No step tracing was found. The scanner looked for OpenTelemetry spans, tracing integrations, and structured step records with a run ID and tool name.")
	}
}

// ---------------------------------------------------------------------------
// AGC-023 Tamper-Evident Audit Trail
// ---------------------------------------------------------------------------

var (
	chainRe    = regexp.MustCompile(`(?i)\b(prev(ious)?_?(hash|digest)|last_?(hash|digest)|chain_?(hash|head)|hash_?chain|parent_?hash)\b`)
	hashCallRe = regexp.MustCompile(`\bhashlib\s*\.\s*\w+\s*\(|\bsha256\s*\(|\bcreateHash\s*\(|\bhmac\s*\.\s*new\s*\(|\bcreateHmac\s*\(|\.sign\s*\(`)
	auditCtxRe = regexp.MustCompile(`(?i)audit|ledger|journal|record|append|log|event`)
	wormRe     = regexp.MustCompile(`(?i)object_?lock|ObjectLockConfiguration|ObjectLockEnabled|immutab|\bWORM\b|append_?only|qldb`)
	plainLogRe = regexp.MustCompile(`\b(logging|logger|console)\s*\.\s*\w+\s*\(|\bprint\s*\(`)
)

func runAuditTrail(c *Context, o *out) {
	limit := "The scanner did not alter a record to test detection. Attach a tamper test."
	for _, x := range c.funcs() {
		code := x.code()
		ctx := auditCtxRe.MatchString(x.f.Name) || auditCtxRe.MatchString(path.Base(x.src.Path)) || auditCtxRe.MatchString(x.f.Class)
		hashed := hashCallRe.MatchString(code)
		for _, callee := range c.callees(x) {
			hashed = hashed || hashCallRe.MatchString(callee.code())
		}
		if ctx && hashed && (chainRe.MatchString(code) || chainRe.MatchString(x.text())) && sinkRe.MatchString(code) {
			o.present(x.src.Path, x.f.Line, "The function "+x.f.Name+" writes audit records that include the hash of the previous record (hash chain).", limit,
				"A hash chain detects edits only when someone verifies it and the chain head is stored safely.")
			return
		}
	}
	for _, x := range c.funcs() {
		code := x.code()
		if regexp.MustCompile(`(?i)audit`).MatchString(x.f.Name+" "+path.Base(x.src.Path)) && regexp.MustCompile(`\bhmac\s*\.\s*new\s*\(|\bcreateHmac\s*\(|\.sign\s*\(`).MatchString(code) {
			o.present(x.src.Path, x.f.Line, "The function "+x.f.Name+" signs audit records.", limit)
			return
		}
	}
	for _, d := range c.Agent.Docs() {
		for _, e := range d.Entries {
			if wormRe.MatchString(e.Path) || (e.Kind == 's' && len(e.Value) < 200 && wormRe.MatchString(e.Value) && strings.Contains(strings.ToLower(e.Path), "log")) {
				o.present(d.Path, e.Line, "Storage configuration enables object lock, immutability, or append-only mode.", limit,
					"The scanner cannot confirm that agent audit records are written to this store.")
				return
			}
		}
	}
	if c.Agent.Agent.Detection != model.Detected {
		return
	}
	if len(c.grepCode(plainLogRe)) > 0 {
		o.absent("Only plain logging was found. Plain application logs are not tamper-evident.",
			"The scanner looks for hash-chained or signed records and for append-only or object-lock storage configuration.")
		return
	}
	o.absent("No audit trail was found. The scanner looked for hash-chained or signed records and for append-only or object-lock storage configuration.")
}

// ---------------------------------------------------------------------------
// AGC-024 Real-Time Operational Monitoring
// ---------------------------------------------------------------------------

var (
	promAlertRe   = regexp.MustCompile(`(^|\.)groups\[\d+\]\.rules\[\d+\]\.(alert|expr|title|condition)$`)
	agentSignalRe = regexp.MustCompile(`(?i)agent|tool|polic|denied|deny|llm|token|approval|kill|guardrail|model`)
	tfAlertRe     = regexp.MustCompile(`resource\s+"(datadog_monitor|aws_cloudwatch_metric_alarm|google_monitoring_alert_policy|azurerm_monitor_metric_alert|grafana_rule_group)"`)
)

func runMonitoring(c *Context, o *out) {
	limit := "Static rules are not a passing runtime assessment. Attach evidence that a synthetic signal raised an alert."
	rulesFile, refFile, refLine := "", "", 0
	for _, d := range c.Agent.Docs() {
		isAlertDoc := false
		for _, e := range d.Entries {
			switch {
			case promAlertRe.MatchString(e.Path):
				isAlertDoc = true
			case e.Kind == 's' && (e.Value == "AWS::CloudWatch::Alarm" || e.Value == "PrometheusRule"):
				isAlertDoc = true
			case strings.HasSuffix(e.Path, "type") && e.Kind == 's' && (strings.HasSuffix(e.Value, " alert") || e.Value == "metric alert" || e.Value == "query alert" || e.Value == "log alert") && d.Has(strings.TrimSuffix(e.Path, "type")+"query"):
				isAlertDoc = true
			}
		}
		if !isAlertDoc {
			continue
		}
		if rulesFile == "" {
			rulesFile = d.Path
		}
		for _, e := range d.Entries {
			if e.Kind == 's' && agentSignalRe.MatchString(e.Value) && refFile == "" {
				refFile, refLine = d.Path, e.Line
			}
		}
	}
	for _, p := range c.Agent.Paths() {
		if !strings.HasSuffix(p, ".tf") {
			continue
		}
		if txt, ok := c.fileText(p); ok && tfAlertRe.MatchString(txt) {
			if rulesFile == "" {
				rulesFile = p
			}
			if agentSignalRe.MatchString(txt) && refFile == "" {
				refFile = p
			}
		}
	}
	switch {
	case refFile != "":
		o.present(refFile, refLine, "Alert rules are defined and refer to agent signals such as tool activity, policy denials, or token use.", limit)
	case rulesFile != "":
		o.absent("Alert rules exist in "+rulesFile+", but none refers to agent signals such as tool activity, policy denials, or token use.", limit)
	case c.Agent.Agent.Detection == model.Detected:
		o.absent("No alert rules or monitors were found. The scanner looked for Prometheus rules, Grafana alerts, Datadog monitors, and CloudWatch alarms.",
			"Monitoring defined outside this repository is not visible to the scanner.")
	}
}
