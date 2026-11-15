// SPDX-License-Identifier: Apache-2.0

package rules

import (
	"regexp"
	"strings"

	"github.com/shahzadarain/agent-governance-auditor/internal/adapters"
	"github.com/shahzadarain/agent-governance-auditor/internal/model"
)

func init() {
	register("AGC-007", "data-layer-identity", runDataLayer)
	register("AGC-009", "policy-engine", runPolicyEngine)
	register("AGC-010", "approval-gate", runApproval)
	register("AGC-011", "guardrails", runGuardrails)
	register("AGC-012", "resource-limits", runLimits)
}

// ---------------------------------------------------------------------------
// AGC-007 User-Enforced Data Layer
// ---------------------------------------------------------------------------

var specSQLFromArgs = findingSpec{
	Slug: "sql-built-from-arguments", Severity: model.SeverityCritical, Confidence: model.ConfidenceHigh,
	Title: "A data tool builds SQL text from its arguments",
	Why: "The model chooses the tool arguments, and those arguments become part of the SQL text. " +
		"A crafted request can change the query to read or change other people's records.",
	Remediation: []string{
		"Use parameterized queries. Pass values as parameters and never join them into the SQL text.",
		"Take the user identity from the authenticated session, not from tool arguments.",
		"Add a filter on that identity to every query.",
	},
	Repro: "Read the query at the reported line and note which tool arguments reach the SQL text.",
}

var specModelIdentity = findingSpec{
	Slug: "identity-supplied-by-model", Severity: model.SeverityHigh, Confidence: model.ConfidenceMedium,
	Title: "Identity supplied by the model",
	Why: "The tool accepts the user or tenant identifier as an ordinary argument. The model fills in tool arguments, " +
		"so it can ask for any user's data. The data layer cannot tell who is really asking.",
	Remediation: []string{
		"Remove the identity parameter from the tool signature the model sees.",
		"Pass the identity from the authenticated session inside trusted code.",
		"Filter every query by that identity.",
	},
}

var (
	scalarIdentRe   = regexp.MustCompile(`(?i)^(user_?id|tenant_?id|owner_?id|org_?id|organization_?id|account_?id|user_?name|user|tenant|principal_?id)$`)
	trustedCtxRe    = regexp.MustCompile(`(?i)^(session|ctx|context|principal|identity|actor|current_user|request|caller|auth|user_ctx|run_?context)$`)
	identFilterRe   = regexp.MustCompile(`(?i)\b(user_?id|tenant_?id|owner_?id|owner|org_?id|account_?id|principal|namespace)\b`)
	placeholderSQL  = regexp.MustCompile(`\?|%s|:\w+|\$\d+`)
	whereRe         = regexp.MustCompile(`(?i)\bWHERE\b`)
	filterKwargRe   = regexp.MustCompile(`(?i)\b(filter|where|filter_by|metadata_filter|namespace|filters)\s*=`)
	sqlConcatAfter  = regexp.MustCompile(`^\s*(\+|%\s*[\w(]|\.\s*format\s*\()`)
	sqlConcatBefore = regexp.MustCompile(`\+\s*[frbFRB]{0,2}$`)
)

// dataFuncs returns the data-access tools' functions and their callees that
// touch a database or vector store.
func (c *Context) dataFuncs() (toolFns []fn, all []fn) {
	for i, t := range c.Agent.Agent.Tools {
		tr := c.Agent.Tools[i]
		if tr.Fn == nil {
			continue
		}
		isData := false
		for _, cap := range t.Capabilities {
			if cap == model.CapDataAccess {
				isData = true
			}
		}
		if isData {
			toolFns = append(toolFns, fn{tr.Src, tr.Fn})
		}
	}
	for _, x := range c.withCallees(toolFns, 2) {
		t := x.src.TraitsIn(x.f.Line, x.f.EndLine)
		if t.DB || t.Vector {
			all = append(all, x)
		}
	}
	return toolFns, all
}

func runDataLayer(c *Context, o *out) {
	if !c.has(model.CapDataAccess) {
		return
	}
	toolFns, dataFns := c.dataFuncs()
	if len(toolFns) == 0 {
		return // data access exists but not through a recognized tool function: cannot tell
	}
	violated, found := false, false
	// SQL text built from arguments.
	for _, x := range dataFns {
		for _, lit := range x.src.Strings {
			if lit.Line < x.f.Line || lit.Line > x.f.EndLine || lit.Doc {
				continue
			}
			if !sqlAnyRe.MatchString(lit.Value) {
				continue
			}
			built := strings.Contains(lit.Prefix, "f") && strings.Contains(lit.Value, "{")
			if lit.Prefix == "`" && strings.Contains(lit.Value, "${") {
				built = true
			}
			after := lit.End + 1
			if after+3 <= len(x.src.Code) && strings.HasPrefix(x.src.Raw[lit.End:], `"""`) || strings.HasPrefix(x.src.Raw[lit.End:], `'''`) {
				after = lit.End + 3
			}
			if after < len(x.src.Code) && sqlConcatAfter.MatchString(x.src.Code[after:min(len(x.src.Code), after+24)]) {
				built = true
			}
			ls := x.src.LineStart(lit.Line)
			if lit.Start-1 > ls && sqlConcatBefore.MatchString(strings.TrimRight(x.src.Code[ls:lit.Start-1], " \t")) {
				built = true
			}
			if !built {
				continue
			}
			ref := o.violation(x.src.Path, lit.Line, "The function "+x.f.Name+" builds SQL text by inserting values into a string.")
			o.finding(specSQLFromArgs, x.src.Path, lit.Line, "",
				"At "+at(x.src.Path, lit.Line)+" the function "+x.f.Name+" builds an SQL statement with string formatting. The function is reachable from a tool the model can call.", ref)
			violated = true
		}
	}
	// Identity taken from model-controlled arguments.
	schemaText := ""
	for _, s := range c.sources() {
		if strings.Contains(s.Text, "parameters") || strings.Contains(s.Text, "input_schema") || strings.Contains(s.Text, "properties") {
			schemaText += s.Text
		}
	}
	for _, x := range toolFns {
		decorated := len(x.f.Decorators) > 0
		for _, p := range x.f.Params {
			if !scalarIdentRe.MatchString(p.Name) {
				continue
			}
			inSchema := strings.Contains(schemaText, `"`+p.Name+`"`) || strings.Contains(schemaText, `'`+p.Name+`'`)
			if !decorated && !inSchema {
				continue
			}
			ref := o.violation(x.src.Path, x.f.Line, "The data tool "+x.f.Name+" accepts the identity parameter "+p.Name+" as an argument the model supplies.")
			o.finding(specModelIdentity, x.src.Path, x.f.Line, "param:"+x.f.Name+"."+p.Name,
				"The tool function "+x.f.Name+" at "+at(x.src.Path, x.f.Line)+" takes \""+p.Name+"\" as a model-supplied argument. Identity supplied by the model cannot be trusted.", ref)
			violated = true
		}
	}
	// Identity from trusted context flowing into the query filter.
	for _, x := range dataFns {
		var ctxParam string
		for _, p := range x.f.Params {
			if trustedCtxRe.MatchString(p.Name) || (scalarIdentRe.MatchString(p.Name) && !isToolFn(toolFns, x)) {
				ctxParam = p.Name
				break
			}
		}
		if ctxParam == "" {
			continue
		}
		text, code := x.text(), x.code()
		identUsed := regexp.MustCompile(`\b`+regexp.QuoteMeta(ctxParam)+`\b`).FindAllStringIndex(code, -1)
		if len(identUsed) < 2 {
			continue // the parameter is never used in the body
		}
		sqlFiltered := false
		for _, lit := range x.src.Strings {
			if lit.Line >= x.f.Line && lit.Line <= x.f.EndLine && !lit.Doc && whereRe.MatchString(lit.Value) &&
				identFilterRe.MatchString(lit.Value) && placeholderSQL.MatchString(lit.Value) && !strings.Contains(lit.Prefix, "f") {
				sqlFiltered = true
			}
		}
		kwFiltered := filterKwargRe.MatchString(code) && identFilterRe.MatchString(text)
		if sqlFiltered || kwFiltered {
			o.present(x.src.Path, x.f.Line, "The data function "+x.f.Name+" receives the caller identity through \""+ctxParam+"\" and uses it in the query filter.",
				"Static analysis shows the identity reaches the query filter. It does not prove the identity is authentic or that every query is filtered.",
				"Attach a test in which one user tries to read another user's record.")
			found = true
		}
	}
	if !found && !violated {
		o.absent("The agent has data-access tools, but no query was found that filters by a caller identity taken from trusted context.",
			"The scanner recognizes SQL WHERE clauses with parameters and filter arguments. Other data layers need external evidence.")
	}
}

func isToolFn(tools []fn, x fn) bool {
	for _, t := range tools {
		if t.f == x.f {
			return true
		}
	}
	return false
}

// ---------------------------------------------------------------------------
// AGC-009 External Policy Engine
// ---------------------------------------------------------------------------

var specFailOpen = findingSpec{
	Slug: "policy-fail-open", Severity: model.SeverityHigh, Confidence: model.ConfidenceMedium,
	Title: "The tool runs even when the policy check fails with an error",
	Why: "When the policy check breaks, the code carries on and runs the tool. An attacker, or a simple outage, " +
		"can switch off the rules by making the check fail.",
	Remediation: []string{
		"Treat any error from the policy check as a denial.",
		"Stop the tool call and report the error.",
		"Add a test that makes the policy check fail and confirms the tool does not run.",
	},
}

var (
	policyCallRe    = regexp.MustCompile(`(?i)(polic|authori[sz]|is_allowed|check_permission|can_execute|permit|decide|evaluate_?(tool|action|request)|enforce)`)
	policyModRe     = regexp.MustCompile(`(?i)polic|authz|authori[sz]|guard|permission|opa|cedar|rego`)
	denyBranchRe    = regexp.MustCompile(`(?i)\bif\s+\(?\s*(not\s+|!\s*)[\w.()\[\]"' ]*(allow|decision|permit|authori[sz]|verdict|ok)|\bif\s+[\w.()\[\]"' ]*(decision|verdict|effect|result|allow\w*)[\w.()\[\]"' ]*\s*(!=|==|is\s+not|is)\s|\bif\s+[\w.]*\.?(denied|deny|is_denied)\b`)
	exceptRe        = regexp.MustCompile(`(?m)^([ \t]*)except\b[^\n]*:[ \t]*(\S[^\n]*)?$|\bcatch\s*(\([^)]*\))?\s*\{`)
	opaTextRe       = regexp.MustCompile(`/v1/data/|\bopa\s+eval\b`)
	opaSymRe        = regexp.MustCompile(`\b(OpaClient|OPAClient|is_authorized|isAuthorized|check_policy_rule|evaluatePolicy)\b`)
	promptPolicyRe  = regexp.MustCompile(`(?i)\b(you must (never|not)|do not|never)\b[^"'\n]{0,80}\b(delete|transfer|refund|pay|approve|without (approval|permission)|policy)`)
	setsDenyRe      = regexp.MustCompile(`(?i)\bFalse\b|\bfalse\b|deny|denied|reject|block`)
	failOpenBodyRe  = regexp.MustCompile(`(?i)^\s*(pass|continue)\s*$|\b(allow\w*|permitted|authorized|ok|decision)\s*=\s*(True|true|"allow"|'allow')`)
	stopsExecRe     = regexp.MustCompile(`\b(raise|return|throw)\b|\bdeny\w*\s*\(`)
	denyReturnRe    = regexp.MustCompile(`(?i)return\s+(False|false|None|"deny"|'deny'|\w*deny\w*\s*\(|\w*Decision\s*\(\s*(False|allowed\s*=\s*False|"deny"|'deny'|effect\s*=\s*["']deny)|\{\s*["']?allow(ed)?["']?\s*:\s*(False|false))`)
	policyOnlyLimit = "The scanner did not run the policy. Attach tests for allow, deny, error, and unavailable-policy cases."
)

// exceptBlocks returns the text of each except/catch body in a function.
func exceptBlocks(x fn) []struct {
	line int
	body string
} {
	var out []struct {
		line int
		body string
	}
	code := x.code()
	for _, m := range exceptRe.FindAllStringSubmatchIndex(code, -1) {
		line := x.src.LineOf(x.f.Start + m[0])
		body := ""
		if x.src.Lang == adapters.LangPython {
			indent := m[3] - m[2]
			if m[4] >= 0 {
				body = code[m[4]:m[5]] + "\n"
			}
			for ln := line + 1; ln <= x.f.EndLine; ln++ {
				cl := x.src.CodeLine(ln)
				trim := strings.TrimLeft(cl, " \t")
				if trim == "" {
					continue
				}
				if len(cl)-len(trim) <= indent {
					break
				}
				body += cl + "\n"
			}
		} else {
			open := strings.LastIndex(code[m[0]:m[1]], "{") + m[0]
			depth := 0
			for i := open; i < len(code); i++ {
				if code[i] == '{' {
					depth++
				} else if code[i] == '}' {
					depth--
					if depth == 0 {
						body = code[open+1 : i]
						break
					}
				}
			}
		}
		out = append(out, struct {
			line int
			body string
		}{line, body})
	}
	return out
}

func runPolicyEngine(c *Context, o *out) {
	found, violated := false, false
	// External engines.
	if s, line, ok := c.hasImport("opa_client", "opa", "cedarpy", "cedar", "casbin", "oso", "@open-policy-agent/opa", "@open-policy-agent/opa-wasm",
		"@cedar-policy/cedar-wasm", "@permitio/permit-js", "permit"); ok {
		o.present(s.Path, line, "The code imports an external policy engine client.", policyOnlyLimit,
			"Confirm that every sensitive tool call passes through the engine before it runs.")
		found = true
	}
	for _, h := range c.grepText(opaTextRe) {
		if strings.TrimSpace(h.src.CodeLine(h.line)) == "" {
			continue
		}
		o.present(h.src.Path, h.line, "The code queries an Open Policy Agent decision endpoint.", policyOnlyLimit)
		found = true
		break
	}
	// Local deterministic policy module called from the dispatch path.
	path := c.withCallees(append(c.dispatchFuncs(), c.sensitiveToolFuncs()...), 1)
	checked := map[*adapters.Func]bool{}
	for _, x := range path {
		if checked[x.f] {
			continue
		}
		checked[x.f] = true
		code := x.code()
		var policyCall *adapters.Call
		var target fn
		for _, call := range callsIn(x) {
			if !policyCallRe.MatchString(call.Name) && !opaSymRe.MatchString(call.Name) {
				continue
			}
			ts, tf := c.Agent.ResolveFunc(x.src, call)
			if tf == nil || tf == x.f {
				continue
			}
			if !(policyModRe.MatchString(ts.Path) || policyCallRe.MatchString(tf.Name)) {
				continue
			}
			cc := call
			policyCall, target = &cc, fn{ts, tf}
			break
		}
		if policyCall == nil {
			continue
		}
		// Fail-open: an except block around the dispatch that neither stops
		// nor denies.
		failOpen := false
		for _, b := range exceptBlocks(x) {
			if b.line < policyCall.Line {
				continue
			}
			if !stopsExecRe.MatchString(b.body) && !setsDenyRe.MatchString(b.body) && b.line-policyCall.Line <= 8 {
				ref := o.violation(x.src.Path, b.line, "The function "+x.f.Name+" catches an error from the policy check and continues.")
				o.finding(specFailOpen, x.src.Path, b.line, "",
					"At "+at(x.src.Path, b.line)+" the function "+x.f.Name+" catches a failure of the policy check and still proceeds to run the tool.", ref)
				failOpen, violated = true, true
			}
		}
		if failOpen {
			continue
		}
		hasDeny := denyBranchRe.MatchString(code)
		raisesInPolicy := strings.Contains(target.code(), "raise ") || strings.Contains(target.code(), "throw ")
		if !hasDeny && !raisesInPolicy {
			continue // the decision is never checked
		}
		summary := "The function " + x.f.Name + " calls the policy decision function " + target.f.Name + " (" + target.src.Path + ") before running a tool and stops when the decision is not allow."
		defaultDeny := false
		for _, b := range exceptBlocks(target) {
			if denyReturnRe.MatchString(b.body) || strings.Contains(b.body, "raise") {
				defaultDeny = true
			}
		}
		for _, b := range exceptBlocks(x) {
			if stopsExecRe.MatchString(b.body) {
				defaultDeny = true
			}
		}
		limits := []string{policyOnlyLimit}
		if defaultDeny {
			summary += " An error in the policy check leads to a denial."
		} else {
			limits = append(limits, "No explicit error handler was found. An exception stops the call, which fails closed, but this is not tested here.")
		}
		o.present(x.src.Path, policyCall.Line, summary, limits...)
		found = true
	}
	if found || violated || !c.has(model.CapSensitiveActions) {
		return
	}
	for _, s := range c.sources() {
		for _, lit := range s.Strings {
			if !lit.Doc && len(lit.Value) > 40 && promptPolicyRe.MatchString(lit.Value) {
				o.absent("Sensitive actions exist and the only policy found is prompt text at "+at(s.Path, lit.Line)+". A system-prompt instruction is not a policy engine: the model can ignore it.",
					"The scanner recognizes OPA, Cedar, and local policy modules called from the dispatch path.")
				return
			}
		}
	}
	o.absent("Sensitive actions exist, but no policy enforcement point was found before tool execution.",
		"The scanner recognizes OPA, Cedar, and local policy modules called from the dispatch path.")
}

// ---------------------------------------------------------------------------
// AGC-010 Human Approval Gates
// ---------------------------------------------------------------------------

var specAutoApprove = findingSpec{
	Slug: "auto-approve", Severity: model.SeverityCritical, Confidence: model.ConfidenceHigh,
	Title: "A sensitive action is approved automatically",
	Why: "The step where a person should say yes is switched off or set to yes by default. " +
		"The agent can move money, delete data, or send messages with no human decision.",
	Remediation: []string{
		"Remove the automatic approval flag or default.",
		"Require an approval record created by an authorized person before the action runs.",
		"Bind the approval to the exact action, its parameters, an expiry time, and a single-use request ID.",
	},
	Repro: "Read the tool signature at the reported line and check the default value of the approval parameter.",
}

var (
	approvalParamRe  = regexp.MustCompile(`(?i)^(approved|is_approved|approval|confirmed|auto_?approve|auto_?confirm|skip_?approval|bypass_?approval|no_?confirm|force|pre_?approved)$`)
	requireParamRe   = regexp.MustCompile(`(?i)^(require_?approval|needs_?approval|ask_?approval|require_?confirmation|human_in_the_loop)$`)
	autoApproveFlag  = regexp.MustCompile(`(?i)\b(auto_?approve\w*|skip_?approval|bypass_?approval|auto_?confirm)\s*[=:]\s*(True|true|1)\b|\b(require_?approval|needs_?approval|needsApproval|human_input)\s*[=:]\s*(False|false)\b`)
	approvalFieldRe  = regexp.MustCompile(`(?i)\b(action|tool|tool_name|request_id|nonce|actor|approver|jti)\b`)
	approvalExpiryRe = regexp.MustCompile(`(?i)\b(expires?_?(at|on)?|expiry|exp|not_after|valid_until|deadline)\b[^\n]{0,60}(<|>)|(<|>)[^\n]{0,60}\b(expires?_?(at|on)?|expiry|exp|not_after|valid_until)\b`)
	approvalDigestRe = regexp.MustCompile(`(?i)compare_digest|timingSafeEqual|\b(params?_digest|args_digest|digest|signature|sig|mac)\b[^\n]{0,60}(==|!=)|(==|!=)[^\n]{0,60}\b(params?_digest|args_digest|digest|signature)\b|\.verify\s*\(`)
	approvalWordRe   = regexp.MustCompile(`(?i)approv`)
	compareRe        = regexp.MustCompile(`(==|!=)`)
	frameworkGates   = []string{"interrupt_before", "interrupt_after", "interruptBefore", "interruptAfter", "needs_approval", "needsApproval", "requires_approval", "human_input_mode", "requireApproval"}
	approvalLimit    = "Binding and replay protection need a test to confirm."
)

func runApproval(c *Context, o *out) {
	if !c.has(model.CapSensitiveActions) {
		return
	}
	found, violated := false, false
	c.calls(func(s *adapters.Source, call adapters.Call) {
		for _, k := range frameworkGates {
			if !call.HasKwarg(k) || !adapters.ImportsAgentFramework(s) {
				continue
			}
			v, _ := s.KwargText(call, k)
			lv := strings.ToLower(strings.TrimSpace(v))
			if lv == "false" || lv == "none" || lv == "[]" || lv == `"never"` || lv == `'never'` || lv == "null" {
				continue
			}
			o.present(s.Path, call.Line, "The call to "+call.Last()+" sets "+k+", a framework approval or interrupt gate.", approvalLimit,
				"The scanner did not confirm that every sensitive tool is behind the gate.")
			found = true
		}
		if call.HasKwarg("human_input") && adapters.ImportsAgentFramework(s) {
			if v, _ := s.KwargText(call, "human_input"); strings.TrimSpace(v) == "True" {
				o.present(s.Path, call.Line, "A task sets human_input=True, which pauses for a human decision.", approvalLimit)
				found = true
			}
		}
		if call.Last() == "interrupt" && strings.HasPrefix(call.Module, "langgraph") {
			o.present(s.Path, call.Line, "The code calls the LangGraph interrupt function to pause for a human decision.", approvalLimit)
			found = true
		}
		if call.Module != "" && (call.Last() == "ApprovalRequired" || call.Last() == "DeferredToolRequests" || call.Last() == "HumanApprovalCallbackHandler") {
			o.present(s.Path, call.Line, "The code uses a framework approval mechanism ("+call.Last()+").", approvalLimit)
			found = true
		}
	})
	// A verification function that binds the approval to the action.
	execPath := c.withCallees(append(c.sensitiveToolFuncs(), c.dispatchFuncs()...), 2)
	for _, x := range execPath {
		code := x.code()
		if !approvalWordRe.MatchString(code) {
			continue
		}
		identity := false
		for _, m := range approvalFieldRe.FindAllStringIndex(code, -1) {
			ls := strings.LastIndex(code[:m[0]], "\n") + 1
			le := strings.Index(code[m[0]:], "\n")
			if le < 0 {
				le = len(code) - m[0]
			}
			if compareRe.MatchString(code[ls:m[0]+le]) || strings.Contains(code[ls:m[0]+le], " in ") {
				identity = true
				break
			}
		}
		expiry := approvalExpiryRe.MatchString(code)
		digest := approvalDigestRe.MatchString(code)
		if identity && (expiry || digest) {
			var parts []string
			parts = append(parts, "action or request identity")
			if expiry {
				parts = append(parts, "expiry")
			}
			if digest {
				parts = append(parts, "a digest or signature")
			}
			o.present(x.src.Path, x.f.Line, "The function "+x.f.Name+" is on the path of a sensitive tool and checks an approval for "+strings.Join(parts, ", ")+".", approvalLimit)
			found = true
		}
	}
	// Approval switched off or defaulting to approved.
	for _, x := range c.sensitiveToolFuncs() {
		for _, p := range x.f.Params {
			d := strings.TrimSpace(p.Default)
			if (approvalParamRe.MatchString(p.Name) && (d == "True" || d == "true")) || (requireParamRe.MatchString(p.Name) && (d == "False" || d == "false")) {
				ref := o.violation(x.src.Path, x.f.Line, "The sensitive tool "+x.f.Name+" has the parameter "+p.Name+" with a default that skips human approval.")
				o.finding(specAutoApprove, x.src.Path, x.f.Line, "param:"+x.f.Name+"."+p.Name,
					"The sensitive tool "+x.f.Name+" at "+at(x.src.Path, x.f.Line)+" declares \""+p.Name+"="+d+"\". The action runs without a human decision unless the caller overrides it.", ref)
				violated = true
			}
		}
	}
	for _, h := range c.grepCode(autoApproveFlag) {
		if f := h.src.FuncAt(h.line); f != nil && f.Line == h.line {
			continue // already reported as a parameter default
		}
		ref := o.violation(h.src.Path, h.line, "An automatic-approval flag is enabled, or the approval requirement is switched off.")
		o.finding(specAutoApprove, h.src.Path, h.line, "",
			"At "+at(h.src.Path, h.line)+" a flag enables automatic approval or disables the approval requirement while the agent has sensitive tools.", ref)
		violated = true
	}
	if !found && !violated {
		o.absent("The agent has sensitive tools, but no human approval gate was found on their execution path.",
			"A function that is only named approve is not counted. The scanner looks for checks on action identity plus expiry or a digest, and for framework interrupts.")
	}
}

// ---------------------------------------------------------------------------
// AGC-011 Dual Content Guardrails
// ---------------------------------------------------------------------------

var specPromptInterpolation = findingSpec{
	Slug: "untrusted-content-in-system-prompt", Severity: model.SeverityMedium, Confidence: model.ConfidenceMedium,
	Title: "Retrieved or tool content is inserted into the system prompt",
	Why: "Text from documents, web pages, or tools can contain instructions written by someone else. " +
		"When that text is placed in the system prompt, the model can treat it as orders.",
	Remediation: []string{
		"Keep retrieved and tool content out of the system prompt.",
		"Pass it as clearly marked data in a separate message.",
		"Validate tool results against a schema before the model sees them.",
	},
}

var (
	guardKwargs      = []string{"input_guardrails", "output_guardrails", "output_type", "result_type", "response_format", "output_schema", "response_model", "inputGuardrails", "outputGuardrails", "outputType", "experimental_output", "guardrails"}
	guardFnRe        = regexp.MustCompile(`(?i)(validat|sanitiz|guard|screen|filter|redact|scrub|check)\w*_?(input|output|result|content|args|arguments|response|message|text)|^(input|output)_guard`)
	untrustedVarRe   = regexp.MustCompile(`(?i)\{[^}]*\b(tool_?(result|output)|retriev\w*|docs?|documents?|observation|search_results?|web_?(content|page)|scraped\w*|page_?(text|content))\b[^}]*\}`)
	systemAssignRe   = regexp.MustCompile(`(?i)\b\w*system\w*(_prompt|_message|prompt)?\s*(\+?=)|["']role["']\s*:\s*["']system["']|\binstructions\s*=|\bSystemMessage\s*\(`)
	guardLimitations = "Guardrail existence does not guarantee protection. Attach adversarial test results."
)

func runGuardrails(c *Context, o *out) {
	var sides []string
	file, line := "", 0
	note := func(side, f string, l int) {
		for _, s := range sides {
			if s == side {
				return
			}
		}
		sides = append(sides, side)
		if file == "" {
			file, line = f, l
		}
	}
	c.calls(func(s *adapters.Source, call adapters.Call) {
		for _, k := range guardKwargs {
			if call.HasKwarg(k) {
				side := "structured output (" + k + ")"
				if strings.Contains(strings.ToLower(k), "input") {
					side = "input guardrail (" + k + ")"
				} else if strings.Contains(strings.ToLower(k), "output_guard") || strings.Contains(k, "outputGuard") {
					side = "output guardrail (" + k + ")"
				}
				note(side, s.Path, call.Line)
			}
		}
		if (call.Last() == "model_validate" || call.Last() == "model_validate_json" || call.Last() == "parse_obj" || call.Last() == "safeParse" ||
			call.Last() == "validate_python") && strings.Contains(call.Name, ".") {
			note("schema validation ("+call.Last()+")", s.Path, call.Line)
		}
	})
	if s, l, ok := c.hasImport("guardrails", "nemoguardrails", "llm_guard", "lakera_guard", "presidio_analyzer", "rebuff", "@openai/guardrails"); ok {
		note("guardrail library", s.Path, l)
	}
	// Project guard functions with a reject path that are actually called.
	for _, x := range c.funcs() {
		if !guardFnRe.MatchString(x.f.Name) || !rejectRe.MatchString(x.code()) {
			continue
		}
		called := false
		c.calls(func(s *adapters.Source, call adapters.Call) {
			if call.Last() == x.f.Name && !(s == x.src && call.Line == x.f.Line) {
				called = true
			}
		})
		if !called {
			continue
		}
		side := "output check (" + x.f.Name + ")"
		if regexp.MustCompile(`(?i)input|args|arguments`).MatchString(x.f.Name) {
			side = "input check (" + x.f.Name + ")"
		}
		note(side, x.src.Path, x.f.Line)
	}
	violated := false
	for _, s := range c.sources() {
		for _, lit := range s.Strings {
			if lit.Doc || !(strings.Contains(lit.Prefix, "f") || lit.Prefix == "`") || !untrustedVarRe.MatchString(lit.Value) {
				continue
			}
			stmt := s.CodeLine(lit.Line)
			if lit.Line > 1 {
				stmt = s.TextLine(lit.Line-1) + "\n" + s.TextLine(lit.Line)
			} else {
				stmt = s.TextLine(lit.Line)
			}
			if !systemAssignRe.MatchString(stmt) {
				continue
			}
			ref := o.violation(s.Path, lit.Line, "Retrieved or tool content is interpolated directly into a system prompt.")
			o.finding(specPromptInterpolation, s.Path, lit.Line, "",
				"At "+at(s.Path, lit.Line)+" a system prompt is built with retrieved or tool content inserted as text.", ref)
			violated = true
		}
	}
	if len(sides) > 0 {
		o.present(file, line, "Guardrail components were found: "+joinMax(sides, 6)+".", guardLimitations,
			"The scanner did not confirm that both inputs and outputs are covered on every path.")
		return
	}
	if !violated && c.Agent.Agent.Detection == model.Detected {
		o.absent("No input or output guardrail was found. The scanner looked for guardrail arguments, schema validation of results, guardrail libraries, and local validation functions with a reject path.")
	}
}

// ---------------------------------------------------------------------------
// AGC-012 Multi-Level Resource Limits
// ---------------------------------------------------------------------------

var specUnboundedLoop = findingSpec{
	Slug: "unbounded-loop", Severity: model.SeverityHigh, Confidence: model.ConfidenceMedium,
	Title: "The agent loop has no step, time, or cost limit",
	Why: "The loop keeps calling the model and tools until the model decides to stop. A confused or manipulated agent can run forever. " +
		"It can repeat a harmful action many times and run up a large bill.",
	Remediation: []string{
		"Add a maximum number of steps and stop when it is reached.",
		"Add a time limit and a token or cost budget.",
		"Check the limits inside the loop before every model or tool call.",
	},
}

var (
	limitKwargs = []string{"max_iterations", "recursion_limit", "max_turns", "max_steps", "max_iter", "max_execution_time", "timeout",
		"max_tokens", "max_consecutive_auto_reply", "maxSteps", "maxTokens", "stopWhen", "max_rpm", "usage_limits", "max_output_tokens",
		"max_completion_tokens", "maxTurns", "request_limit", "total_tokens_limit", "max_round", "timeout_seconds", "maxRetries"}
	limitKeyRe   = regexp.MustCompile(`["'](recursion_limit|max_iterations|max_steps|max_turns)["']\s*:`)
	stepBoundRe  = regexp.MustCompile(`(?i)\b\w*(steps?|iterations?|turns?|rounds?|attempts?|count|calls)\w*\s*(>=|>|<=|<)|(>=|>|<=|<)\s*\w*(max_?(steps?|iterations?|turns?|rounds?))\w*|\bfor\b[^\n]*\brange\s*\(`)
	timeBoundRe  = regexp.MustCompile(`(?i)\b(time\.(monotonic|time|perf_counter)\(\)|Date\.now\(\)|deadline|elapsed|timeout)\b[^\n]{0,80}(>=|>|<=|<)|(>=|>|<=|<)[^\n]{0,80}\b(deadline|elapsed|timeout|max_seconds)\b`)
	budgetRe     = regexp.MustCompile(`(?i)\b\w*(budget|tokens?_used|token_count|total_tokens|cost|spend|spent)\w*\s*(>=|>|<=|<)|(>=|>|<=|<)\s*[\w.]*(budget|max_tokens|max_cost|token_limit)\b`)
	limitsLimits = "The scanner did not run an over-limit request. Attach a test that exceeds each limit."
)

func runLimits(c *Context, o *out) {
	levels := map[string]bool{}
	file, line := "", 0
	note := func(level, f string, l int) {
		levels[level] = true
		if file == "" {
			file, line = f, l
		}
	}
	c.calls(func(s *adapters.Source, call adapters.Call) {
		for _, k := range limitKwargs {
			if !call.HasKwarg(k) {
				continue
			}
			if v, _ := s.KwargText(call, k); strings.TrimSpace(v) == "None" || strings.TrimSpace(v) == "null" {
				continue
			}
			lk := strings.ToLower(k)
			switch {
			case strings.Contains(lk, "token"):
				note("token limit ("+k+")", s.Path, call.Line)
			case strings.Contains(lk, "time"):
				note("time limit ("+k+")", s.Path, call.Line)
			default:
				note("step limit ("+k+")", s.Path, call.Line)
			}
		}
	})
	for _, h := range c.grepText(limitKeyRe) {
		if strings.TrimSpace(h.src.CodeLine(h.line)) != "" {
			note("step limit (configuration key)", h.src.Path, h.line)
		}
	}
	violated := false
	for _, x := range c.loopFuncs() {
		code := x.code()
		bounded := false
		if stepBoundRe.MatchString(code) {
			note("step limit in the loop of "+x.f.Name, x.src.Path, x.lineOf(stepBoundRe, code))
			bounded = true
		}
		if timeBoundRe.MatchString(code) {
			note("time limit in the loop of "+x.f.Name, x.src.Path, x.lineOf(timeBoundRe, code))
			bounded = true
		}
		if budgetRe.MatchString(code) {
			note("budget limit in the loop of "+x.f.Name, x.src.Path, x.lineOf(budgetRe, code))
			bounded = true
		}
		if !bounded {
			for _, callee := range c.callees(x) {
				cc := callee.code()
				if (stepBoundRe.MatchString(cc) || timeBoundRe.MatchString(cc) || budgetRe.MatchString(cc)) && rejectRe.MatchString(cc) {
					note("limit check in "+callee.f.Name+", called from the loop of "+x.f.Name, callee.src.Path, callee.f.Line)
					bounded = true
				}
			}
		}
		if !bounded && whileTrueRe.MatchString(code) {
			ln := x.lineOf(whileTrueRe, code)
			ref := o.violation(x.src.Path, ln, "The agent loop in "+x.f.Name+" runs until the model stops, with no step, time, or budget limit.")
			o.finding(specUnboundedLoop, x.src.Path, ln, "",
				"The loop at "+at(x.src.Path, ln)+" in "+x.f.Name+" calls the model or tools repeatedly and has no bound.", ref)
			violated = true
		}
	}
	if len(levels) > 0 {
		var names []string
		for k := range levels {
			names = append(names, k)
		}
		sortStrings(names)
		o.present(file, line, "Resource limits were found: "+joinMax(names, 6)+".", limitsLimits,
			"Not every level may be covered. Review step, time, token or cost, and spending limits together.")
		return
	}
	if !violated && c.Agent.Agent.Detection == model.Detected {
		o.absent("No step, time, token, or cost limit was found for the agent.")
	}
}

func sortStrings(s []string) {
	for i := 1; i < len(s); i++ {
		for j := i; j > 0 && s[j] < s[j-1]; j-- {
			s[j], s[j-1] = s[j-1], s[j]
		}
	}
}
