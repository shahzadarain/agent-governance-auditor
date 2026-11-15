// SPDX-License-Identifier: Apache-2.0

package rules

import (
	"path"
	"regexp"
	"strings"

	"github.com/shahzadarain/agent-governance-auditor/internal/config"
	"github.com/shahzadarain/agent-governance-auditor/internal/model"
)

func init() {
	register("AGC-001", "owner-inventory", runOwnerInventory)
	register("AGC-002", "risk-tier", runRiskTier)
	register("AGC-003", "change-control", runChangeControl)
}

func (c *Context) configPath() string {
	if c.Config != nil && c.Config.Path != "" {
		return c.Config.Path
	}
	return config.FileName
}

func isConfigFile(p string) bool {
	b := path.Base(p)
	return b == config.FileName || b == ".agentgov.yml"
}

var specUndeclaredTool = findingSpec{
	Slug: "undeclared-tool", Severity: model.SeverityMedium, Confidence: model.ConfidenceMedium,
	Title: "A tool exists in code but is missing from the declared inventory",
	Why: "The inventory tells reviewers what the agent can do. A tool that is not listed was never reviewed. " +
		"It can give the agent abilities that nobody approved.",
	Remediation: []string{
		"Decide whether the agent needs this tool.",
		"If it does, add it to capabilities.declared_tools in .agentgov.yaml and have the owner review it.",
		"If it does not, remove the tool from the code.",
	},
}

var specIncompleteDeclaration = findingSpec{
	Slug: "incomplete-declaration", Severity: model.SeverityLow, Confidence: model.ConfidenceHigh,
	Title: "The agent declaration is incomplete",
	Why: "Without a named owner, a purpose, and a risk tier, nobody is clearly accountable for the agent. " +
		"Problems take longer to route and fix.",
	Remediation: []string{
		"Add the missing fields to the agent section of .agentgov.yaml.",
		"Ask the named owner to confirm the entry.",
	},
}

func runOwnerInventory(c *Context, o *out) {
	if c.malformedInScope(isConfigFile) {
		o.ev(model.SignalError, model.StrengthDeclared, c.configPath(), 0,
			"The configuration file is malformed. The declaration could not be read.")
		return
	}
	ca := c.Agent.ConfigAgent
	if c.Config == nil || ca == nil {
		o.absent("No declaration was found for this agent. The scanner looked for an agent entry with an identifier, owner, purpose, and risk tier in .agentgov.yaml.",
			"A declaration is the starting point only. Stronger evidence is a registry record or a signed owner attestation.")
		return
	}
	var missing []string
	if ca.ID == "" {
		missing = append(missing, "id")
	}
	if ca.Owner == "" {
		missing = append(missing, "owner")
	}
	if ca.Purpose == "" && ca.Description == "" {
		missing = append(missing, "purpose or description")
	}
	if ca.RiskTier == "" {
		missing = append(missing, "risk_tier")
	}
	file := c.configPath()
	if ca.ID == "" && ca.Owner == "" {
		o.absent("The configuration has an agent entry, but it names neither an identifier nor an owner.")
		return
	}
	summary := "The configuration declares the agent identifier, owner, purpose, and risk tier."
	if len(missing) > 0 {
		summary = "The configuration declares the agent, but these fields are missing: " + strings.Join(missing, ", ") + "."
	}
	ref := o.declared(file, 0, summary,
		"A declared owner is a string in a file. It does not prove that the owner exists or has accepted responsibility.",
		"Attach a registry record or a signed owner attestation to raise this control above declared.")
	if len(missing) > 0 {
		o.finding(specIncompleteDeclaration, file, 0, "agent:"+strings.Join(missing, ","),
			"The agent entry in "+file+" is missing: "+strings.Join(missing, ", ")+".", ref)
	}
	if len(c.Config.Capabilities.DeclaredTools) > 0 {
		for _, t := range c.Agent.Agent.Tools {
			if !t.Declared {
				o.finding(specUndeclaredTool, t.Location.Path, t.Location.Line, "tool:"+t.Name,
					"The tool \""+t.Name+"\" was detected at "+at(t.Location.Path, t.Location.Line)+" but capabilities.declared_tools does not list it.", ref)
			}
		}
	}
}

var tierRank = map[string]int{"low": 1, "medium": 2, "high": 3}

var specTierMismatch = findingSpec{
	Slug: "declared-tier-too-low", Severity: model.SeverityHigh, Confidence: model.ConfidenceMedium,
	Title: "Declared tier lower than detected capabilities",
	Why: "The risk tier decides how strict the checks are. If the tier is set too low, the agent is held to rules " +
		"meant for a much safer system. Dangerous abilities then go without the review they need.",
	Remediation: []string{
		"Review the detected capabilities listed in this finding.",
		"Raise agent.risk_tier in .agentgov.yaml to match them, or remove the capabilities.",
		"If a lower tier is correct, have an authorized governance reviewer record the reason as an exception.",
	},
}

func runRiskTier(c *Context, o *out) {
	if c.malformedInScope(isConfigFile) {
		return
	}
	ca := c.Agent.ConfigAgent
	if ca == nil || strings.TrimSpace(ca.RiskTier) == "" {
		o.absent("No risk tier is declared for this agent. The scanner looked for agent.risk_tier in .agentgov.yaml.")
		return
	}
	declared := strings.ToLower(strings.TrimSpace(ca.RiskTier))
	inferred := c.Agent.Agent.InferredRiskTier
	file := c.configPath()
	dr, okD := tierRank[declared]
	ir, okI := tierRank[inferred]
	if !okD {
		o.declared(file, 0, "A risk tier is declared, but its value is not one of low, medium, or high.")
		return
	}
	if okI && dr < ir {
		caps := strings.Join(c.Agent.Agent.Capabilities, ", ")
		ref := o.violation(file, 0, "The declared risk tier is "+declared+", but the detected capabilities suggest "+inferred+" ("+caps+").",
			"The inferred tier is a heuristic based on detected capabilities.")
		o.finding(specTierMismatch, file, 0, "risk_tier:"+declared+"<"+inferred,
			"The configuration declares risk tier \""+declared+"\". The scanner detected these capabilities: "+caps+". They suggest tier \""+inferred+"\".", ref)
		return
	}
	if strings.TrimSpace(ca.RiskRationale) != "" {
		o.declared(file, 0, "The configuration declares risk tier "+declared+" with a written rationale. The tier is not lower than the detected capabilities suggest.",
			"The scanner cannot confirm that an authorized reviewer approved the tier.")
		return
	}
	o.declared(file, 0, "The configuration declares risk tier "+declared+" without a written rationale.",
		"Add agent.risk_rationale so reviewers can see why the tier was chosen.",
		"The scanner cannot confirm that an authorized reviewer approved the tier.")
}

var codeownersPathRe = regexp.MustCompile(`(?i)prompt|polic|tool|agent|\.agentgov`)

func runChangeControl(c *Context, o *out) {
	workflows := c.ciWorkflows()
	codeowners := ""
	for _, p := range c.Agent.Paths() {
		if path.Base(p) == "CODEOWNERS" {
			if txt, ok := c.fileText(p); ok {
				for _, line := range strings.Split(txt, "\n") {
					line = strings.TrimSpace(line)
					if line != "" && !strings.HasPrefix(line, "#") && codeownersPathRe.MatchString(strings.Fields(line)[0]) {
						codeowners = p
					}
				}
			}
		}
	}
	if w, e, ok := c.ciTestRun(); ok {
		summary := "A CI workflow runs on code changes and runs tests or the auditor."
		if codeowners != "" {
			summary += " A CODEOWNERS file covers agent, prompt, policy, or tool paths."
		}
		o.present(w.doc.Path, e.Line, summary,
			"This is the workflow definition only. Attach CI run records and approvals to show that it runs and gates releases.")
		return
	}
	isWorkflow := func(p string) bool {
		return strings.Contains("/"+p, workflowDir) || strings.HasPrefix(path.Base(p), ".gitlab-ci") || strings.HasPrefix(path.Base(p), "azure-pipelines")
	}
	if c.malformedInScope(isWorkflow) {
		return // a workflow exists but could not be parsed: unknown, not missing
	}
	if len(workflows) == 0 {
		o.absent("No CI workflow was found. The scanner looked for GitHub Actions, GitLab CI, Azure Pipelines, and CircleCI files.")
		return
	}
	o.absent("CI workflow files exist, but none runs tests or the auditor on push or pull request.")
}
