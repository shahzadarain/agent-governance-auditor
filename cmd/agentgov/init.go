// SPDX-License-Identifier: Apache-2.0

package main

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"

	"github.com/spf13/cobra"

	"github.com/shahzadarain/agent-governance-auditor/internal/config"
	"github.com/shahzadarain/agent-governance-auditor/internal/model"
	"github.com/shahzadarain/agent-governance-auditor/internal/scanner"
)

func newInitCmd() *cobra.Command {
	var yes, force, withWorkflow bool
	var profile string
	cmd := &cobra.Command{
		Use:   "init [path]",
		Short: "Create a starter .agentgov.yaml (and optionally a CI workflow)",
		Long: `Create a starter .agentgov.yaml for the agent in this folder.

init looks at the folder first, so the file starts with what was actually
detected: the agent, its tools, and a suggested risk tier. It asks a few
short questions and writes a commented file you can edit.

Existing files are never overwritten unless you pass --force.`,
		Example: `  agentgov init
  agentgov init --yes --with-workflow
  agentgov init ./services/support-agent`,
		Args: cobra.MaximumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			target := "."
			if len(args) == 1 {
				target = args[0]
			}
			return runInit(cmd, target, yes, force, withWorkflow, profile)
		},
	}
	cmd.Flags().BoolVarP(&yes, "yes", "y", false, "accept detected defaults without asking")
	cmd.Flags().BoolVar(&force, "force", false, "overwrite existing files")
	cmd.Flags().BoolVar(&withWorkflow, "with-workflow", false, "also write .github/workflows/agentgov.yml")
	cmd.Flags().StringVar(&profile, "profile", "", "risk profile to record: baseline, standard, high-risk")
	return cmd
}

var slugRe = regexp.MustCompile(`[^a-z0-9]+`)

func slugify(s string) string {
	s = strings.Trim(slugRe.ReplaceAllString(strings.ToLower(s), "-"), "-")
	if s == "" {
		return "my-agent"
	}
	return s
}

func runInit(cmd *cobra.Command, target string, yes, force, withWorkflow bool, profile string) error {
	out := cmd.OutOrStdout()
	root, err := filepath.Abs(target)
	if err != nil {
		return err
	}
	if info, err := os.Stat(root); err != nil || !info.IsDir() {
		return fmt.Errorf("%s is not a folder", target)
	}
	cfgPath := filepath.Join(root, config.FileName)
	if _, err := os.Stat(cfgPath); err == nil && !force {
		return fmt.Errorf("%s already exists; edit it, or pass --force to replace it", cfgPath)
	}

	// Look at the folder without any existing configuration influencing the result.
	fmt.Fprintf(out, "Looking at %s (read-only) ...\n", target)
	var res *model.ScanResult
	if scanned, err := scanner.Scan(cmd.Context(), scanner.Options{Root: root, Version: version}); err == nil {
		res = scanned
	}

	id := slugify(filepath.Base(root))
	tier := "medium"
	var tools, sensitive []string
	if res != nil && len(res.Agents) > 0 {
		a := res.Agents[0]
		if a.ID != "" {
			id = slugify(a.ID)
		}
		if t := a.InferredRiskTier; t == "low" || t == "medium" || t == "high" {
			tier = t
		}
		for _, t := range a.Tools {
			tools = append(tools, t.Name)
			if t.Sensitive {
				sensitive = append(sensitive, t.Name)
			}
		}
		fmt.Fprintf(out, "Detected agent %q (%s, %s) with %d tool(s). Suggested risk tier: %s.\n",
			a.ID, a.Framework, a.Language, len(a.Tools), tier)
		if len(res.Agents) > 1 {
			fmt.Fprintf(out, "Note: %d agents were detected. This file describes the first one; add the others under \"agents:\".\n", len(res.Agents))
		}
	} else {
		fmt.Fprintln(out, "No AI agent was detected. The file will describe an agent you declare by hand.")
	}
	sort.Strings(tools)
	sort.Strings(sensitive)

	owner := "REPLACE-with-owning-team"
	description := "REPLACE with one sentence about what this agent does"
	classification := "internal"
	if !yes {
		id = slugify(ask("Agent ID", id))
		owner = ask("Owning team or person", owner)
		description = ask("What does the agent do (one sentence)", description)
		tier = pick(ask("Risk tier (low, medium, high)", tier), []string{"low", "medium", "high"}, tier)
		classification = pick(ask("Data classification (public, internal, confidential, restricted)", classification),
			[]string{"public", "internal", "confidential", "restricted"}, classification)
	}
	if profile == "" {
		profile = map[string]string{"low": "baseline", "medium": "standard", "high": "high-risk"}[tier]
	}

	content := renderConfig(id, owner, description, tier, classification, profile, tools, sensitive)
	if diags := config.Validate([]byte(content)); len(diags) > 0 {
		return errors.New("internal error: generated configuration did not validate: " + strings.Join(diags, "; "))
	}
	if err := writeFileAtomic(cfgPath, []byte(content)); err != nil {
		return err
	}
	fmt.Fprintf(out, "Wrote %s\n", cfgPath)

	if !withWorkflow && !yes {
		withWorkflow = confirm("Add a GitHub Actions workflow that scans every pull request?", false)
	}
	if withWorkflow {
		wfPath := filepath.Join(root, ".github", "workflows", "agentgov.yml")
		if _, err := os.Stat(wfPath); err == nil && !force {
			fmt.Fprintf(out, "Skipped %s: it already exists (pass --force to replace it).\n", wfPath)
		} else {
			if err := writeFileAtomic(wfPath, []byte(workflowTemplate)); err != nil {
				return err
			}
			fmt.Fprintf(out, "Wrote %s\n", wfPath)
		}
	}

	fmt.Fprintln(out, "\nNext steps:")
	fmt.Fprintln(out, "  1. Open .agentgov.yaml and replace any REPLACE values.")
	fmt.Fprintln(out, "  2. Run: agentgov scan .")
	fmt.Fprintln(out, "  3. Run: agentgov explain <control-id> for any control you want to understand.")
	fmt.Fprintln(out, "\nRemember: this file is a declaration. It tells the auditor what to expect.")
	fmt.Fprintln(out, "It is not evidence that a control works. Evidence comes from code, tests, and operations.")
	return nil
}

func pick(value string, allowed []string, def string) string {
	value = strings.ToLower(strings.TrimSpace(value))
	for _, a := range allowed {
		if a == value {
			return a
		}
	}
	return def
}

func yamlString(s string) string {
	s = strings.ReplaceAll(s, `\`, `\\`)
	s = strings.ReplaceAll(s, `"`, `\"`)
	s = strings.Map(func(r rune) rune {
		if r < 0x20 {
			return ' '
		}
		return r
	}, s)
	return `"` + s + `"`
}

func yamlList(items []string, indent string) string {
	if len(items) == 0 {
		return " []\n"
	}
	var b strings.Builder
	b.WriteString("\n")
	for _, it := range items {
		b.WriteString(indent + "- " + yamlString(it) + "\n")
	}
	return b.String()
}

func renderConfig(id, owner, description, tier, classification, profile string, tools, sensitive []string) string {
	var b strings.Builder
	b.WriteString("# AgentGov Auditor configuration.\n")
	b.WriteString("# This file declares what the agent is and what it may do. A declaration is\n")
	b.WriteString("# not evidence: controls are verified from code, tests, and operations.\n")
	b.WriteString("# Reference: docs/policy-reference.md    Check it: agentgov policy validate\n")
	b.WriteString("schema_version: \"1\"\n\n")
	b.WriteString("agent:\n")
	b.WriteString("  id: " + yamlString(id) + "\n")
	b.WriteString("  owner: " + yamlString(owner) + "            # the accountable team or person\n")
	b.WriteString("  description: " + yamlString(description) + "\n")
	b.WriteString("  risk_tier: " + tier + "                 # low | medium | high\n")
	b.WriteString("  data_classification: " + classification + "   # public | internal | confidential | restricted\n\n")
	b.WriteString("capabilities:\n")
	b.WriteString("  # Tools the agent is allowed to use. Detected tools that are missing here are reported.\n")
	b.WriteString("  declared_tools:" + yamlList(tools, "    "))
	b.WriteString("  # Tools that change records, move money, delete, send, or execute. These need approval gates.\n")
	b.WriteString("  sensitive_actions:" + yamlList(sensitive, "    "))
	b.WriteString("\nverification:\n")
	b.WriteString("  profile: " + profile + "               # baseline | standard | high-risk\n")
	b.WriteString("  tests_path: tests/governance\n")
	b.WriteString("  evidence_paths:\n    - .agentgov/evidence\n")
	b.WriteString("\npolicy:\n")
	b.WriteString("  pack: builtin/v1\n")
	b.WriteString("  # You can add mandatory controls or raise the minimum maturity here.\n")
	b.WriteString("  # You cannot remove or lower what the profile or an organization baseline requires.\n")
	b.WriteString("  mandatory_controls: []\n")
	return b.String()
}

// workflowTemplate is the workflow written by `agentgov init --with-workflow`.
// It needs no secrets and no paid service, and it never runs repository code.
const workflowTemplate = `# AgentGov Auditor: scan every pull request and push to the default branch.
# The scan is read-only and offline. It needs no secrets.
name: AgentGov

on:
  pull_request:
  push:
    branches: [main]

permissions:
  contents: read

jobs:
  agentgov:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@3d3c42e5aac5ba805825da76410c181273ba90b1 # v7.0.1
        with:
          persist-credentials: false
      # For production use, replace "main" with a full commit SHA of the action.
      - uses: shahzadarain/agent-governance-auditor@main
        with:
          path: .
          fail_on: block
`
