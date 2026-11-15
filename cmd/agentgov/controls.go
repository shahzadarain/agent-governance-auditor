// SPDX-License-Identifier: Apache-2.0

package main

import (
	"encoding/json"
	"fmt"
	"io"
	"os"
	"strings"
	"text/tabwriter"

	"github.com/spf13/cobra"

	"github.com/shahzadarain/agent-governance-auditor/internal/config"
	"github.com/shahzadarain/agent-governance-auditor/internal/controls"
	"github.com/shahzadarain/agent-governance-auditor/internal/model"
	"github.com/shahzadarain/agent-governance-auditor/internal/policy"
)

func normalizeControlID(arg string) string {
	id := strings.ToUpper(strings.TrimSpace(arg))
	id = strings.TrimPrefix(id, "AGC-")
	id = strings.TrimPrefix(id, "AGC")
	for len(id) < 3 {
		id = "0" + id
	}
	return "AGC-" + id
}

func newExplainCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "explain <control-id>",
		Short: "Explain one control in plain language",
		Example: `  agentgov explain AGC-010
  agentgov explain 10`,
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			return showControl(cmd.OutOrStdout(), args[0], false)
		},
	}
	return cmd
}

func newControlsCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "controls",
		Short: "List or show the 24 governance controls",
	}
	var asJSON bool
	list := &cobra.Command{
		Use:   "list",
		Short: "List all 24 controls by domain",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			cat, err := controls.Load()
			if err != nil {
				return err
			}
			out := cmd.OutOrStdout()
			if asJSON {
				enc := json.NewEncoder(out)
				enc.SetIndent("", "  ")
				return enc.Encode(cat)
			}
			fmt.Fprintf(out, "AgentGov control catalog %s, version %s\n", cat.Pack, cat.Version)
			fmt.Fprintln(out, "These controls are this project's own model. They are not an official standard or a certification.")
			domain := ""
			tw := tabwriter.NewWriter(out, 0, 4, 2, ' ', 0)
			for _, c := range cat.Controls {
				if c.Domain != domain {
					tw.Flush()
					domain = c.Domain
					fmt.Fprintf(out, "\n%s\n", domain)
					tw = tabwriter.NewWriter(out, 0, 4, 2, ' ', 0)
				}
				fmt.Fprintf(tw, "  %s\t%s\t%s\n", c.ID, c.Title, c.PlainLanguage)
			}
			tw.Flush()
			fmt.Fprintln(out, "\nDetails: agentgov explain AGC-010")
			return nil
		},
	}
	list.Flags().BoolVar(&asJSON, "json", false, "print the catalog as JSON")

	var showJSON bool
	show := &cobra.Command{
		Use:   "show <control-id>",
		Short: "Show the full definition of one control",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			return showControl(cmd.OutOrStdout(), args[0], showJSON)
		},
	}
	show.Flags().BoolVar(&showJSON, "json", false, "print the definition as JSON")
	cmd.AddCommand(list, show)
	return cmd
}

func showControl(out io.Writer, arg string, asJSON bool) error {
	cat, err := controls.Load()
	if err != nil {
		return err
	}
	id := normalizeControlID(arg)
	c, ok := controls.Find(cat, id)
	if !ok {
		return fmt.Errorf("no control %q; run \"agentgov controls list\" to see all 24", arg)
	}
	if asJSON {
		enc := json.NewEncoder(out)
		enc.SetIndent("", "  ")
		return enc.Encode(c)
	}
	printControl(out, c)
	return nil
}

func printControl(out io.Writer, c model.Control) {
	fmt.Fprintf(out, "%s  %s\n", c.ID, c.Title)
	fmt.Fprintf(out, "Domain: %s    Default severity: %s    Default weight: %d\n\n", c.Domain, c.Severity, c.DefaultWeight)
	section := func(title string) { fmt.Fprintf(out, "%s\n", strings.ToUpper(title)) }
	para := func(text string) {
		for _, line := range wrapText(strings.TrimSpace(text), 86) {
			fmt.Fprintf(out, "  %s\n", line)
		}
		fmt.Fprintln(out)
	}
	bullets := func(items []string, numbered bool) {
		for i, it := range items {
			prefix := "- "
			if numbered {
				prefix = fmt.Sprintf("%d. ", i+1)
			}
			lines := wrapText(strings.TrimSpace(it), 84)
			for j, line := range lines {
				if j == 0 {
					fmt.Fprintf(out, "  %s%s\n", prefix, line)
				} else {
					fmt.Fprintf(out, "  %s%s\n", strings.Repeat(" ", len(prefix)), line)
				}
			}
		}
		fmt.Fprintln(out)
	}

	section("In plain words")
	para(c.PlainLanguage)
	section("Why it exists")
	para(c.Intent)
	section("When it applies")
	if c.Applicability.Mode == "always" {
		para("Every agent. " + c.Applicability.Rationale)
	} else {
		para("Agents with any of these capabilities: " + strings.Join(c.Applicability.CapabilitiesAny, ", ") + ". " + c.Applicability.Rationale)
	}
	section("How it is verified")
	level := func(label, text string) {
		lines := wrapText(strings.TrimSpace(text), 60)
		for i, line := range lines {
			if i > 0 {
				label = ""
			}
			fmt.Fprintf(out, "  %-24s%s\n", label, line)
		}
	}
	level("Level 2, implemented:", c.VerificationRules.Implementation)
	level("Level 3, tested:", c.VerificationRules.Tested)
	level("Level 4, in operation:", c.VerificationRules.Operational)
	fmt.Fprintf(out, "  A static scan alone can support level %d at most.\n\n", c.VerificationRules.MaxStaticMaturity)
	section("How to fix")
	bullets(c.Remediation, true)
	if c.Examples.Positive != "" || c.Examples.Negative != "" {
		section("Examples")
		fmt.Fprintf(out, "  Good evidence: %s\n", strings.TrimSpace(c.Examples.Positive))
		fmt.Fprintf(out, "  Not evidence:  %s\n\n", strings.TrimSpace(c.Examples.Negative))
	}
	section("Limits of this check")
	bullets(c.Limitations, false)
	if len(c.StandardsMappings) > 0 {
		section("Related published standards (references only, not certification)")
		for _, m := range c.StandardsMappings {
			fmt.Fprintf(out, "  - %s %s, %s\n    %s\n", m.Standard, m.Version, m.RequirementID, m.URL)
		}
		fmt.Fprintln(out)
	}
}

// wrapText wraps text at word boundaries.
func wrapText(text string, width int) []string {
	words := strings.Fields(text)
	if len(words) == 0 {
		return []string{""}
	}
	var lines []string
	line := words[0]
	for _, w := range words[1:] {
		if len(line)+1+len(w) > width {
			lines = append(lines, line)
			line = w
			continue
		}
		line += " " + w
	}
	return append(lines, line)
}

func newPolicyCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "policy",
		Short: "Validate configuration and inspect risk profiles",
	}
	validate := &cobra.Command{
		Use:     "validate [file]",
		Short:   "Check that a .agentgov.yaml file is valid",
		Example: `  agentgov policy validate .agentgov.yaml`,
		Args:    cobra.MaximumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			path := config.FileName
			if len(args) == 1 {
				path = args[0]
			}
			info, err := os.Stat(path)
			if err != nil {
				return err
			}
			if info.Size() > 256<<10 {
				return fmt.Errorf("%s is larger than 256 KiB", path)
			}
			data, err := os.ReadFile(path)
			if err != nil {
				return err
			}
			diags := config.Validate(data)
			out := cmd.OutOrStdout()
			if len(diags) == 0 {
				fmt.Fprintf(out, "%s is valid.\n", path)
				return nil
			}
			fmt.Fprintf(out, "%s has %d problem(s):\n", path, len(diags))
			for _, d := range diags {
				fmt.Fprintf(out, "  - %s\n", d)
			}
			return fmt.Errorf("configuration is not valid")
		},
	}
	profiles := &cobra.Command{
		Use:   "profiles",
		Short: "Show the built-in risk profiles",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			out := cmd.OutOrStdout()
			fmt.Fprintln(out, "Built-in risk profiles (project defaults; edit through .agentgov.yaml or --baseline):")
			for _, name := range policy.ProfileNames() {
				p, err := policy.LoadProfile(name)
				if err != nil {
					return err
				}
				fmt.Fprintf(out, "\n%s (version %s)\n", p.Name, p.Version)
				for _, line := range wrapText(p.Description, 86) {
					fmt.Fprintf(out, "  %s\n", line)
				}
				fmt.Fprintf(out, "  Mandatory controls: %s\n", strings.Join(p.MandatoryControls, ", "))
				fmt.Fprintf(out, "  Minimum maturity for mandatory controls: %d of 4\n", p.MinMaturity)
				fmt.Fprintf(out, "  Signed evidence required for levels 3 and 4: %v\n", p.RequireSignedEvidence)
			}
			return nil
		},
	}
	cmd.AddCommand(validate, profiles)
	return cmd
}
