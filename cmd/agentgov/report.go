// SPDX-License-Identifier: Apache-2.0

package main

import (
	"bytes"
	"fmt"
	"os"
	"strings"

	"github.com/spf13/cobra"

	"github.com/shahzadarain/agent-governance-auditor/internal/reporting"
)

func newReportCmd() *cobra.Command {
	var format, output string
	var full, noColor bool
	cmd := &cobra.Command{
		Use:   "report <results.json>",
		Short: "Render a saved JSON result in another format",
		Long: `Render a saved JSON result in another format.

This does not scan again. It reads a file written by
"agentgov scan --format json" and renders it as terminal text, Markdown,
HTML, or SARIF.`,
		Example: `  agentgov report results.json --format html --output report.html
  agentgov report results.json --format markdown`,
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			if !validFormat(format) {
				return fmt.Errorf("unknown format %q (available: %s)", format, strings.Join(reporting.Formats(), ", "))
			}
			res, err := readResult(args[0])
			if err != nil {
				return err
			}
			if output != "" {
				if err := renderToFile(res, format, output); err != nil {
					return err
				}
				fmt.Fprintf(cmd.ErrOrStderr(), "Wrote %s report: %s\n", format, output)
				return nil
			}
			return reporting.Render(cmd.OutOrStdout(), res, format, reporting.Options{
				Color: format == "terminal" && useColor(os.Stdout, noColor),
				Full:  full,
				Width: terminalWidth(os.Stdout),
			})
		},
	}
	cmd.Flags().StringVarP(&format, "format", "f", "terminal", "output format: "+strings.Join(reporting.Formats(), ", "))
	cmd.Flags().StringVarP(&output, "output", "o", "", "write to this file instead of the screen")
	cmd.Flags().BoolVar(&full, "full", false, "show all 24 controls in terminal output")
	cmd.Flags().BoolVar(&noColor, "no-color", false, "disable color")
	return cmd
}

func newCompareCmd() *cobra.Command {
	var format, output string
	var noColor bool
	cmd := &cobra.Command{
		Use:   "compare <before.json> <after.json>",
		Short: "Show what changed between two saved results",
		Long: `Show what changed between two saved results: new findings, resolved
findings, and controls whose status changed.

A score trend is shown only when both scans used the same policy pack,
policy version, and profile. Otherwise the comparison says why the scores
are not comparable.`,
		Example: `  agentgov compare before.json after.json
  agentgov compare before.json after.json --format markdown`,
		Args: cobra.ExactArgs(2),
		RunE: func(cmd *cobra.Command, args []string) error {
			before, err := readResult(args[0])
			if err != nil {
				return err
			}
			after, err := readResult(args[1])
			if err != nil {
				return err
			}
			c := reporting.Compare(before, after)
			opts := reporting.Options{Color: format == "terminal" && useColor(os.Stdout, noColor), Width: terminalWidth(os.Stdout)}
			if output != "" {
				var buf bytes.Buffer
				opts.Color = false
				if err := reporting.RenderComparison(&buf, c, format, opts); err != nil {
					return err
				}
				return writeFileAtomic(output, buf.Bytes())
			}
			return reporting.RenderComparison(cmd.OutOrStdout(), c, format, opts)
		},
	}
	cmd.Flags().StringVarP(&format, "format", "f", "terminal", "output format: terminal, markdown, json")
	cmd.Flags().StringVarP(&output, "output", "o", "", "write to this file instead of the screen")
	cmd.Flags().BoolVar(&noColor, "no-color", false, "disable color")
	return cmd
}
