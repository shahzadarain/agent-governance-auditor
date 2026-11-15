// SPDX-License-Identifier: Apache-2.0

// Command agentgov is the AgentGov Auditor command-line tool.
package main

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/signal"

	"github.com/spf13/cobra"
)

// Build metadata, set at release time with -ldflags.
var (
	version = "0.1.0-dev"
	commit  = "unknown"
	date    = "unknown"
)

// Exit codes. Tool failure and governance failure are never conflated.
const (
	exitOK     = 0 // scan completed and the release policy did not fail
	exitPolicy = 1 // scan completed and the release policy failed
	exitError  = 2 // the scan could not run, or the configuration is invalid
)

// policyFailure signals a completed scan whose decision fails --fail-on.
type policyFailure struct{ outcome string }

func (p *policyFailure) Error() string { return "release policy result: " + p.outcome }

func main() {
	os.Exit(run())
}

func run() int {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt)
	defer stop()

	root := newRootCmd()
	err := root.ExecuteContext(ctx)
	if err == nil {
		return exitOK
	}
	var pf *policyFailure
	if errors.As(err, &pf) {
		return exitPolicy
	}
	fmt.Fprintln(os.Stderr, "agentgov: error: "+err.Error())
	return exitError
}

func newRootCmd() *cobra.Command {
	root := &cobra.Command{
		Use:   "agentgov",
		Short: "Check which AI-agent safety controls are in place before release",
		Long: `AgentGov Auditor checks a repository for AI agents and reports which of
24 governance controls have real evidence behind them.

It runs on your machine. It does not need an account, an API key, or a
network connection. It never runs code from the repository it scans.`,
		Example: `  agentgov scan .                      Scan the current folder
  agentgov scan . --open               Scan and open a visual report
  agentgov explain AGC-010             Explain one control in plain language
  agentgov init                        Create a starter .agentgov.yaml
  agentgov new my-agent                Create a governed starter agent`,
		SilenceUsage:  true,
		SilenceErrors: true,
		Version:       version,
	}
	root.SetVersionTemplate("agentgov {{.Version}}\n")
	root.AddCommand(
		newScanCmd(),
		newReportCmd(),
		newCompareCmd(),
		newExplainCmd(),
		newControlsCmd(),
		newPolicyCmd(),
		newInitCmd(),
		newNewCmd(),
		newDoctorCmd(),
		newEvidenceCmd(),
		newServeCmd(),
		newHealthcheckCmd(),
		newVersionCmd(),
	)
	return root
}

func newVersionCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "version",
		Short: "Print version and build information",
		Args:  cobra.NoArgs,
		Run: func(cmd *cobra.Command, _ []string) {
			out := cmd.OutOrStdout()
			fmt.Fprintf(out, "agentgov %s\n", version)
			fmt.Fprintf(out, "commit:  %s\n", commit)
			fmt.Fprintf(out, "built:   %s\n", date)
			fmt.Fprintf(out, "policy:  builtin/v1\n")
		},
	}
}
