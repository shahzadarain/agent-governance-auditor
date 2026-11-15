// SPDX-License-Identifier: Apache-2.0

package main

import (
	"fmt"
	"io/fs"
	"os"
	"path"
	"path/filepath"
	"strings"

	"github.com/spf13/cobra"

	"github.com/shahzadarain/agent-governance-auditor/examples"
)

func newNewCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "new <folder>",
		Short: "Create a governed starter agent you can build on",
		Long: `Create a new folder that holds a small, working, governed agent.

The starter is plain Python with no third-party packages. It already
includes a tool allowlist, a policy check, human approval for risky
actions, a kill switch, step limits, step tracing, a tamper-evident audit
log, and governance tests. Replace the example tools with your own.

The folder must not exist yet, or must be empty. Nothing is overwritten.`,
		Example: `  agentgov new my-agent
  cd my-agent
  python tools/run_governance_tests.py
  agentgov scan .`,
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			return runNew(cmd, args[0])
		},
	}
	return cmd
}

func runNew(cmd *cobra.Command, target string) error {
	out := cmd.OutOrStdout()
	dest, err := filepath.Abs(target)
	if err != nil {
		return err
	}
	if entries, err := os.ReadDir(dest); err == nil && len(entries) > 0 {
		return fmt.Errorf("%s exists and is not empty; choose a new folder name", target)
	} else if err != nil && !os.IsNotExist(err) {
		return err
	}

	const base = "safe-agent"
	count := 0
	err = fs.WalkDir(examples.SafeAgent, base, func(p string, d fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		rel := strings.TrimPrefix(strings.TrimPrefix(p, base), "/")
		if rel == "" {
			return os.MkdirAll(dest, 0o755)
		}
		name := path.Base(p)
		// Evidence is bound to file content and must be produced by running
		// the tests in the new folder, so it is never copied.
		if d.IsDir() && (name == "__pycache__" || rel == ".agentgov/evidence") {
			return fs.SkipDir
		}
		if strings.HasSuffix(name, ".pyc") {
			return nil
		}
		to := filepath.Join(dest, filepath.FromSlash(rel))
		if d.IsDir() {
			return os.MkdirAll(to, 0o755)
		}
		data, err := fs.ReadFile(examples.SafeAgent, p)
		if err != nil {
			return err
		}
		if err := os.MkdirAll(filepath.Dir(to), 0o755); err != nil {
			return err
		}
		f, err := os.OpenFile(to, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o644)
		if err != nil {
			return err
		}
		if _, err := f.Write(data); err != nil {
			f.Close()
			return err
		}
		count++
		return f.Close()
	})
	if err != nil {
		return fmt.Errorf("create starter: %w", err)
	}

	fmt.Fprintf(out, "Created a governed starter agent in %s (%d files).\n\n", target, count)
	fmt.Fprintln(out, "Next steps:")
	fmt.Fprintf(out, "  1. cd %s\n", target)
	fmt.Fprintln(out, "  2. python tools/run_governance_tests.py    Runs the governance tests and records evidence")
	fmt.Fprintln(out, "  3. agentgov scan .                         Shows which controls are verified")
	fmt.Fprintln(out, "  4. Edit .agentgov.yaml: set your own agent ID and owner.")
	fmt.Fprintln(out, "  5. Replace the example tools with your own. Keep every tool behind the dispatcher.")
	fmt.Fprintln(out, "\nThe starter is a foundation, not a guarantee. Re-run the tests and the scan after every change.")
	return nil
}
