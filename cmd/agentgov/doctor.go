// SPDX-License-Identifier: Apache-2.0

package main

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"

	"github.com/spf13/cobra"

	"github.com/shahzadarain/agent-governance-auditor/internal/config"
	"github.com/shahzadarain/agent-governance-auditor/internal/controls"
	"github.com/shahzadarain/agent-governance-auditor/internal/policy"
)

func newDoctorCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "doctor",
		Short: "Check that agentgov is set up correctly on this machine",
		Long: `Check that agentgov is set up correctly on this machine.

doctor runs local checks only. It sends no data anywhere and does not run
any program it finds.`,
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			out := cmd.OutOrStdout()
			problems := 0
			ok := func(format string, a ...any) { fmt.Fprintf(out, "[ok]   "+format+"\n", a...) }
			info := func(format string, a ...any) { fmt.Fprintf(out, "[info] "+format+"\n", a...) }
			bad := func(format string, a ...any) { problems++; fmt.Fprintf(out, "[fail] "+format+"\n", a...) }

			ok("agentgov %s on %s/%s", version, runtime.GOOS, runtime.GOARCH)

			if cat, err := controls.Load(); err != nil {
				bad("control catalog did not load: %v", err)
			} else if len(cat.Controls) != 24 {
				bad("control catalog has %d controls; expected 24", len(cat.Controls))
			} else {
				ok("control catalog %s version %s loaded (24 controls)", cat.Pack, cat.Version)
			}

			names := policy.ProfileNames()
			loaded := 0
			for _, n := range names {
				if _, err := policy.LoadProfile(n); err != nil {
					bad("profile %s did not load: %v", n, err)
				} else {
					loaded++
				}
			}
			if loaded > 0 {
				ok("%d risk profiles loaded", loaded)
			}

			cwd, _ := os.Getwd()
			cfgPath := filepath.Join(cwd, config.FileName)
			if data, err := os.ReadFile(cfgPath); err == nil {
				if diags := config.Validate(data); len(diags) > 0 {
					bad("%s has %d problem(s); run: agentgov policy validate", config.FileName, len(diags))
				} else {
					ok("%s in this folder is valid", config.FileName)
				}
			} else {
				info("no %s in this folder (optional; create one with: agentgov init)", config.FileName)
			}

			if _, err := os.Stat(filepath.Join(cwd, ".git")); err == nil {
				ok("this folder is a Git repository; results will record the commit")
			} else {
				info("this folder is not a Git repository; the commit will be recorded as unknown")
			}

			tmp, err := os.CreateTemp("", "agentgov-doctor-*")
			if err != nil {
				bad("cannot write to the temporary folder: %v", err)
			} else {
				tmp.Close()
				os.Remove(tmp.Name())
				ok("temporary folder is writable (used by --open)")
			}

			if useColor(os.Stdout, false) {
				ok("terminal supports color")
			} else {
				info("color is off (not a terminal, or NO_COLOR is set); text labels are always shown")
			}

			info("optional tools (only looked up, never run):")
			for _, tool := range []struct{ name, use string }{
				{"python", "run the governance tests of the starter agent"},
				{"python3", "run the governance tests of the starter agent"},
				{"docker", "run the self-hosted dashboard in a container"},
				{"git", "not needed; the commit is read from .git directly"},
			} {
				if p, err := exec.LookPath(tool.name); err == nil {
					fmt.Fprintf(out, "         %-8s found at %s (%s)\n", tool.name, p, tool.use)
				} else {
					fmt.Fprintf(out, "         %-8s not found (%s)\n", tool.name, tool.use)
				}
			}

			info("network: not used. Scans are offline. Upload happens only with --upload-url.")
			info("telemetry: none. This tool does not collect usage data.")

			if problems > 0 {
				return fmt.Errorf("%d check(s) failed", problems)
			}
			fmt.Fprintln(out, "\nEverything needed for local scans is in place. Try: agentgov scan .")
			return nil
		},
	}
}
