// SPDX-License-Identifier: Apache-2.0

package detect

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"testing"
	"time"

	"gopkg.in/yaml.v3"

	"github.com/shahzadarain/agent-governance-auditor/internal/config"
	"github.com/shahzadarain/agent-governance-auditor/internal/model"
)

var fixedNow = time.Date(2026, 11, 15, 12, 0, 0, 0, time.UTC)

// repoRoot returns the repository root (two levels above this package).
func repoRoot(t testing.TB) string {
	t.Helper()
	wd, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	return filepath.Join(wd, "..", "..")
}

// loadConfig reads .agentgov.yaml from dir with a plain YAML decode. The
// real loader belongs to another package; tests only need the declared
// values. It returns nil when the file is absent.
func loadConfig(t testing.TB, dir string) *config.Config {
	t.Helper()
	data, err := os.ReadFile(filepath.Join(dir, config.FileName))
	if err != nil {
		return nil
	}
	var cfg config.Config
	if err := yaml.Unmarshal(data, &cfg); err != nil {
		return nil // a malformed configuration is the same as none for these tests
	}
	cfg.Path = config.FileName
	return &cfg
}

func scan(t testing.TB, dir string) *model.Detection {
	t.Helper()
	det, err := Run(context.Background(), Options{
		Root: dir, Config: loadConfig(t, dir), ScannerVersion: "test", PolicyVersion: "1.0", Now: fixedNow,
	})
	if err != nil {
		t.Fatalf("scan %s: %v", dir, err)
	}
	return det
}

// TestDump prints a compact view of a scan. It is a development aid:
// AGENTGOV_DUMP=<dir> go test ./internal/detect -run TestDump -v
func TestDump(t *testing.T) {
	dir := os.Getenv("AGENTGOV_DUMP")
	if dir == "" {
		t.Skip("set AGENTGOV_DUMP to a directory to print its detection")
	}
	det := scan(t, dir)
	for _, a := range det.Agents {
		fmt.Printf("AGENT %s root=%s fw=%s(%s) det=%s lang=%s entry=%s tier=%s/%s caps=%v\n", a.ID, a.Root, a.Framework, a.FrameworkVersion,
			a.Detection, a.Language, a.Entrypoint, a.RiskTier, a.InferredRiskTier, a.Capabilities)
		for _, tl := range a.Tools {
			fmt.Printf("  TOOL %-24s %-10s sens=%v decl=%v %v %s:%d (%s)\n", tl.Name, tl.Kind, tl.Sensitive, tl.Declared, tl.Capabilities, tl.Location.Path, tl.Location.Line, tl.SensitiveWhy)
		}
		for _, m := range a.MCPConnections {
			fmt.Printf("  MCP %s %s %s pinned=%v %s\n", m.Name, m.Transport, m.Target, m.Pinned, m.Version)
		}
	}
	for _, e := range det.Evidence {
		fmt.Printf("EV %s %-22s %-9s %-14s %-8s %-28s %s | %s\n", e.ControlID, e.AgentID, e.Signal, e.Strength, e.Validity, e.SourceLocation, e.Collector, e.Summary)
	}
	for _, f := range det.Findings {
		loc := ""
		if f.Location != nil {
			loc = fmt.Sprintf("%s:%d", f.Location.Path, f.Location.Line)
		}
		fmt.Printf("FIND %-44s %-8s %s | %s\n", f.RuleID, f.Severity, loc, f.Description)
	}
	for _, w := range det.Warnings {
		fmt.Println("WARN", w)
	}
	for _, l := range det.Limitations {
		fmt.Println("LIMIT", l)
	}
	fmt.Printf("STATS %+v commit=%s\n", det.Stats, det.CommitSHA)
}
