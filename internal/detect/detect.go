// SPDX-License-Identifier: Apache-2.0

// Package detect is the facade of the detection engine: it walks the target
// directory, runs the language and configuration adapters, discovers
// agents, runs the detectors, loads external evidence, and returns one
// sorted model.Detection. It is read-only and offline, and it never executes
// anything from the scanned directory.
package detect

import (
	"context"
	"crypto/ed25519"
	"fmt"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/shahzadarain/agent-governance-auditor/internal/adapters"
	"github.com/shahzadarain/agent-governance-auditor/internal/config"
	"github.com/shahzadarain/agent-governance-auditor/internal/discovery"
	"github.com/shahzadarain/agent-governance-auditor/internal/evidence"
	"github.com/shahzadarain/agent-governance-auditor/internal/model"
	"github.com/shahzadarain/agent-governance-auditor/internal/rules"
)

// DefaultEvidencePath is where external evidence is read from when the
// configuration names no evidence paths.
const DefaultEvidencePath = ".agentgov/evidence"

// Options configures one detection run.
type Options struct {
	Root           string              // directory to scan
	Config         *config.Config      // may be nil
	ScannerVersion string              //
	PolicyVersion  string              //
	MaxFileSize    int64               // bytes; 0 means default (1 MiB)
	Include        []string            //
	Exclude        []string            //
	Now            time.Time           // injected clock for determinism
	TrustedKeys    []ed25519.PublicKey // keys that may verify signed evidence
	Progress       func(stage string)  // optional; called at the start of each stage
}

// Run performs detection. It returns an error only when the root cannot be
// scanned at all, an include or exclude pattern is unsafe, or the context
// ends before discovery completes.
func Run(ctx context.Context, opts Options) (*model.Detection, error) {
	started := time.Now()
	now := opts.Now
	if now.IsZero() {
		now = time.Now()
	}
	now = now.UTC()
	progress := func(stage string) {
		if opts.Progress != nil {
			opts.Progress(stage)
		}
	}
	wopts := discovery.Options{Root: opts.Root, MaxFileSize: opts.MaxFileSize, Include: opts.Include, Exclude: opts.Exclude}
	if opts.Config != nil {
		wopts.Include = append(append([]string{}, wopts.Include...), opts.Config.Scan.Include...)
		wopts.Exclude = append(append([]string{}, wopts.Exclude...), opts.Config.Scan.Exclude...)
		if wopts.MaxFileSize <= 0 && opts.Config.Scan.MaxFileSize > 0 {
			wopts.MaxFileSize = opts.Config.Scan.MaxFileSize
		}
	}
	progress("walk")
	inv, err := discovery.Walk(ctx, wopts)
	if err != nil {
		return nil, err
	}
	det := &model.Detection{
		CommitSHA: discovery.ReadCommit(inv.Root),
		Agents:    []model.Agent{}, Evidence: []model.Evidence{}, Findings: []model.Finding{},
		Warnings: []string{}, Limitations: []string{},
	}
	det.Warnings = append(det.Warnings, inv.Warnings...)

	progress("analyze")
	repo := adapters.Analyze(ctx, inv)
	det.Warnings = append(det.Warnings, repo.Warnings...)
	if err := ctx.Err(); err != nil {
		return nil, err
	}

	progress("discover")
	disc := adapters.Discover(repo, opts.Config, filepath.Base(inv.Root))
	det.Limitations = append(det.Limitations, disc.Limitations...)
	det.Warnings = append(det.Warnings, disc.Warnings...)

	progress("detect")
	for _, ag := range disc.Agents {
		det.Agents = append(det.Agents, ag.Agent)
		rc := &rules.Context{Agent: ag, Repo: repo, Config: opts.Config, Now: now}
		evs, fs := rules.RunAll(ctx, rc)
		det.Evidence = append(det.Evidence, evs...)
		det.Findings = append(det.Findings, fs...)
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	for i := range det.Evidence {
		e := &det.Evidence[i]
		e.CommitSHA = det.CommitSHA
		e.ObservedAt = now
		// The static scanner never claims tested or operational strength.
		if e.Strength != model.StrengthDeclared {
			e.Strength = model.StrengthImplementation
		}
		e.Integrity = model.IntegrityNotAvailable
		e.Validity = model.ValidityValid
		if e.SourceType != model.SourceConfiguration {
			e.SourceType = model.SourceStatic
		}
	}

	progress("evidence")
	paths := []string{DefaultEvidencePath}
	if opts.Config != nil && len(opts.Config.Verification.EvidencePaths) > 0 {
		paths = opts.Config.Verification.EvidencePaths
	}
	if len(disc.Agents) > 0 {
		seenDir := map[string]bool{}
		for _, ag := range disc.Agents {
			for _, p := range paths {
				// Evidence paths are relative to the scan root; each agent
				// root is tried as well so monorepo agents keep their own.
				for _, dir := range []string{p, joinRel(ag.Root, p)} {
					if seenDir[dir] {
						continue
					}
					seenDir[dir] = true
					evs, probs := evidence.LoadDir(inv.Root, dir, det.CommitSHA, now, opts.TrustedKeys)
					det.Evidence = append(det.Evidence, evs...)
					det.Warnings = append(det.Warnings, probs...)
				}
			}
		}
	}
	for i := range det.Evidence {
		det.Evidence[i].PolicyVersion = opts.PolicyVersion
		det.Evidence[i].ScannerVersion = opts.ScannerVersion
		if det.Evidence[i].Limitations == nil {
			det.Evidence[i].Limitations = []string{}
		}
	}

	det.Limitations = append(det.Limitations,
		"Static analysis is lexical. It reads code and configuration and does not run the agent, so it cannot confirm behavior at run time.",
		"Static evidence supports implementation maturity at most. Tested and operational maturity need external evidence files.",
	)
	if inv.Truncated {
		det.Limitations = append(det.Limitations, "A scan bound was reached, so part of the directory was not read. See the warnings.")
	}
	secretStores := 0
	for i := range inv.Files {
		if inv.Files[i].Skipped == discovery.SkipSecretStore {
			secretStores++
		}
	}
	if secretStores > 0 {
		det.Limitations = append(det.Limitations,
			fmt.Sprintf("%d file(s) that look like secret stores (for example .env or key files) were listed but their content was not read.", secretStores))
	}

	sortDetection(det)
	det.Stats = model.Stats{FilesScanned: inv.FilesScanned, FilesSkipped: inv.FilesSkipped, BytesRead: inv.BytesRead,
		DurationMilli: time.Since(started).Milliseconds()}
	progress("done")
	return det, nil
}

func joinRel(root, p string) string {
	if root == "." || root == "" {
		return p
	}
	return strings.TrimSuffix(root, "/") + "/" + strings.TrimPrefix(strings.ReplaceAll(p, "\\", "/"), "./")
}

func dedupe(s []string) []string {
	sort.Strings(s)
	out := s[:0]
	for i, v := range s {
		if i == 0 || v != s[i-1] {
			out = append(out, v)
		}
	}
	return out
}

func sortDetection(det *model.Detection) {
	sort.SliceStable(det.Agents, func(i, j int) bool { return det.Agents[i].ID < det.Agents[j].ID })
	// Drop exact duplicate evidence IDs (the same directory reached twice).
	seen := map[string]bool{}
	evs := det.Evidence[:0]
	for _, e := range det.Evidence {
		if seen[e.EvidenceID] {
			continue
		}
		seen[e.EvidenceID] = true
		evs = append(evs, e)
	}
	det.Evidence = evs
	sort.SliceStable(det.Evidence, func(i, j int) bool {
		a, b := det.Evidence[i], det.Evidence[j]
		if a.ControlID != b.ControlID {
			return a.ControlID < b.ControlID
		}
		if a.AgentID != b.AgentID {
			return a.AgentID < b.AgentID
		}
		if a.SourceLocation != b.SourceLocation {
			return a.SourceLocation < b.SourceLocation
		}
		return a.EvidenceID < b.EvidenceID
	})
	sort.SliceStable(det.Findings, func(i, j int) bool {
		a, b := det.Findings[i], det.Findings[j]
		if a.ControlID != b.ControlID {
			return a.ControlID < b.ControlID
		}
		if a.AgentID != b.AgentID {
			return a.AgentID < b.AgentID
		}
		if a.RuleID != b.RuleID {
			return a.RuleID < b.RuleID
		}
		ap, bp, al, bl := "", "", 0, 0
		if a.Location != nil {
			ap, al = a.Location.Path, a.Location.Line
		}
		if b.Location != nil {
			bp, bl = b.Location.Path, b.Location.Line
		}
		if ap != bp {
			return ap < bp
		}
		if al != bl {
			return al < bl
		}
		return a.FindingID < b.FindingID
	})
	det.Warnings = dedupe(det.Warnings)
	if det.Warnings == nil {
		det.Warnings = []string{}
	}
}
