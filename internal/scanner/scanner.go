// SPDX-License-Identifier: Apache-2.0

// Package scanner orchestrates one scan: configuration, detection, policy
// evaluation, and assembly of the normalized result. It never executes code
// from the scanned repository and never contacts the network.
package scanner

import (
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/shahzadarain/agent-governance-auditor/internal/config"
	"github.com/shahzadarain/agent-governance-auditor/internal/controls"
	"github.com/shahzadarain/agent-governance-auditor/internal/detect"
	"github.com/shahzadarain/agent-governance-auditor/internal/model"
	"github.com/shahzadarain/agent-governance-auditor/internal/policy"
)

// ToolName is the product name written into every result.
const ToolName = "AgentGov Auditor"

// ConfigError reports an invalid configuration, baseline, or profile. The
// CLI maps it to the scan-error exit code, never to a policy failure.
type ConfigError struct {
	Message     string
	Diagnostics []string
}

func (e *ConfigError) Error() string {
	if len(e.Diagnostics) == 0 {
		return e.Message
	}
	return e.Message + ":\n  - " + strings.Join(e.Diagnostics, "\n  - ")
}

// Options configures a scan.
type Options struct {
	Root         string // directory to scan
	ConfigPath   string // explicit configuration file; empty means auto-discover
	Profile      string // profile name from the command line; empty means select
	BaselinePath string // organization baseline profile from outside the repository
	Version      string // scanner version
	MaxFileSize  int64
	Include      []string
	Exclude      []string
	Timeout      time.Duration
	Now          time.Time // zero means time.Now().UTC()
	TrustedKeys  []ed25519.PublicKey
}

// Scan runs a complete assessment of opts.Root.
func Scan(ctx context.Context, opts Options) (*model.ScanResult, error) {
	started := opts.Now
	if started.IsZero() {
		started = time.Now().UTC()
	}
	started = started.UTC().Truncate(time.Second)

	root, err := filepath.Abs(opts.Root)
	if err != nil {
		return nil, fmt.Errorf("resolve scan path: %w", err)
	}
	info, err := os.Stat(root)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, fmt.Errorf("scan path %q does not exist", opts.Root)
		}
		return nil, fmt.Errorf("scan path %q cannot be read", opts.Root)
	}
	if !info.IsDir() {
		return nil, fmt.Errorf("scan path %q is not a directory", opts.Root)
	}

	if opts.Timeout > 0 {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, opts.Timeout)
		defer cancel()
	}

	cfg, diags, err := config.Load(root, opts.ConfigPath)
	if err != nil {
		return nil, &ConfigError{Message: "configuration is not valid: " + err.Error(), Diagnostics: diags}
	}

	cat, err := controls.Load()
	if err != nil {
		return nil, fmt.Errorf("load control catalog: %w", err)
	}

	include := append([]string(nil), opts.Include...)
	exclude := append([]string(nil), opts.Exclude...)
	maxSize := opts.MaxFileSize
	if cfg != nil {
		include = append(include, cfg.Scan.Include...)
		exclude = append(exclude, cfg.Scan.Exclude...)
		if maxSize == 0 {
			maxSize = cfg.Scan.MaxFileSize
		}
	}

	det, err := detect.Run(ctx, detect.Options{
		Root:           root,
		Config:         cfg,
		ScannerVersion: opts.Version,
		PolicyVersion:  cat.Version,
		MaxFileSize:    maxSize,
		Include:        include,
		Exclude:        exclude,
		Now:            started,
		TrustedKeys:    opts.TrustedKeys,
	})
	if err != nil {
		if errors.Is(err, context.DeadlineExceeded) {
			return nil, fmt.Errorf("scan timed out after %s; raise --timeout or narrow the scan with --include", opts.Timeout)
		}
		return nil, fmt.Errorf("scan failed: %w", err)
	}

	var baseline *model.Profile
	if opts.BaselinePath != "" {
		baseline, err = policy.LoadBaseline(opts.BaselinePath)
		if err != nil {
			return nil, &ConfigError{Message: "organization baseline is not valid: " + err.Error()}
		}
	}

	profileName, profileSource := policy.SelectProfileName(opts.Profile, cfg, det.Agents)
	base, err := policy.LoadProfile(profileName)
	if err != nil {
		return nil, &ConfigError{Message: fmt.Sprintf("profile %q: %v (available: %s)", profileName, err, strings.Join(policy.ProfileNames(), ", "))}
	}
	effective := policy.Effective(base, cfg, baseline)

	// A repository may choose its own profile. When that choice is weaker
	// than what the detected capabilities suggest, say so in the result.
	if inferredName, _ := policy.SelectProfileName("", nil, det.Agents); profileSource == "config" &&
		policy.ProfileRank(profileName) < policy.ProfileRank(inferredName) {
		det.Warnings = append(det.Warnings, fmt.Sprintf(
			"The configuration selects profile %q, but the detected capabilities suggest %q. Use --profile %s or an organization --baseline to apply the stricter requirements.",
			profileName, inferredName, inferredName))
	}

	assessments, score, decision := policy.Evaluate(policy.Input{
		Detection: det,
		Catalog:   cat,
		Profile:   effective,
		Config:    cfg,
		Now:       started,
	})
	policy.AttachMappings(det.Findings, cat)

	res := &model.ScanResult{
		SchemaVersion: model.SchemaVersion,
		Tool:          model.ToolInfo{Name: ToolName, Version: opts.Version},
		Scan: model.ScanMeta{
			StartedAt:     started,
			Target:        filepath.Base(root),
			CommitSHA:     det.CommitSHA,
			Profile:       effective.Name,
			ProfileSource: profileSource,
			PolicyPack:    cat.Pack,
			PolicyVersion: cat.Version,
			Offline:       true,
		},
		Agents:      det.Agents,
		Assessments: assessments,
		Evidence:    det.Evidence,
		Findings:    det.Findings,
		Score:       score,
		Decision:    decision,
		Stats:       det.Stats,
		Warnings:    det.Warnings,
		Limitations: det.Limitations,
	}
	if cfg != nil {
		res.Scan.ConfigPath = cfg.Path
	}
	if baseline != nil {
		res.Scan.ProfileSource = profileSource + "+baseline-lock"
	}
	normalize(res)
	res.Scan.ScanID = scanID(res)
	res.Scan.FinishedAt = time.Now().UTC().Truncate(time.Second)
	if !opts.Now.IsZero() {
		res.Scan.FinishedAt = started
	}
	return res, nil
}

// normalize replaces nil slices and maps with empty ones so the JSON output
// has a stable shape, and sorts the top-level string lists.
func normalize(res *model.ScanResult) {
	if res.Agents == nil {
		res.Agents = []model.Agent{}
	}
	if res.Assessments == nil {
		res.Assessments = []model.AgentAssessment{}
	}
	if res.Evidence == nil {
		res.Evidence = []model.Evidence{}
	}
	if res.Findings == nil {
		res.Findings = []model.Finding{}
	}
	if res.Warnings == nil {
		res.Warnings = []string{}
	}
	if res.Limitations == nil {
		res.Limitations = []string{}
	}
	if res.Decision.Reasons == nil {
		res.Decision.Reasons = []model.Reason{}
	}
	sort.Strings(res.Warnings)
}

// scanID derives a stable identifier from the scan content. Timestamps and
// durations are excluded so identical inputs produce an identical ID.
func scanID(res *model.ScanResult) string {
	clone := *res
	clone.Scan.ScanID = ""
	clone.Scan.StartedAt = time.Time{}
	clone.Scan.FinishedAt = time.Time{}
	clone.Stats.DurationMilli = 0
	clone.Evidence = make([]model.Evidence, len(res.Evidence))
	for i, ev := range res.Evidence {
		ev.ObservedAt = time.Time{}
		clone.Evidence[i] = ev
	}
	data, err := json.Marshal(clone)
	if err != nil {
		return "scan-unknown"
	}
	sum := sha256.Sum256(data)
	return "scan-" + hex.EncodeToString(sum[:8])
}
