// SPDX-License-Identifier: Apache-2.0

package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/spf13/cobra"

	"github.com/shahzadarain/agent-governance-auditor/internal/model"
	"github.com/shahzadarain/agent-governance-auditor/internal/reporting"
	"github.com/shahzadarain/agent-governance-auditor/internal/scanner"
)

type scanFlags struct {
	format      string
	output      string
	jsonOut     string
	sarifOut    string
	htmlOut     string
	markdownOut string
	profile     string
	configPath  string
	baseline    string
	failOn      string
	full        bool
	summaryOnly bool
	quiet       bool
	verbose     bool
	noColor     bool
	noProgress  bool
	offline     bool
	open        bool
	maxFileSize int64
	timeout     time.Duration
	include     []string
	exclude     []string
	trustKeys   []string
	uploadURL   string
	uploadEnv   string
	uploadPlain bool
	ghOutput    string
}

func newScanCmd() *cobra.Command {
	var f scanFlags
	cmd := &cobra.Command{
		Use:   "scan [path]",
		Short: "Scan a folder for AI agents and assess the 24 controls",
		Long: `Scan a folder for AI agents and assess the 24 governance controls.

The scan is read-only and offline. It reads files, never runs them, and
sends nothing anywhere unless you pass --upload-url.

Exit codes:
  0  the scan completed and the release policy did not fail
  1  the scan completed and the release policy failed (see --fail-on)
  2  the scan could not run, or the configuration is not valid`,
		Example: `  agentgov scan .
  agentgov scan . --open
  agentgov scan ./my-agent --format json --output results.json
  agentgov scan . --format sarif --output findings.sarif
  agentgov scan . --profile high-risk --fail-on review
  agentgov scan . --json-out results.json --html-out report.html --summary-only`,
		Args: cobra.MaximumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			target := "."
			if len(args) == 1 {
				target = args[0]
			}
			return runScan(cmd.Context(), cmd, target, &f)
		},
	}
	fl := cmd.Flags()
	fl.StringVarP(&f.format, "format", "f", "terminal", "output format: "+strings.Join(reporting.Formats(), ", "))
	fl.StringVarP(&f.output, "output", "o", "", "write the --format output to this file instead of the screen")
	fl.StringVar(&f.jsonOut, "json-out", "", "also write a JSON result to this file")
	fl.StringVar(&f.sarifOut, "sarif-out", "", "also write a SARIF 2.1.0 file")
	fl.StringVar(&f.htmlOut, "html-out", "", "also write a self-contained HTML report")
	fl.StringVar(&f.markdownOut, "markdown-out", "", "also write a Markdown summary")
	fl.StringVar(&f.profile, "profile", "", "risk profile: baseline, standard, high-risk (default: from config, else inferred)")
	fl.StringVar(&f.configPath, "config", "", "path to .agentgov.yaml (default: auto-discover in the scanned folder)")
	fl.StringVar(&f.baseline, "baseline", os.Getenv("AGENTGOV_BASELINE"), "organization baseline profile file that the repository cannot weaken")
	fl.StringVar(&f.failOn, "fail-on", "block", "exit 1 when the decision is: block, review (block or review), never")
	fl.BoolVar(&f.full, "full", false, "show all 24 controls in terminal output")
	fl.BoolVar(&f.summaryOnly, "summary-only", false, "print only the score, decision, and reasons")
	fl.BoolVarP(&f.quiet, "quiet", "q", false, "print nothing except errors (use with --output or --fail-on)")
	fl.BoolVarP(&f.verbose, "verbose", "v", false, "print warnings and scan statistics")
	fl.BoolVar(&f.noColor, "no-color", false, "disable color (NO_COLOR is also respected)")
	fl.BoolVar(&f.noProgress, "no-progress", false, "do not print progress messages")
	fl.BoolVar(&f.offline, "offline", true, "never contact the network during the scan (always on in this release)")
	fl.BoolVar(&f.open, "open", false, "write an HTML report to a temporary file and open it in the browser")
	fl.Int64Var(&f.maxFileSize, "max-file-size", 0, "skip files larger than this many bytes (default 1048576)")
	fl.DurationVar(&f.timeout, "timeout", 5*time.Minute, "stop the scan after this long")
	fl.StringSliceVar(&f.include, "include", nil, "only scan paths matching these glob patterns")
	fl.StringSliceVar(&f.exclude, "exclude", nil, "skip paths matching these glob patterns")
	fl.StringSliceVar(&f.trustKeys, "trust-key", nil, "Ed25519 public key file used to verify signed evidence (repeatable)")
	fl.StringVar(&f.uploadURL, "upload-url", "", "send the result to a self-hosted AgentGov server (opt-in)")
	fl.StringVar(&f.uploadEnv, "upload-token-env", "AGENTGOV_TOKEN", "environment variable that holds the project upload token")
	fl.BoolVar(&f.uploadPlain, "upload-allow-http", false, "allow upload over plain HTTP to a non-local host (not recommended)")
	fl.StringVar(&f.ghOutput, "github-output", "", "append decision, score, and finding count to this GitHub Actions output file")
	_ = fl.MarkHidden("github-output")
	return cmd
}

func normalizeFailOn(v string) (string, error) {
	switch strings.ToLower(strings.TrimSpace(v)) {
	case "block", "policy", "":
		return "block", nil
	case "review", "review-required", "review_required":
		return "review", nil
	case "never", "none":
		return "never", nil
	}
	return "", fmt.Errorf("--fail-on must be block, review, or never (got %q)", v)
}

func runScan(ctx context.Context, cmd *cobra.Command, target string, f *scanFlags) error {
	failOn, err := normalizeFailOn(f.failOn)
	if err != nil {
		return err
	}
	if !f.offline {
		return errors.New("this release has no online lookups; remove --offline=false")
	}
	if !validFormat(f.format) {
		return fmt.Errorf("unknown format %q (available: %s)", f.format, strings.Join(reporting.Formats(), ", "))
	}
	keys, err := loadPublicKeys(f.trustKeys)
	if err != nil {
		return err
	}

	stderr := cmd.ErrOrStderr()
	progress := !f.quiet && !f.noProgress && isTerminalFile(os.Stderr)
	if progress {
		fmt.Fprintf(stderr, "Scanning %s (read-only, offline) ...\n", target)
	}

	res, err := scanner.Scan(ctx, scanner.Options{
		Root:         target,
		ConfigPath:   f.configPath,
		Profile:      f.profile,
		BaselinePath: f.baseline,
		Version:      version,
		MaxFileSize:  f.maxFileSize,
		Include:      f.include,
		Exclude:      f.exclude,
		Timeout:      f.timeout,
		TrustedKeys:  keys,
	})
	if err != nil {
		return err
	}

	// Additional output files.
	extra := []struct{ format, path string }{
		{"json", f.jsonOut}, {"sarif", f.sarifOut}, {"html", f.htmlOut}, {"markdown", f.markdownOut},
	}
	for _, e := range extra {
		if e.path == "" {
			continue
		}
		if err := renderToFile(res, e.format, e.path); err != nil {
			return err
		}
		if !f.quiet {
			fmt.Fprintf(stderr, "Wrote %s report: %s\n", e.format, e.path)
		}
	}

	// Primary output.
	out := cmd.OutOrStdout()
	switch {
	case f.output != "":
		if err := renderToFile(res, f.format, f.output); err != nil {
			return err
		}
		if !f.quiet {
			fmt.Fprintf(stderr, "Wrote %s report: %s\n", f.format, f.output)
			if f.format != "terminal" {
				printBrief(stderr, res)
			}
		}
	case !f.quiet || f.format != "terminal":
		// --quiet silences the human-readable report and progress messages.
		// A machine format requested on standard output is still written.
		opts := reporting.Options{
			Color:       f.format == "terminal" && useColor(os.Stdout, f.noColor),
			Full:        f.full,
			SummaryOnly: f.summaryOnly,
			Width:       terminalWidth(os.Stdout),
		}
		if err := reporting.Render(out, res, f.format, opts); err != nil {
			return err
		}
	}

	if f.verbose && !f.quiet {
		fmt.Fprintf(stderr, "\nFiles scanned: %d, skipped: %d, bytes read: %d, time: %d ms\n",
			res.Stats.FilesScanned, res.Stats.FilesSkipped, res.Stats.BytesRead, res.Stats.DurationMilli)
		for _, w := range res.Warnings {
			fmt.Fprintf(stderr, "warning: %s\n", w)
		}
	}

	if f.ghOutput != "" {
		if err := appendGitHubOutput(f.ghOutput, res); err != nil {
			return fmt.Errorf("write GitHub output: %w", err)
		}
	}

	if f.open {
		path := filepath.Join(os.TempDir(), "agentgov-report-"+res.Scan.ScanID+".html")
		if err := renderToFile(res, "html", path); err != nil {
			return err
		}
		if err := openInBrowser(path); err != nil {
			fmt.Fprintf(stderr, "Could not open the browser. The report is at: %s\n", path)
		} else if !f.quiet {
			fmt.Fprintf(stderr, "Opened report: %s\n", path)
		}
	}

	if f.uploadURL != "" {
		id, err := uploadResult(ctx, res, f.uploadURL, f.uploadEnv, f.uploadPlain)
		if err != nil {
			return fmt.Errorf("upload failed (the scan itself completed): %w", err)
		}
		if !f.quiet {
			fmt.Fprintf(stderr, "Uploaded scan to %s (server scan id: %s)\n", redactURL(f.uploadURL), id)
		}
	}

	switch res.Decision.Outcome {
	case model.OutcomeBlock:
		if failOn != "never" {
			return &policyFailure{outcome: string(res.Decision.Outcome)}
		}
	case model.OutcomeReviewRequired:
		if failOn == "review" {
			return &policyFailure{outcome: string(res.Decision.Outcome)}
		}
	}
	return nil
}

func validFormat(name string) bool {
	for _, f := range reporting.Formats() {
		if f == name {
			return true
		}
	}
	return false
}

func isTerminalFile(f *os.File) bool {
	fi, err := f.Stat()
	return err == nil && fi.Mode()&os.ModeCharDevice != 0
}

func renderToFile(res *model.ScanResult, format, path string) error {
	var buf bytes.Buffer
	if err := reporting.Render(&buf, res, format, reporting.Options{Full: true, Width: 100}); err != nil {
		return err
	}
	if err := writeFileAtomic(path, buf.Bytes()); err != nil {
		return fmt.Errorf("write %s: %w", path, err)
	}
	return nil
}

// printBrief prints a two-line summary when the main report went to a file.
func printBrief(w io.Writer, res *model.ScanResult) {
	fmt.Fprintf(w, "Agents detected: %d. Assessment maturity: %s (illustrative only). Release decision: %s.\n",
		len(res.Agents), res.Score.Label, res.Decision.Outcome)
}

// uploadResult sends the normalized result to a self-hosted server. Only the
// result document is sent: no source files, prompts, or secret values.
func uploadResult(ctx context.Context, res *model.ScanResult, rawURL, tokenEnv string, allowPlain bool) (string, error) {
	token := strings.TrimSpace(os.Getenv(tokenEnv))
	if token == "" {
		return "", fmt.Errorf("environment variable %s is empty; set it to a project upload token", tokenEnv)
	}
	u, err := url.Parse(rawURL)
	if err != nil || u.Host == "" {
		return "", fmt.Errorf("--upload-url is not a valid URL")
	}
	switch u.Scheme {
	case "https":
	case "http":
		if !isLoopbackHost(u.Hostname()) && !allowPlain {
			return "", errors.New("refusing to send the token over plain HTTP to a non-local host; use https or pass --upload-allow-http")
		}
	default:
		return "", errors.New("--upload-url must start with https:// or http://")
	}
	u.User = nil
	u.RawQuery = ""
	u.Fragment = ""
	u.Path = strings.TrimRight(u.Path, "/") + "/api/v1/scans"

	body, err := json.Marshal(res)
	if err != nil {
		return "", err
	}
	ctx, cancel := context.WithTimeout(ctx, 60*time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, u.String(), bytes.NewReader(body))
	if err != nil {
		return "", err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("User-Agent", "agentgov/"+version)

	client := &http.Client{
		// Never follow redirects: the token must not travel to another host.
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
	}
	resp, err := client.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	data, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if resp.StatusCode < 200 || resp.StatusCode > 299 {
		var e struct {
			Error struct {
				Code    string `json:"code"`
				Message string `json:"message"`
			} `json:"error"`
		}
		if json.Unmarshal(data, &e) == nil && e.Error.Message != "" {
			return "", fmt.Errorf("server answered %d: %s", resp.StatusCode, e.Error.Message)
		}
		return "", fmt.Errorf("server answered %d", resp.StatusCode)
	}
	var ok map[string]any
	if json.Unmarshal(data, &ok) == nil {
		for _, key := range []string{"id", "scan_id"} {
			if v, found := ok[key]; found {
				return fmt.Sprint(v), nil
			}
		}
	}
	return "accepted", nil
}

func isLoopbackHost(host string) bool {
	if strings.EqualFold(host, "localhost") {
		return true
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}

func redactURL(raw string) string {
	u, err := url.Parse(raw)
	if err != nil {
		return "server"
	}
	return u.Scheme + "://" + u.Host
}

// appendGitHubOutput writes step outputs for the GitHub Action. Every value
// comes from a fixed vocabulary or a number, so no multi-line escaping is
// needed.
func appendGitHubOutput(path string, res *model.ScanResult) error {
	fh, err := os.OpenFile(path, os.O_APPEND|os.O_WRONLY|os.O_CREATE, 0o600)
	if err != nil {
		return err
	}
	defer fh.Close()
	score := "insufficient-evidence"
	if res.Score.Value != nil {
		score = fmt.Sprint(*res.Score.Value)
	}
	_, err = fmt.Fprintf(fh, "decision=%s\nscore=%s\nfindings=%d\nversion=%s\n",
		res.Decision.Outcome, score, len(res.Findings), version)
	return err
}
