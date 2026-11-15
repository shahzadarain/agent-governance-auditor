// SPDX-License-Identifier: Apache-2.0

package config

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"time"

	"gopkg.in/yaml.v3"

	"github.com/shahzadarain/agent-governance-auditor/policies"
)

// MaxSize is the largest configuration file the loader reads (256 KiB).
const MaxSize = 256 * 1024

// AltFileName is the second file name the loader looks for at the root.
const AltFileName = ".agentgov.yml"

// maxDiagnostic is the longest diagnostic line, in characters.
const maxDiagnostic = 300

// dateLayout is the format of every date in the configuration.
const dateLayout = "2006-01-02"

// Load finds, reads, and validates the configuration.
//
// With an empty explicitPath it looks for .agentgov.yaml and then
// .agentgov.yml directly under root. When neither exists it returns
// (nil, nil, nil): a configuration file is optional.
//
// With an explicitPath the file must exist. A relative explicitPath is
// resolved against the current working directory.
//
// When the file is invalid, Load returns a nil Config, the list of
// diagnostics (each starts with a field path), and a non-nil error.
func Load(root, explicitPath string) (*Config, []string, error) {
	path, display, err := locate(root, explicitPath)
	if err != nil {
		return nil, []string{err.Error()}, err
	}
	if path == "" {
		return nil, nil, nil
	}

	info, err := os.Lstat(path)
	if err != nil {
		e := fmt.Errorf("%s: cannot read configuration: %w", display, err)
		return nil, []string{e.Error()}, e
	}
	if !info.Mode().IsRegular() {
		e := fmt.Errorf("%s: configuration must be a regular file, not a link or a directory", display)
		return nil, []string{e.Error()}, e
	}
	if info.Size() > MaxSize {
		e := fmt.Errorf("%s: configuration is %d bytes; the limit is %d bytes", display, info.Size(), MaxSize)
		return nil, []string{e.Error()}, e
	}

	f, err := os.Open(path)
	if err != nil {
		e := fmt.Errorf("%s: cannot read configuration: %w", display, err)
		return nil, []string{e.Error()}, e
	}
	defer f.Close()
	// Read one byte past the limit so growth after the size check is caught.
	data, err := io.ReadAll(io.LimitReader(f, MaxSize+1))
	if err != nil {
		e := fmt.Errorf("%s: cannot read configuration: %w", display, err)
		return nil, []string{e.Error()}, e
	}

	if diags := Validate(data); len(diags) > 0 {
		return nil, diags, fmt.Errorf("%s: configuration is invalid (%s)", display, plural(len(diags), "problem"))
	}
	cfg, err := decode(data)
	if err != nil {
		e := fmt.Errorf("%s: %w", display, err)
		return nil, []string{e.Error()}, e
	}
	cfg.Path = display
	return cfg, nil, nil
}

// locate returns the file to read and the path to show to users. An empty
// path with a nil error means no configuration exists.
func locate(root, explicitPath string) (path, display string, err error) {
	if explicitPath != "" {
		if _, statErr := os.Lstat(explicitPath); statErr != nil {
			if errors.Is(statErr, os.ErrNotExist) {
				return "", "", fmt.Errorf("%s: configuration file not found", filepath.ToSlash(explicitPath))
			}
			return "", "", fmt.Errorf("%s: cannot read configuration: %w", filepath.ToSlash(explicitPath), statErr)
		}
		return explicitPath, displayPath(root, explicitPath), nil
	}
	if root == "" {
		root = "."
	}
	for _, name := range []string{FileName, AltFileName} {
		p := filepath.Join(root, name)
		if _, statErr := os.Lstat(p); statErr == nil {
			return p, name, nil
		} else if !errors.Is(statErr, os.ErrNotExist) {
			return "", "", fmt.Errorf("%s: cannot read configuration: %w", name, statErr)
		}
	}
	return "", "", nil
}

// displayPath returns a root-relative path with forward slashes when the
// file is inside root, and the given path otherwise.
func displayPath(root, p string) string {
	if root != "" {
		absRoot, err1 := filepath.Abs(root)
		absP, err2 := filepath.Abs(p)
		if err1 == nil && err2 == nil {
			if rel, err := filepath.Rel(absRoot, absP); err == nil && rel != ".." && !strings.HasPrefix(rel, ".."+string(filepath.Separator)) {
				return filepath.ToSlash(rel)
			}
		}
	}
	return filepath.ToSlash(p)
}

// Validate checks configuration content and returns human-readable
// diagnostics. Each diagnostic starts with the path of the field it concerns,
// for example "policy.min_maturity: ...". An empty result means the content
// is valid.
//
// Validation is strict: an unknown field is a problem, because a misspelled
// key would otherwise be ignored without notice.
func Validate(data []byte) []string {
	if len(data) > MaxSize {
		return []string{fmt.Sprintf("(document): configuration is larger than the limit of %d bytes", MaxSize)}
	}
	v, problem := policies.DecodeYAML(data)
	if problem != "" {
		return []string{"(document): " + problem}
	}
	if v == nil {
		return []string{`schema_version: required field is missing (the file is empty); add schema_version: "1"`}
	}
	root, ok := v.(map[string]any)
	if !ok {
		return []string{"(document): the configuration must be a mapping of keys to values"}
	}

	// Give a precise message for the version field before the general schema
	// check, because every other rule depends on the version.
	switch sv := root["schema_version"].(type) {
	case nil:
		if _, present := root["schema_version"]; !present {
			return []string{`schema_version: required field is missing; add schema_version: "1"`}
		}
		return []string{`schema_version: must be the string "1"`}
	case string:
		if sv != CurrentSchemaVersion {
			return []string{fmt.Sprintf("schema_version: unsupported version %q; this release supports %q (see docs/policy-reference.md for the migration policy)", sv, CurrentSchemaVersion)}
		}
	default:
		return []string{fmt.Sprintf(`schema_version: must be the string "1" in quotes, found %v`, sv)}
	}

	diags, err := policies.ValidateValue(policies.ConfigSchema, v)
	if err != nil {
		return []string{"(document): internal error: " + err.Error()}
	}
	diags = friendly(diags)
	if len(diags) > 0 {
		return diags
	}

	cfg, err := decode(data)
	if err != nil {
		return []string{"(document): " + err.Error()}
	}
	return semantic(cfg)
}

// decode parses the YAML strictly into a Config. Unknown fields are errors.
func decode(data []byte) (*Config, error) {
	var cfg Config
	dec := yaml.NewDecoder(bytes.NewReader(data))
	dec.KnownFields(true)
	if err := dec.Decode(&cfg); err != nil && !errors.Is(err, io.EOF) {
		return nil, fmt.Errorf("malformed YAML: %s", strings.TrimPrefix(err.Error(), "yaml: "))
	}
	return &cfg, nil
}

var (
	reMissing    = regexp.MustCompile(`^(.*): missing propert(?:y|ies) (.+)$`)
	reAdditional = regexp.MustCompile(`^(.*): additional properties (.+) not allowed$`)
	reQuoted     = regexp.MustCompile(`'([^']*)'`)
	rePathLike   = regexp.MustCompile(`(^|\.)(tests_path|root)$|(^|\.)(evidence_paths|include|exclude)\[\d+\]$`)
	reControlRef = regexp.MustCompile(`(mandatory_controls\[\d+\]|\.control)$`)
)

// friendly rewrites schema messages into field-first diagnostics that say
// what to change.
func friendly(in []string) []string {
	seen := map[string]bool{}
	var out []string
	add := func(s string) {
		// Keep diagnostics short, so a long value is never echoed in full.
		if r := []rune(s); len(r) > maxDiagnostic {
			s = string(r[:maxDiagnostic]) + "..."
		}
		if !seen[s] {
			seen[s] = true
			out = append(out, s)
		}
	}
	join := func(parent, name string) string {
		if parent == "(document)" || parent == "" {
			return name
		}
		return parent + "." + name
	}
	for _, d := range in {
		if m := reMissing.FindStringSubmatch(d); m != nil {
			for _, q := range reQuoted.FindAllStringSubmatch(m[2], -1) {
				add(join(m[1], q[1]) + ": required field is missing")
			}
			continue
		}
		if m := reAdditional.FindStringSubmatch(d); m != nil {
			for _, q := range reQuoted.FindAllStringSubmatch(m[2], -1) {
				add(join(m[1], q[1]) + ": unknown field; check the spelling against docs/policy-reference.md")
			}
			continue
		}
		path, msg, _ := strings.Cut(d, ": ")
		switch {
		case rePathLike.MatchString(path) && (strings.Contains(msg, "pattern") || strings.Contains(msg, "'not' failed") || strings.Contains(msg, "not failed")):
			add(path + `: must be a repository-relative path with forward slashes, with no leading "/", no drive letter, and no ".." segment`)
		case reControlRef.MatchString(path) && strings.Contains(msg, "pattern"):
			add(path + ": must be a control ID from AGC-001 to AGC-024")
		case (strings.HasSuffix(path, ".expires") || strings.HasSuffix(path, ".last_reviewed")) && strings.Contains(msg, "pattern"):
			add(path + ": must be a date in the form YYYY-MM-DD")
		default:
			add(d)
		}
	}
	sort.Strings(out)
	return out
}

// semantic applies the rules a JSON Schema cannot express.
func semantic(cfg *Config) []string {
	var out []string
	checkDate := func(path, value string) {
		if value == "" {
			return
		}
		if _, err := time.Parse(dateLayout, value); err != nil {
			out = append(out, fmt.Sprintf("%s: %q is not a real calendar date; use YYYY-MM-DD", path, value))
		}
	}
	checkDate("agent.last_reviewed", cfg.Agent.LastReviewed)
	ids := map[string]string{}
	if cfg.Agent.ID != "" {
		ids[cfg.Agent.ID] = "agent.id"
	}
	for i, a := range cfg.Agents {
		p := fmt.Sprintf("agents[%d]", i)
		checkDate(p+".last_reviewed", a.LastReviewed)
		if prev, dup := ids[a.ID]; dup {
			out = append(out, fmt.Sprintf("%s.id: agent ID %q is already used by %s; each agent needs its own ID", p, a.ID, prev))
		} else {
			ids[a.ID] = p + ".id"
		}
	}
	seen := map[string]string{}
	exceptions := func(list []Exception, name string) {
		for i, e := range list {
			p := fmt.Sprintf("policy.%s[%d]", name, i)
			checkDate(p+".expires", e.Expires)
			if strings.TrimSpace(e.Reason) == "" {
				out = append(out, p+".reason: must not be blank")
			}
			if strings.TrimSpace(e.ApprovedBy) == "" {
				out = append(out, p+".approved_by: must not be blank")
			}
			if prev, dup := seen[e.Control]; dup {
				out = append(out, fmt.Sprintf("%s.control: %s already has an exception at %s; keep one entry per control", p, e.Control, prev))
			} else {
				seen[e.Control] = p
			}
		}
	}
	exceptions(cfg.Policy.NotApplicable, "not_applicable")
	exceptions(cfg.Policy.AcceptedRisks, "accepted_risks")
	sort.Strings(out)
	return out
}

func plural(n int, word string) string {
	if n == 1 {
		return fmt.Sprintf("1 %s", word)
	}
	return fmt.Sprintf("%d %ss", n, word)
}
