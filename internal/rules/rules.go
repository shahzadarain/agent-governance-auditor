// SPDX-License-Identifier: Apache-2.0

// Package rules holds the static detectors, one per rule. A detector reports
// what it observed as evidence with a signal:
//
//   - present: the control mechanism was observed in code or configuration.
//   - absent: the detector can see the mechanism, the triggering capability
//     exists, and nothing was found.
//   - violation: a concrete breach was observed.
//   - declared: only a declaration exists.
//
// When a detector cannot tell, it emits nothing. Static evidence never
// claims more than implementation strength; tested and operational strength
// come only from external evidence files.
package rules

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"path"
	"sort"
	"strings"
	"time"

	"github.com/shahzadarain/agent-governance-auditor/internal/adapters"
	"github.com/shahzadarain/agent-governance-auditor/internal/config"
	"github.com/shahzadarain/agent-governance-auditor/internal/model"
)

// Context is what a detector may inspect for one agent.
type Context struct {
	Agent  *adapters.AgentScope
	Repo   *adapters.Repo
	Config *config.Config // may be nil
	Now    time.Time

	cache map[string]any
}

// Detector is one rule.
type Detector interface {
	ID() string
	ControlID() string
	Run(ctx context.Context, c *Context) ([]model.Evidence, []model.Finding)
}

type detector struct {
	id      string
	control string
	run     func(c *Context, o *out)
}

func (d detector) ID() string        { return d.id }
func (d detector) ControlID() string { return d.control }
func (d detector) Run(_ context.Context, c *Context) ([]model.Evidence, []model.Finding) {
	o := &out{c: c, det: d.id, control: d.control, fpSeen: map[string]int{}, evSeen: map[string]bool{}}
	d.run(c, o)
	return o.evidence, o.findings
}

var registry []Detector

func register(control, slug string, run func(c *Context, o *out)) {
	registry = append(registry, detector{id: control + "." + slug, control: control, run: run})
}

// All returns every registered detector in deterministic order.
func All() []Detector {
	out := append([]Detector(nil), registry...)
	sort.SliceStable(out, func(i, j int) bool { return out[i].ID() < out[j].ID() })
	return out
}

// EvidenceID derives the stable evidence identifier.
func EvidenceID(control, agent, collector, sourceLocation string, signal model.Signal) string {
	h := sha256.Sum256([]byte(strings.Join([]string{control, agent, collector, sourceLocation, string(signal)}, "\x00")))
	return "E-" + hex.EncodeToString(h[:])[:12]
}

// RunDetector runs one detector and converts a panic into an error-signal
// evidence item, so a broken collector can never look like a pass.
func RunDetector(ctx context.Context, d Detector, c *Context) (evs []model.Evidence, fs []model.Finding) {
	defer func() {
		if r := recover(); r != nil {
			agent := model.AllAgents
			if c != nil && c.Agent != nil {
				agent = c.Agent.Agent.ID
			}
			loc := "detector:" + d.ID()
			evs = []model.Evidence{{
				EvidenceID: EvidenceID(d.ControlID(), agent, d.ID(), loc, model.SignalError),
				ControlID:  d.ControlID(), AgentID: agent, SourceType: model.SourceStatic, SourceLocation: loc,
				Collector: d.ID(), Integrity: model.IntegrityNotAvailable, Result: model.ResultInconclusive,
				Signal: model.SignalError, Strength: model.StrengthDeclared, Validity: model.ValidityValid,
				Summary:     "The detector failed while analyzing this agent. The control could not be assessed.",
				Limitations: []string{"A collector error is never treated as a pass."},
			}}
			fs = nil
		}
	}()
	return d.Run(ctx, c)
}

// RunAll runs every detector for one agent.
func RunAll(ctx context.Context, c *Context) ([]model.Evidence, []model.Finding) {
	var evs []model.Evidence
	var fs []model.Finding
	for _, d := range All() {
		if ctx.Err() != nil {
			break
		}
		e, f := RunDetector(ctx, d, c)
		evs = append(evs, e...)
		fs = append(fs, f...)
	}
	return evs, fs
}

// ---------------------------------------------------------------------------
// Output builder
// ---------------------------------------------------------------------------

type out struct {
	c        *Context
	det      string
	control  string
	evidence []model.Evidence
	findings []model.Finding
	fpSeen   map[string]int
	evSeen   map[string]bool
}

func isSourcePath(p string) bool {
	switch strings.ToLower(path.Ext(p)) {
	case ".py", ".pyi", ".js", ".mjs", ".cjs", ".jsx", ".ts", ".mts", ".cts", ".tsx":
		return true
	}
	return false
}

// ev records one evidence item and returns its ID. file may be "" for
// evidence without a file location.
func (o *out) ev(signal model.Signal, strength model.Strength, file string, line int, summary string, limitations ...string) string {
	e := model.Evidence{
		ControlID: o.control, AgentID: o.c.Agent.Agent.ID, SourceType: model.SourceStatic, Collector: o.det,
		Integrity: model.IntegrityNotAvailable, Signal: signal, Strength: strength, Validity: model.ValidityValid,
		Summary: summary, Limitations: append([]string{}, limitations...),
	}
	switch signal {
	case model.SignalPresent:
		e.Result = model.ResultPass
	case model.SignalViolation:
		e.Result = model.ResultFail
	default:
		e.Result = model.ResultInconclusive
	}
	if signal == model.SignalDeclared || signal == model.SignalAbsent || signal == model.SignalError {
		e.Strength = model.StrengthDeclared
	}
	if e.Strength != model.StrengthDeclared {
		e.Strength = model.StrengthImplementation // static evidence never claims more
	}
	if file == "" {
		e.SourceLocation = "repository"
		e.SourceType = model.SourceStatic
	} else {
		e.SourceLocation = file
		if line > 0 {
			e.SourceLocation = fmt.Sprintf("%s:%d", file, line)
		}
		e.Location = &model.Location{Path: file, Line: line}
		if !isSourcePath(file) {
			e.SourceType = model.SourceConfiguration
		}
	}
	e.EvidenceID = EvidenceID(e.ControlID, e.AgentID, e.Collector, e.SourceLocation, e.Signal)
	if o.evSeen[e.EvidenceID] {
		return e.EvidenceID
	}
	o.evSeen[e.EvidenceID] = true
	o.evidence = append(o.evidence, e)
	return e.EvidenceID
}

func (o *out) present(file string, line int, summary string, limitations ...string) string {
	return o.ev(model.SignalPresent, model.StrengthImplementation, file, line, summary, limitations...)
}

func (o *out) absent(summary string, limitations ...string) string {
	return o.ev(model.SignalAbsent, model.StrengthDeclared, "", 0, summary, limitations...)
}

func (o *out) violation(file string, line int, summary string, limitations ...string) string {
	return o.ev(model.SignalViolation, model.StrengthImplementation, file, line, summary, limitations...)
}

func (o *out) declared(file string, line int, summary string, limitations ...string) string {
	return o.ev(model.SignalDeclared, model.StrengthDeclared, file, line, summary, limitations...)
}

// findingSpec is the fixed text of one finding type.
type findingSpec struct {
	Slug        string
	Severity    model.Severity
	Confidence  model.Confidence
	Title       string
	Why         string
	Remediation []string
	Repro       string
}

var spaceCollapse = strings.NewReplacer("\t", " ", "\r", " ", "\n", " ")

func normalizeSnippet(s string) string {
	return strings.Join(strings.Fields(spaceCollapse.Replace(s)), " ")
}

// finding records one finding. context is the fingerprint context: for
// source files pass "" to use the code-view line (string contents are
// blanked there, so no secret value can enter the hash); for other files
// pass a key name or path. Never pass a secret value.
func (o *out) finding(spec findingSpec, file string, line int, context, description string, evRefs ...string) {
	if context == "" && file != "" {
		if src := o.c.Repo.Source(file); src != nil && line > 0 {
			context = normalizeSnippet(src.CodeLine(line))
		}
	}
	ruleID := o.control + "." + spec.Slug
	agent := o.c.Agent.Agent.ID
	base := strings.Join([]string{ruleID, agent, file, normalizeSnippet(context)}, "\x00")
	n := o.fpSeen[base]
	o.fpSeen[base] = n + 1
	if n > 0 {
		base += fmt.Sprintf("\x00#%d", n)
	}
	sum := sha256.Sum256([]byte(base))
	fp := hex.EncodeToString(sum[:])
	f := model.Finding{
		FindingID: "F-" + fp[:12], Fingerprint: fp, RuleID: ruleID, ControlID: o.control, AgentID: agent,
		Severity: spec.Severity, Confidence: spec.Confidence, Title: spec.Title, Description: description,
		WhyItMatters: spec.Why, Remediation: append([]string{}, spec.Remediation...), Reproduction: spec.Repro,
		EvidenceRefs: append([]string{}, evRefs...), Mappings: []model.Mapping{},
	}
	if file != "" {
		f.Location = &model.Location{Path: file, Line: line}
	}
	o.findings = append(o.findings, f)
}

func at(file string, line int) string {
	if line > 0 {
		return fmt.Sprintf("%s:%d", file, line)
	}
	return file
}

func (c *Context) has(cap string) bool {
	for _, x := range c.Agent.Agent.Capabilities {
		if x == cap {
			return true
		}
	}
	return false
}

// sources returns the non-test sources of the agent.
func (c *Context) sources() []*adapters.Source {
	if v, ok := c.cache["sources"]; ok {
		return v.([]*adapters.Source)
	}
	var out []*adapters.Source
	for _, s := range c.Agent.Sources {
		if !c.Agent.IsTest(s.Path) {
			out = append(out, s)
		}
	}
	c.memo("sources", out)
	return out
}

func (c *Context) memo(key string, v any) {
	if c.cache == nil {
		c.cache = map[string]any{}
	}
	c.cache[key] = v
}
