// SPDX-License-Identifier: Apache-2.0

package server

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math"
	"mime"
	"net/http"
	"reflect"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/shahzadarain/agent-governance-auditor/internal/model"
	"github.com/shahzadarain/agent-governance-auditor/internal/storage"
)

// Upload limits. The body size limit is Config.MaxUploadBytes.
const (
	maxAgents       = 200
	maxFindings     = 10000
	maxEvidence     = 20000
	maxSliceLen     = 20000 // any other array in the document
	maxMapLen       = 256
	maxStringBytes  = 8192 // any string field
	maxIDBytes      = 256  // identifiers
	maxFutureSkew   = 24 * time.Hour
	maxValidationEr = 10
)

var (
	controlIDRe  = regexp.MustCompile(`^AGC-0(0[1-9]|1[0-9]|2[0-4])$`)
	earliestTime = time.Date(2000, 1, 1, 0, 0, 0, 0, time.UTC)
)

var (
	validStatuses = set(model.StatusVerifiedOperational, model.StatusVerifiedTested, model.StatusVerifiedImplementation,
		model.StatusDeclaredOnly, model.StatusMissing, model.StatusFailed, model.StatusUnknown, model.StatusNotApplicable,
		model.StatusAcceptedRisk, model.StatusError)
	validSeverities = set(model.SeverityCritical, model.SeverityHigh, model.SeverityMedium, model.SeverityLow, model.SeverityInfo)
	validOutcomes   = set(model.OutcomeAllow, model.OutcomeBlock, model.OutcomeReviewRequired)
	// The enumerations below are checked only when the field is not empty.
	validConfidence = set(model.ConfidenceHigh, model.ConfidenceMedium, model.ConfidenceLow)
	validDetection  = set(model.Detected, model.Suspected, model.NotDetected)
	validSource     = set(model.SourceStatic, model.SourceConfiguration, model.SourceTest, model.SourceRuntime, model.SourceAttestation, model.SourceManualReview)
	validIntegrity  = set(model.IntegrityVerified, model.IntegrityUnsigned, model.IntegrityInvalid, model.IntegrityNotAvailable)
	validResult     = set(model.ResultPass, model.ResultFail, model.ResultInconclusive)
	validSignal     = set(model.SignalPresent, model.SignalAbsent, model.SignalViolation, model.SignalDeclared, model.SignalError)
	validStrength   = set(model.StrengthDeclared, model.StrengthImplementation, model.StrengthTested, model.StrengthOperational)
	validValidity   = set(model.ValidityValid, model.ValidityExpired, model.ValidityCommitMismatch, model.ValidityDigestMismatch,
		model.ValidityUnbound, model.ValidityInvalidSignature, model.ValidityMalformed)
)

func set[T ~string](vals ...T) map[T]bool {
	m := make(map[T]bool, len(vals))
	for _, v := range vals {
		m[v] = true
	}
	return m
}

// problems collects validation messages up to a small cap. Messages name the
// field and the rule. They never echo field content.
type problems struct{ list []string }

func (p *problems) add(format string, args ...any) {
	if len(p.list) < maxValidationEr {
		p.list = append(p.list, fmt.Sprintf(format, args...))
	}
}

func (p *problems) full() bool { return len(p.list) >= maxValidationEr }

var timeType = reflect.TypeOf(time.Time{})

// walkLimits bounds every string, array, and map in the decoded document.
// The document depth is fixed by the Go types, so recursion is bounded.
func walkLimits(v reflect.Value, path string, p *problems) {
	if p.full() {
		return
	}
	switch v.Kind() {
	case reflect.String:
		if v.Len() > maxStringBytes {
			p.add("%s: string is longer than %d bytes", path, maxStringBytes)
		}
	case reflect.Pointer:
		if !v.IsNil() {
			walkLimits(v.Elem(), path, p)
		}
	case reflect.Slice:
		if v.Len() > maxSliceLen {
			p.add("%s: array has more than %d items", path, maxSliceLen)
			return
		}
		for i := 0; i < v.Len() && !p.full(); i++ {
			walkLimits(v.Index(i), path+"["+strconv.Itoa(i)+"]", p)
		}
	case reflect.Map:
		if v.Len() > maxMapLen {
			p.add("%s: object has more than %d keys", path, maxMapLen)
			return
		}
		for _, k := range v.MapKeys() {
			if k.Kind() == reflect.String && k.Len() > maxIDBytes {
				p.add("%s: object key is longer than %d bytes", path, maxIDBytes)
				return
			}
			walkLimits(v.MapIndex(k), path+"{}", p)
		}
	case reflect.Struct:
		if v.Type() == timeType {
			return
		}
		t := v.Type()
		for i := 0; i < v.NumField(); i++ {
			name := strings.Split(t.Field(i).Tag.Get("json"), ",")[0]
			if name == "" {
				name = t.Field(i).Name
			}
			sub := name
			if path != "" {
				sub = path + "." + name
			}
			walkLimits(v.Field(i), sub, p)
		}
	}
}

func checkID(p *problems, path, v string, required bool) {
	if v == "" {
		if required {
			p.add("%s: value is required", path)
		}
		return
	}
	if len(v) > maxIDBytes {
		p.add("%s: identifier is longer than %d bytes", path, maxIDBytes)
	}
}

func checkTime(p *problems, path string, t, now time.Time) {
	if t.IsZero() {
		return
	}
	if t.After(now.Add(maxFutureSkew)) {
		p.add("%s: timestamp is more than 24 hours in the future", path)
	}
	if t.Before(earliestTime) {
		p.add("%s: timestamp is before the year 2000", path)
	}
}

func checkScore(p *problems, path string, s model.Score) {
	if s.Value != nil && (*s.Value < 0 || *s.Value > 100) {
		p.add("%s.value: score must be between 0 and 100", path)
	}
}

func checkOptEnum[T ~string](p *problems, path string, v T, valid map[T]bool) {
	if v != "" && !valid[v] {
		p.add("%s: value is not allowed", path)
	}
}

// validateScanResult applies the semantic rules after strict decoding. It
// returns human-readable problems; an empty list means the document is
// accepted.
func validateScanResult(res *model.ScanResult, now time.Time) []string {
	p := &problems{}
	if res.SchemaVersion != model.SchemaVersion {
		p.add("schema_version: must be %q", model.SchemaVersion)
		return p.list
	}
	if len(res.Agents) > maxAgents {
		p.add("agents: more than %d items", maxAgents)
	}
	if len(res.Assessments) > maxAgents {
		p.add("assessments: more than %d items", maxAgents)
	}
	if len(res.Findings) > maxFindings {
		p.add("findings: more than %d items", maxFindings)
	}
	if len(res.Evidence) > maxEvidence {
		p.add("evidence: more than %d items", maxEvidence)
	}
	if len(p.list) > 0 {
		return p.list
	}
	walkLimits(reflect.ValueOf(res).Elem(), "", p)
	if len(p.list) > 0 {
		return p.list
	}

	checkID(p, "tool.name", res.Tool.Name, true)
	checkID(p, "tool.version", res.Tool.Version, false)
	checkID(p, "scan.scan_id", res.Scan.ScanID, true)
	checkID(p, "scan.commit_sha", res.Scan.CommitSHA, false)
	checkID(p, "scan.profile", res.Scan.Profile, false)
	checkID(p, "scan.policy_pack", res.Scan.PolicyPack, false)
	checkID(p, "scan.policy_version", res.Scan.PolicyVersion, false)
	checkTime(p, "scan.started_at", res.Scan.StartedAt, now)
	checkTime(p, "scan.finished_at", res.Scan.FinishedAt, now)
	if !validOutcomes[res.Decision.Outcome] {
		p.add("decision.outcome: must be ALLOW, BLOCK, or REVIEW_REQUIRED")
	}
	checkScore(p, "score", res.Score)

	agentIDs := map[string]bool{}
	for i, a := range res.Agents {
		path := fmt.Sprintf("agents[%d]", i)
		checkID(p, path+".id", a.ID, true)
		if a.ID == model.AllAgents {
			p.add("%s.id: %q is reserved", path, model.AllAgents)
		}
		if agentIDs[a.ID] {
			p.add("%s.id: duplicate agent ID", path)
		}
		agentIDs[a.ID] = true
		checkOptEnum(p, path+".detection", a.Detection, validDetection)
		checkOptEnum(p, path+".confidence", a.Confidence, validConfidence)
	}

	assessed := map[string]bool{}
	for i, as := range res.Assessments {
		path := fmt.Sprintf("assessments[%d]", i)
		if !agentIDs[as.AgentID] {
			p.add("%s.agent_id: does not match an agent in this document", path)
		}
		if assessed[as.AgentID] {
			p.add("%s.agent_id: duplicate assessment", path)
		}
		assessed[as.AgentID] = true
		if !validOutcomes[as.Decision.Outcome] {
			p.add("%s.decision.outcome: must be ALLOW, BLOCK, or REVIEW_REQUIRED", path)
		}
		checkScore(p, path+".score", as.Score)
		if len(as.Controls) > 24 {
			p.add("%s.controls: more than 24 items", path)
			continue
		}
		seen := map[string]bool{}
		for j, c := range as.Controls {
			cp := fmt.Sprintf("%s.controls[%d]", path, j)
			if !controlIDRe.MatchString(c.ControlID) {
				p.add("%s.control_id: must be AGC-001 to AGC-024", cp)
			}
			if seen[c.ControlID] {
				p.add("%s.control_id: duplicate control", cp)
			}
			seen[c.ControlID] = true
			if c.AgentID != "" && c.AgentID != as.AgentID {
				p.add("%s.agent_id: does not match the assessment", cp)
			}
			if !validStatuses[c.Status] {
				p.add("%s.status: value is not allowed", cp)
			}
			if c.Maturity < 0 || c.Maturity > 4 {
				p.add("%s.maturity: must be between 0 and 4", cp)
			}
			checkOptEnum(p, cp+".severity", c.Severity, validSeverities)
		}
	}

	for i, f := range res.Findings {
		path := fmt.Sprintf("findings[%d]", i)
		checkID(p, path+".finding_id", f.FindingID, true)
		checkID(p, path+".fingerprint", f.Fingerprint, true)
		checkID(p, path+".agent_id", f.AgentID, false)
		if !controlIDRe.MatchString(f.ControlID) {
			p.add("%s.control_id: must be AGC-001 to AGC-024", path)
		}
		if !validSeverities[f.Severity] {
			p.add("%s.severity: value is not allowed", path)
		}
		checkOptEnum(p, path+".confidence", f.Confidence, validConfidence)
		if f.Location != nil && (f.Location.Line < 0 || f.Location.Line > math.MaxInt32) {
			p.add("%s.location.line: out of range", path)
		}
		if p.full() {
			break
		}
	}

	for i, e := range res.Evidence {
		path := fmt.Sprintf("evidence[%d]", i)
		checkID(p, path+".evidence_id", e.EvidenceID, false)
		if !controlIDRe.MatchString(e.ControlID) {
			p.add("%s.control_id: must be AGC-001 to AGC-024", path)
		}
		checkTime(p, path+".observed_at", e.ObservedAt, now)
		checkOptEnum(p, path+".source_type", e.SourceType, validSource)
		checkOptEnum(p, path+".integrity", e.Integrity, validIntegrity)
		checkOptEnum(p, path+".result", e.Result, validResult)
		checkOptEnum(p, path+".signal", e.Signal, validSignal)
		checkOptEnum(p, path+".strength", e.Strength, validStrength)
		checkOptEnum(p, path+".validity", e.Validity, validValidity)
		if p.full() {
			break
		}
	}
	return p.list
}

// decodeStrictJSON decodes exactly one JSON value into dst and rejects
// unknown fields and trailing data.
func decodeStrictJSON(data []byte, dst any) error {
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.DisallowUnknownFields()
	if err := dec.Decode(dst); err != nil {
		return err
	}
	if _, err := dec.Token(); !errors.Is(err, io.EOF) {
		return errors.New("unexpected data after the JSON document")
	}
	return nil
}

func isJSONContentType(r *http.Request) bool {
	mt, _, err := mime.ParseMediaType(r.Header.Get("Content-Type"))
	return err == nil && mt == "application/json"
}

// safeDecodeMessage turns a decoder error into a message that is safe to
// return: it names the problem and the field, never the content.
func safeDecodeMessage(err error) string {
	var syn *json.SyntaxError
	var typ *json.UnmarshalTypeError
	switch {
	case errors.As(err, &syn):
		return fmt.Sprintf("The body is not valid JSON (offset %d).", syn.Offset)
	case errors.As(err, &typ):
		return fmt.Sprintf("Field %q has the wrong JSON type.", typ.Field)
	case errors.Is(err, io.ErrUnexpectedEOF), errors.Is(err, io.EOF):
		return "The body is not a complete JSON document."
	case strings.HasPrefix(err.Error(), "json: unknown field "):
		name := strings.TrimPrefix(err.Error(), "json: unknown field ")
		if len(name) > 80 {
			name = name[:80]
		}
		return "Unknown field " + name + "."
	case strings.HasPrefix(err.Error(), "parsing time"):
		return "A timestamp is not in RFC 3339 format."
	case strings.HasPrefix(err.Error(), "unexpected data"):
		return "Unexpected data after the JSON document."
	}
	return "The body does not match the expected schema."
}

// handleIngest implements POST /api/v1/scans. The body is untrusted. The
// project always comes from the token, never from the body.
func (a *App) handleIngest(w http.ResponseWriter, r *http.Request, rc *reqCtx) {
	tok := rc.token
	if ok, wait := a.ingestRL.allow(tok.ID); !ok {
		a.metrics.ingest("rate_limited")
		w.Header().Set("Retry-After", strconv.Itoa(int(wait.Seconds())+1))
		writeError(w, http.StatusTooManyRequests, "rate_limited", "Too many uploads for this token. Retry later.")
		return
	}
	reject := func(status int, code, msg string) {
		a.metrics.ingest("rejected")
		writeError(w, status, code, msg)
	}
	if !isJSONContentType(r) {
		reject(http.StatusUnsupportedMediaType, "unsupported_media_type", "Content-Type must be application/json.")
		return
	}
	if r.ContentLength > a.cfg.MaxUploadBytes {
		reject(http.StatusRequestEntityTooLarge, "payload_too_large", fmt.Sprintf("The upload limit is %d bytes.", a.cfg.MaxUploadBytes))
		return
	}
	body, err := io.ReadAll(http.MaxBytesReader(w, r.Body, a.cfg.MaxUploadBytes))
	if err != nil {
		var tooBig *http.MaxBytesError
		if errors.As(err, &tooBig) {
			reject(http.StatusRequestEntityTooLarge, "payload_too_large", fmt.Sprintf("The upload limit is %d bytes.", a.cfg.MaxUploadBytes))
			return
		}
		reject(http.StatusBadRequest, "bad_request", "The request body could not be read.")
		return
	}
	var res model.ScanResult
	if err := decodeStrictJSON(body, &res); err != nil {
		reject(http.StatusBadRequest, "invalid_payload", safeDecodeMessage(err))
		return
	}
	now := a.cfg.Now()
	if probs := validateScanResult(&res, now); len(probs) > 0 {
		reject(http.StatusBadRequest, "invalid_payload", "The scan result failed validation: "+strings.Join(probs, "; ")+".")
		return
	}

	sum := sha256.Sum256(body)
	in := buildIngest(&res, body, hex.EncodeToString(sum[:]), tok, now)
	scan, created, err := a.store.IngestScan(r.Context(), in)
	if err != nil {
		a.internalError(w, r, "ingest scan", err)
		return
	}
	_ = a.store.TouchToken(r.Context(), tok.ID, now)
	status := http.StatusOK
	if created {
		status = http.StatusCreated
		a.metrics.ingest("created")
	} else {
		a.metrics.ingest("duplicate")
	}
	writeJSON(w, status, ingestResponse{ID: scan.ID, ScanID: scan.ScanID, ProjectID: scan.ProjectID, Created: created,
		ReceivedAt: scan.ReceivedAt, URL: "/api/v1/scans/" + scan.ID})
}

type ingestResponse struct {
	ID         string    `json:"id"`
	ScanID     string    `json:"scan_id"`
	ProjectID  string    `json:"project_id"`
	Created    bool      `json:"created"`
	ReceivedAt time.Time `json:"received_at"`
	URL        string    `json:"url"`
}

// buildIngest maps a validated ScanResult to the rows the store writes.
func buildIngest(res *model.ScanResult, body []byte, sha string, tok storage.APIToken, now time.Time) storage.IngestInput {
	rowID := "scn_" + randomHex(16)
	in := storage.IngestInput{
		Scan: storage.Scan{
			ID: rowID, ProjectID: tok.ProjectID, ScanID: res.Scan.ScanID, Target: res.Scan.Target, CommitSHA: res.Scan.CommitSHA,
			Profile: res.Scan.Profile, PolicyPack: res.Scan.PolicyPack, PolicyVersion: res.Scan.PolicyVersion,
			ToolVersion: res.Tool.Version, Decision: string(res.Decision.Outcome), Score: res.Score.Value, ScoreLabel: res.Score.Label,
			ReceivedAt: now, UploadedByToken: tok.ID, PayloadSHA256: sha,
		},
		Payload: body,
	}
	byAgent := map[string]*model.AgentAssessment{}
	for i := range res.Assessments {
		as := &res.Assessments[i]
		byAgent[as.AgentID] = as
		for _, c := range as.Controls {
			in.Controls = append(in.Controls, storage.IngestControl{AgentID: as.AgentID, ControlID: c.ControlID,
				Status: string(c.Status), Maturity: c.Maturity, Mandatory: c.Mandatory})
		}
	}
	for _, ag := range res.Agents {
		row := storage.IngestAgent{NewKey: "agk_" + randomHex(16), AgentID: ag.ID, Name: ag.Name, Framework: ag.Framework,
			Language: ag.Language, Owner: ag.Owner, RiskTier: ag.RiskTier}
		// An agent without an assessment keeps an empty decision: the server
		// does not guess one.
		if as := byAgent[ag.ID]; as != nil {
			row.Decision, row.Score, row.ScoreLabel = string(as.Decision.Outcome), as.Score.Value, as.Score.Label
		}
		in.Agents = append(in.Agents, row)
	}
	for _, f := range res.Findings {
		row := storage.IngestFinding{FindingID: f.FindingID, Fingerprint: f.Fingerprint, ControlID: f.ControlID, AgentID: f.AgentID,
			Severity: string(f.Severity), Title: f.Title}
		if f.Location != nil {
			row.Path, row.Line = f.Location.Path, f.Location.Line
		}
		in.Findings = append(in.Findings, row)
	}
	detail, _ := json.Marshal(map[string]any{
		"scan_id": res.Scan.ScanID, "commit_sha": res.Scan.CommitSHA, "tool_version": res.Tool.Version,
		"payload_sha256": sha, "decision": res.Decision.Outcome, "agents": len(res.Agents), "findings": len(res.Findings),
	})
	in.Audit = &storage.AuditEvent{At: now, ActorType: storage.ActorToken, ActorID: tok.ID, Action: "scan.ingested",
		Target: "scan:" + rowID, ProjectID: tok.ProjectID, Detail: string(detail)}
	return in
}
