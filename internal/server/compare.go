// SPDX-License-Identifier: Apache-2.0

package server

import (
	"bytes"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"sort"
	"strings"
	"time"

	"github.com/shahzadarain/agent-governance-auditor/internal/model"
)

// compareScans computes the difference between two scans of one project.
//
// Findings are matched by fingerprint: new (only in after), resolved (only
// in before), unchanged (in both). Control changes list every agent and
// control present in both scans whose status or maturity differs; controls
// of an agent that exists in only one scan are not listed.
//
// Comparable is false when the policy pack, policy version, or profile
// differ. The numbers are still returned, but a client must not present
// them as a trend.
//
// This is a local implementation because the server may not import
// internal/reporting yet. It follows the same model.Comparison contract.
func compareScans(before, after *model.ScanResult) model.Comparison {
	c := model.Comparison{
		Comparable:       true,
		BeforeCommit:     before.Scan.CommitSHA,
		AfterCommit:      after.Scan.CommitSHA,
		BeforeScore:      before.Score,
		AfterScore:       after.Score,
		BeforeDecision:   before.Decision.Outcome,
		AfterDecision:    after.Decision.Outcome,
		NewFindings:      []model.Finding{},
		ResolvedFindings: []model.Finding{},
		ControlChanges:   []model.ControlChange{},
	}
	var why []string
	if before.Scan.PolicyPack != after.Scan.PolicyPack {
		why = append(why, "policy pack differs")
	}
	if before.Scan.PolicyVersion != after.Scan.PolicyVersion {
		why = append(why, "policy version differs")
	}
	if before.Scan.Profile != after.Scan.Profile {
		why = append(why, "profile differs")
	}
	if len(why) > 0 {
		c.Comparable = false
		c.NotComparableWhy = strings.Join(why, "; ")
	}

	beforeFP := map[string]bool{}
	for _, f := range before.Findings {
		beforeFP[f.Fingerprint] = true
	}
	afterFP := map[string]bool{}
	for _, f := range after.Findings {
		if afterFP[f.Fingerprint] {
			continue
		}
		afterFP[f.Fingerprint] = true
		if beforeFP[f.Fingerprint] {
			c.UnchangedCount++
		} else {
			c.NewFindings = append(c.NewFindings, f)
		}
	}
	seen := map[string]bool{}
	for _, f := range before.Findings {
		if !afterFP[f.Fingerprint] && !seen[f.Fingerprint] {
			seen[f.Fingerprint] = true
			c.ResolvedFindings = append(c.ResolvedFindings, f)
		}
	}

	type key struct{ agent, control string }
	prev := map[key]model.ControlResult{}
	for _, as := range before.Assessments {
		for _, cr := range as.Controls {
			prev[key{as.AgentID, cr.ControlID}] = cr
		}
	}
	for _, as := range after.Assessments {
		for _, cr := range as.Controls {
			b, ok := prev[key{as.AgentID, cr.ControlID}]
			if !ok || (b.Status == cr.Status && b.Maturity == cr.Maturity) {
				continue
			}
			c.ControlChanges = append(c.ControlChanges, model.ControlChange{ControlID: cr.ControlID, AgentID: as.AgentID,
				BeforeStatus: b.Status, AfterStatus: cr.Status, BeforeMaturity: b.Maturity, AfterMaturity: cr.Maturity})
		}
	}
	sort.Slice(c.ControlChanges, func(i, j int) bool {
		if c.ControlChanges[i].AgentID != c.ControlChanges[j].AgentID {
			return c.ControlChanges[i].AgentID < c.ControlChanges[j].AgentID
		}
		return c.ControlChanges[i].ControlID < c.ControlChanges[j].ControlID
	})
	return c
}

// CanonicalEvidence returns the byte string that an evidence signature
// covers.
//
// It mirrors the canonical form defined and documented in
// internal/evidence (the CLI's "evidence sign" and "evidence verify"), so a
// signature made by the CLI verifies here. The server keeps its own copy
// because it was built while internal/evidence was still changing.
// TODO(unify): replace this function with a call into internal/evidence once
// that package exports its canonical form. TestEvidenceCanonicalGolden pins
// the exact bytes so a drift in either copy is visible.
//
// The canonical form is one JSON object with exactly these keys, sorted, no
// insignificant white space, no trailing newline, and no HTML escaping:
//
//	agent_id, collector, commit_sha, control_id, identity_context,
//	limitations, observed_at, result, signal, source_type, strength,
//	subject_digest, subject_paths, summary, valid_until
//
// Rules: commit_sha is "" when it is "unknown"; subject_digest is "" and
// subject_paths is [] without a subject; subject_paths is sorted;
// limitations keeps its order and is [] when empty; observed_at and
// valid_until are UTC RFC 3339 with nanoseconds only when non-zero;
// valid_until is "" when no expiry is stated. Every field the scanner sets
// (evidence_id, policy_version, scanner_version, source_location, location,
// artifact_digest, integrity, validity, validity_reason) is excluded.
func CanonicalEvidence(ev model.Evidence) ([]byte, error) {
	commit := ev.CommitSHA
	if commit == model.Unknown {
		commit = ""
	}
	limitations := ev.Limitations
	if limitations == nil {
		limitations = []string{}
	}
	paths, digest := []string{}, ""
	if ev.Subject != nil {
		paths = append(paths, ev.Subject.Paths...)
		sort.Strings(paths)
		digest = ev.Subject.Digest
	}
	validUntil := ""
	if ev.ValidUntil != nil {
		validUntil = ev.ValidUntil.UTC().Format(time.RFC3339Nano)
	}
	m := map[string]any{ // encoding/json writes map keys sorted
		"agent_id": ev.AgentID, "collector": ev.Collector, "commit_sha": commit, "control_id": ev.ControlID,
		"identity_context": ev.IdentityContext, "limitations": limitations,
		"observed_at": ev.ObservedAt.UTC().Format(time.RFC3339Nano), "result": string(ev.Result), "signal": string(ev.Signal),
		"source_type": string(ev.SourceType), "strength": string(ev.Strength), "subject_digest": digest, "subject_paths": paths,
		"summary": ev.Summary, "valid_until": validUntil,
	}
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetEscapeHTML(false)
	if err := enc.Encode(m); err != nil {
		return nil, err
	}
	return bytes.TrimRight(buf.Bytes(), "\n"), nil
}

type evidenceVerifyRequest struct {
	Evidence  model.Evidence `json:"evidence"`
	Signature string         `json:"signature"` // base64 (standard or URL alphabet) Ed25519 signature
	KeyID     string         `json:"key_id"`    // key in Config.TrustedKeys
}

type evidenceVerifyResponse struct {
	Verified bool   `json:"verified"`
	KeyID    string `json:"key_id"`
	Reason   string `json:"reason"`
}

func decodeSignature(s string) ([]byte, bool) {
	s = strings.TrimSpace(s)
	for _, enc := range []*base64.Encoding{base64.StdEncoding, base64.RawStdEncoding, base64.URLEncoding, base64.RawURLEncoding} {
		if b, err := enc.DecodeString(s); err == nil {
			return b, true
		}
	}
	return nil, false
}

// handleEvidenceVerify checks a detached Ed25519 signature over one evidence
// item against a key configured on the server. It stores nothing and
// fetches nothing.
func (a *App) handleEvidenceVerify(w http.ResponseWriter, r *http.Request, _ *reqCtx) {
	var req evidenceVerifyRequest
	if !readJSON(w, r, &req, 4*smallBodyLimit) {
		return
	}
	resp := evidenceVerifyResponse{KeyID: req.KeyID}
	key, ok := a.cfg.TrustedKeys[req.KeyID]
	sig, sigOK := decodeSignature(req.Signature)
	switch {
	case !ok || len(key) != ed25519.PublicKeySize:
		resp.Reason = "The key ID is not a trusted key on this server."
	case !sigOK || len(sig) != ed25519.SignatureSize:
		resp.Reason = "The signature is not a base64-encoded Ed25519 signature."
	default:
		msg, err := CanonicalEvidence(req.Evidence)
		if err != nil {
			a.internalError(w, r, "canonicalize evidence", err)
			return
		}
		if ed25519.Verify(key, msg, sig) {
			resp.Verified = true
			resp.Reason = "The signature is valid for this evidence and key."
		} else {
			resp.Reason = "The signature does not match this evidence and key."
		}
	}
	writeJSON(w, http.StatusOK, resp)
}
