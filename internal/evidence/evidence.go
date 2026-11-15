// SPDX-License-Identifier: Apache-2.0

// Package evidence loads, binds, signs, and verifies external evidence.
//
// External evidence is a JSON document described by
// policies/schema/evidence.schema.json:
//
//	{ "schema_version": "1", "evidence": [ { ...item... } ] }
//
// Evidence files are untrusted input. Each item is schema-validated, bound to
// the repository (by commit SHA, by a content digest of named files, or
// both), and checked for expiry. An item may only claim the source types
// test, runtime, external-attestation, or manual-review; static and
// configuration evidence can only come from the scanner.
//
// # Canonical form for signatures
//
// A signature is the base64 (standard encoding, with padding) Ed25519
// signature over the canonical JSON encoding of an item. The canonical form
// is a single JSON object with exactly these keys in this (alphabetical)
// order, no insignificant whitespace, and no HTML escaping:
//
//	agent_id, collector, commit_sha, control_id, identity_context,
//	limitations, observed_at, result, signal, source_type, strength,
//	subject_digest, subject_paths, summary, valid_until
//
// Rules: commit_sha is "" when the item is not commit-bound; subject_digest
// is "" and subject_paths is [] when there is no subject; subject_paths is
// sorted; limitations keeps its order and is [] when empty; observed_at and
// valid_until are UTC in RFC 3339 form with nanoseconds only when non-zero;
// valid_until is "" when no expiry is stated. The signature itself and
// every field the scanner sets (evidence_id, policy_version,
// scanner_version, source_location, integrity, validity) are excluded.
package evidence

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	_ "embed"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"time"

	"github.com/santhosh-tekuri/jsonschema/v6"

	"github.com/shahzadarain/agent-governance-auditor/internal/model"
)

// Limits for untrusted evidence input.
const (
	MaxFileBytes   = 256 << 10 // per evidence file
	MaxItems       = 500       // per evidence file
	MaxFiles       = 200       // per evidence directory
	maxSubjectFile = 32 << 20  // per subject file
)

//go:embed evidence.schema.json
var schemaJSON []byte

// SchemaJSON returns the JSON Schema of the external evidence document.
func SchemaJSON() []byte { return append([]byte(nil), schemaJSON...) }

var compiled struct {
	doc, item *jsonschema.Schema
	err       error
	done      bool
}

func schemas() (*jsonschema.Schema, *jsonschema.Schema, error) {
	if compiled.done {
		return compiled.doc, compiled.item, compiled.err
	}
	compiled.done = true
	doc, err := jsonschema.UnmarshalJSON(bytes.NewReader(schemaJSON))
	if err != nil {
		compiled.err = err
		return nil, nil, err
	}
	c := jsonschema.NewCompiler()
	const url = "https://agentgov.invalid/evidence.schema.json"
	if err := c.AddResource(url, doc); err != nil {
		compiled.err = err
		return nil, nil, err
	}
	if compiled.doc, err = c.Compile(url); err != nil {
		compiled.err = err
		return nil, nil, err
	}
	compiled.item, compiled.err = c.Compile(url + "#/$defs/item")
	return compiled.doc, compiled.item, compiled.err
}

// cleanRel validates a repo-relative path and returns it with forward
// slashes. It rejects absolute paths and anything that leaves the root.
func cleanRel(p string) (string, error) {
	if p == "" || strings.ContainsRune(p, 0) {
		return "", fmt.Errorf("empty or invalid path")
	}
	n := strings.ReplaceAll(p, "\\", "/")
	if strings.HasPrefix(n, "/") || (len(n) >= 2 && n[1] == ':') {
		return "", fmt.Errorf("path %q is absolute", p)
	}
	c := path.Clean(n)
	if c == ".." || strings.HasPrefix(c, "../") || c == "." {
		return "", fmt.Errorf("path %q leaves the repository root", p)
	}
	return c, nil
}

// insideRoot resolves links and confirms the file stays inside root.
func insideRoot(root, rel string) (string, error) {
	absRoot, err := filepath.Abs(root)
	if err != nil {
		return "", err
	}
	if r, err := filepath.EvalSymlinks(absRoot); err == nil {
		absRoot = r
	}
	full := filepath.Join(absRoot, filepath.FromSlash(rel))
	resolved, err := filepath.EvalSymlinks(full)
	if err != nil {
		return "", fmt.Errorf("%s: not readable", rel)
	}
	r, err := filepath.Rel(absRoot, resolved)
	if err != nil || r == ".." || strings.HasPrefix(r, ".."+string(filepath.Separator)) || filepath.IsAbs(r) {
		return "", fmt.Errorf("%s: resolves outside the repository root", rel)
	}
	return resolved, nil
}

// SubjectDigest returns the lowercase hex SHA-256 binding for the given
// repo-relative paths. Paths are cleaned, de-duplicated, and sorted. Each
// contributes: the path, a NUL byte, the lowercase hex SHA-256 of the file
// content with CRLF normalized to LF, and a newline. Paths that escape the
// root are rejected.
func SubjectDigest(root string, paths []string) (string, error) {
	if len(paths) == 0 {
		return "", fmt.Errorf("no subject paths")
	}
	seen := map[string]bool{}
	var clean []string
	for _, p := range paths {
		c, err := cleanRel(p)
		if err != nil {
			return "", err
		}
		if !seen[c] {
			seen[c] = true
			clean = append(clean, c)
		}
	}
	sort.Strings(clean)
	h := sha256.New()
	for _, rel := range clean {
		full, err := insideRoot(root, rel)
		if err != nil {
			return "", err
		}
		fi, err := os.Stat(full)
		if err != nil || !fi.Mode().IsRegular() {
			return "", fmt.Errorf("%s: not a regular file", rel)
		}
		if fi.Size() > maxSubjectFile {
			return "", fmt.Errorf("%s: too large to bind", rel)
		}
		data, err := os.ReadFile(full)
		if err != nil {
			return "", fmt.Errorf("%s: not readable", rel)
		}
		data = bytes.ReplaceAll(data, []byte("\r\n"), []byte("\n"))
		sum := sha256.Sum256(data)
		h.Write([]byte(rel))
		h.Write([]byte{0})
		h.Write([]byte(hex.EncodeToString(sum[:])))
		h.Write([]byte{'\n'})
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}

// Item is one entry of an external evidence document, in file field order.
type Item struct {
	ControlID       string         `json:"control_id"`
	AgentID         string         `json:"agent_id"`
	SourceType      string         `json:"source_type"`
	Collector       string         `json:"collector"`
	ObservedAt      string         `json:"observed_at"`
	ValidUntil      *string        `json:"valid_until"`
	Result          string         `json:"result"`
	Signal          string         `json:"signal"`
	Strength        string         `json:"strength"`
	Summary         string         `json:"summary"`
	Limitations     []string       `json:"limitations"`
	CommitSHA       string         `json:"commit_sha,omitempty"`
	Subject         *model.Subject `json:"subject,omitempty"`
	IdentityContext string         `json:"identity_context,omitempty"`
	Signature       string         `json:"signature,omitempty"`
}

// Document is an external evidence file.
type Document struct {
	SchemaVersion string `json:"schema_version"`
	Evidence      []Item `json:"evidence"`
}

func parseTime(s string) (time.Time, error) {
	for _, layout := range []string{time.RFC3339Nano, "2006-01-02T15:04:05", "2006-01-02"} {
		if t, err := time.Parse(layout, s); err == nil {
			return t.UTC(), nil
		}
	}
	return time.Time{}, fmt.Errorf("not an RFC 3339 timestamp")
}

// toEvidence converts a validated item. It does not set validity.
func (it Item) toEvidence() (model.Evidence, error) {
	ev := model.Evidence{
		ControlID: it.ControlID, AgentID: it.AgentID, CommitSHA: it.CommitSHA, SourceType: model.SourceType(it.SourceType),
		Collector: it.Collector, IdentityContext: it.IdentityContext, Result: model.Result(it.Result), Signal: model.Signal(it.Signal),
		Strength: model.Strength(it.Strength), Summary: it.Summary, Limitations: append([]string{}, it.Limitations...),
	}
	if ev.CommitSHA == "" {
		ev.CommitSHA = model.Unknown
	}
	t, err := parseTime(it.ObservedAt)
	if err != nil {
		return ev, fmt.Errorf("observed_at is %v", err)
	}
	ev.ObservedAt = t
	if it.ValidUntil != nil {
		vu, err := parseTime(*it.ValidUntil)
		if err != nil {
			return ev, fmt.Errorf("valid_until is %v", err)
		}
		ev.ValidUntil = &vu
	}
	if it.Subject != nil {
		s := model.Subject{Paths: append([]string{}, it.Subject.Paths...), Digest: it.Subject.Digest}
		ev.Subject = &s
	}
	return ev, nil
}

func canonical(ev model.Evidence) ([]byte, error) {
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
	// encoding/json writes map keys in sorted order.
	m := map[string]any{
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

// Sign returns the detached base64 Ed25519 signature over the canonical
// form of the evidence item.
func Sign(ev model.Evidence, key ed25519.PrivateKey) (string, error) {
	if len(key) != ed25519.PrivateKeySize {
		return "", fmt.Errorf("invalid Ed25519 private key")
	}
	msg, err := canonical(ev)
	if err != nil {
		return "", err
	}
	return base64.StdEncoding.EncodeToString(ed25519.Sign(key, msg)), nil
}

// Verify reports whether sig is a valid signature over the canonical form of
// the evidence item by one of the trusted keys.
func Verify(ev model.Evidence, sig string, keys []ed25519.PublicKey) bool {
	raw, err := base64.StdEncoding.DecodeString(strings.TrimSpace(sig))
	if err != nil || len(raw) != ed25519.SignatureSize {
		return false
	}
	msg, err := canonical(ev)
	if err != nil {
		return false
	}
	for _, k := range keys {
		if len(k) == ed25519.PublicKeySize && ed25519.Verify(k, msg, raw) {
			return true
		}
	}
	return false
}

var signingNoteRe = regexp.MustCompile(`(?i)^\s*(the )?evidence is (un)?signed\.?\s*$|^\s*signature verified`)

var controlIDRe = regexp.MustCompile(`^AGC-0(0[1-9]|1[0-9]|2[0-4])$`)

func evidenceID(control, agent, collector, loc string, signal model.Signal) string {
	h := sha256.Sum256([]byte(strings.Join([]string{control, agent, collector, loc, string(signal)}, "\x00")))
	return "E-" + hex.EncodeToString(h[:])[:12]
}

func readLimited(p string, limit int64) ([]byte, error) {
	fi, err := os.Lstat(p)
	if err != nil {
		return nil, fmt.Errorf("not readable")
	}
	if !fi.Mode().IsRegular() {
		return nil, fmt.Errorf("not a regular file")
	}
	if fi.Size() > limit {
		return nil, fmt.Errorf("larger than the %d KiB limit for evidence files", limit>>10)
	}
	f, err := os.Open(p)
	if err != nil {
		return nil, fmt.Errorf("not readable")
	}
	defer f.Close()
	data, err := io.ReadAll(io.LimitReader(f, limit+1))
	if err != nil {
		return nil, fmt.Errorf("not readable")
	}
	if int64(len(data)) > limit {
		return nil, fmt.Errorf("larger than the %d KiB limit for evidence files", limit>>10)
	}
	return data, nil
}

// loadBytes validates one evidence document and returns its items with
// validity and integrity set. label is the source location prefix.
func loadBytes(root, label string, data []byte, commit string, now time.Time, keys []ed25519.PublicKey) ([]model.Evidence, []string) {
	var problems []string
	fail := func(format string, a ...any) ([]model.Evidence, []string) {
		return nil, append(problems, label+": "+fmt.Sprintf(format, a...))
	}
	_, itemSchema, err := schemas()
	if err != nil {
		return fail("the evidence schema could not be loaded")
	}
	data = bytes.TrimPrefix(data, []byte("\xef\xbb\xbf"))
	var top struct {
		SchemaVersion any               `json:"schema_version"`
		Evidence      []json.RawMessage `json:"evidence"`
	}
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&top); err != nil {
		return fail("malformed evidence document; it is not valid JSON with the keys schema_version and evidence")
	}
	if v, ok := top.SchemaVersion.(string); !ok || v != "1" {
		return fail("unsupported schema_version; this scanner reads version \"1\"")
	}
	if top.Evidence == nil {
		return fail("malformed evidence document; the evidence array is missing")
	}
	if len(top.Evidence) > MaxItems {
		return fail("holds %d items; the limit is %d per file", len(top.Evidence), MaxItems)
	}
	var out []model.Evidence
	for i, raw := range top.Evidence {
		loc := fmt.Sprintf("%s#%d", label, i)
		// Lenient peek so a malformed item can still be attributed.
		var peek struct {
			ControlID  any `json:"control_id"`
			AgentID    any `json:"agent_id"`
			SourceType any `json:"source_type"`
		}
		_ = json.Unmarshal(raw, &peek)
		control, _ := peek.ControlID.(string)
		agent, _ := peek.AgentID.(string)
		malformed := func(reason string) {
			problems = append(problems, loc+": "+reason)
			if !controlIDRe.MatchString(control) || agent == "" || len(agent) > 200 {
				return // cannot be attributed to a control and agent
			}
			out = append(out, model.Evidence{
				EvidenceID: evidenceID(control, agent, "external-evidence", loc, model.SignalError),
				ControlID:  control, AgentID: agent, CommitSHA: model.Unknown, SourceType: model.SourceManualReview,
				SourceLocation: loc, Collector: "external-evidence", ObservedAt: now.UTC(), Integrity: model.IntegrityUnsigned,
				Result: model.ResultInconclusive, Signal: model.SignalDeclared, Strength: model.StrengthDeclared,
				Validity: model.ValidityMalformed, ValidityReason: reason,
				Summary:     "An external evidence item failed validation and was not credited.",
				Limitations: []string{},
			})
		}
		inst, err := jsonschema.UnmarshalJSON(bytes.NewReader(raw))
		if err != nil {
			malformed("the item is not valid JSON")
			continue
		}
		if st, _ := peek.SourceType.(string); st == string(model.SourceStatic) || st == string(model.SourceConfiguration) {
			malformed("external evidence cannot claim source_type " + st + "; only the scanner produces static and configuration evidence")
			continue
		}
		if err := itemSchema.Validate(inst); err != nil {
			malformed("the item does not match the evidence schema")
			continue
		}
		var it Item
		if err := json.Unmarshal(raw, &it); err != nil {
			malformed("the item does not match the evidence schema")
			continue
		}
		ev, err := it.toEvidence()
		if err != nil {
			malformed(err.Error())
			continue
		}
		wantResult := model.ResultInconclusive
		switch ev.Signal {
		case model.SignalPresent:
			wantResult = model.ResultPass
		case model.SignalViolation:
			wantResult = model.ResultFail
		}
		if ev.Result != wantResult {
			malformed("result and signal disagree: signal " + string(ev.Signal) + " requires result " + string(wantResult))
			continue
		}
		if ev.SourceType == model.SourceTest && ev.Strength == model.StrengthOperational {
			malformed("test evidence cannot claim operational strength")
			continue
		}
		ev.SourceLocation = loc
		ev.EvidenceID = evidenceID(ev.ControlID, ev.AgentID, ev.Collector, loc, ev.Signal)
		ev.Validity = model.ValidityValid
		// Integrity.
		ev.Integrity = model.IntegrityUnsigned
		if it.Signature != "" {
			if Verify(ev, it.Signature, keys) {
				ev.Integrity = model.IntegrityVerified
			} else {
				ev.Integrity = model.IntegrityInvalid
				ev.Validity = model.ValidityInvalidSignature
				ev.ValidityReason = "the signature does not verify against any trusted key"
				if len(keys) == 0 {
					ev.ValidityReason = "the item is signed, but no trusted key was supplied to verify it"
				}
			}
		}
		// The scanner, not the file, states the signing status. The note is
		// added after verification, so it is never part of the signed form.
		kept := ev.Limitations[:0:0]
		for _, l := range ev.Limitations {
			if !signingNoteRe.MatchString(l) {
				kept = append(kept, l)
			}
		}
		switch ev.Integrity {
		case model.IntegrityVerified:
			kept = append(kept, "Signature verified against a trusted key.")
		case model.IntegrityInvalid:
			kept = append(kept, "The evidence is signed, but the signature did not verify against a trusted key.")
		default:
			kept = append(kept, "The evidence is unsigned.")
		}
		ev.Limitations = kept
		// Binding and expiry, in order of precedence.
		if ev.Validity == model.ValidityValid && ev.ValidUntil != nil && !now.Before(*ev.ValidUntil) {
			ev.Validity = model.ValidityExpired
			ev.ValidityReason = "evidence expired on " + ev.ValidUntil.Format("2006-01-02")
		}
		if ev.Validity == model.ValidityValid && it.CommitSHA != "" && it.CommitSHA != commit {
			ev.Validity = model.ValidityCommitMismatch
			ev.ValidityReason = "evidence is bound to a different commit"
			if commit == model.Unknown || commit == "" {
				ev.ValidityReason = "evidence is bound to a commit, but the repository commit could not be read"
			}
		}
		if ev.Validity == model.ValidityValid && it.Subject != nil {
			got, err := SubjectDigest(root, it.Subject.Paths)
			switch {
			case err != nil:
				ev.Validity = model.ValidityDigestMismatch
				ev.ValidityReason = "the subject files could not be read: " + err.Error()
			case got != it.Subject.Digest:
				ev.Validity = model.ValidityDigestMismatch
				ev.ValidityReason = "the subject files changed after the evidence was collected"
			}
		}
		if ev.Validity == model.ValidityValid && it.CommitSHA == "" && it.Subject == nil {
			ev.Validity = model.ValidityUnbound
			ev.ValidityReason = "evidence names neither a commit nor a subject digest, so it cannot be tied to this code"
		}
		out = append(out, ev)
	}
	return out, problems
}

// LoadDir reads the external evidence JSON files directly inside dir (a
// repo-relative directory) and sets Validity and Integrity on every item.
// The second result lists human-readable problems. A missing directory is
// not a problem.
func LoadDir(root, dir string, commit string, now time.Time, keys []ed25519.PublicKey) ([]model.Evidence, []string) {
	rel, err := cleanRel(dir)
	if err != nil {
		return nil, []string{"evidence path " + fmt.Sprintf("%q", dir) + " was ignored: it must be a directory inside the repository"}
	}
	full, err := insideRoot(root, rel)
	if err != nil {
		if _, statErr := os.Lstat(filepath.Join(root, filepath.FromSlash(rel))); os.IsNotExist(statErr) {
			return nil, nil
		}
		return nil, []string{"evidence path " + rel + " was ignored: it resolves outside the repository"}
	}
	entries, err := os.ReadDir(full)
	if err != nil {
		return nil, nil
	}
	var names []string
	for _, e := range entries {
		if !e.IsDir() && strings.HasSuffix(strings.ToLower(e.Name()), ".json") {
			names = append(names, e.Name())
		}
	}
	sort.Strings(names)
	var out []model.Evidence
	var problems []string
	if len(names) > MaxFiles {
		problems = append(problems, fmt.Sprintf("%s holds %d evidence files; only the first %d were read", rel, len(names), MaxFiles))
		names = names[:MaxFiles]
	}
	for _, n := range names {
		label := rel + "/" + n
		data, err := readLimited(filepath.Join(full, n), MaxFileBytes)
		if err != nil {
			problems = append(problems, label+": "+err.Error()+"; the file was not used")
			continue
		}
		evs, probs := loadBytes(root, label, data, commit, now, keys)
		out = append(out, evs...)
		problems = append(problems, probs...)
	}
	return out, problems
}

// VerifyFile loads one evidence file exactly as LoadDir would, with validity
// and integrity set on every item.
func VerifyFile(root, file, commit string, now time.Time, keys []ed25519.PublicKey) ([]model.Evidence, []string) {
	label := filepath.Base(file)
	if absRoot, err := filepath.Abs(root); err == nil {
		if absFile, err := filepath.Abs(file); err == nil {
			if r, err := filepath.Rel(absRoot, absFile); err == nil && !strings.HasPrefix(r, "..") && !filepath.IsAbs(r) {
				label = filepath.ToSlash(r)
			}
		}
	}
	data, err := readLimited(file, MaxFileBytes)
	if err != nil {
		return nil, []string{label + ": " + err.Error() + "; the file was not used"}
	}
	return loadBytes(root, label, data, commit, now, keys)
}

// SignFile signs every item of an external evidence document in place and
// returns the number of items signed. Existing signatures are replaced. The
// file is rewritten atomically in the documented field order.
func SignFile(file string, key ed25519.PrivateKey) (int, error) {
	if len(key) != ed25519.PrivateKeySize {
		return 0, fmt.Errorf("invalid Ed25519 private key")
	}
	data, err := readLimited(file, MaxFileBytes)
	if err != nil {
		return 0, fmt.Errorf("%s: %v", filepath.Base(file), err)
	}
	docSchema, _, err := schemas()
	if err != nil {
		return 0, err
	}
	data = bytes.TrimPrefix(data, []byte("\xef\xbb\xbf"))
	inst, err := jsonschema.UnmarshalJSON(bytes.NewReader(data))
	if err != nil {
		return 0, fmt.Errorf("%s: not valid JSON", filepath.Base(file))
	}
	if err := docSchema.Validate(inst); err != nil {
		return 0, fmt.Errorf("%s: does not match the evidence schema; nothing was signed", filepath.Base(file))
	}
	var doc Document
	if err := json.Unmarshal(data, &doc); err != nil {
		return 0, fmt.Errorf("%s: does not match the evidence schema; nothing was signed", filepath.Base(file))
	}
	for i := range doc.Evidence {
		ev, err := doc.Evidence[i].toEvidence()
		if err != nil {
			return 0, fmt.Errorf("%s: item %d: %v", filepath.Base(file), i, err)
		}
		sig, err := Sign(ev, key)
		if err != nil {
			return 0, err
		}
		doc.Evidence[i].Signature = sig
		if doc.Evidence[i].Limitations == nil {
			doc.Evidence[i].Limitations = []string{}
		}
	}
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetEscapeHTML(false)
	enc.SetIndent("", "  ")
	if err := enc.Encode(doc); err != nil {
		return 0, err
	}
	tmp, err := os.CreateTemp(filepath.Dir(file), ".agentgov-sign-*")
	if err != nil {
		return 0, err
	}
	tmpName := tmp.Name()
	cleanup := func() { _ = os.Remove(tmpName) }
	if _, err := tmp.Write(buf.Bytes()); err != nil {
		tmp.Close()
		cleanup()
		return 0, err
	}
	if err := tmp.Close(); err != nil {
		cleanup()
		return 0, err
	}
	if fi, err := os.Stat(file); err == nil {
		_ = os.Chmod(tmpName, fi.Mode().Perm())
	}
	if err := os.Rename(tmpName, file); err != nil {
		cleanup()
		return 0, err
	}
	return len(doc.Evidence), nil
}
