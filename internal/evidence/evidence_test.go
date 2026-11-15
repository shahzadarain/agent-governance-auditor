// SPDX-License-Identifier: Apache-2.0

package evidence

import (
	"bytes"
	"crypto/ed25519"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/shahzadarain/agent-governance-auditor/internal/model"
)

var now = time.Date(2026, 11, 15, 12, 0, 0, 0, time.UTC)

const commitA = "0123456789abcdef0123456789abcdef01234567"
const commitB = "89abcdef0123456789abcdef0123456789abcdef"

func write(t *testing.T, root, rel, content string) {
	t.Helper()
	p := filepath.Join(root, filepath.FromSlash(rel))
	if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(p, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
}

// item returns a valid, commit-bound evidence item as a generic map.
func item(over map[string]any) map[string]any {
	m := map[string]any{
		"control_id": "AGC-010", "agent_id": "demo-agent", "source_type": "test", "collector": "unit-test",
		"observed_at": "2026-11-01T10:00:00Z", "valid_until": "2027-01-01T00:00:00Z", "result": "pass", "signal": "present",
		"strength": "tested", "summary": "approval tests passed", "limitations": []string{"synthetic"}, "commit_sha": commitA,
	}
	for k, v := range over {
		if v == nil {
			delete(m, k)
		} else {
			m[k] = v
		}
	}
	return m
}

func doc(items ...map[string]any) string {
	b, _ := json.MarshalIndent(map[string]any{"schema_version": "1", "evidence": items}, "", "  ")
	return string(b)
}

func load(t *testing.T, root string, keys ...ed25519.PublicKey) ([]model.Evidence, []string) {
	t.Helper()
	return LoadDir(root, ".agentgov/evidence", commitA, now, keys)
}

func TestSubjectDigest(t *testing.T) {
	root := t.TempDir()
	write(t, root, "src/a.py", "line one\nline two\n")
	write(t, root, "src/b.py", "other\n")
	d1, err := SubjectDigest(root, []string{"src/a.py", "src/b.py"})
	if err != nil || len(d1) != 64 || d1 != strings.ToLower(d1) {
		t.Fatalf("digest %q err %v", d1, err)
	}
	d2, _ := SubjectDigest(root, []string{"src/b.py", "./src/a.py", "src\\a.py", "src/a.py"})
	if d1 != d2 {
		t.Error("order, duplicates, and path spelling must not change the digest")
	}
	// CRLF and LF checkouts of the same file must agree.
	write(t, root, "src/a.py", "line one\r\nline two\r\n")
	if d3, _ := SubjectDigest(root, []string{"src/a.py", "src/b.py"}); d3 != d1 {
		t.Error("CRLF line endings must be normalized before hashing")
	}
	write(t, root, "src/a.py", "line one\nline 2\n")
	if d4, _ := SubjectDigest(root, []string{"src/a.py", "src/b.py"}); d4 == d1 {
		t.Error("a content change must change the digest")
	}
	if d5, _ := SubjectDigest(root, []string{"src/b.py"}); d5 == d1 {
		t.Error("a different path set must change the digest")
	}
	outside := t.TempDir()
	write(t, outside, "x.py", "x")
	for _, bad := range [][]string{{"../x.py"}, {"src/../../x.py"}, {filepath.Join(outside, "x.py")}, {"/etc/passwd"}, {`C:\Windows\win.ini`}, {""}, {"src/missing.py"}, {"src"}, {}} {
		if _, err := SubjectDigest(root, bad); err == nil {
			t.Errorf("SubjectDigest(%v) should fail", bad)
		}
	}
	if err := os.Symlink(filepath.Join(outside, "x.py"), filepath.Join(root, "link.py")); err == nil {
		if _, err := SubjectDigest(root, []string{"link.py"}); err == nil {
			t.Error("a link that leaves the root must be rejected")
		}
	}
}

func TestLoadDirValidity(t *testing.T) {
	root := t.TempDir()
	write(t, root, "impl.py", "def gate(): pass\n")
	good, _ := SubjectDigest(root, []string{"impl.py"})
	subject := func(digest string) map[string]any {
		return map[string]any{"paths": []string{"impl.py"}, "digest": digest}
	}
	cases := []struct {
		name string
		it   map[string]any
		want model.Validity
	}{
		{"valid commit bound", item(nil), model.ValidityValid},
		{"valid subject bound", item(map[string]any{"commit_sha": nil, "subject": subject(good)}), model.ValidityValid},
		{"valid commit and subject", item(map[string]any{"subject": subject(good)}), model.ValidityValid},
		{"no expiry stated", item(map[string]any{"valid_until": nil}), model.ValidityValid},
		{"expired", item(map[string]any{"valid_until": "2026-11-15T11:59:59Z"}), model.ValidityExpired},
		{"commit mismatch", item(map[string]any{"commit_sha": commitB}), model.ValidityCommitMismatch},
		{"digest mismatch", item(map[string]any{"commit_sha": nil, "subject": subject(strings.Repeat("0", 64))}), model.ValidityDigestMismatch},
		{"subject file missing", item(map[string]any{"commit_sha": nil, "subject": map[string]any{"paths": []string{"gone.py"}, "digest": good}}), model.ValidityDigestMismatch},
		{"subject escapes root", item(map[string]any{"commit_sha": nil, "subject": map[string]any{"paths": []string{"../../etc/passwd"}, "digest": good}}), model.ValidityDigestMismatch},
		{"unbound", item(map[string]any{"commit_sha": nil}), model.ValidityUnbound},
		{"claims static", item(map[string]any{"source_type": "static"}), model.ValidityMalformed},
		{"claims configuration", item(map[string]any{"source_type": "configuration"}), model.ValidityMalformed},
		{"unknown field", item(map[string]any{"integrity": "verified"}), model.ValidityMalformed},
		{"bad strength", item(map[string]any{"strength": "certified"}), model.ValidityMalformed},
		{"missing summary", item(map[string]any{"summary": nil}), model.ValidityMalformed},
		{"bad timestamp", item(map[string]any{"observed_at": "yesterday"}), model.ValidityMalformed},
		{"result contradicts signal", item(map[string]any{"result": "pass", "signal": "violation"}), model.ValidityMalformed},
		{"test claiming operational", item(map[string]any{"strength": "operational"}), model.ValidityMalformed},
		{"short commit", item(map[string]any{"commit_sha": "abc123"}), model.ValidityMalformed},
	}
	for i, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			dir := filepath.Join(root, fmt.Sprintf("case%d", i))
			write(t, dir, "impl.py", "def gate(): pass\n")
			write(t, dir, ".agentgov/evidence/e.json", doc(c.it))
			evs, probs := load(t, dir)
			if len(evs) != 1 {
				t.Fatalf("expected one item, got %d (problems %v)", len(evs), probs)
			}
			ev := evs[0]
			if ev.Validity != c.want {
				t.Fatalf("validity = %s (%s), want %s", ev.Validity, ev.ValidityReason, c.want)
			}
			if ev.Validity != model.ValidityValid && ev.ValidityReason == "" {
				t.Error("an invalid item must say why")
			}
			if ev.Validity == model.ValidityMalformed && len(probs) == 0 {
				t.Error("a malformed item must produce a problem message")
			}
			if ev.Integrity != model.IntegrityUnsigned {
				t.Errorf("unsigned evidence must be reported as unsigned, got %s", ev.Integrity)
			}
			if ev.EvidenceID == "" || ev.ControlID != "AGC-010" || ev.AgentID != "demo-agent" || !strings.HasPrefix(ev.SourceLocation, ".agentgov/evidence/e.json#") {
				t.Errorf("identity fields: %+v", ev)
			}
		})
	}
}

func TestLoadDirFileLevelProblems(t *testing.T) {
	t.Run("missing directory is not a problem", func(t *testing.T) {
		evs, probs := load(t, t.TempDir())
		if len(evs) != 0 || len(probs) != 0 {
			t.Fatalf("evs=%d probs=%v", len(evs), probs)
		}
	})
	t.Run("oversized file", func(t *testing.T) {
		root := t.TempDir()
		write(t, root, ".agentgov/evidence/big.json", doc(item(map[string]any{"summary": strings.Repeat("a", 1900)}))+strings.Repeat(" ", MaxFileBytes))
		evs, probs := load(t, root)
		if len(evs) != 0 || len(probs) != 1 || !strings.Contains(probs[0], "256 KiB") {
			t.Fatalf("evs=%d probs=%v", len(evs), probs)
		}
	})
	t.Run("too many items", func(t *testing.T) {
		root := t.TempDir()
		items := make([]map[string]any, MaxItems+1)
		for i := range items {
			items[i] = map[string]any{"control_id": "AGC-010"}
		}
		b, _ := json.Marshal(map[string]any{"schema_version": "1", "evidence": items})
		write(t, root, ".agentgov/evidence/many.json", string(b))
		evs, probs := load(t, root)
		if len(evs) != 0 || len(probs) != 1 || !strings.Contains(probs[0], "limit is 500") {
			t.Fatalf("evs=%d probs=%v", len(evs), probs)
		}
	})
	t.Run("not JSON, wrong version, wrong shape", func(t *testing.T) {
		root := t.TempDir()
		write(t, root, ".agentgov/evidence/a.json", "{not json")
		write(t, root, ".agentgov/evidence/b.json", `{"schema_version":"2","evidence":[]}`)
		write(t, root, ".agentgov/evidence/c.json", `{"schema_version":"1","evidence":[],"extra":true}`)
		write(t, root, ".agentgov/evidence/d.json", `{"schema_version":"1"}`)
		write(t, root, ".agentgov/evidence/e.json", `[1,2,3]`)
		write(t, root, ".agentgov/evidence/notes.txt", "ignored")
		evs, probs := load(t, root)
		if len(evs) != 0 || len(probs) != 5 {
			t.Fatalf("evs=%d probs=%v", len(evs), probs)
		}
	})
	t.Run("item that cannot be attributed is dropped with a problem", func(t *testing.T) {
		root := t.TempDir()
		write(t, root, ".agentgov/evidence/a.json", doc(item(map[string]any{"control_id": "AGC-999"}), map[string]any{"x": 1}, item(nil)))
		evs, probs := load(t, root)
		if len(evs) != 1 || evs[0].Validity != model.ValidityValid || len(probs) != 2 {
			t.Fatalf("evs=%+v probs=%v", evs, probs)
		}
	})
	t.Run("evidence path cannot leave the repository", func(t *testing.T) {
		root := t.TempDir()
		outside := t.TempDir()
		write(t, outside, "e.json", doc(item(nil)))
		for _, dir := range []string{"..", "../" + filepath.Base(outside), outside, "/tmp"} {
			evs, probs := LoadDir(root, dir, commitA, now, nil)
			if len(evs) != 0 || len(probs) != 1 {
				t.Errorf("dir %q: evs=%d probs=%v", dir, len(evs), probs)
			}
		}
	})
	t.Run("commit bound evidence when the repository commit is unknown", func(t *testing.T) {
		root := t.TempDir()
		write(t, root, ".agentgov/evidence/a.json", doc(item(nil)))
		evs, _ := LoadDir(root, ".agentgov/evidence", model.Unknown, now, nil)
		if len(evs) != 1 || evs[0].Validity != model.ValidityCommitMismatch {
			t.Fatalf("evs=%+v", evs)
		}
	})
}

func TestSignAndVerify(t *testing.T) {
	pub, priv, _ := ed25519.GenerateKey(nil)
	otherPub, _, _ := ed25519.GenerateKey(nil)
	var it Item
	raw, _ := json.Marshal(item(map[string]any{"subject": map[string]any{"paths": []string{"b.py", "a.py"}, "digest": strings.Repeat("a", 64)}}))
	if err := json.Unmarshal(raw, &it); err != nil {
		t.Fatal(err)
	}
	ev, err := it.toEvidence()
	if err != nil {
		t.Fatal(err)
	}
	sig, err := Sign(ev, priv)
	if err != nil || sig == "" {
		t.Fatalf("Sign: %v", err)
	}
	if !Verify(ev, sig, []ed25519.PublicKey{otherPub, pub}) {
		t.Fatal("a good signature must verify against a trusted key")
	}
	if Verify(ev, sig, []ed25519.PublicKey{otherPub}) || Verify(ev, sig, nil) {
		t.Error("a signature must not verify without the signing key")
	}
	if Verify(ev, "not-base64!", []ed25519.PublicKey{pub}) || Verify(ev, "", []ed25519.PublicKey{pub}) {
		t.Error("garbage signatures must not verify")
	}
	// Scanner-set fields are outside the signature.
	scannerSet := ev
	scannerSet.EvidenceID, scannerSet.PolicyVersion, scannerSet.ScannerVersion = "E-x", "9", "9"
	scannerSet.SourceLocation, scannerSet.Integrity, scannerSet.Validity = "elsewhere", model.IntegrityVerified, model.ValidityExpired
	if !Verify(scannerSet, sig, []ed25519.PublicKey{pub}) {
		t.Error("scanner-set fields must not affect the signature")
	}
	// Every content field is inside the signature.
	later := ev.ObservedAt.Add(time.Second)
	mutations := map[string]func(e *model.Evidence){
		"control":  func(e *model.Evidence) { e.ControlID = "AGC-011" },
		"agent":    func(e *model.Evidence) { e.AgentID = "other" },
		"result":   func(e *model.Evidence) { e.Result = model.ResultFail },
		"signal":   func(e *model.Evidence) { e.Signal = model.SignalViolation },
		"strength": func(e *model.Evidence) { e.Strength = model.StrengthOperational },
		"source":   func(e *model.Evidence) { e.SourceType = model.SourceRuntime },
		"summary":  func(e *model.Evidence) { e.Summary += "!" },
		"commit":   func(e *model.Evidence) { e.CommitSHA = commitB },
		"observed": func(e *model.Evidence) { e.ObservedAt = later },
		"expiry":   func(e *model.Evidence) { e.ValidUntil = nil },
		"digest": func(e *model.Evidence) {
			e.Subject = &model.Subject{Paths: e.Subject.Paths, Digest: strings.Repeat("b", 64)}
		},
		"paths":    func(e *model.Evidence) { e.Subject = &model.Subject{Paths: []string{"a.py"}, Digest: e.Subject.Digest} },
		"limits":   func(e *model.Evidence) { e.Limitations = nil },
		"identity": func(e *model.Evidence) { e.IdentityContext = "someone else" },
	}
	for name, mutate := range mutations {
		changed := ev
		mutate(&changed)
		if Verify(changed, sig, []ed25519.PublicKey{pub}) {
			t.Errorf("changing %s must break the signature", name)
		}
	}
	msg, _ := canonical(ev)
	if !bytes.HasPrefix(msg, []byte(`{"agent_id":"demo-agent","collector":"unit-test","commit_sha":"`+commitA+`","control_id":"AGC-010"`)) ||
		!bytes.Contains(msg, []byte(`"subject_paths":["a.py","b.py"]`)) || bytes.Contains(msg, []byte("\n")) {
		t.Errorf("canonical form is not as documented: %s", msg)
	}
	if _, err := Sign(ev, ed25519.PrivateKey("short")); err == nil {
		t.Error("Sign must reject an invalid key")
	}
}

func TestSignFileAndVerifyFile(t *testing.T) {
	pub, priv, _ := ed25519.GenerateKey(nil)
	otherPub, _, _ := ed25519.GenerateKey(nil)
	root := t.TempDir()
	file := filepath.Join(root, ".agentgov", "evidence", "e.json")
	write(t, root, ".agentgov/evidence/e.json", doc(item(nil), item(map[string]any{"control_id": "AGC-017", "limitations": nil})))

	evs, probs := VerifyFile(root, file, commitA, now, []ed25519.PublicKey{pub})
	if len(evs) != 2 || len(probs) != 0 || evs[0].Integrity != model.IntegrityUnsigned {
		t.Fatalf("before signing: %+v %v", evs, probs)
	}
	n, err := SignFile(file, priv)
	if err != nil || n != 2 {
		t.Fatalf("SignFile = %d, %v", n, err)
	}
	evs, probs = VerifyFile(root, file, commitA, now, []ed25519.PublicKey{pub})
	if len(evs) != 2 || len(probs) != 0 {
		t.Fatalf("after signing: %+v %v", evs, probs)
	}
	for _, ev := range evs {
		if ev.Integrity != model.IntegrityVerified || ev.Validity != model.ValidityValid {
			t.Errorf("signed item: integrity=%s validity=%s (%s)", ev.Integrity, ev.Validity, ev.ValidityReason)
		}
	}
	// LoadDir agrees with VerifyFile.
	fromDir, _ := LoadDir(root, ".agentgov/evidence", commitA, now, []ed25519.PublicKey{pub})
	if len(fromDir) != 2 || fromDir[0].EvidenceID != evs[0].EvidenceID || fromDir[0].Integrity != model.IntegrityVerified {
		t.Errorf("LoadDir and VerifyFile disagree: %+v", fromDir)
	}
	// Untrusted key, and no key at all.
	for _, keys := range [][]ed25519.PublicKey{{otherPub}, nil} {
		bad, _ := VerifyFile(root, file, commitA, now, keys)
		if bad[0].Integrity != model.IntegrityInvalid || bad[0].Validity != model.ValidityInvalidSignature || bad[0].ValidityReason == "" {
			t.Errorf("untrusted key: integrity=%s validity=%s", bad[0].Integrity, bad[0].Validity)
		}
	}
	// Tampering after signing.
	data, _ := os.ReadFile(file)
	tampered := strings.Replace(string(data), "approval tests passed", "approval tests passed and more", 1)
	if tampered == string(data) {
		t.Fatal("test setup: summary not found")
	}
	if err := os.WriteFile(file, []byte(tampered), 0o644); err != nil {
		t.Fatal(err)
	}
	evs, _ = VerifyFile(root, file, commitA, now, []ed25519.PublicKey{pub})
	if evs[0].Validity != model.ValidityInvalidSignature || evs[0].Integrity != model.IntegrityInvalid {
		t.Errorf("a tampered item must fail verification: %s %s", evs[0].Validity, evs[0].Integrity)
	}
	if evs[1].Integrity != model.IntegrityVerified {
		t.Errorf("an untouched item in the same file must still verify: %s", evs[1].Integrity)
	}
	// Signing again replaces the signatures and leaves no temporary file.
	if n, err := SignFile(file, priv); err != nil || n != 2 {
		t.Fatalf("re-sign: %d %v", n, err)
	}
	evs, _ = VerifyFile(root, file, commitA, now, []ed25519.PublicKey{pub})
	if evs[0].Integrity != model.IntegrityVerified {
		t.Error("re-signed file must verify")
	}
	entries, _ := os.ReadDir(filepath.Dir(file))
	if len(entries) != 1 {
		t.Errorf("temporary files left behind: %v", entries)
	}
	// A malformed document is not signed or changed.
	bad := filepath.Join(root, "bad.json")
	os.WriteFile(bad, []byte(`{"schema_version":"1","evidence":[{"control_id":"nope"}]}`), 0o644)
	if _, err := SignFile(bad, priv); err == nil {
		t.Error("SignFile must refuse a document that fails the schema")
	}
	if after, _ := os.ReadFile(bad); !strings.Contains(string(after), `"nope"`) || strings.Contains(string(after), "signature") {
		t.Error("a refused document must be left unchanged")
	}
	if _, err := SignFile(filepath.Join(root, "missing.json"), priv); err == nil {
		t.Error("SignFile must fail for a missing file")
	}
}

func TestSchemaCopiesMatch(t *testing.T) {
	published, err := os.ReadFile(filepath.Join("..", "..", "policies", "schema", "evidence.schema.json"))
	if err != nil {
		t.Fatalf("published schema missing: %v", err)
	}
	norm := func(b []byte) string { return strings.ReplaceAll(string(b), "\r\n", "\n") }
	if norm(published) != norm(SchemaJSON()) {
		t.Fatal("policies/schema/evidence.schema.json and internal/evidence/evidence.schema.json differ; keep them identical")
	}
	if _, _, err := schemas(); err != nil {
		t.Fatalf("schema does not compile: %v", err)
	}
}

// TestPythonGeneratedDigestsMatch cross-checks the Python implementation of
// the subject digest in examples/safe-agent/tools/run_governance_tests.py
// against SubjectDigest, using the evidence file that script generated.
func TestPythonGeneratedDigestsMatch(t *testing.T) {
	root := filepath.Join("..", "..", "examples", "safe-agent")
	data, err := os.ReadFile(filepath.Join(root, ".agentgov", "evidence", "governance-tests.json"))
	if err != nil {
		t.Fatalf("generated evidence file missing; run python tools/run_governance_tests.py in examples/safe-agent: %v", err)
	}
	var d Document
	if err := json.Unmarshal(data, &d); err != nil {
		t.Fatal(err)
	}
	if len(d.Evidence) < 10 {
		t.Fatalf("expected at least 10 generated items, got %d", len(d.Evidence))
	}
	for _, it := range d.Evidence {
		if it.Subject == nil {
			t.Errorf("%s: generated evidence must be subject-bound", it.ControlID)
			continue
		}
		got, err := SubjectDigest(root, it.Subject.Paths)
		if err != nil {
			t.Errorf("%s: %v", it.ControlID, err)
			continue
		}
		if got != it.Subject.Digest {
			t.Errorf("%s: Go digest %s differs from the Python digest %s; re-run the governance tests if the files changed", it.ControlID, got, it.Subject.Digest)
		}
		if it.SourceType != "test" || it.Strength != "tested" || it.Signature != "" {
			t.Errorf("%s: unexpected generated fields: %+v", it.ControlID, it)
		}
	}
}

func TestSigningStatusLimitationFollowsIntegrity(t *testing.T) {
	pub, priv, _ := ed25519.GenerateKey(nil)
	root := t.TempDir()
	file := filepath.Join(root, ".agentgov", "evidence", "e.json")
	write(t, root, ".agentgov/evidence/e.json", doc(item(map[string]any{"limitations": []string{"synthetic", "The evidence is unsigned."}})))
	notes := func(keys ...ed25519.PublicKey) string {
		evs, _ := VerifyFile(root, file, commitA, now, keys)
		if len(evs) != 1 {
			t.Fatalf("items: %d", len(evs))
		}
		return strings.Join(evs[0].Limitations, " | ")
	}
	if got := notes(); got != "synthetic | The evidence is unsigned." {
		t.Errorf("unsigned: %q", got)
	}
	if _, err := SignFile(file, priv); err != nil {
		t.Fatal(err)
	}
	if got := notes(pub); got != "synthetic | Signature verified against a trusted key." {
		t.Errorf("verified: %q", got)
	}
	if got := notes(); got != "synthetic | The evidence is signed, but the signature did not verify against a trusted key." {
		t.Errorf("invalid: %q", got)
	}
}
