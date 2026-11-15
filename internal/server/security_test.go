// SPDX-License-Identifier: Apache-2.0

package server

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"
	"testing"
	"testing/fstest"
	"time"

	"github.com/shahzadarain/agent-governance-auditor/internal/model"
	"github.com/shahzadarain/agent-governance-auditor/internal/storage"
)

// ---------------------------------------------------------------------------
// Bootstrap and setup
// ---------------------------------------------------------------------------

func TestBootstrapTokenPrintedOnceStoredHashed(t *testing.T) {
	e := newEnv(t, nil)
	out := e.boot.String()
	if n := strings.Count(out, "Bootstrap token:"); n != 1 {
		t.Fatalf("bootstrap token printed %d times", n)
	}
	token := e.bootstrapToken()
	raw, err := base64.RawURLEncoding.DecodeString(token)
	if err != nil || len(raw) != 32 {
		t.Fatalf("bootstrap token is not 32 random bytes in base64url: %q", token)
	}
	stored, ok, _ := e.store.GetSetting(context.Background(), settingBootstrapHash)
	if !ok || stored == token || stored != sha256Hex(token) {
		t.Fatal("only the hash of the bootstrap token may be stored")
	}
	if strings.Contains(e.logs.String(), token) {
		t.Fatal("bootstrap token leaked into the structured log")
	}
}

func TestNoDefaultCredentials(t *testing.T) {
	e := newEnv(t, nil)
	for _, cred := range [][2]string{{"admin", "admin"}, {"admin", "password"}, {"admin", ""}, {"administrator", "agentgov"}, {"root", "changeme-changeme"}} {
		rec := e.anon().do("POST", "/api/v1/login", loginRequest{Username: cred[0], Password: cred[1]})
		wantError(t, rec, http.StatusUnauthorized, "invalid_credentials")
	}
	if n, _ := e.store.CountUsers(context.Background()); n != 0 {
		t.Fatalf("users exist before setup: %d", n)
	}
}

func TestSetupRejectsWrongTokenAndWeakPassword(t *testing.T) {
	e := newEnv(t, nil)
	wantError(t, e.anon().do("POST", "/api/v1/setup", setupRequest{BootstrapToken: "wrong", Username: "admin", Password: testPassword}), http.StatusForbidden, "invalid_bootstrap_token")
	wantError(t, e.anon().do("POST", "/api/v1/setup", setupRequest{Username: "admin", Password: testPassword}), http.StatusForbidden, "invalid_bootstrap_token")
	// A weak password is rejected and does not consume the token.
	wantError(t, e.anon().do("POST", "/api/v1/setup", setupRequest{BootstrapToken: e.bootstrapToken(), Username: "admin", Password: "short"}), http.StatusBadRequest, "invalid_request")
	wantError(t, e.anon().do("POST", "/api/v1/setup", setupRequest{BootstrapToken: e.bootstrapToken(), Username: "admin", Password: "elevenchars"}), http.StatusBadRequest, "invalid_request")
	wantStatus(t, e.anon().do("POST", "/api/v1/setup", setupRequest{BootstrapToken: e.bootstrapToken(), Username: "Admin", Password: testPassword}), http.StatusCreated)
	u, err := e.store.GetUserByUsername(context.Background(), "admin")
	if err != nil || u.Role != storage.RoleAdministrator || !strings.HasPrefix(u.PasswordHash, "$argon2id$v=19$m=") || strings.Contains(u.PasswordHash, testPassword) {
		t.Fatalf("first user: %+v %v", u, err)
	}
}

func TestBootstrapTokenReuse(t *testing.T) {
	e := newEnv(t, nil)
	token := e.bootstrapToken()
	e.setup()
	rec := e.anon().do("POST", "/api/v1/setup", setupRequest{BootstrapToken: token, Username: "second", Password: testPassword})
	wantError(t, rec, http.StatusConflict, "setup_complete")
	if n, _ := e.store.CountUsers(context.Background()); n != 1 {
		t.Fatalf("users = %d after token reuse", n)
	}
	if _, ok, _ := e.store.GetSetting(context.Background(), settingBootstrapHash); ok {
		t.Fatal("bootstrap hash must be deleted after first use")
	}
}

func TestBootstrapTokenExpiry(t *testing.T) {
	e := newEnv(t, nil)
	e.clock.Advance(59 * time.Minute)
	wantError(t, e.anon().do("POST", "/api/v1/setup", setupRequest{BootstrapToken: e.bootstrapToken(), Username: "admin", Password: "short"}), http.StatusBadRequest, "invalid_request")
	e.clock.Advance(2 * time.Minute)
	rec := e.anon().do("POST", "/api/v1/setup", setupRequest{BootstrapToken: e.bootstrapToken(), Username: "admin", Password: testPassword})
	wantError(t, rec, http.StatusForbidden, "bootstrap_expired")
	if n, _ := e.store.CountUsers(context.Background()); n != 0 {
		t.Fatal("expired bootstrap token created a user")
	}

	// A restart without users issues a fresh token; the old one is dead.
	old := e.bootstrapToken()
	e.store.Close()
	e2 := newEnvAt(t, e.path, func(c *Config) { c.Now = e.clock.Now })
	fresh := e2.bootstrapToken()
	if fresh == old {
		t.Fatal("restart must generate a new bootstrap token")
	}
	wantError(t, e2.anon().do("POST", "/api/v1/setup", setupRequest{BootstrapToken: old, Username: "admin", Password: testPassword}), http.StatusForbidden, "invalid_bootstrap_token")
	wantStatus(t, e2.anon().do("POST", "/api/v1/setup", setupRequest{BootstrapToken: fresh, Username: "admin", Password: testPassword}), http.StatusCreated)
}

func TestPasswordHashing(t *testing.T) {
	h1, err := hashPassword(testPassword, testArgonKiB)
	if err != nil {
		t.Fatal(err)
	}
	h2, _ := hashPassword(testPassword, testArgonKiB)
	if h1 == h2 {
		t.Fatal("hashes of the same password must differ (per-user salt)")
	}
	if !strings.HasPrefix(h1, "$argon2id$v=19$m=64,t=2,p=2$") {
		t.Fatalf("encoded parameters: %s", h1)
	}
	if !verifyPassword(testPassword, h1) || verifyPassword(testPassword+"x", h1) || verifyPassword("", h1) {
		t.Fatal("verifyPassword gave a wrong answer")
	}
	for _, bad := range []string{"", "plain", "$argon2i$v=19$m=64,t=2,p=2$AAAA$AAAA", "$argon2id$v=19$m=999999999,t=2,p=2$AAAA$AAAA", "$argon2id$v=19$m=64,t=2,p=2$!!$!!"} {
		if verifyPassword(testPassword, bad) {
			t.Fatalf("malformed hash %q verified", bad)
		}
	}
	if DefaultArgon2Memory != 64*1024 || argonTime != 2 || argonThreads != 2 {
		t.Fatal("production argon2id parameters changed")
	}
}

// ---------------------------------------------------------------------------
// Sessions, cookies, CSRF
// ---------------------------------------------------------------------------

func sessionCookieFrom(t *testing.T, h http.Header) *http.Cookie {
	t.Helper()
	resp := http.Response{Header: h}
	for _, c := range resp.Cookies() {
		if c.Name == sessionCookie {
			return c
		}
	}
	t.Fatal("no session cookie")
	return nil
}

func TestSessionCookieAttributes(t *testing.T) {
	e := newEnv(t, func(c *Config) { c.TrustedProxies = []string{"10.0.0.0/8"} })
	e.setup()
	login := func(opts ...reqOpt) *http.Cookie {
		c := e.anon()
		rec := c.do("POST", "/api/v1/login", loginRequest{Username: adminUsername, Password: testPassword}, opts...)
		wantStatus(t, rec, http.StatusOK)
		return sessionCookieFrom(t, rec.Header())
	}
	ck := login()
	if !ck.HttpOnly || ck.SameSite != http.SameSiteStrictMode || ck.Path != "/" || ck.Secure {
		t.Fatalf("plain HTTP cookie attributes: %+v", ck)
	}
	raw, err := base64.RawURLEncoding.DecodeString(ck.Value)
	if err != nil || len(raw) != 32 {
		t.Fatalf("session ID is not 32 random bytes: %q", ck.Value)
	}
	// Stored hashed.
	if _, err := e.store.GetSession(context.Background(), ck.Value); !errors.Is(err, storage.ErrNotFound) {
		t.Fatal("the raw session ID must not be a storage key")
	}
	if _, err := e.store.GetSession(context.Background(), sha256Hex(ck.Value)); err != nil {
		t.Fatalf("session not stored by hash: %v", err)
	}
	// X-Forwarded-Proto from an untrusted peer is ignored.
	if login(header("X-Forwarded-Proto", "https")).Secure {
		t.Fatal("Secure set from an untrusted X-Forwarded-Proto")
	}
	// The same header from a trusted proxy sets Secure.
	trusted := func(r *http.Request) { r.RemoteAddr = "10.1.2.3:4444"; r.Header.Set("X-Forwarded-Proto", "https") }
	if !login(trusted).Secure {
		t.Fatal("Secure not set behind a trusted HTTPS proxy")
	}
}

func TestSessionIdleAndAbsoluteExpiry(t *testing.T) {
	e := newEnv(t, nil)
	admin := e.setup()

	// Idle: 2 hours without a request ends the session.
	e.clock.Advance(119 * time.Minute)
	wantStatus(t, admin.do("GET", "/api/v1/session", nil), http.StatusOK)
	e.clock.Advance(2 * time.Hour)
	rec := admin.do("GET", "/api/v1/session", nil)
	wantError(t, rec, http.StatusUnauthorized, "unauthenticated")
	if ck := sessionCookieFrom(t, rec.Header()); ck.MaxAge >= 0 {
		t.Fatal("expired session must clear the cookie")
	}
	if _, err := e.store.GetSession(context.Background(), sha256Hex(admin.cookie.Value)); !errors.Is(err, storage.ErrNotFound) {
		t.Fatal("expired session must be deleted")
	}

	// Absolute: an active session still ends 12 hours after login.
	admin = e.login(adminUsername, testPassword)
	for i := 0; i < 11; i++ {
		e.clock.Advance(time.Hour)
		wantStatus(t, admin.do("GET", "/api/v1/session", nil), http.StatusOK)
	}
	e.clock.Advance(59 * time.Minute)
	wantStatus(t, admin.do("GET", "/api/v1/session", nil), http.StatusOK)
	e.clock.Advance(time.Minute)
	wantError(t, admin.do("GET", "/api/v1/session", nil), http.StatusUnauthorized, "unauthenticated")

	// A forged or random cookie is not a session.
	forged := e.anon()
	forged.cookie = &http.Cookie{Name: sessionCookie, Value: randomToken(32)}
	wantError(t, forged.do("GET", "/api/v1/session", nil), http.StatusUnauthorized, "unauthenticated")
}

func TestCSRF(t *testing.T) {
	e := newEnv(t, nil)
	admin := e.setup()
	body := createProjectRequest{Slug: "csrf-test", Name: "x"}
	post := func(opts ...reqOpt) int {
		return admin.do("POST", "/api/v1/projects", body, opts...).Code
	}
	// Missing token.
	wantError(t, admin.do("POST", "/api/v1/projects", body, noHeader(csrfHeader)), http.StatusForbidden, "csrf_failed")
	// Wrong token.
	wantError(t, admin.do("POST", "/api/v1/projects", body, header(csrfHeader, "wrong")), http.StatusForbidden, "csrf_failed")
	// Another session's token.
	other := e.login(adminUsername, testPassword)
	wantError(t, admin.do("POST", "/api/v1/projects", body, header(csrfHeader, other.csrf)), http.StatusForbidden, "csrf_failed")
	// A correct token from a foreign origin still fails.
	wantError(t, admin.do("POST", "/api/v1/projects", body, header("Origin", "https://evil.example")), http.StatusForbidden, "cross_origin")
	wantError(t, admin.do("POST", "/api/v1/projects", body, header("Sec-Fetch-Site", "cross-site")), http.StatusForbidden, "cross_origin")
	wantError(t, admin.do("POST", "/api/v1/projects", body, header("Sec-Fetch-Site", "same-site")), http.StatusForbidden, "cross_origin")
	wantError(t, admin.do("POST", "/api/v1/projects", body, header("Origin", "null")), http.StatusForbidden, "cross_origin")
	// DELETE and logout are covered as well.
	wantError(t, admin.do("DELETE", "/api/v1/projects/x/tokens/y", nil, noHeader(csrfHeader)), http.StatusForbidden, "csrf_failed")
	wantError(t, admin.do("POST", "/api/v1/logout", nil, noHeader(csrfHeader)), http.StatusForbidden, "csrf_failed")
	// Login from a foreign origin is refused too (login CSRF).
	rec := e.anon().do("POST", "/api/v1/login", loginRequest{Username: adminUsername, Password: testPassword}, header("Origin", "https://evil.example"))
	wantError(t, rec, http.StatusForbidden, "cross_origin")
	if n := len(decode[listBody[storage.Project]](t, admin.do("GET", "/api/v1/projects", nil)).Items); n != 0 {
		t.Fatalf("a rejected request created %d projects", n)
	}
	// Same origin with the right token passes. httptest uses Host example.com.
	if code := post(header("Origin", "http://example.com"), header("Sec-Fetch-Site", "same-origin")); code != http.StatusCreated {
		t.Fatalf("same-origin request: %d", code)
	}
	// GET requests need no CSRF token.
	wantStatus(t, admin.do("GET", "/api/v1/projects", nil, header("Sec-Fetch-Site", "cross-site")), http.StatusOK)
}

func TestLoginGenericErrorAndLockout(t *testing.T) {
	e := newEnv(t, nil)
	e.setup()
	wrongPw := e.anon().do("POST", "/api/v1/login", loginRequest{Username: adminUsername, Password: "wrong-password-123"})
	noUser := e.anon().do("POST", "/api/v1/login", loginRequest{Username: "nobody", Password: "wrong-password-123"})
	wantError(t, wrongPw, http.StatusUnauthorized, "invalid_credentials")
	if wrongPw.Code != noUser.Code || wrongPw.Body.String() != noUser.Body.String() {
		t.Fatalf("unknown user and wrong password must be indistinguishable:\n%s\n%s", wrongPw.Body, noUser.Body)
	}
	for i := 0; i < 4; i++ { // failures 2..5 for admin
		wantError(t, e.anon().do("POST", "/api/v1/login", loginRequest{Username: adminUsername, Password: "wrong-password-123"}), http.StatusUnauthorized, "invalid_credentials")
	}
	// Locked: even the right password is refused, with Retry-After.
	rec := e.anon().do("POST", "/api/v1/login", loginRequest{Username: adminUsername, Password: testPassword})
	wantError(t, rec, http.StatusTooManyRequests, "rate_limited")
	if rec.Header().Get("Retry-After") == "" {
		t.Fatal("no Retry-After on lockout")
	}
	// The lock is per username and IP: another address is not locked.
	elsewhere := e.anon()
	elsewhere.remote = "198.51.100.7:1000"
	wantStatus(t, elsewhere.do("POST", "/api/v1/login", loginRequest{Username: adminUsername, Password: testPassword}), http.StatusOK)
	// After the backoff the right password works again.
	e.clock.Advance(31 * time.Second)
	e.login(adminUsername, testPassword)

	failures := 0
	for _, ev := range mustAudit(t, e) {
		if ev.Action == "login.failed" {
			failures++
		}
	}
	if failures != 6 {
		t.Fatalf("login.failed audit events = %d, want 6", failures)
	}
}

func mustAudit(t *testing.T, e *env) []storage.AuditEvent {
	t.Helper()
	evs, err := e.store.ListAudit(context.Background(), storage.AuditFilter{Limit: 1000})
	if err != nil {
		t.Fatal(err)
	}
	return evs
}

func TestLoginRateLimitPerIP(t *testing.T) {
	e := newEnv(t, nil)
	e.setup() // one login from the default address
	limited := false
	for i := 0; i < 25; i++ {
		rec := e.anon().do("POST", "/api/v1/login", loginRequest{Username: fmt.Sprintf("user%d", i), Password: "wrong-password-123"})
		if rec.Code == http.StatusTooManyRequests {
			limited = true
			if i < 15 {
				t.Fatalf("rate limit hit too early at attempt %d", i)
			}
			break
		}
		wantStatus(t, rec, http.StatusUnauthorized)
	}
	if !limited {
		t.Fatal("25 rapid login attempts from one IP were not rate limited")
	}
	// The bucket refills with time.
	e.clock.Advance(2 * time.Minute)
	e.login(adminUsername, testPassword)
}

func TestClientIPHonorsOnlyTrustedProxies(t *testing.T) {
	e := newEnv(t, func(c *Config) { c.TrustedProxies = []string{"10.0.0.0/8", "127.0.0.1"} })
	a, err := newApp(e.cfg, e.store)
	if err != nil {
		t.Fatal(err)
	}
	mk := func(remote, xff string) *http.Request {
		r, _ := http.NewRequest("GET", "/", nil)
		r.RemoteAddr = remote
		if xff != "" {
			r.Header.Set("X-Forwarded-For", xff)
		}
		return r
	}
	cases := []struct{ remote, xff, want string }{
		{"203.0.113.9:1", "1.2.3.4", "203.0.113.9"},             // untrusted peer: header ignored
		{"10.0.0.5:1", "1.2.3.4", "1.2.3.4"},                    // trusted proxy
		{"10.0.0.5:1", "6.6.6.6, 1.2.3.4, 10.0.0.9", "1.2.3.4"}, // rightmost untrusted entry; spoofed left entry ignored
		{"10.0.0.5:1", "", "10.0.0.5"},
		{"127.0.0.1:1", "garbage", "127.0.0.1"},
	}
	for _, c := range cases {
		if got := a.clientIP(mk(c.remote, c.xff)); got != c.want {
			t.Errorf("clientIP(%s, %q) = %s, want %s", c.remote, c.xff, got, c.want)
		}
	}
	if _, err := parseTrustedProxies([]string{"not-an-ip"}); err == nil {
		t.Fatal("invalid trusted proxy accepted")
	}
}

// ---------------------------------------------------------------------------
// API tokens
// ---------------------------------------------------------------------------

func TestTokenLifecycle(t *testing.T) {
	e := newEnv(t, nil)
	admin := e.setup()
	proj := e.createProject(admin, "p1")
	created := e.createToken(admin, proj.ID)
	scan := func() *model.ScanResult { return sampleScan(e.clock.Now(), randomHex(4)) }

	// The secret is returned once and never again; only the hash is stored.
	listRec := admin.do("GET", "/api/v1/projects/"+proj.ID+"/tokens", nil)
	secret := created.Token[strings.LastIndex(created.Token[:len(created.Token)-43], "_")+1:]
	if strings.Contains(listRec.Body.String(), secret) || strings.Contains(listRec.Body.String(), "token_hash") || strings.Contains(listRec.Body.String(), sha256Hex(created.Token)) {
		t.Fatalf("token list leaks secret material: %s", listRec.Body)
	}
	stored, err := e.store.GetTokenByHash(context.Background(), sha256Hex(created.Token))
	if err != nil || stored.ID != created.Record.ID {
		t.Fatalf("token not stored by sha256: %v", err)
	}
	var export bytes.Buffer
	if err := e.store.ExportProject(context.Background(), proj.ID, &export); err != nil || strings.Contains(export.String(), secret) || strings.Contains(export.String(), sha256Hex(created.Token)) {
		t.Fatalf("export leaks token material (%v)", err)
	}

	wantStatus(t, e.upload(created.Token, scan()), http.StatusCreated)

	// Every bad token gets the same answer.
	var bodies []string
	check := func(name, token string, opts ...reqOpt) {
		c := e.anon()
		c.bearer = token
		rec := c.do("POST", "/api/v1/scans", scan(), opts...)
		wantError(t, rec, http.StatusUnauthorized, "invalid_token")
		if rec.Header().Get("WWW-Authenticate") == "" {
			t.Errorf("%s: no WWW-Authenticate header", name)
		}
		bodies = append(bodies, rec.Body.String())
	}
	check("missing", "")
	check("garbage", "not-a-token")
	check("forged", "agt_"+created.Record.Prefix+"_"+randomToken(32))
	check("truncated", created.Token[:len(created.Token)-1])
	check("basic scheme", "", header("Authorization", "Basic "+created.Token))

	expiring := decode[createTokenResponse](t, admin.do("POST", "/api/v1/projects/"+proj.ID+"/tokens", createTokenRequest{Name: "short", ExpiresInDays: 1}))
	wantStatus(t, e.upload(expiring.Token, scan()), http.StatusCreated)
	e.clock.Advance(25 * time.Hour)
	admin = e.login(adminUsername, testPassword)
	check("expired", expiring.Token)

	wantStatus(t, admin.do("DELETE", "/api/v1/projects/"+proj.ID+"/tokens/"+created.Record.ID, nil), http.StatusOK)
	check("revoked", created.Token)
	for _, b := range bodies[1:] {
		if b != bodies[0] {
			t.Fatalf("token failures must be indistinguishable:\n%s\n%s", bodies[0], b)
		}
	}
	// A revoked token also fails the version check.
	c := e.anon()
	c.bearer = created.Token
	wantError(t, c.do("GET", "/api/v1/version", nil), http.StatusUnauthorized, "invalid_token")

	list := decode[listBody[storage.APIToken]](t, admin.do("GET", "/api/v1/projects/"+proj.ID+"/tokens", nil))
	revoked := 0
	for _, tk := range list.Items {
		if tk.RevokedAt != nil {
			revoked++
		}
	}
	if len(list.Items) != 2 || revoked != 1 {
		t.Fatalf("token list after revoke: %+v", list.Items)
	}
	wantError(t, admin.do("DELETE", "/api/v1/projects/"+proj.ID+"/tokens/tok_missing", nil), http.StatusNotFound, "not_found")
}

func TestProjectTokenCannotReachOtherEndpoints(t *testing.T) {
	e := newEnv(t, nil)
	admin := e.setup()
	proj := e.createProject(admin, "p1")
	tok := e.createToken(admin, proj.ID)
	up := e.mustUpload(tok.Token, sampleScan(e.clock.Now(), "abc"))
	agents := decode[listBody[storage.Agent]](t, admin.do("GET", "/api/v1/projects/"+proj.ID+"/agents", nil))

	c := e.anon()
	c.bearer = tok.Token
	// A token authenticates POST /api/v1/scans and GET /api/v1/version only.
	// Every other route ignores the Authorization header and demands a session.
	for _, rt := range routeTable() {
		if rt.access != accessSession {
			continue
		}
		path := strings.NewReplacer("{projectId}", proj.ID, "{scanId}", up.ID, "{otherScanId}", up.ID, "{agentId}", agents.Items[0].Key, "{tokenId}", tok.Record.ID).Replace(rt.Path)
		var body any
		if rt.Method == "POST" {
			body = map[string]string{}
		}
		rec := c.do(rt.Method, path, body)
		if rec.Code != http.StatusUnauthorized {
			t.Errorf("%s %s with a project token: status %d, want 401", rt.Method, rt.Path, rec.Code)
		}
	}
	if n, _ := e.store.CountUsers(context.Background()); n != 1 {
		t.Fatal("a token created a user")
	}
	// The token was not revoked by its own DELETE attempt.
	wantStatus(t, e.upload(tok.Token, sampleScan(e.clock.Now(), "def")), http.StatusCreated)
	// A session cookie is not accepted for uploads.
	wantError(t, admin.do("POST", "/api/v1/scans", sampleScan(e.clock.Now(), "ghi")), http.StatusUnauthorized, "invalid_token")
}

func TestTokenUploadsOnlyToItsOwnProject(t *testing.T) {
	e := newEnv(t, nil)
	admin := e.setup()
	pa, pb := e.createProject(admin, "proj-a"), e.createProject(admin, "proj-b")
	tokA := e.createToken(admin, pa.ID).Token

	// The body cannot name a project: unknown fields are rejected.
	var doc map[string]any
	_ = json.Unmarshal(rawJSON(t, sampleScan(e.clock.Now(), "abc")), &doc)
	doc["project_id"] = pb.ID
	c := e.anon()
	c.bearer = tokA
	wantError(t, c.do("POST", "/api/v1/scans", doc), http.StatusBadRequest, "invalid_payload")
	// Neither can a query parameter or a header.
	rec := c.do("POST", "/api/v1/scans?project="+pb.ID+"&project_id="+pb.ID, sampleScan(e.clock.Now(), "abc"), header("X-Project-ID", pb.ID))
	wantStatus(t, rec, http.StatusCreated)
	if got := decode[ingestResponse](t, rec).ProjectID; got != pa.ID {
		t.Fatalf("scan landed in %s, want %s", got, pa.ID)
	}
	if n := decode[projectDetail](t, admin.do("GET", "/api/v1/projects/"+pb.ID, nil)).Overview.ScanCount; n != 0 {
		t.Fatalf("project B received %d scans from a project A token", n)
	}
}

func TestIngestRateLimitPerToken(t *testing.T) {
	e := newEnv(t, func(c *Config) { c.IngestRatePerMinute = 3 })
	admin := e.setup()
	proj := e.createProject(admin, "p1")
	t1, t2 := e.createToken(admin, proj.ID).Token, e.createToken(admin, proj.ID).Token
	for i := 0; i < 3; i++ {
		wantStatus(t, e.upload(t1, sampleScan(e.clock.Now(), fmt.Sprintf("c%d", i))), http.StatusCreated)
	}
	rec := e.upload(t1, sampleScan(e.clock.Now(), "c9"))
	wantError(t, rec, http.StatusTooManyRequests, "rate_limited")
	if rec.Header().Get("Retry-After") == "" {
		t.Fatal("no Retry-After")
	}
	// The limit is per token.
	wantStatus(t, e.upload(t2, sampleScan(e.clock.Now(), "d1")), http.StatusCreated)
	e.clock.Advance(time.Minute)
	wantStatus(t, e.upload(t1, sampleScan(e.clock.Now(), "c9")), http.StatusCreated)
}

// ---------------------------------------------------------------------------
// Authorization and cross-project isolation
// ---------------------------------------------------------------------------

func TestCrossProjectIsolationAndRoles(t *testing.T) {
	e := newEnv(t, nil)
	admin := e.setup()
	pa, pb := e.createProject(admin, "proj-a"), e.createProject(admin, "proj-b")
	tokA, tokB := e.createToken(admin, pa.ID), e.createToken(admin, pb.ID)
	scanA1 := e.mustUpload(tokA.Token, sampleScan(e.clock.Now(), "a1"))
	scanA2 := e.mustUpload(tokA.Token, sampleScan(e.clock.Now(), "a2"))
	scanB := e.mustUpload(tokB.Token, sampleScan(e.clock.Now(), "b1"))
	agentsB := decode[listBody[storage.Agent]](t, admin.do("GET", "/api/v1/projects/"+pb.ID+"/agents", nil)).Items
	agentsA := decode[listBody[storage.Agent]](t, admin.do("GET", "/api/v1/projects/"+pa.ID+"/agents", nil)).Items

	viewer := e.createUser(admin, "viewer-a")
	reviewer := e.createUser(admin, "reviewer-a")
	owner := e.createUser(admin, "owner-a")
	outsider := e.createUser(admin, "outsider")
	e.addMember(admin, pa.ID, "viewer-a", storage.ProjectViewer)
	e.addMember(admin, pa.ID, "reviewer-a", storage.ProjectReviewer)
	e.addMember(admin, pa.ID, "owner-a", storage.ProjectOwner)

	// What a missing object looks like. Project B must look exactly the same.
	missing := viewer.do("GET", "/api/v1/projects/prj_doesnotexist", nil)
	wantError(t, missing, http.StatusNotFound, "not_found")

	// 1. Members of A (every role) cannot reach anything of B by ID.
	bPaths := []struct{ method, path string }{
		{"GET", "/api/v1/projects/" + pb.ID},
		{"GET", "/api/v1/projects/" + pb.ID + "/agents"},
		{"GET", "/api/v1/projects/" + pb.ID + "/tokens"},
		{"POST", "/api/v1/projects/" + pb.ID + "/tokens"},
		{"DELETE", "/api/v1/projects/" + pb.ID + "/tokens/" + tokB.Record.ID},
		{"GET", "/api/v1/projects/" + pb.ID + "/members"},
		{"POST", "/api/v1/projects/" + pb.ID + "/members"},
		{"DELETE", "/api/v1/projects/" + pb.ID + "/members?user_id=x"},
		{"GET", "/api/v1/agents/" + agentsB[0].Key},
		{"GET", "/api/v1/agents/" + agentsB[0].Key + "?project=" + pa.ID},
		{"GET", "/api/v1/agents/" + agentsB[0].Key + "/scans"},
		{"GET", "/api/v1/scans/" + scanB.ID},
		{"GET", "/api/v1/scans/" + scanB.ID + "/findings"},
		{"GET", "/api/v1/scans/" + scanB.ID + "/controls"},
		{"GET", "/api/v1/scans/" + scanB.ID + "/compare/" + scanB.ID},
		{"GET", "/api/v1/scans/" + scanA1.ID + "/compare/" + scanB.ID}, // own scan against a foreign one
		{"GET", "/api/v1/scans/" + scanB.ID + "/compare/" + scanA1.ID},
		{"GET", "/api/v1/audit-events?project=" + pb.ID},
	}
	for name, c := range map[string]*client{"viewer": viewer, "reviewer": reviewer, "owner": owner, "outsider": outsider} {
		for _, p := range bPaths {
			var body any
			if p.method == "POST" {
				body = map[string]string{"name": "x", "username": "viewer-a", "role": "owner"}
			}
			rec := c.do(p.method, p.path, body)
			if rec.Code != http.StatusNotFound || rec.Body.String() != missing.Body.String() {
				t.Errorf("%s %s %s: status %d body %s; want the same 404 as a missing object", name, p.method, p.path, rec.Code, rec.Body)
			}
		}
		// Listings are filtered.
		want := 1
		if name == "outsider" {
			want = 0
		}
		if got := decode[listBody[storage.Project]](t, c.do("GET", "/api/v1/projects", nil)).Items; len(got) != want || (want == 1 && got[0].ID != pa.ID) {
			t.Errorf("%s sees projects %+v", name, got)
		}
		ov := decode[overviewResponse](t, c.do("GET", "/api/v1/overview", nil))
		if len(ov.Projects) != want {
			t.Errorf("%s overview has %d projects", name, len(ov.Projects))
		}
		for _, p := range ov.Projects {
			if p.Project.ID == pb.ID {
				t.Errorf("%s overview includes project B", name)
			}
		}
	}
	// Even an administrator cannot compare scans across projects.
	wantError(t, admin.do("GET", "/api/v1/scans/"+scanA1.ID+"/compare/"+scanB.ID, nil), http.StatusNotFound, "not_found")
	// Project B's token was not revoked by the attempts above.
	wantStatus(t, e.upload(tokB.Token, sampleScan(e.clock.Now(), "b2")), http.StatusCreated)
	if m := decode[listBody[storage.Member]](t, admin.do("GET", "/api/v1/projects/"+pb.ID+"/members", nil)).Items; len(m) != 0 {
		t.Fatalf("project B gained members: %+v", m)
	}

	// 2. The outsider has no access to project A either.
	for _, p := range []string{"/api/v1/projects/" + pa.ID, "/api/v1/scans/" + scanA1.ID, "/api/v1/agents/" + agentsA[0].Key, "/api/v1/audit-events?project=" + pa.ID} {
		wantError(t, outsider.do("GET", p, nil), http.StatusNotFound, "not_found")
	}

	// 3. Roles inside project A.
	readPaths := []string{
		"/api/v1/projects/" + pa.ID, "/api/v1/projects/" + pa.ID + "/agents", "/api/v1/agents/" + agentsA[0].Key,
		"/api/v1/agents/" + agentsA[0].Key + "/scans", "/api/v1/scans/" + scanA1.ID, "/api/v1/scans/" + scanA1.ID + "/findings",
		"/api/v1/scans/" + scanA1.ID + "/controls", "/api/v1/scans/" + scanA2.ID + "/compare/" + scanA1.ID,
	}
	for name, c := range map[string]*client{"viewer": viewer, "reviewer": reviewer, "owner": owner} {
		for _, p := range readPaths {
			if rec := c.do("GET", p, nil); rec.Code != http.StatusOK {
				t.Errorf("%s GET %s: %d", name, p, rec.Code)
			}
		}
	}
	// A viewer and a reviewer cannot manage tokens or members.
	for name, c := range map[string]*client{"viewer": viewer, "reviewer": reviewer} {
		wantError(t, c.do("POST", "/api/v1/projects/"+pa.ID+"/tokens", createTokenRequest{Name: "x"}), http.StatusForbidden, "forbidden")
		wantError(t, c.do("GET", "/api/v1/projects/"+pa.ID+"/tokens", nil), http.StatusForbidden, "forbidden")
		wantError(t, c.do("DELETE", "/api/v1/projects/"+pa.ID+"/tokens/"+tokA.Record.ID, nil), http.StatusForbidden, "forbidden")
		wantError(t, c.do("GET", "/api/v1/projects/"+pa.ID+"/members", nil), http.StatusForbidden, "forbidden")
		wantError(t, c.do("POST", "/api/v1/projects/"+pa.ID+"/members", setMemberRequest{Username: name + "-a", Role: storage.ProjectOwner}), http.StatusForbidden, "forbidden")
		wantError(t, c.do("DELETE", "/api/v1/projects/"+pa.ID+"/members?user_id=x", nil), http.StatusForbidden, "forbidden")
	}
	// Audit events: owner and reviewer yes, viewer no; all-project listing is admin only.
	wantStatus(t, owner.do("GET", "/api/v1/audit-events?project="+pa.ID, nil), http.StatusOK)
	wantStatus(t, reviewer.do("GET", "/api/v1/audit-events?project="+pa.ID, nil), http.StatusOK)
	wantError(t, viewer.do("GET", "/api/v1/audit-events?project="+pa.ID, nil), http.StatusForbidden, "forbidden")
	for _, c := range []*client{viewer, reviewer, owner, outsider} {
		wantError(t, c.do("GET", "/api/v1/audit-events", nil), http.StatusForbidden, "forbidden")
	}
	for _, ev := range decode[listBody[storage.AuditEvent]](t, owner.do("GET", "/api/v1/audit-events?project="+pa.ID, nil)).Items {
		if ev.ProjectID != pa.ID {
			t.Fatalf("project audit listing leaked an event of %q", ev.ProjectID)
		}
	}
	// The owner manages tokens and members of A.
	ownTok := e.createToken(owner, pa.ID)
	wantStatus(t, owner.do("DELETE", "/api/v1/projects/"+pa.ID+"/tokens/"+ownTok.Record.ID, nil), http.StatusOK)
	// A token ID of project B addressed through project A is not found, and stays valid.
	wantError(t, owner.do("DELETE", "/api/v1/projects/"+pa.ID+"/tokens/"+tokB.Record.ID, nil), http.StatusNotFound, "not_found")
	wantStatus(t, e.upload(tokB.Token, sampleScan(e.clock.Now(), "b3")), http.StatusCreated)
	wantStatus(t, owner.do("POST", "/api/v1/projects/"+pa.ID+"/members", setMemberRequest{Username: "outsider", Role: storage.ProjectViewer}), http.StatusOK)
	wantStatus(t, outsider.do("GET", "/api/v1/projects/"+pa.ID, nil), http.StatusOK)
	out, _ := e.store.GetUserByUsername(context.Background(), "outsider")
	wantStatus(t, owner.do("DELETE", "/api/v1/projects/"+pa.ID+"/members?user_id="+out.ID, nil), http.StatusOK)
	wantError(t, outsider.do("GET", "/api/v1/projects/"+pa.ID, nil), http.StatusNotFound, "not_found")
	wantError(t, owner.do("POST", "/api/v1/projects/"+pa.ID+"/members", setMemberRequest{Username: "outsider", Role: "administrator"}), http.StatusBadRequest, "invalid_request")

	// 4. Global administration is closed to every non-administrator.
	for _, c := range []*client{viewer, reviewer, owner, outsider} {
		wantError(t, c.do("GET", "/api/v1/users", nil), http.StatusForbidden, "forbidden")
		wantError(t, c.do("POST", "/api/v1/users", createUserRequest{Username: "mallory", Password: testPassword, Role: storage.RoleAdministrator}), http.StatusForbidden, "forbidden")
		wantError(t, c.do("POST", "/api/v1/projects", createProjectRequest{Slug: "mine", Name: "x"}), http.StatusForbidden, "forbidden")
		if rec := c.do("GET", "/metrics", nil); rec.Code != http.StatusNotFound {
			t.Errorf("non-admin reached /metrics: %d", rec.Code)
		}
	}
	users := decode[listBody[storage.User]](t, admin.do("GET", "/api/v1/users", nil))
	if len(users.Items) != 5 || strings.Contains(admin.do("GET", "/api/v1/users", nil).Body.String(), "argon2") {
		t.Fatalf("user list: %d users, or it leaks password hashes", len(users.Items))
	}

	// 5. Unauthenticated callers get 401 on every session route.
	for _, rt := range routeTable() {
		if rt.access != accessSession {
			continue
		}
		path := strings.NewReplacer("{projectId}", pa.ID, "{scanId}", scanA1.ID, "{otherScanId}", scanA2.ID, "{agentId}", agentsA[0].Key, "{tokenId}", tokA.Record.ID).Replace(rt.Path)
		var body any
		if rt.Method == "POST" {
			body = map[string]string{}
		}
		if rec := e.anon().do(rt.Method, path, body); rec.Code != http.StatusUnauthorized {
			t.Errorf("anonymous %s %s: %d, want 401", rt.Method, rt.Path, rec.Code)
		}
	}
}

// Every session route must declare a permission, and every route with an ID
// in its path must resolve its project through a scope function.
func TestRouteTableDeclaresAuthorization(t *testing.T) {
	for _, rt := range routeTable() {
		hasID := strings.Contains(rt.Path, "{")
		switch rt.access {
		case accessSession:
			if rt.perm == permNone {
				t.Errorf("%s %s: session route without a permission", rt.Method, rt.Path)
			}
			if hasID && rt.scope == nil {
				t.Errorf("%s %s: path has an ID but no scope function", rt.Method, rt.Path)
			}
			if hasID && rt.perm != permProjectRead && rt.perm != permProjectManage && rt.perm != permProjectAudit {
				t.Errorf("%s %s: path has an ID but no project permission", rt.Method, rt.Path)
			}
		case accessToken:
			if rt.Method != "POST" || rt.Path != "/api/v1/scans" {
				t.Errorf("%s %s: only POST /api/v1/scans may accept an API token", rt.Method, rt.Path)
			}
		case accessPublic:
			switch rt.Path {
			case "/healthz", "/readyz", "/api/v1/version", "/api/v1/setup", "/api/v1/login":
			default:
				t.Errorf("%s %s: unexpected public route", rt.Method, rt.Path)
			}
		}
	}
}

// ---------------------------------------------------------------------------
// Ingestion validation
// ---------------------------------------------------------------------------

func TestIngestRejectsBadInput(t *testing.T) {
	e := newEnv(t, func(c *Config) { c.MaxUploadBytes = 256 << 10; c.IngestRatePerMinute = 1000 })
	admin := e.setup()
	proj := e.createProject(admin, "p1")
	tok := e.createToken(admin, proj.ID).Token
	c := e.anon()
	c.bearer = tok
	now := e.clock.Now()
	good := func() *model.ScanResult { return sampleScan(now, "abc") }
	asMap := func(mut func(m map[string]any)) []byte {
		var m map[string]any
		_ = json.Unmarshal(rawJSON(t, good()), &m)
		mut(m)
		return rawJSON(t, m)
	}
	mutated := func(mut func(r *model.ScanResult)) []byte {
		r := good()
		mut(r)
		return rawJSON(t, r)
	}

	// Authentication comes first.
	wantError(t, e.anon().do("POST", "/api/v1/scans", good()), http.StatusUnauthorized, "invalid_token")

	// Wrong or missing content type.
	for _, ct := range []string{"text/plain", "application/x-www-form-urlencoded", "multipart/form-data; boundary=x", "application/xml", ""} {
		rec := c.do("POST", "/api/v1/scans", rawJSON(t, good()), func(r *http.Request) {
			if ct == "" {
				r.Header.Del("Content-Type")
			} else {
				r.Header.Set("Content-Type", ct)
			}
		})
		wantError(t, rec, http.StatusUnsupportedMediaType, "unsupported_media_type")
	}

	// Oversized, with and without an honest Content-Length.
	big := mutated(func(r *model.ScanResult) {
		for i := 0; i < 80; i++ {
			r.Limitations = append(r.Limitations, strings.Repeat("x", 4000))
		}
	})
	if len(big) <= 256<<10 {
		t.Fatalf("test payload too small: %d", len(big))
	}
	wantError(t, c.do("POST", "/api/v1/scans", big), http.StatusRequestEntityTooLarge, "payload_too_large")
	wantError(t, c.do("POST", "/api/v1/scans", big, func(r *http.Request) { r.ContentLength = -1 }), http.StatusRequestEntityTooLarge, "payload_too_large")
	wantError(t, c.do("POST", "/api/v1/scans", nil, func(r *http.Request) {
		r.Header.Set("Content-Type", "application/json")
		r.Body = io.NopCloser(io.LimitReader(neverEnding('['), 10<<20))
		r.ContentLength = -1
	}), http.StatusRequestEntityTooLarge, "payload_too_large")

	hugeTime := now.Add(25 * time.Hour)
	cases := map[string][]byte{
		"empty body":            []byte(""),
		"not json":              []byte("this is not json"),
		"truncated":             rawJSON(t, good())[:200],
		"json array":            []byte(`[1,2,3]`),
		"json null fields":      []byte(`{}`),
		"trailing data":         append(rawJSON(t, good()), []byte(` {"x":1}`)...),
		"deep nesting":          []byte(strings.Repeat(`{"scan":`, 5000) + "1" + strings.Repeat("}", 5000)),
		"unknown top field":     asMap(func(m map[string]any) { m["extra"] = true }),
		"unknown nested field":  asMap(func(m map[string]any) { m["scan"].(map[string]any)["source_code"] = "print(1)" }),
		"unknown finding field": asMap(func(m map[string]any) { m["findings"].([]any)[0].(map[string]any)["secret_value"] = "x" }),
		"wrong type":            asMap(func(m map[string]any) { m["agents"] = "none" }),
		"bad timestamp format":  asMap(func(m map[string]any) { m["scan"].(map[string]any)["started_at"] = "yesterday" }),
		"schema version 2":      mutated(func(r *model.ScanResult) { r.SchemaVersion = "2" }),
		"schema version empty":  mutated(func(r *model.ScanResult) { r.SchemaVersion = "" }),
		"missing scan id":       mutated(func(r *model.ScanResult) { r.Scan.ScanID = "" }),
		"bad outcome":           mutated(func(r *model.ScanResult) { r.Decision.Outcome = "PASS" }),
		"bad agent outcome":     mutated(func(r *model.ScanResult) { r.Assessments[0].Decision.Outcome = "allow" }),
		"bad status":            mutated(func(r *model.ScanResult) { r.Assessments[0].Controls[0].Status = "passed" }),
		"bad severity":          mutated(func(r *model.ScanResult) { r.Findings[0].Severity = "catastrophic" }),
		"bad control id":        mutated(func(r *model.ScanResult) { r.Findings[0].ControlID = "AGC-025" }),
		"control id zero":       mutated(func(r *model.ScanResult) { r.Assessments[0].Controls[0].ControlID = "AGC-000" }),
		"control id injection":  mutated(func(r *model.ScanResult) { r.Evidence[0].ControlID = "AGC-001'; DROP TABLE scans;--" }),
		"maturity out of range": mutated(func(r *model.ScanResult) { r.Assessments[0].Controls[0].Maturity = 9 }),
		"score out of range":    mutated(func(r *model.ScanResult) { r.Score.Value = intp(250) }),
		"future started_at":     mutated(func(r *model.ScanResult) { r.Scan.StartedAt = hugeTime }),
		"future evidence":       mutated(func(r *model.ScanResult) { r.Evidence[0].ObservedAt = hugeTime }),
		"ancient timestamp":     mutated(func(r *model.ScanResult) { r.Scan.FinishedAt = time.Date(1970, 1, 2, 0, 0, 0, 0, time.UTC) }),
		"duplicate agent":       mutated(func(r *model.ScanResult) { r.Agents[1].ID = r.Agents[0].ID }),
		"reserved agent id":     mutated(func(r *model.ScanResult) { r.Agents[0].ID = "*" }),
		"assessment no agent":   mutated(func(r *model.ScanResult) { r.Assessments[0].AgentID = "ghost" }),
		"duplicate control":     mutated(func(r *model.ScanResult) { r.Assessments[0].Controls[1].ControlID = "AGC-001" }),
		"missing fingerprint":   mutated(func(r *model.ScanResult) { r.Findings[0].Fingerprint = "" }),
		"bad evidence signal":   mutated(func(r *model.ScanResult) { r.Evidence[0].Signal = "maybe" }),
		"long string":           mutated(func(r *model.ScanResult) { r.Findings[0].Description = strings.Repeat("a", maxStringBytes+1) }),
		"long identifier":       mutated(func(r *model.ScanResult) { r.Agents[0].ID = strings.Repeat("a", maxIDBytes+1) }),
		"too many agents": mutated(func(r *model.ScanResult) {
			r.Assessments = nil
			r.Agents = nil
			for i := 0; i <= maxAgents; i++ {
				r.Agents = append(r.Agents, model.Agent{ID: fmt.Sprintf("a%d", i)})
			}
		}),
	}
	for name, body := range cases {
		rec := c.do("POST", "/api/v1/scans", body)
		if rec.Code != http.StatusBadRequest {
			t.Errorf("%s: status %d, want 400: %s", name, rec.Code, rec.Body)
			continue
		}
		if got := decode[errorBody](t, rec).Error.Code; got != "invalid_payload" {
			t.Errorf("%s: code %q", name, got)
		}
	}
	// Nothing was stored.
	if n := decode[projectDetail](t, admin.do("GET", "/api/v1/projects/"+proj.ID, nil)).Overview.ScanCount; n != 0 {
		t.Fatalf("rejected uploads stored %d scans", n)
	}
	// Error messages never echo content.
	rec := c.do("POST", "/api/v1/scans", mutated(func(r *model.ScanResult) { r.Findings[0].Severity = "sk-live-SECRETVALUE" }))
	if strings.Contains(rec.Body.String(), "SECRETVALUE") {
		t.Fatalf("validation error echoes field content: %s", rec.Body)
	}
	// The boundary values are accepted.
	ok := mutated(func(r *model.ScanResult) {
		r.Scan.StartedAt = now.Add(23 * time.Hour)
		r.Findings[0].Description = strings.Repeat("a", maxStringBytes)
		r.Findings[0].ControlID = "AGC-024"
	})
	wantStatus(t, c.do("POST", "/api/v1/scans", ok), http.StatusCreated)
	// A scan with no agents is valid (truthful "no agent found" result).
	wantStatus(t, c.do("POST", "/api/v1/scans", mutated(func(r *model.ScanResult) {
		r.Agents, r.Assessments, r.Findings = []model.Agent{}, []model.AgentAssessment{}, []model.Finding{}
		r.Decision.Outcome = model.OutcomeReviewRequired
		r.Score.Value = nil
		r.Score.Label = "insufficient-evidence"
	})), http.StatusCreated)

	// Limits on the item counts (needs a larger body limit).
	e2 := newEnv(t, nil)
	admin2 := e2.setup()
	tok2 := e2.createToken(admin2, e2.createProject(admin2, "p1").ID).Token
	many := sampleScan(e2.clock.Now(), "abc")
	many.Findings = make([]model.Finding, maxFindings+1)
	for i := range many.Findings {
		many.Findings[i] = model.Finding{FindingID: "f", Fingerprint: "p", ControlID: "AGC-001", Severity: model.SeverityLow}
	}
	if rec := e2.upload(tok2, many); rec.Code != http.StatusBadRequest || !strings.Contains(rec.Body.String(), "findings: more than") {
		t.Fatalf("too many findings: %d %s", rec.Code, rec.Body)
	}
}

type neverEnding byte

func (b neverEnding) Read(p []byte) (int, error) {
	for i := range p {
		p[i] = byte(b)
	}
	return len(p), nil
}

func TestSmallEndpointsRejectBadBodies(t *testing.T) {
	e := newEnv(t, nil)
	admin := e.setup()
	wantError(t, admin.do("POST", "/api/v1/projects", `{"slug":"ok","name":"x","admin":true}`), http.StatusBadRequest, "invalid_request")
	wantError(t, admin.do("POST", "/api/v1/projects", `{"slug":"ok","name":"x"}`, header("Content-Type", "text/plain")), http.StatusUnsupportedMediaType, "unsupported_media_type")
	wantError(t, admin.do("POST", "/api/v1/projects", `{"slug":"ok","name":"`+strings.Repeat("x", smallBodyLimit)+`"}`), http.StatusRequestEntityTooLarge, "payload_too_large")
	wantError(t, e.anon().do("POST", "/api/v1/login", `{"username":"admin","password":"x","role":"administrator"}`), http.StatusBadRequest, "invalid_request")
	wantError(t, admin.do("POST", "/api/v1/users", createUserRequest{Username: "bob", Password: "too-short"}), http.StatusBadRequest, "invalid_request")
	wantError(t, admin.do("POST", "/api/v1/users", createUserRequest{Username: "bob", Password: testPassword, Role: "superuser"}), http.StatusBadRequest, "invalid_request")
	wantError(t, admin.do("POST", "/api/v1/users", createUserRequest{Username: adminUsername, Password: testPassword}), http.StatusConflict, "conflict")
	wantError(t, admin.do("GET", "/api/v1/nope", nil), http.StatusNotFound, "not_found")
	wantError(t, admin.do("PUT", "/api/v1/projects", `{}`), http.StatusNotFound, "not_found")
}

// ---------------------------------------------------------------------------
// Injection: SQL metacharacters and stored XSS
// ---------------------------------------------------------------------------

func TestSQLMetacharactersAreInert(t *testing.T) {
	e := newEnv(t, nil)
	admin := e.setup()
	evil := `x'); DROP TABLE users;-- " OR ""=" \ % _ ; SELECT * FROM api_tokens`
	for _, slug := range []string{`a'; DROP TABLE projects;--`, `a" OR "1"="1`, "a b", "a;b", "A", "-a", "a-", "a/../b", strings.Repeat("a", 65), ""} {
		wantError(t, admin.do("POST", "/api/v1/projects", createProjectRequest{Slug: slug, Name: "x"}), http.StatusBadRequest, "invalid_request")
	}
	rec := admin.do("POST", "/api/v1/projects", createProjectRequest{Slug: "inert", Name: evil})
	wantStatus(t, rec, http.StatusCreated)
	p := decode[storage.Project](t, rec)
	if p.Name != evil {
		t.Fatalf("name changed: %q", p.Name)
	}
	if got := decode[projectDetail](t, admin.do("GET", "/api/v1/projects/"+p.ID, nil)).Project.Name; got != evil {
		t.Fatalf("name did not round-trip: %q", got)
	}
	tok := decode[createTokenResponse](t, admin.do("POST", "/api/v1/projects/"+p.ID+"/tokens", createTokenRequest{Name: evil}))
	if tok.Record.Name != evil {
		t.Fatalf("token name changed: %q", tok.Record.Name)
	}

	// Metacharacters in IDs, query parameters, and credentials match nothing.
	inj := `%27%20OR%20%271%27=%271`
	wantError(t, admin.do("GET", "/api/v1/projects/"+inj, nil), http.StatusNotFound, "not_found")
	wantError(t, admin.do("GET", "/api/v1/scans/"+inj, nil), http.StatusNotFound, "not_found")
	wantError(t, admin.do("GET", "/api/v1/agents/"+inj, nil), http.StatusNotFound, "not_found")
	wantError(t, admin.do("GET", "/api/v1/audit-events?project="+inj, nil), http.StatusNotFound, "not_found")
	wantError(t, e.anon().do("POST", "/api/v1/login", loginRequest{Username: `admin' --`, Password: "anything-at-all"}), http.StatusUnauthorized, "invalid_credentials")
	wantError(t, e.anon().do("POST", "/api/v1/login", loginRequest{Username: `' OR '1'='1`, Password: `' OR '1'='1`}), http.StatusUnauthorized, "invalid_credentials")
	wantError(t, admin.do("POST", "/api/v1/users", createUserRequest{Username: `bob'; DROP TABLE users;--`, Password: testPassword}), http.StatusBadRequest, "invalid_request")

	// Scan content with metacharacters is stored and returned verbatim.
	scan := sampleScan(e.clock.Now(), "abc")
	scan.Agents[0].Name = evil
	scan.Findings[0].Title = evil
	scan.Scan.CommitSHA = `abc'; DELETE FROM scans;--`
	up := e.mustUpload(tok.Token, scan)
	agents := decode[listBody[storage.Agent]](t, admin.do("GET", "/api/v1/projects/"+p.ID+"/agents", nil)).Items
	if len(agents) != 2 || agents[1].Name != evil {
		t.Fatalf("agent name: %+v", agents)
	}
	if got := decode[pageBody[model.Finding]](t, admin.do("GET", "/api/v1/scans/"+up.ID+"/findings?severity=critical%27%20OR%201=1", nil)); got.Total != 0 {
		t.Fatalf("injected filter matched %d findings", got.Total)
	}

	// Every table still exists and the data is intact.
	if n, err := e.store.CountUsers(context.Background()); err != nil || n != 1 {
		t.Fatalf("users table damaged: %d %v", n, err)
	}
	if ps := decode[listBody[storage.Project]](t, admin.do("GET", "/api/v1/projects", nil)).Items; len(ps) != 1 {
		t.Fatalf("projects: %+v", ps)
	}
	if _, err := e.store.VerifyAuditChain(context.Background()); err != nil {
		t.Fatal(err)
	}
}

func TestStoredXSSIsInertJSON(t *testing.T) {
	e := newEnv(t, nil)
	admin := e.setup()
	payload := `<script>alert(document.cookie)</script><img src=x onerror=alert(1)>"'&`
	rec := admin.do("POST", "/api/v1/projects", createProjectRequest{Slug: "xss", Name: payload})
	wantStatus(t, rec, http.StatusCreated)
	proj := decode[storage.Project](t, rec)
	tok := e.createToken(admin, proj.ID).Token
	scan := sampleScan(e.clock.Now(), "abc")
	scan.Findings[0].Title = payload
	scan.Findings[0].Description = payload
	scan.Findings[0].Location.Path = `"><script>alert(2)</script>.py`
	scan.Agents[0].Name = payload
	scan.Agents[0].Owner = payload
	scan.Assessments[0].Controls[0].StatusReason = payload
	scan.Scan.Target = payload
	up := e.mustUpload(tok, scan)
	agents := decode[listBody[storage.Agent]](t, admin.do("GET", "/api/v1/projects/"+proj.ID+"/agents", nil)).Items

	paths := []string{
		"/api/v1/projects", "/api/v1/projects/" + proj.ID, "/api/v1/projects/" + proj.ID + "/agents", "/api/v1/overview",
		"/api/v1/scans/" + up.ID, "/api/v1/scans/" + up.ID + "/findings", "/api/v1/scans/" + up.ID + "/controls",
		"/api/v1/scans/" + up.ID + "/compare/" + up.ID, "/api/v1/agents/" + agents[0].Key, "/api/v1/agents/" + agents[1].Key,
		"/api/v1/audit-events",
	}
	sawPayload := 0
	for _, p := range paths {
		rec := admin.do("GET", p, nil)
		wantStatus(t, rec, http.StatusOK)
		if ct := rec.Header().Get("Content-Type"); ct != "application/json; charset=utf-8" {
			t.Errorf("%s: content type %q", p, ct)
		}
		if rec.Header().Get("X-Content-Type-Options") != "nosniff" {
			t.Errorf("%s: nosniff missing", p)
		}
		// The raw bytes hold no markup: encoding/json escapes < > &.
		if bytes.Contains(rec.Body.Bytes(), []byte("<script")) || bytes.Contains(rec.Body.Bytes(), []byte("<img")) {
			t.Errorf("%s: raw response contains unescaped markup", p)
		}
		var v any
		if err := json.Unmarshal(rec.Body.Bytes(), &v); err != nil {
			t.Errorf("%s: invalid JSON: %v", p, err)
		}
		if strings.Contains(fmt.Sprint(v), payload) {
			sawPayload++
		}
	}
	if sawPayload < 6 {
		t.Fatalf("the payload should round-trip as data on most endpoints, saw it on %d", sawPayload)
	}
	// Exact round trip of the finding title.
	fl := decode[pageBody[model.Finding]](t, admin.do("GET", "/api/v1/scans/"+up.ID+"/findings?severity=critical", nil))
	if fl.Items[0].Title != payload || fl.Items[0].Location.Path != `"><script>alert(2)</script>.py` {
		t.Fatalf("finding did not round-trip: %+v", fl.Items[0])
	}
	// Reflected input: a hostile path or query never comes back as HTML.
	for _, p := range []string{"/api/v1/scans/%3Cscript%3Ealert(1)%3C%2Fscript%3E", "/api/v1/%3Cscript%3E", "/api/v1/audit-events?project=%3Cscript%3Ealert(1)%3C/script%3E"} {
		rec := admin.do("GET", p, nil)
		if rec.Header().Get("Content-Type") != "application/json; charset=utf-8" || strings.Contains(rec.Body.String(), "<script") {
			t.Errorf("%s: reflected markup or wrong content type: %s", p, rec.Body)
		}
	}
	// The fallback page escapes too and reflects nothing.
	rec = e.anon().do("GET", "/%3Cscript%3Ealert(1)%3C/script%3E", nil)
	if strings.Contains(rec.Body.String(), "alert(1)") {
		t.Fatal("fallback page reflects the request path")
	}
}

// ---------------------------------------------------------------------------
// Headers, UI, health, metrics, panic recovery
// ---------------------------------------------------------------------------

func TestSecurityHeadersEverywhere(t *testing.T) {
	e := newEnv(t, nil)
	admin := e.setup()
	check := func(rec interface{ Header() http.Header }, name string, api bool) {
		h := rec.Header()
		for k, want := range map[string]string{"X-Content-Type-Options": "nosniff", "Referrer-Policy": "no-referrer", "X-Frame-Options": "DENY", "Cross-Origin-Opener-Policy": "same-origin"} {
			if h.Get(k) != want {
				t.Errorf("%s: %s = %q, want %q", name, k, h.Get(k), want)
			}
		}
		if h.Get("X-Request-ID") == "" {
			t.Errorf("%s: no request ID", name)
		}
		if api {
			if h.Get("Cache-Control") != "no-store" {
				t.Errorf("%s: Cache-Control = %q", name, h.Get("Cache-Control"))
			}
		} else if h.Get("Content-Security-Policy") != uiCSP {
			t.Errorf("%s: CSP = %q", name, h.Get("Content-Security-Policy"))
		}
	}
	check(e.anon().do("GET", "/healthz", nil), "healthz", true)
	check(e.anon().do("GET", "/readyz", nil), "readyz", true)
	check(e.anon().do("GET", "/api/v1/version", nil), "version", true)
	check(e.anon().do("GET", "/api/v1/projects", nil), "401", true)
	check(admin.do("GET", "/api/v1/projects", nil), "projects", true)
	check(admin.do("GET", "/api/v1/unknown", nil), "api 404", true)
	check(e.anon().do("POST", "/api/v1/login", "{"), "400", true)
	check(e.anon().do("GET", "/", nil), "ui root", false)
	check(e.anon().do("GET", "/agents/123", nil), "ui route", false)
	want := "default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; connect-src 'self'; frame-ancestors 'none'; base-uri 'none'; form-action 'self'"
	if uiCSP != want {
		t.Fatalf("CSP changed:\n%s", uiCSP)
	}
}

func TestHealthEndpoints(t *testing.T) {
	e := newEnv(t, nil)
	rec := e.anon().do("GET", "/healthz", nil)
	wantStatus(t, rec, http.StatusOK)
	if strings.TrimSpace(rec.Body.String()) != `{"status":"ok"}` {
		t.Fatalf("healthz must carry no detail: %s", rec.Body)
	}
	rec = e.anon().do("GET", "/readyz", nil)
	wantStatus(t, rec, http.StatusOK)
	if strings.TrimSpace(rec.Body.String()) != `{"status":"ready"}` {
		t.Fatalf("readyz: %s", rec.Body)
	}
	e.store.Close()
	wantStatus(t, e.anon().do("GET", "/healthz", nil), http.StatusOK) // liveness does not touch the database
	rec = e.anon().do("GET", "/readyz", nil)
	wantError(t, rec, http.StatusServiceUnavailable, "not_ready")
	if strings.Contains(rec.Body.String(), "sql") || strings.Contains(rec.Body.String(), "closed") {
		t.Fatalf("readyz leaks database detail: %s", rec.Body)
	}
}

func TestBuiltinPageWhenNoUI(t *testing.T) {
	e := newEnv(t, nil)
	rec := e.anon().do("GET", "/", nil)
	wantStatus(t, rec, http.StatusOK)
	body := rec.Body.String()
	if !strings.HasPrefix(rec.Header().Get("Content-Type"), "text/html") || !strings.Contains(body, "dashboard bundle is not included") ||
		!strings.Contains(body, "Ready") || !strings.Contains(body, "test-1.2.3") || strings.Contains(body, "<script") {
		t.Fatalf("builtin page: %s", body)
	}
	if strings.Contains(body, e.bootstrapToken()) {
		t.Fatal("builtin page shows the bootstrap token")
	}
	wantStatus(t, e.anon().do("POST", "/", nil), http.StatusMethodNotAllowed)
}

func TestUIServingAndSPAFallback(t *testing.T) {
	ui := fstest.MapFS{
		"index.html":                {Data: []byte("<!doctype html><title>dash</title>")},
		"assets/index-4f3a9c1b.js":  {Data: []byte("console.log(1)")},
		"assets/style-aa11bb22.css": {Data: []byte("body{}")},
		"favicon.svg":               {Data: []byte("<svg xmlns='http://www.w3.org/2000/svg'/>")},
	}
	e := newEnv(t, func(c *Config) { c.UI = ui })
	get := func(p string) (int, http.Header, string) {
		rec := e.anon().do("GET", p, nil)
		return rec.Code, rec.Header(), rec.Body.String()
	}
	for _, p := range []string{"/", "/index.html", "/projects/prj_1/agents", "/setup", "/scans/scn_1/compare/scn_2"} {
		code, h, body := get(p)
		if code != 200 || !strings.Contains(body, "<title>dash</title>") || h.Get("Cache-Control") != "no-cache" || !strings.HasPrefix(h.Get("Content-Type"), "text/html") {
			t.Errorf("%s: %d cache=%q type=%q", p, code, h.Get("Cache-Control"), h.Get("Content-Type"))
		}
		if h.Get("Content-Security-Policy") != uiCSP {
			t.Errorf("%s: CSP missing", p)
		}
	}
	code, h, body := get("/assets/index-4f3a9c1b.js")
	if code != 200 || body != "console.log(1)" || h.Get("Cache-Control") != "public, max-age=31536000, immutable" || !strings.HasPrefix(h.Get("Content-Type"), "text/javascript") {
		t.Fatalf("hashed asset: %d %v", code, h)
	}
	if _, h, _ := get("/assets/style-aa11bb22.css"); !strings.HasPrefix(h.Get("Content-Type"), "text/css") {
		t.Fatalf("css type: %v", h.Get("Content-Type"))
	}
	if _, h, _ := get("/favicon.svg"); h.Get("Cache-Control") != "no-cache" {
		t.Fatalf("unhashed asset must not get a long cache lifetime: %q", h.Get("Cache-Control"))
	}
	// A missing asset is 404, not index.html.
	if code, _, body := get("/assets/missing-00000000.js"); code != 404 || strings.Contains(body, "dash") {
		t.Fatalf("missing asset: %d %q", code, body)
	}
	// API paths never fall back to the dashboard.
	for _, p := range []string{"/api/v1/unknown", "/api/", "/api/v2/projects"} {
		rec := e.anon().do("GET", p, nil)
		wantError(t, rec, http.StatusNotFound, "not_found")
	}
	// Path traversal stays inside the bundle.
	for _, p := range []string{"/../../etc/passwd", "/assets/../../secret.txt", "/..%2f..%2fetc%2fpasswd"} {
		if code, _, body := get(p); code == 200 && !strings.Contains(body, "<title>dash</title>") {
			t.Fatalf("%s served unexpected content: %q", p, body)
		}
	}
}

func TestMetricsAccessAndContent(t *testing.T) {
	e := newEnv(t, func(c *Config) { c.TrustedProxies = []string{"127.0.0.1"} })
	admin := e.setup()
	proj := e.createProject(admin, "secret-project-name")
	e.mustUpload(e.createToken(admin, proj.ID).Token, sampleScan(e.clock.Now(), "abc"))
	e.anon().do("POST", "/api/v1/login", loginRequest{Username: adminUsername, Password: "wrong-password-123"})

	// Anonymous remote caller: hidden.
	wantError(t, e.anon().do("GET", "/metrics", nil), http.StatusNotFound, "not_found")
	// Loopback caller: allowed.
	local := e.anon()
	local.remote = "127.0.0.1:50000"
	rec := local.do("GET", "/metrics", nil)
	wantStatus(t, rec, http.StatusOK)
	body := rec.Body.String()
	for _, want := range []string{"agentgov_http_requests_total{method=\"POST\",code=\"201\"}", "agentgov_scan_ingests_total{result=\"created\"} 1", "agentgov_auth_failures_total{kind=\"login\"} 1", "# TYPE agentgov_http_requests_total counter"} {
		if !strings.Contains(body, want) {
			t.Errorf("metrics lack %q:\n%s", want, body)
		}
	}
	for _, leak := range []string{"secret-project-name", proj.ID, "support-bot", "Hard-coded", adminUsername} {
		if strings.Contains(body, leak) {
			t.Errorf("metrics leak %q", leak)
		}
	}
	// Loopback peer that is really a reverse proxy: not treated as local.
	wantError(t, local.do("GET", "/metrics", nil, header("X-Forwarded-For", "203.0.113.5")), http.StatusNotFound, "not_found")
	// Administrator session from anywhere: allowed.
	wantStatus(t, admin.do("GET", "/metrics", nil), http.StatusOK)
}

type panicStore struct{ storage.Store }

func (panicStore) Ping(context.Context) error { panic("boom: secret-internal-detail") }

func TestPanicRecovery(t *testing.T) {
	e := newEnv(t, nil)
	h, err := NewHandler(e.cfg, panicStore{e.store})
	if err != nil {
		t.Fatal(err)
	}
	e.h = h
	rec := e.anon().do("GET", "/readyz", nil)
	wantError(t, rec, http.StatusInternalServerError, "internal_error")
	if strings.Contains(rec.Body.String(), "boom") || strings.Contains(rec.Body.String(), "goroutine") || strings.Contains(rec.Body.String(), ".go:") {
		t.Fatalf("panic detail reached the client: %s", rec.Body)
	}
	if !strings.Contains(e.logs.String(), "panic in handler") || !strings.Contains(e.logs.String(), "boom") {
		t.Fatal("panic was not logged on the server")
	}
	// The server keeps serving.
	wantStatus(t, e.anon().do("GET", "/healthz", nil), http.StatusOK)
}

// ---------------------------------------------------------------------------
// Catalog, policies, evidence verification
// ---------------------------------------------------------------------------

func TestControlsAndPolicies(t *testing.T) {
	e := newEnv(t, nil)
	admin := e.setup()
	rec := admin.do("GET", "/api/v1/controls", nil)
	wantError(t, rec, http.StatusServiceUnavailable, "catalog_not_loaded")
	if !strings.Contains(rec.Body.String(), "catalog not loaded") {
		t.Fatalf("message: %s", rec.Body)
	}
	wantError(t, admin.do("GET", "/api/v1/policies", nil), http.StatusServiceUnavailable, "profiles_not_loaded")

	e2 := newEnv(t, func(c *Config) {
		c.Catalog = &model.Catalog{Pack: "builtin/v1", Version: "1.0", Controls: []model.Control{{ID: "AGC-001", Title: "Named owner", Severity: model.SeverityHigh}}}
		c.Profiles = []model.Profile{{Name: "standard", Version: "1.0", MandatoryControls: []string{"AGC-001"}, MinMaturity: 2}}
	})
	wantError(t, e2.anon().do("GET", "/api/v1/controls", nil), http.StatusUnauthorized, "unauthenticated")
	admin2 := e2.setup()
	cat := decode[model.Catalog](t, admin2.do("GET", "/api/v1/controls", nil))
	if cat.Pack != "builtin/v1" || len(cat.Controls) != 1 || cat.Controls[0].ID != "AGC-001" {
		t.Fatalf("catalog: %+v", cat)
	}
	pol := decode[policiesResponse](t, admin2.do("GET", "/api/v1/policies", nil))
	if len(pol.Profiles) != 1 || pol.Profiles[0].Name != "standard" {
		t.Fatalf("policies: %+v", pol)
	}
	// Policies are read-only.
	wantError(t, admin2.do("POST", "/api/v1/policies", `{}`), http.StatusNotFound, "not_found")
}

func TestEvidenceVerify(t *testing.T) {
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	otherPub, _, _ := ed25519.GenerateKey(rand.Reader)
	e := newEnv(t, func(c *Config) { c.TrustedKeys = map[string]ed25519.PublicKey{"ci-key": pub, "other": otherPub} })
	admin := e.setup()
	ev := sampleScan(e.clock.Now(), "abc").Evidence[2]
	ev.Summary = "Result <ok> & signed"
	msg, err := CanonicalEvidence(ev)
	if err != nil {
		t.Fatal(err)
	}
	// The canonical form is sorted-key compact JSON of the signed fields only.
	if !bytes.HasPrefix(msg, []byte(`{"agent_id":"billing-agent","collector":"external","commit_sha":"abc","control_id":"AGC-012",`)) ||
		!bytes.Contains(msg, []byte(`"summary":"Result <ok> & signed"`)) || bytes.HasSuffix(msg, []byte("\n")) {
		t.Fatalf("canonical form: %s", msg)
	}
	for _, f := range []string{"evidence_id", "policy_version", "scanner_version", "source_location", "integrity", "validity", "validity_reason", "signature"} {
		if bytes.Contains(msg, []byte(`"`+f+`":`)) {
			t.Fatalf("canonical form contains excluded field %q", f)
		}
	}
	sig := base64.StdEncoding.EncodeToString(ed25519.Sign(priv, msg))
	verify := func(c *client, req evidenceVerifyRequest) evidenceVerifyResponse {
		rec := c.do("POST", "/api/v1/evidence/verify", req)
		wantStatus(t, rec, http.StatusOK)
		return decode[evidenceVerifyResponse](t, rec)
	}
	if r := verify(admin, evidenceVerifyRequest{Evidence: ev, Signature: sig, KeyID: "ci-key"}); !r.Verified {
		t.Fatalf("valid signature rejected: %+v", r)
	}
	// Fields the scanner recomputes are outside the signature.
	recomputed := ev
	recomputed.Validity, recomputed.Integrity, recomputed.EvidenceID, recomputed.ValidityReason = model.ValidityValid, model.IntegrityVerified, "other-id", ""
	recomputed.ScannerVersion, recomputed.PolicyVersion = "9.9", "9.9"
	if r := verify(admin, evidenceVerifyRequest{Evidence: recomputed, Signature: sig, KeyID: "ci-key"}); !r.Verified {
		t.Fatalf("excluded fields must not affect verification: %+v", r)
	}
	tampered := ev
	tampered.Result = model.ResultFail
	wrongCommit := ev
	wrongCommit.CommitSHA = "def"
	for name, req := range map[string]evidenceVerifyRequest{
		"tampered result": {Evidence: tampered, Signature: sig, KeyID: "ci-key"},
		"other commit":    {Evidence: wrongCommit, Signature: sig, KeyID: "ci-key"},
		"wrong key":       {Evidence: ev, Signature: sig, KeyID: "other"},
		"unknown key":     {Evidence: ev, Signature: sig, KeyID: "nope"},
		"empty key id":    {Evidence: ev, Signature: sig},
		"garbage sig":     {Evidence: ev, Signature: "!!!", KeyID: "ci-key"},
		"short sig":       {Evidence: ev, Signature: "AAAA", KeyID: "ci-key"},
		"empty sig":       {Evidence: ev, KeyID: "ci-key"},
	} {
		if r := verify(admin, req); r.Verified || r.Reason == "" {
			t.Errorf("%s: verified=%v reason=%q", name, r.Verified, r.Reason)
		}
	}
	// Authentication and CSRF apply; a caller-supplied key is not accepted.
	wantError(t, e.anon().do("POST", "/api/v1/evidence/verify", evidenceVerifyRequest{Evidence: ev, Signature: sig, KeyID: "ci-key"}), http.StatusUnauthorized, "unauthenticated")
	wantError(t, admin.do("POST", "/api/v1/evidence/verify", evidenceVerifyRequest{Evidence: ev, Signature: sig, KeyID: "ci-key"}, noHeader(csrfHeader)), http.StatusForbidden, "csrf_failed")
	wantError(t, admin.do("POST", "/api/v1/evidence/verify", `{"evidence":{},"signature":"x","key_id":"k","public_key":"AAAA"}`), http.StatusBadRequest, "invalid_request")
	wantError(t, admin.do("POST", "/api/v1/evidence/verify", `{"evidence":{},"signature":"x","key_id":"k","url":"http://169.254.169.254/"}`), http.StatusBadRequest, "invalid_request")
}

// ---------------------------------------------------------------------------
// Listening
// ---------------------------------------------------------------------------

func TestCheckListenAddress(t *testing.T) {
	for _, addr := range []string{"127.0.0.1:8080", "localhost:8080", "[::1]:8080", "127.0.0.2:0"} {
		if public, err := CheckListenAddress(addr, false); err != nil || public {
			t.Errorf("%s: public=%v err=%v", addr, public, err)
		}
	}
	for _, addr := range []string{"0.0.0.0:8080", ":8080", "[::]:8080", "192.168.1.10:8080", "example.com:8080", "10.0.0.1:80"} {
		if _, err := CheckListenAddress(addr, false); !errors.Is(err, ErrPublicBindRefused) {
			t.Errorf("%s: want ErrPublicBindRefused, got %v", addr, err)
		}
		if public, err := CheckListenAddress(addr, true); err != nil || !public {
			t.Errorf("%s with AllowPublic: public=%v err=%v", addr, public, err)
		}
	}
	for _, addr := range []string{"", "8080", "127.0.0.1", "127.0.0.1:"} {
		if _, err := CheckListenAddress(addr, true); err == nil {
			t.Errorf("%q: expected an error", addr)
		}
	}
	if DefaultListen != "127.0.0.1:8080" {
		t.Fatal("default listen address changed")
	}
}

func TestRunRefusesPublicBind(t *testing.T) {
	dir := t.TempDir()
	logs := &syncBuffer{}
	cfg := Config{Listen: "0.0.0.0:0", DatabaseURL: dir + "/agentgov.db", Logger: testLogger(logs), BootstrapOut: io.Discard, Argon2MemoryKiB: testArgonKiB}
	err := Run(context.Background(), cfg)
	if !errors.Is(err, ErrPublicBindRefused) {
		t.Fatalf("Run on 0.0.0.0 without AllowPublic: %v", err)
	}
	// It refuses before it touches the database.
	if matches, _ := fsGlob(dir); len(matches) != 0 {
		t.Fatalf("database created despite refusal: %v", matches)
	}
	if err := Run(context.Background(), Config{Listen: "127.0.0.1:0", Logger: testLogger(logs)}); err == nil {
		t.Fatal("Run without DatabaseURL must fail")
	}
}

func TestRunServesAndShutsDownGracefully(t *testing.T) {
	for _, tc := range []struct {
		name, listen string
		public       bool
	}{{"loopback", "127.0.0.1:0", false}, {"public with AllowPublic", "0.0.0.0:0", true}} {
		t.Run(tc.name, func(t *testing.T) {
			logs, boot := &syncBuffer{}, &syncBuffer{}
			addrc := make(chan net.Addr, 1)
			cfg := Config{Listen: tc.listen, AllowPublic: tc.public, DatabaseURL: "sqlite:///" + strings.ReplaceAll(t.TempDir(), `\`, "/") + "/agentgov.db",
				Logger: testLogger(logs), BootstrapOut: boot, Argon2MemoryKiB: testArgonKiB, OnListening: func(a net.Addr) { addrc <- a }}
			ctx, cancel := context.WithCancel(context.Background())
			done := make(chan error, 1)
			go func() { done <- Run(ctx, cfg) }()
			var addr net.Addr
			select {
			case addr = <-addrc:
			case err := <-done:
				t.Fatalf("Run exited early: %v", err)
			case <-time.After(20 * time.Second):
				t.Fatal("server did not start")
			}
			_, port, _ := net.SplitHostPort(addr.String())
			base := "http://127.0.0.1:" + port
			resp, err := http.Get(base + "/readyz")
			if err != nil {
				t.Fatal(err)
			}
			body, _ := io.ReadAll(resp.Body)
			resp.Body.Close()
			if resp.StatusCode != 200 || resp.Header.Get("X-Content-Type-Options") != "nosniff" || !strings.Contains(string(body), "ready") {
				t.Fatalf("readyz over TCP: %d %s", resp.StatusCode, body)
			}
			if !bootTokenRe.MatchString(boot.String()) {
				t.Fatal("no bootstrap token printed by Run")
			}
			warned := strings.Contains(logs.String(), "SECURITY WARNING")
			if warned != tc.public {
				t.Fatalf("public-bind warning logged = %v, want %v", warned, tc.public)
			}
			if tc.public && !strings.Contains(logs.String(), "TLS") {
				t.Fatal("the warning must mention TLS termination")
			}
			cancel()
			select {
			case err := <-done:
				if err != nil {
					t.Fatalf("graceful shutdown returned %v", err)
				}
			case <-time.After(30 * time.Second):
				t.Fatal("server did not shut down")
			}
			if _, err := http.Get(base + "/healthz"); err == nil {
				t.Fatal("server still answers after shutdown")
			}
		})
	}
}

func TestHTTPServerLimits(t *testing.T) {
	srv := newHTTPServer(http.NotFoundHandler(), testLogger(io.Discard))
	if srv.ReadHeaderTimeout <= 0 || srv.ReadHeaderTimeout > 30*time.Second {
		t.Errorf("ReadHeaderTimeout = %v", srv.ReadHeaderTimeout)
	}
	if srv.ReadTimeout <= 0 || srv.WriteTimeout <= 0 || srv.IdleTimeout <= 0 {
		t.Errorf("timeouts must be set: read=%v write=%v idle=%v", srv.ReadTimeout, srv.WriteTimeout, srv.IdleTimeout)
	}
	if srv.MaxHeaderBytes <= 0 || srv.MaxHeaderBytes > 1<<20 {
		t.Errorf("MaxHeaderBytes = %d", srv.MaxHeaderBytes)
	}
	// An oversized header is refused by a real listener.
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	go srv.Serve(ln)
	defer srv.Close()
	req, _ := http.NewRequest("GET", "http://"+ln.Addr().String()+"/", nil)
	req.Header.Set("X-Big", strings.Repeat("a", 200<<10))
	resp, err := http.DefaultClient.Do(req)
	if err == nil {
		resp.Body.Close()
		if resp.StatusCode != http.StatusRequestHeaderFieldsTooLarge {
			t.Fatalf("oversized header: status %d", resp.StatusCode)
		}
	}
}

// TestEvidenceCanonicalGolden pins the exact canonical bytes. The expected
// value was produced by internal/evidence (the CLI signer) for the same
// item, so the two implementations agree byte for byte.
func TestEvidenceCanonicalGolden(t *testing.T) {
	until := time.Date(2027, 1, 2, 3, 4, 5, 0, time.UTC)
	ev := model.Evidence{
		EvidenceID: "ignored", ControlID: "AGC-012", AgentID: "billing-agent", CommitSHA: "unknown", PolicyVersion: "1.0", ScannerVersion: "0.1.0",
		Subject:    &model.Subject{Paths: []string{"b.py", "a.py"}, Digest: "deadbeef"},
		SourceType: model.SourceTest, SourceLocation: "evidence/x.json", Collector: "ci <pipeline> & co", ObservedAt: time.Date(2026, 2, 3, 4, 5, 6, 700, time.UTC),
		ValidUntil: &until, IdentityContext: "ci-job-7", Integrity: model.IntegrityUnsigned, Result: model.ResultPass, Signal: model.SignalPresent,
		Strength: model.StrengthTested, Validity: model.ValidityValid, Summary: "Approval test passed.", Limitations: nil,
	}
	got, err := CanonicalEvidence(ev)
	if err != nil {
		t.Fatal(err)
	}
	const want = `{"agent_id":"billing-agent","collector":"ci <pipeline> & co","commit_sha":"","control_id":"AGC-012","identity_context":"ci-job-7","limitations":[],"observed_at":"2026-02-03T04:05:06.0000007Z","result":"pass","signal":"present","source_type":"test","strength":"tested","subject_digest":"deadbeef","subject_paths":["a.py","b.py"],"summary":"Approval test passed.","valid_until":"2027-01-02T03:04:05Z"}`
	if string(got) != want {
		t.Fatalf("canonical form drifted:\n got: %s\nwant: %s", got, want)
	}
}

// TestProductionArgon2Parameters hashes once with the production memory
// setting (64 MiB) to prove the default parameters work end to end.
func TestProductionArgon2Parameters(t *testing.T) {
	if testing.Short() {
		t.Skip("uses 64 MiB of memory")
	}
	cfg := Config{}.withDefaults()
	if cfg.Argon2MemoryKiB != 64*1024 || cfg.Listen != "127.0.0.1:8080" || cfg.MaxUploadBytes != 5<<20 || cfg.SessionTTL != 12*time.Hour || cfg.SessionIdleTTL != 2*time.Hour {
		t.Fatalf("defaults changed: %+v", cfg)
	}
	h, err := hashPassword(testPassword, cfg.Argon2MemoryKiB)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(h, "$argon2id$v=19$m=65536,t=2,p=2$") || !verifyPassword(testPassword, h) || verifyPassword("wrong", h) {
		t.Fatalf("production hash: %s", h)
	}
}
