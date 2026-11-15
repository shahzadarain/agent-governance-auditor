// SPDX-License-Identifier: Apache-2.0

package server

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"regexp"
	"strconv"
	"strings"
	"time"

	"golang.org/x/crypto/argon2"

	"github.com/shahzadarain/agent-governance-auditor/internal/storage"
)

const (
	sessionCookie = "agentgov_session"
	csrfHeader    = "X-CSRF-Token"
	tokenScheme   = "agt"
	// ScopeScansWrite is the only API token scope.
	ScopeScansWrite = "scans:write"

	settingBootstrapHash    = "bootstrap_token_hash"
	settingBootstrapExpires = "bootstrap_expires_at"
)

// Authorization outcomes. Their HTTP mapping is in writeAuthError.
var (
	errUnauthenticated = errors.New("unauthenticated")
	errInvalidToken    = errors.New("invalid token")
	errForbidden       = errors.New("forbidden")
	errNotFound        = errors.New("not found")
)

// permission is what a route requires of a signed-in user.
type permission int

const (
	permNone          permission = iota // not a session route
	permAuthenticated                   // any signed-in user
	permAdmin                           // global administrator
	permProjectRead                     // any project member (owner, reviewer, viewer)
	permProjectAudit                    // owner or reviewer; administrator when no project is named
	permProjectManage                   // project owner
)

// reqCtx carries the authenticated principal and the objects the scope
// function loaded while resolving the target project.
type reqCtx struct {
	user      storage.User
	session   storage.Session
	token     storage.APIToken
	projectID string
	scan      storage.Scan
	otherScan storage.Scan
	agent     storage.Agent
}

// scopeFunc resolves the project a request targets. It returns errNotFound
// when the object does not exist. The caller then authorizes against the
// returned project, so an object in a project the user cannot see produces
// the same "not found" answer as a missing object.
type scopeFunc func(a *App, r *http.Request, rc *reqCtx) (projectID string, err error)

func scopeProjectPath(_ *App, r *http.Request, _ *reqCtx) (string, error) {
	id := r.PathValue("projectId")
	if id == "" {
		return "", errNotFound
	}
	return id, nil
}

// scopeProjectQuery reads the optional ?project= parameter.
func scopeProjectQuery(_ *App, r *http.Request, _ *reqCtx) (string, error) {
	return r.URL.Query().Get("project"), nil
}

func scopeScanPath(a *App, r *http.Request, rc *reqCtx) (string, error) {
	sc, err := a.store.GetScan(r.Context(), r.PathValue("scanId"))
	if err != nil {
		return "", storeErr(err)
	}
	rc.scan = sc
	return sc.ProjectID, nil
}

func scopeComparePath(a *App, r *http.Request, rc *reqCtx) (string, error) {
	pid, err := scopeScanPath(a, r, rc)
	if err != nil {
		return "", err
	}
	other, err := a.store.GetScan(r.Context(), r.PathValue("otherScanId"))
	if err != nil {
		return "", storeErr(err)
	}
	// Both scans must belong to the same project.
	if other.ProjectID != pid {
		return "", errNotFound
	}
	rc.otherScan = other
	return pid, nil
}

func scopeAgentPath(a *App, r *http.Request, rc *reqCtx) (string, error) {
	ag, err := a.store.GetAgent(r.Context(), r.PathValue("agentId"))
	if err != nil {
		return "", storeErr(err)
	}
	if p := r.URL.Query().Get("project"); p != "" && p != ag.ProjectID {
		return "", errNotFound
	}
	rc.agent = ag
	return ag.ProjectID, nil
}

func storeErr(err error) error {
	if errors.Is(err, storage.ErrNotFound) {
		return errNotFound
	}
	return err
}

// authorize is the single authorization decision point for signed-in users.
//
//	administrator      every permission, every project
//	owner              read, audit, manage (tokens, members) in own projects
//	reviewer           read and audit in own projects
//	viewer             read in own projects
//
// A user who is not a member of the project gets errNotFound, never
// errForbidden, so project IDs cannot be probed.
func (a *App) authorize(ctx context.Context, u storage.User, perm permission, projectID string) error {
	if u.ID == "" || u.Disabled {
		return errUnauthenticated
	}
	admin := u.Role == storage.RoleAdministrator
	switch perm {
	case permAuthenticated:
		return nil
	case permAdmin:
		if admin {
			return nil
		}
		return errForbidden
	case permProjectRead, permProjectAudit, permProjectManage:
		if projectID == "" {
			// Only the audit listing may omit the project, and only for an
			// administrator (all events).
			if perm == permProjectAudit && admin {
				return nil
			}
			return errForbidden
		}
		if admin {
			if _, err := a.store.GetProject(ctx, projectID); err != nil {
				return storeErr(err)
			}
			return nil
		}
		role, err := a.store.MemberRole(ctx, projectID, u.ID)
		if err != nil {
			return storeErr(err)
		}
		switch perm {
		case permProjectRead:
			if role == storage.ProjectOwner || role == storage.ProjectReviewer || role == storage.ProjectViewer {
				return nil
			}
		case permProjectAudit:
			if role == storage.ProjectOwner || role == storage.ProjectReviewer {
				return nil
			}
		case permProjectManage:
			if role == storage.ProjectOwner {
				return nil
			}
		}
		return errForbidden
	}
	return errForbidden
}

func writeAuthError(w http.ResponseWriter, err error) {
	switch {
	case errors.Is(err, errUnauthenticated):
		writeError(w, http.StatusUnauthorized, "unauthenticated", "Sign in to continue.")
	case errors.Is(err, errInvalidToken):
		w.Header().Set("WWW-Authenticate", `Bearer realm="agentgov"`)
		writeError(w, http.StatusUnauthorized, "invalid_token", "The API token is missing, invalid, expired, or revoked.")
	case errors.Is(err, errForbidden):
		writeError(w, http.StatusForbidden, "forbidden", "You do not have permission to perform this action.")
	case errors.Is(err, errNotFound):
		writeError(w, http.StatusNotFound, "not_found", "The requested resource does not exist.")
	default:
		writeError(w, http.StatusInternalServerError, "internal_error", "Internal server error.")
	}
}

// ---------------------------------------------------------------------------
// Passwords (argon2id)
// ---------------------------------------------------------------------------

const (
	argonTime    = 2
	argonThreads = 2
	argonKeyLen  = 32
	argonSaltLen = 16
)

// hashPassword returns "$argon2id$v=19$m=<KiB>,t=<n>,p=<n>$<salt>$<hash>"
// with a fresh random salt.
func hashPassword(password string, memoryKiB uint32) (string, error) {
	salt := make([]byte, argonSaltLen)
	if _, err := rand.Read(salt); err != nil {
		return "", err
	}
	key := argon2.IDKey([]byte(password), salt, argonTime, memoryKiB, argonThreads, argonKeyLen)
	return fmt.Sprintf("$argon2id$v=%d$m=%d,t=%d,p=%d$%s$%s", argon2.Version, memoryKiB, argonTime, argonThreads,
		base64.RawStdEncoding.EncodeToString(salt), base64.RawStdEncoding.EncodeToString(key)), nil
}

// verifyPassword checks a password against an encoded hash in constant time
// with respect to the hash value.
func verifyPassword(password, encoded string) bool {
	parts := strings.Split(encoded, "$")
	if len(parts) != 6 || parts[1] != "argon2id" || parts[2] != "v="+strconv.Itoa(argon2.Version) {
		return false
	}
	var mem, t uint32
	var p uint8
	if _, err := fmt.Sscanf(parts[3], "m=%d,t=%d,p=%d", &mem, &t, &p); err != nil {
		return false
	}
	// Bound the work a stored hash can demand.
	if mem == 0 || mem > 1<<20 || t == 0 || t > 10 || p == 0 || p > 16 {
		return false
	}
	salt, err := base64.RawStdEncoding.DecodeString(parts[4])
	if err != nil {
		return false
	}
	want, err := base64.RawStdEncoding.DecodeString(parts[5])
	if err != nil || len(want) == 0 || len(want) > 128 {
		return false
	}
	got := argon2.IDKey([]byte(password), salt, t, mem, p, uint32(len(want)))
	return subtle.ConstantTimeCompare(got, want) == 1
}

// withHashSlot bounds concurrent argon2 computations (64 MiB each).
func (a *App) withHashSlot(ctx context.Context, fn func()) error {
	select {
	case a.hashSlots <- struct{}{}:
		defer func() { <-a.hashSlots }()
		fn()
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

var usernameRe = regexp.MustCompile(`^[a-z0-9][a-z0-9._@-]{2,63}$`)

func normalizeUsername(s string) string { return strings.ToLower(strings.TrimSpace(s)) }

func validateCredentials(username, password string) string {
	if !usernameRe.MatchString(username) {
		return "The username must have 3 to 64 characters: letters, digits, dot, underscore, hyphen, or @."
	}
	if len([]rune(password)) < minPasswordLength {
		return fmt.Sprintf("The password must have at least %d characters.", minPasswordLength)
	}
	if len(password) > maxPasswordBytes {
		return "The password is too long."
	}
	return ""
}

// ---------------------------------------------------------------------------
// Random tokens and hashing
// ---------------------------------------------------------------------------

// randomToken returns n random bytes as unpadded base64url.
func randomToken(n int) string {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		panic("server: crypto/rand failed: " + err.Error())
	}
	return base64.RawURLEncoding.EncodeToString(b)
}

func sha256Hex(s string) string {
	sum := sha256.Sum256([]byte(s))
	return hex.EncodeToString(sum[:])
}

func constantTimeEqual(a, b string) bool {
	return subtle.ConstantTimeCompare([]byte(a), []byte(b)) == 1
}

// ---------------------------------------------------------------------------
// Bootstrap
// ---------------------------------------------------------------------------

// ensureBootstrap generates the one-time bootstrap token when no user
// exists. Only the hash is stored. A restart without users replaces it.
func (a *App) ensureBootstrap(ctx context.Context) error {
	n, err := a.store.CountUsers(ctx)
	if err != nil {
		return err
	}
	if n > 0 {
		return nil
	}
	token := randomToken(32)
	expires := a.cfg.Now().Add(bootstrapTTL)
	err = a.store.SetSettings(ctx, map[string]string{
		settingBootstrapHash:    sha256Hex(token),
		settingBootstrapExpires: strconv.FormatInt(expires.UnixMicro(), 10),
	}, &storage.AuditEvent{At: a.cfg.Now(), ActorType: storage.ActorSystem, ActorID: "system", Action: "bootstrap.token_generated", Target: "server"})
	if err != nil {
		return err
	}
	fmt.Fprintf(a.cfg.BootstrapOut, `
======================================================================
AgentGov Auditor: first-run setup

No administrator account exists. Create one with this one-time
bootstrap token. It expires at %s (one hour) or on first use.

    Bootstrap token: %s

Open the dashboard and follow the setup screen, or send:

    POST /api/v1/setup
    {"bootstrap_token": "<token>", "username": "<name>", "password": "<12+ characters>"}

The token is shown only this once and is not stored in readable form.
Restart the server to generate a new one.
======================================================================

`, expires.UTC().Format(time.RFC3339), token)
	return nil
}

// ---------------------------------------------------------------------------
// Sessions and CSRF
// ---------------------------------------------------------------------------

func (a *App) setSessionCookie(w http.ResponseWriter, r *http.Request, value string, expires time.Time) {
	http.SetCookie(w, &http.Cookie{
		Name:     sessionCookie,
		Value:    value,
		Path:     "/",
		Expires:  expires,
		HttpOnly: true,
		Secure:   a.isHTTPS(r),
		SameSite: http.SameSiteStrictMode,
	})
}

func (a *App) clearSessionCookie(w http.ResponseWriter, r *http.Request) {
	http.SetCookie(w, &http.Cookie{
		Name: sessionCookie, Value: "", Path: "/", MaxAge: -1,
		HttpOnly: true, Secure: a.isHTTPS(r), SameSite: http.SameSiteStrictMode,
	})
}

// newSession creates a session and returns the cookie value. The store
// keeps only its SHA-256.
func (a *App) newSession(ctx context.Context, u storage.User, ev *storage.AuditEvent) (string, storage.Session, error) {
	id := randomToken(32)
	now := a.cfg.Now()
	se := storage.Session{
		IDHash:    sha256Hex(id),
		UserID:    u.ID,
		CSRFToken: randomToken(32),
		CreatedAt: now,
		ExpiresAt: now.Add(a.cfg.SessionTTL),
		LastSeen:  now,
	}
	return id, se, a.store.CreateSession(ctx, se, ev)
}

// authenticateSession resolves the session cookie. It enforces the absolute
// and idle lifetimes at request time.
func (a *App) authenticateSession(w http.ResponseWriter, r *http.Request, rc *reqCtx) error {
	c, err := r.Cookie(sessionCookie)
	if err != nil || c.Value == "" || len(c.Value) > 128 {
		return errUnauthenticated
	}
	ctx := r.Context()
	se, err := a.store.GetSession(ctx, sha256Hex(c.Value))
	if err != nil {
		if errors.Is(err, storage.ErrNotFound) {
			a.clearSessionCookie(w, r)
			return errUnauthenticated
		}
		return err
	}
	now := a.cfg.Now()
	if !now.Before(se.ExpiresAt) || now.Sub(se.LastSeen) >= a.cfg.SessionIdleTTL {
		_ = a.store.DeleteSession(ctx, se.IDHash, nil)
		a.clearSessionCookie(w, r)
		return errUnauthenticated
	}
	u, err := a.store.GetUserByID(ctx, se.UserID)
	if err != nil || u.Disabled {
		if err == nil || errors.Is(err, storage.ErrNotFound) {
			_ = a.store.DeleteSession(ctx, se.IDHash, nil)
			a.clearSessionCookie(w, r)
			return errUnauthenticated
		}
		return err
	}
	if now.Sub(se.LastSeen) > time.Minute {
		if err := a.store.TouchSession(ctx, se.IDHash, now); err == nil {
			se.LastSeen = now
		}
	}
	rc.user, rc.session = u, se
	return nil
}

func csrfTokenMatches(r *http.Request, want string) bool {
	got := r.Header.Get(csrfHeader)
	return got != "" && want != "" && constantTimeEqual(got, want)
}

// sameOrigin is the second CSRF layer. Browsers send Sec-Fetch-Site on
// every request and Origin on every cross-origin or mutating request:
//   - Sec-Fetch-Site present: only "same-origin" passes.
//   - Otherwise Origin present: its host must equal the request Host.
//   - Neither present: the client is not a browser (curl, scripts). Such a
//     client cannot be driven by a hostile page, and it still needs the
//     session cookie and the CSRF token.
func sameOrigin(r *http.Request) bool {
	if sfs := r.Header.Get("Sec-Fetch-Site"); sfs != "" {
		return sfs == "same-origin"
	}
	origin := r.Header.Get("Origin")
	if origin == "" {
		return true
	}
	u, err := url.Parse(origin)
	if err != nil || u.Host == "" {
		return false
	}
	return strings.EqualFold(u.Host, r.Host)
}

// ---------------------------------------------------------------------------
// API tokens
// ---------------------------------------------------------------------------

// newAPIToken returns a token "agt_<prefix>_<secret>": prefix is 8 hex
// characters for display, secret is 32 random bytes as base64url.
func newAPIToken() (token, prefix string) {
	prefix = randomHex(4)
	return tokenScheme + "_" + prefix + "_" + randomToken(32), prefix
}

func bearerToken(r *http.Request) (string, bool) {
	h := r.Header.Get("Authorization")
	if len(h) < 8 || !strings.EqualFold(h[:7], "Bearer ") {
		return "", false
	}
	t := strings.TrimSpace(h[7:])
	return t, t != ""
}

// authenticateToken resolves a Bearer token. Unknown, malformed, expired,
// and revoked tokens take the same path (hash, one lookup by hash, the same
// checks) and get the same answer.
func (a *App) authenticateToken(r *http.Request, rc *reqCtx) error {
	raw, ok := bearerToken(r)
	if !ok || len(raw) > 256 {
		return errInvalidToken
	}
	hash := sha256Hex(raw)
	t, err := a.store.GetTokenByHash(r.Context(), hash)
	if err != nil && !errors.Is(err, storage.ErrNotFound) {
		return err
	}
	now := a.cfg.Now()
	valid := err == nil
	valid = constantTimeEqual(t.TokenHash, hash) && valid
	valid = t.RevokedAt == nil && valid
	valid = (t.ExpiresAt == nil || now.Before(*t.ExpiresAt)) && valid
	valid = hasScope(t.Scopes, ScopeScansWrite) && valid
	if !valid {
		return errInvalidToken
	}
	rc.token = t
	return nil
}

func hasScope(scopes []string, want string) bool {
	for _, s := range scopes {
		if s == want {
			return true
		}
	}
	return false
}
