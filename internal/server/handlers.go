// SPDX-License-Identifier: Apache-2.0

package server

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"regexp"
	"strconv"
	"strings"
	"time"
	"unicode"

	"github.com/shahzadarain/agent-governance-auditor/internal/model"
	"github.com/shahzadarain/agent-governance-auditor/internal/storage"
)

// ---------------------------------------------------------------------------
// Response and request helpers
// ---------------------------------------------------------------------------

type errorBody struct {
	Error errorDetail `json:"error"`
}

type errorDetail struct {
	Code    string `json:"code"`
	Message string `json:"message"`
}

type listBody[T any] struct {
	Items []T `json:"items"`
}

type statusBody struct {
	Status string `json:"status"`
}

// writeJSON writes a JSON response. Stored strings are returned as JSON data
// only; encoding/json also escapes <, >, and & inside strings.
func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

func writeError(w http.ResponseWriter, status int, code, message string) {
	writeJSON(w, status, errorBody{Error: errorDetail{Code: code, Message: message}})
}

func (a *App) internalError(w http.ResponseWriter, r *http.Request, what string, err error) {
	a.log.Error("internal error", "request_id", stateFrom(r).id, "operation", what, "error", err.Error())
	writeError(w, http.StatusInternalServerError, "internal_error", "Internal server error.")
}

// readJSON strictly decodes a small JSON request body. It writes the error
// response itself and returns false on failure.
func readJSON(w http.ResponseWriter, r *http.Request, dst any, limit int64) bool {
	if !isJSONContentType(r) {
		writeError(w, http.StatusUnsupportedMediaType, "unsupported_media_type", "Content-Type must be application/json.")
		return false
	}
	body, err := io.ReadAll(http.MaxBytesReader(w, r.Body, limit))
	if err != nil {
		var tooBig *http.MaxBytesError
		if errors.As(err, &tooBig) {
			writeError(w, http.StatusRequestEntityTooLarge, "payload_too_large", fmt.Sprintf("The request limit is %d bytes.", limit))
			return false
		}
		writeError(w, http.StatusBadRequest, "bad_request", "The request body could not be read.")
		return false
	}
	if err := decodeStrictJSON(body, dst); err != nil {
		writeError(w, http.StatusBadRequest, "invalid_request", safeDecodeMessage(err))
		return false
	}
	return true
}

func queryInt(r *http.Request, name string, def, min, max int) int {
	v, err := strconv.Atoi(r.URL.Query().Get(name))
	if err != nil {
		return def
	}
	if v < min {
		return min
	}
	if v > max {
		return max
	}
	return v
}

func (a *App) userEvent(rc *reqCtx, action, target, projectID string, detail map[string]any) *storage.AuditEvent {
	d := "{}"
	if len(detail) > 0 {
		if b, err := json.Marshal(detail); err == nil {
			d = string(b)
		}
	}
	return &storage.AuditEvent{At: a.cfg.Now(), ActorType: storage.ActorUser, ActorID: rc.user.ID, Action: action,
		Target: target, ProjectID: projectID, Detail: d}
}

func retryAfter(w http.ResponseWriter, wait time.Duration) {
	w.Header().Set("Retry-After", strconv.Itoa(int(wait.Seconds())+1))
}

// ---------------------------------------------------------------------------
// Health, version, metrics
// ---------------------------------------------------------------------------

func (a *App) handleHealthz(w http.ResponseWriter, _ *http.Request, _ *reqCtx) {
	writeJSON(w, http.StatusOK, statusBody{Status: "ok"})
}

func (a *App) ready(r *http.Request) bool {
	if err := a.store.Ping(r.Context()); err != nil {
		return false
	}
	applied, known, err := a.store.MigrationStatus(r.Context())
	return err == nil && applied == known
}

func (a *App) handleReadyz(w http.ResponseWriter, r *http.Request, _ *reqCtx) {
	if !a.ready(r) {
		writeError(w, http.StatusServiceUnavailable, "not_ready", "The server is not ready.")
		return
	}
	writeJSON(w, http.StatusOK, statusBody{Status: "ready"})
}

type versionResponse struct {
	Name          string        `json:"name"`
	Version       string        `json:"version"`
	APIVersion    string        `json:"api_version"`
	SchemaVersion string        `json:"schema_version"`
	SetupRequired bool          `json:"setup_required"`
	Token         *tokenContext `json:"token,omitempty"`
}

type tokenContext struct {
	TokenID   string   `json:"token_id"`
	ProjectID string   `json:"project_id"`
	Scopes    []string `json:"scopes"`
}

// handleVersion is public. A request that carries a Bearer token gets the
// token's project back, or 401 when the token is not valid; the CLI uses
// this to verify a connection.
func (a *App) handleVersion(w http.ResponseWriter, r *http.Request, rc *reqCtx) {
	resp := versionResponse{Name: "agentgov", Version: a.cfg.Version, APIVersion: "v1", SchemaVersion: model.SchemaVersion}
	if r.Header.Get("Authorization") != "" {
		if err := a.authenticateToken(r, rc); err != nil {
			a.metrics.authFailure("token")
			writeAuthError(w, err)
			return
		}
		stateFrom(r).actor = "token:" + rc.token.ID
		resp.Token = &tokenContext{TokenID: rc.token.ID, ProjectID: rc.token.ProjectID, Scopes: rc.token.Scopes}
	}
	n, err := a.store.CountUsers(r.Context())
	if err != nil {
		a.internalError(w, r, "count users", err)
		return
	}
	resp.SetupRequired = n == 0
	writeJSON(w, http.StatusOK, resp)
}

func (a *App) handleMetrics(w http.ResponseWriter, _ *http.Request, _ *reqCtx) {
	w.Header().Set("Content-Type", "text/plain; version=0.0.4; charset=utf-8")
	a.metrics.write(w)
}

// ---------------------------------------------------------------------------
// Setup, login, session
// ---------------------------------------------------------------------------

type setupRequest struct {
	BootstrapToken string `json:"bootstrap_token"`
	Username       string `json:"username"`
	Password       string `json:"password"`
}

type userResponse struct {
	User storage.User `json:"user"`
}

func (a *App) handleSetup(w http.ResponseWriter, r *http.Request, _ *reqCtx) {
	if ok, wait := a.loginIP.allow("setup|" + a.clientIP(r)); !ok {
		retryAfter(w, wait)
		writeError(w, http.StatusTooManyRequests, "rate_limited", "Too many attempts. Retry later.")
		return
	}
	var req setupRequest
	if !readJSON(w, r, &req, smallBodyLimit) {
		return
	}
	ctx := r.Context()
	hash, ok, err := a.store.GetSetting(ctx, settingBootstrapHash)
	if err != nil {
		a.internalError(w, r, "read bootstrap state", err)
		return
	}
	if !ok {
		writeError(w, http.StatusConflict, "setup_complete", "Setup is already complete.")
		return
	}
	expRaw, _, err := a.store.GetSetting(ctx, settingBootstrapExpires)
	if err != nil {
		a.internalError(w, r, "read bootstrap state", err)
		return
	}
	expUS, _ := strconv.ParseInt(expRaw, 10, 64)
	now := a.cfg.Now()
	if !now.Before(time.UnixMicro(expUS)) {
		writeError(w, http.StatusForbidden, "bootstrap_expired", "The bootstrap token has expired. Restart the server to generate a new one.")
		return
	}
	if len(req.BootstrapToken) > 256 || !constantTimeEqual(sha256Hex(req.BootstrapToken), hash) {
		a.metrics.authFailure("bootstrap")
		writeError(w, http.StatusForbidden, "invalid_bootstrap_token", "The bootstrap token is not valid.")
		return
	}
	username := normalizeUsername(req.Username)
	if msg := validateCredentials(username, req.Password); msg != "" {
		writeError(w, http.StatusBadRequest, "invalid_request", msg)
		return
	}
	var pwHash string
	var herr error
	if err := a.withHashSlot(ctx, func() { pwHash, herr = hashPassword(req.Password, a.cfg.Argon2MemoryKiB) }); err != nil || herr != nil {
		a.internalError(w, r, "hash password", errors.Join(err, herr))
		return
	}
	u := storage.User{ID: "usr_" + randomHex(12), Username: username, PasswordHash: pwHash, Role: storage.RoleAdministrator, CreatedAt: now}
	ev := &storage.AuditEvent{At: now, ActorType: storage.ActorUser, ActorID: u.ID, Action: "setup.completed", Target: "user:" + u.ID, Detail: "{}"}
	err = a.store.CreateFirstUser(ctx, u, settingBootstrapHash, hash, []string{settingBootstrapHash, settingBootstrapExpires}, ev)
	if errors.Is(err, storage.ErrConflict) {
		writeError(w, http.StatusConflict, "setup_complete", "Setup is already complete.")
		return
	}
	if err != nil {
		a.internalError(w, r, "create first user", err)
		return
	}
	writeJSON(w, http.StatusCreated, userResponse{User: u})
}

type loginRequest struct {
	Username string `json:"username"`
	Password string `json:"password"`
}

type sessionResponse struct {
	User          storage.User `json:"user"`
	CSRFToken     string       `json:"csrf_token"`
	ExpiresAt     time.Time    `json:"expires_at"`
	IdleExpiresAt time.Time    `json:"idle_expires_at"`
}

func (a *App) sessionBody(u storage.User, se storage.Session) sessionResponse {
	idle := se.LastSeen.Add(a.cfg.SessionIdleTTL)
	if idle.After(se.ExpiresAt) {
		idle = se.ExpiresAt
	}
	return sessionResponse{User: u, CSRFToken: se.CSRFToken, ExpiresAt: se.ExpiresAt, IdleExpiresAt: idle}
}

// handleLogin answers every failure with the same generic message. Limits:
// a token bucket per client IP, and an exponential lockout per username and
// client IP after repeated failures.
func (a *App) handleLogin(w http.ResponseWriter, r *http.Request, _ *reqCtx) {
	ip := a.clientIP(r)
	if ok, wait := a.loginIP.allow("login|" + ip); !ok {
		retryAfter(w, wait)
		writeError(w, http.StatusTooManyRequests, "rate_limited", "Too many sign-in attempts. Retry later.")
		return
	}
	var req loginRequest
	if !readJSON(w, r, &req, smallBodyLimit) {
		return
	}
	ctx := r.Context()
	username := normalizeUsername(req.Username)
	if len(username) > 64 {
		username = username[:64]
	}
	key := username + "|" + ip
	if locked, wait := a.loginLock.locked(key); locked {
		a.metrics.authFailure("login")
		retryAfter(w, wait)
		writeError(w, http.StatusTooManyRequests, "rate_limited", "Too many failed sign-in attempts. Retry later.")
		return
	}
	u, err := a.store.GetUserByUsername(ctx, username)
	found := err == nil
	if err != nil && !errors.Is(err, storage.ErrNotFound) {
		a.internalError(w, r, "load user", err)
		return
	}
	hash := a.dummyHash
	if found {
		hash = u.PasswordHash
	}
	password := req.Password
	tooLong := len(password) > maxPasswordBytes
	if tooLong {
		password = ""
	}
	okPw := false
	if err := a.withHashSlot(ctx, func() { okPw = verifyPassword(password, hash) }); err != nil {
		a.internalError(w, r, "verify password", err)
		return
	}
	now := a.cfg.Now()
	if !found || !okPw || tooLong || u.Disabled {
		a.loginLock.fail(key)
		a.metrics.authFailure("login")
		target := "user:unknown"
		if found {
			target = "user:" + u.ID
		}
		detail, _ := json.Marshal(map[string]string{"client_ip": ip})
		_ = a.store.AppendAudit(ctx, storage.AuditEvent{At: now, ActorType: storage.ActorSystem, ActorID: "system",
			Action: "login.failed", Target: target, Detail: string(detail)})
		writeError(w, http.StatusUnauthorized, "invalid_credentials", "Invalid username or password.")
		return
	}
	a.loginLock.success(key)
	detail, _ := json.Marshal(map[string]string{"client_ip": ip})
	id, se, err := a.newSession(ctx, u, &storage.AuditEvent{At: now, ActorType: storage.ActorUser, ActorID: u.ID,
		Action: "login.succeeded", Target: "user:" + u.ID, Detail: string(detail)})
	if err != nil {
		a.internalError(w, r, "create session", err)
		return
	}
	stateFrom(r).actor = "user:" + u.ID
	a.setSessionCookie(w, r, id, se.ExpiresAt)
	writeJSON(w, http.StatusOK, a.sessionBody(u, se))
}

func (a *App) handleLogout(w http.ResponseWriter, r *http.Request, rc *reqCtx) {
	if err := a.store.DeleteSession(r.Context(), rc.session.IDHash, a.userEvent(rc, "logout", "user:"+rc.user.ID, "", nil)); err != nil {
		a.internalError(w, r, "delete session", err)
		return
	}
	a.clearSessionCookie(w, r)
	writeJSON(w, http.StatusOK, statusBody{Status: "logged_out"})
}

func (a *App) handleSession(w http.ResponseWriter, _ *http.Request, rc *reqCtx) {
	writeJSON(w, http.StatusOK, a.sessionBody(rc.user, rc.session))
}

// ---------------------------------------------------------------------------
// Users
// ---------------------------------------------------------------------------

func (a *App) handleListUsers(w http.ResponseWriter, r *http.Request, _ *reqCtx) {
	users, err := a.store.ListUsers(r.Context())
	if err != nil {
		a.internalError(w, r, "list users", err)
		return
	}
	writeJSON(w, http.StatusOK, listBody[storage.User]{Items: users})
}

type createUserRequest struct {
	Username string `json:"username"`
	Password string `json:"password"`
	Role     string `json:"role"`
}

func (a *App) handleCreateUser(w http.ResponseWriter, r *http.Request, rc *reqCtx) {
	var req createUserRequest
	if !readJSON(w, r, &req, smallBodyLimit) {
		return
	}
	username := normalizeUsername(req.Username)
	if msg := validateCredentials(username, req.Password); msg != "" {
		writeError(w, http.StatusBadRequest, "invalid_request", msg)
		return
	}
	if req.Role == "" {
		req.Role = storage.RoleUser
	}
	if req.Role != storage.RoleUser && req.Role != storage.RoleAdministrator {
		writeError(w, http.StatusBadRequest, "invalid_request", `The role must be "user" or "administrator".`)
		return
	}
	var pwHash string
	var herr error
	if err := a.withHashSlot(r.Context(), func() { pwHash, herr = hashPassword(req.Password, a.cfg.Argon2MemoryKiB) }); err != nil || herr != nil {
		a.internalError(w, r, "hash password", errors.Join(err, herr))
		return
	}
	u := storage.User{ID: "usr_" + randomHex(12), Username: username, PasswordHash: pwHash, Role: req.Role, CreatedAt: a.cfg.Now()}
	err := a.store.CreateUser(r.Context(), u, a.userEvent(rc, "user.created", "user:"+u.ID, "", map[string]any{"role": u.Role}))
	if errors.Is(err, storage.ErrConflict) {
		writeError(w, http.StatusConflict, "conflict", "The username is already taken.")
		return
	}
	if err != nil {
		a.internalError(w, r, "create user", err)
		return
	}
	writeJSON(w, http.StatusCreated, userResponse{User: u})
}

// ---------------------------------------------------------------------------
// Projects, members, tokens
// ---------------------------------------------------------------------------

var slugRe = regexp.MustCompile(`^[a-z0-9](?:[a-z0-9-]{0,62}[a-z0-9])?$`)

// cleanName trims a display name and rejects control characters. Any other
// character is allowed: names are data, bound as SQL parameters and returned
// as JSON.
func cleanName(s string, max int) (string, bool) {
	s = strings.TrimSpace(s)
	if s == "" || len([]rune(s)) > max {
		return "", false
	}
	for _, r := range s {
		if unicode.IsControl(r) {
			return "", false
		}
	}
	return s, true
}

func (a *App) visibleProjects(r *http.Request, rc *reqCtx) ([]storage.Project, error) {
	if rc.user.Role == storage.RoleAdministrator {
		ps, err := a.store.ListProjects(r.Context())
		for i := range ps {
			ps[i].Role = storage.RoleAdministrator
		}
		return ps, err
	}
	return a.store.ListProjectsForUser(r.Context(), rc.user.ID)
}

func (a *App) handleListProjects(w http.ResponseWriter, r *http.Request, rc *reqCtx) {
	ps, err := a.visibleProjects(r, rc)
	if err != nil {
		a.internalError(w, r, "list projects", err)
		return
	}
	writeJSON(w, http.StatusOK, listBody[storage.Project]{Items: ps})
}

type createProjectRequest struct {
	Slug string `json:"slug"`
	Name string `json:"name"`
}

func (a *App) handleCreateProject(w http.ResponseWriter, r *http.Request, rc *reqCtx) {
	var req createProjectRequest
	if !readJSON(w, r, &req, smallBodyLimit) {
		return
	}
	if !slugRe.MatchString(req.Slug) {
		writeError(w, http.StatusBadRequest, "invalid_request", "The slug must have 1 to 64 lower-case letters, digits, or hyphens, and must not start or end with a hyphen.")
		return
	}
	name, ok := cleanName(req.Name, 200)
	if !ok {
		writeError(w, http.StatusBadRequest, "invalid_request", "The name must have 1 to 200 characters and no control characters.")
		return
	}
	p := storage.Project{ID: "prj_" + randomHex(12), Slug: req.Slug, Name: name, CreatedBy: rc.user.ID, CreatedAt: a.cfg.Now()}
	err := a.store.CreateProject(r.Context(), p, a.userEvent(rc, "project.created", "project:"+p.ID, p.ID, map[string]any{"slug": p.Slug}))
	if errors.Is(err, storage.ErrConflict) {
		writeError(w, http.StatusConflict, "conflict", "A project with this slug already exists.")
		return
	}
	if err != nil {
		a.internalError(w, r, "create project", err)
		return
	}
	p.Role = storage.RoleAdministrator
	writeJSON(w, http.StatusCreated, p)
}

type projectDetail struct {
	Project     storage.Project  `json:"project"`
	Overview    storage.Overview `json:"overview"`
	RecentScans []storage.Scan   `json:"recent_scans"`
}

func (a *App) handleGetProject(w http.ResponseWriter, r *http.Request, rc *reqCtx) {
	ctx := r.Context()
	p, err := a.store.GetProject(ctx, rc.projectID)
	if err != nil {
		writeAuthErrorOr500(a, w, r, err)
		return
	}
	if rc.user.Role == storage.RoleAdministrator {
		p.Role = storage.RoleAdministrator
	} else if role, err := a.store.MemberRole(ctx, p.ID, rc.user.ID); err == nil {
		p.Role = role
	}
	ov, err := a.store.ProjectOverview(ctx, p.ID)
	if err != nil {
		a.internalError(w, r, "project overview", err)
		return
	}
	scans, err := a.store.ListScans(ctx, p.ID, 20)
	if err != nil {
		a.internalError(w, r, "list scans", err)
		return
	}
	writeJSON(w, http.StatusOK, projectDetail{Project: p, Overview: ov, RecentScans: scans})
}

// writeAuthErrorOr500 maps a store error: not found gives 404, anything else
// is logged and gives 500.
func writeAuthErrorOr500(a *App, w http.ResponseWriter, r *http.Request, err error) {
	if errors.Is(err, storage.ErrNotFound) {
		writeAuthError(w, errNotFound)
		return
	}
	a.internalError(w, r, "store", err)
}

func (a *App) handleListAgents(w http.ResponseWriter, r *http.Request, rc *reqCtx) {
	agents, err := a.store.ListAgents(r.Context(), rc.projectID)
	if err != nil {
		a.internalError(w, r, "list agents", err)
		return
	}
	writeJSON(w, http.StatusOK, listBody[storage.Agent]{Items: agents})
}

func (a *App) handleListTokens(w http.ResponseWriter, r *http.Request, rc *reqCtx) {
	tokens, err := a.store.ListTokens(r.Context(), rc.projectID)
	if err != nil {
		a.internalError(w, r, "list tokens", err)
		return
	}
	writeJSON(w, http.StatusOK, listBody[storage.APIToken]{Items: tokens})
}

type createTokenRequest struct {
	Name          string `json:"name"`
	ExpiresInDays int    `json:"expires_in_days"`
}

type createTokenResponse struct {
	// Token is the secret. It is returned only in this response.
	Token  string           `json:"token"`
	Record storage.APIToken `json:"record"`
}

func (a *App) handleCreateToken(w http.ResponseWriter, r *http.Request, rc *reqCtx) {
	var req createTokenRequest
	if !readJSON(w, r, &req, smallBodyLimit) {
		return
	}
	name, ok := cleanName(req.Name, 100)
	if !ok {
		writeError(w, http.StatusBadRequest, "invalid_request", "The token name must have 1 to 100 characters and no control characters.")
		return
	}
	if req.ExpiresInDays < 0 || req.ExpiresInDays > 366 {
		writeError(w, http.StatusBadRequest, "invalid_request", "expires_in_days must be between 1 and 366, or 0 for no expiry.")
		return
	}
	now := a.cfg.Now()
	token, prefix := newAPIToken()
	rec := storage.APIToken{ID: "tok_" + randomHex(12), ProjectID: rc.projectID, Name: name, TokenHash: sha256Hex(token), Prefix: prefix,
		Scopes: []string{ScopeScansWrite}, CreatedBy: rc.user.ID, CreatedAt: now}
	if req.ExpiresInDays > 0 {
		exp := now.Add(time.Duration(req.ExpiresInDays) * 24 * time.Hour)
		rec.ExpiresAt = &exp
	}
	err := a.store.CreateToken(r.Context(), rec, a.userEvent(rc, "token.created", "token:"+rec.ID, rc.projectID,
		map[string]any{"name": name, "prefix": prefix, "expires_in_days": req.ExpiresInDays}))
	if err != nil {
		a.internalError(w, r, "create token", err)
		return
	}
	writeJSON(w, http.StatusCreated, createTokenResponse{Token: token, Record: rec})
}

func (a *App) handleRevokeToken(w http.ResponseWriter, r *http.Request, rc *reqCtx) {
	tokenID := r.PathValue("tokenId")
	err := a.store.RevokeToken(r.Context(), rc.projectID, tokenID, a.cfg.Now(), a.userEvent(rc, "token.revoked", "token:"+tokenID, rc.projectID, nil))
	if err != nil {
		writeAuthErrorOr500(a, w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, statusBody{Status: "revoked"})
}

func (a *App) handleListMembers(w http.ResponseWriter, r *http.Request, rc *reqCtx) {
	members, err := a.store.ListMembers(r.Context(), rc.projectID)
	if err != nil {
		a.internalError(w, r, "list members", err)
		return
	}
	writeJSON(w, http.StatusOK, listBody[storage.Member]{Items: members})
}

type setMemberRequest struct {
	UserID   string `json:"user_id"`
	Username string `json:"username"`
	Role     string `json:"role"`
}

func (a *App) handleSetMember(w http.ResponseWriter, r *http.Request, rc *reqCtx) {
	var req setMemberRequest
	if !readJSON(w, r, &req, smallBodyLimit) {
		return
	}
	if req.Role != storage.ProjectOwner && req.Role != storage.ProjectReviewer && req.Role != storage.ProjectViewer {
		writeError(w, http.StatusBadRequest, "invalid_request", `The role must be "owner", "reviewer", or "viewer".`)
		return
	}
	var u storage.User
	var err error
	switch {
	case req.UserID != "":
		u, err = a.store.GetUserByID(r.Context(), req.UserID)
	case req.Username != "":
		u, err = a.store.GetUserByUsername(r.Context(), normalizeUsername(req.Username))
	default:
		writeError(w, http.StatusBadRequest, "invalid_request", "Provide user_id or username.")
		return
	}
	if errors.Is(err, storage.ErrNotFound) {
		writeError(w, http.StatusNotFound, "user_not_found", "The user does not exist.")
		return
	}
	if err != nil {
		a.internalError(w, r, "load user", err)
		return
	}
	m := storage.Member{ProjectID: rc.projectID, UserID: u.ID, Username: u.Username, Role: req.Role}
	if err := a.store.SetMember(r.Context(), m, a.userEvent(rc, "member.set", "user:"+u.ID, rc.projectID, map[string]any{"role": req.Role})); err != nil {
		a.internalError(w, r, "set member", err)
		return
	}
	writeJSON(w, http.StatusOK, m)
}

func (a *App) handleRemoveMember(w http.ResponseWriter, r *http.Request, rc *reqCtx) {
	userID := r.URL.Query().Get("user_id")
	if userID == "" {
		writeError(w, http.StatusBadRequest, "invalid_request", "The user_id query parameter is required.")
		return
	}
	err := a.store.RemoveMember(r.Context(), rc.projectID, userID, a.userEvent(rc, "member.removed", "user:"+userID, rc.projectID, nil))
	if err != nil {
		writeAuthErrorOr500(a, w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, statusBody{Status: "removed"})
}

// ---------------------------------------------------------------------------
// Agents and scans
// ---------------------------------------------------------------------------

func (a *App) loadResult(r *http.Request, scanRowID string) (*model.ScanResult, error) {
	payload, err := a.store.GetScanPayload(r.Context(), scanRowID)
	if err != nil {
		return nil, err
	}
	var res model.ScanResult
	if err := json.Unmarshal(payload, &res); err != nil {
		return nil, fmt.Errorf("stored scan %s is not readable: %w", scanRowID, err)
	}
	return &res, nil
}

type agentDetail struct {
	Agent      storage.Agent          `json:"agent"`
	Scan       *storage.Scan          `json:"scan"`       // latest scan that included the agent
	Detail     *model.Agent           `json:"detail"`     // agent as reported by that scan
	Assessment *model.AgentAssessment `json:"assessment"` // null when the scan carried none
}

func (a *App) handleGetAgent(w http.ResponseWriter, r *http.Request, rc *reqCtx) {
	out := agentDetail{Agent: rc.agent}
	sc, err := a.store.GetScan(r.Context(), rc.agent.LastScanID)
	if err == nil && sc.ProjectID == rc.agent.ProjectID {
		res, err := a.loadResult(r, sc.ID)
		if err != nil {
			a.internalError(w, r, "load scan", err)
			return
		}
		out.Scan = &sc
		for i := range res.Agents {
			if res.Agents[i].ID == rc.agent.AgentID {
				out.Detail = &res.Agents[i]
			}
		}
		for i := range res.Assessments {
			if res.Assessments[i].AgentID == rc.agent.AgentID {
				out.Assessment = &res.Assessments[i]
			}
		}
	} else if err != nil && !errors.Is(err, storage.ErrNotFound) {
		a.internalError(w, r, "load scan", err)
		return
	}
	writeJSON(w, http.StatusOK, out)
}

func (a *App) handleAgentScans(w http.ResponseWriter, r *http.Request, rc *reqCtx) {
	hist, err := a.store.ListAgentScans(r.Context(), rc.agent.ProjectID, rc.agent.AgentID, queryInt(r, "limit", 100, 1, 500))
	if err != nil {
		a.internalError(w, r, "agent history", err)
		return
	}
	writeJSON(w, http.StatusOK, listBody[storage.AgentScan]{Items: hist})
}

type scanDetail struct {
	Scan   storage.Scan    `json:"scan"`
	Result json.RawMessage `json:"result"`
}

func (a *App) handleGetScan(w http.ResponseWriter, r *http.Request, rc *reqCtx) {
	payload, err := a.store.GetScanPayload(r.Context(), rc.scan.ID)
	if err != nil {
		writeAuthErrorOr500(a, w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, scanDetail{Scan: rc.scan, Result: payload})
}

type pageBody[T any] struct {
	Items  []T `json:"items"`
	Total  int `json:"total"`
	Limit  int `json:"limit"`
	Offset int `json:"offset"`
}

func page[T any](r *http.Request, all []T) pageBody[T] {
	limit := queryInt(r, "limit", 200, 1, 1000)
	offset := queryInt(r, "offset", 0, 0, 1<<30)
	out := pageBody[T]{Items: []T{}, Total: len(all), Limit: limit, Offset: offset}
	if offset < len(all) {
		end := offset + limit
		if end > len(all) {
			end = len(all)
		}
		out.Items = all[offset:end]
	}
	return out
}

// handleScanFindings returns the findings of a scan. Filters: severity,
// control_id, agent_id. The agent_id filter also returns repository-level
// findings (agent_id "*"), because they apply to every agent.
func (a *App) handleScanFindings(w http.ResponseWriter, r *http.Request, rc *reqCtx) {
	res, err := a.loadResult(r, rc.scan.ID)
	if err != nil {
		writeAuthErrorOr500(a, w, r, err)
		return
	}
	q := r.URL.Query()
	sev, ctl, agent := q.Get("severity"), q.Get("control_id"), q.Get("agent_id")
	out := []model.Finding{}
	for _, f := range res.Findings {
		if sev != "" && string(f.Severity) != sev {
			continue
		}
		if ctl != "" && f.ControlID != ctl {
			continue
		}
		if agent != "" && f.AgentID != agent && f.AgentID != model.AllAgents {
			continue
		}
		out = append(out, f)
	}
	writeJSON(w, http.StatusOK, page(r, out))
}

// handleScanControls returns the control results of a scan, one per agent
// and control. Filters: agent_id, status, control_id.
func (a *App) handleScanControls(w http.ResponseWriter, r *http.Request, rc *reqCtx) {
	res, err := a.loadResult(r, rc.scan.ID)
	if err != nil {
		writeAuthErrorOr500(a, w, r, err)
		return
	}
	q := r.URL.Query()
	agent, status, ctl := q.Get("agent_id"), q.Get("status"), q.Get("control_id")
	out := []model.ControlResult{}
	for _, as := range res.Assessments {
		if agent != "" && as.AgentID != agent {
			continue
		}
		for _, c := range as.Controls {
			if status != "" && string(c.Status) != status {
				continue
			}
			if ctl != "" && c.ControlID != ctl {
				continue
			}
			c.AgentID = as.AgentID
			out = append(out, c)
		}
	}
	writeJSON(w, http.StatusOK, page(r, out))
}

type compareResponse struct {
	Before     storage.Scan     `json:"before"`
	After      storage.Scan     `json:"after"`
	Comparison model.Comparison `json:"comparison"`
}

// handleCompare compares {scanId} (after) with {otherScanId} (before). Both
// scans must be in the same project; the scope function enforces that.
func (a *App) handleCompare(w http.ResponseWriter, r *http.Request, rc *reqCtx) {
	after, err := a.loadResult(r, rc.scan.ID)
	if err != nil {
		writeAuthErrorOr500(a, w, r, err)
		return
	}
	before, err := a.loadResult(r, rc.otherScan.ID)
	if err != nil {
		writeAuthErrorOr500(a, w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, compareResponse{Before: rc.otherScan, After: rc.scan, Comparison: compareScans(before, after)})
}

// ---------------------------------------------------------------------------
// Catalog, policies, audit, overview
// ---------------------------------------------------------------------------

func (a *App) handleControls(w http.ResponseWriter, _ *http.Request, _ *reqCtx) {
	if a.cfg.Catalog == nil {
		writeError(w, http.StatusServiceUnavailable, "catalog_not_loaded", "catalog not loaded")
		return
	}
	writeJSON(w, http.StatusOK, a.cfg.Catalog)
}

type policiesResponse struct {
	Profiles []model.Profile `json:"profiles"`
}

func (a *App) handlePolicies(w http.ResponseWriter, _ *http.Request, _ *reqCtx) {
	if len(a.cfg.Profiles) == 0 {
		writeError(w, http.StatusServiceUnavailable, "profiles_not_loaded", "profiles not loaded")
		return
	}
	writeJSON(w, http.StatusOK, policiesResponse{Profiles: a.cfg.Profiles})
}

type auditEventView struct {
	storage.AuditEvent
	Detail json.RawMessage `json:"detail"`
}

// handleAuditEvents lists audit events, newest first. An administrator may
// omit ?project= to see every event. Owners and reviewers must name a
// project they belong to. Page with ?before=<id of the last item>.
func (a *App) handleAuditEvents(w http.ResponseWriter, r *http.Request, rc *reqCtx) {
	limit := queryInt(r, "limit", 100, 1, 1000)
	before, _ := strconv.ParseInt(r.URL.Query().Get("before"), 10, 64)
	evs, err := a.store.ListAudit(r.Context(), storage.AuditFilter{ProjectID: rc.projectID, BeforeSeq: before, Limit: limit})
	if err != nil {
		a.internalError(w, r, "list audit events", err)
		return
	}
	out := make([]auditEventView, 0, len(evs))
	for _, e := range evs {
		d := json.RawMessage(e.Detail)
		if !json.Valid(d) {
			d = json.RawMessage(`{}`)
		}
		out = append(out, auditEventView{AuditEvent: e, Detail: d})
	}
	writeJSON(w, http.StatusOK, listBody[auditEventView]{Items: out})
}

type overviewProject struct {
	Project  storage.Project  `json:"project"`
	Overview storage.Overview `json:"overview"`
}

type overviewTotals struct {
	Projects     int            `json:"projects"`
	Agents       int            `json:"agents"`
	Scans        int            `json:"scans"`
	OpenCritical int            `json:"open_critical"`
	OpenHigh     int            `json:"open_high"`
	Decisions    map[string]int `json:"decisions"`
	LatestScanAt *time.Time     `json:"latest_scan_at"`
}

type overviewResponse struct {
	Projects []overviewProject `json:"projects"`
	Totals   overviewTotals    `json:"totals"`
}

func (a *App) handleOverview(w http.ResponseWriter, r *http.Request, rc *reqCtx) {
	ps, err := a.visibleProjects(r, rc)
	if err != nil {
		a.internalError(w, r, "list projects", err)
		return
	}
	resp := overviewResponse{Projects: []overviewProject{}, Totals: overviewTotals{Decisions: map[string]int{}}}
	for _, p := range ps {
		ov, err := a.store.ProjectOverview(r.Context(), p.ID)
		if err != nil {
			a.internalError(w, r, "project overview", err)
			return
		}
		resp.Projects = append(resp.Projects, overviewProject{Project: p, Overview: ov})
		t := &resp.Totals
		t.Projects++
		t.Agents += ov.AgentCount
		t.Scans += ov.ScanCount
		t.OpenCritical += ov.OpenCritical
		t.OpenHigh += ov.OpenHigh
		for k, v := range ov.Decisions {
			t.Decisions[k] += v
		}
		if ov.LatestScanAt != nil && (t.LatestScanAt == nil || ov.LatestScanAt.After(*t.LatestScanAt)) {
			t.LatestScanAt = ov.LatestScanAt
		}
	}
	writeJSON(w, http.StatusOK, resp)
}
