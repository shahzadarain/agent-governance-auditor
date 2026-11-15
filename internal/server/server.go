// SPDX-License-Identifier: Apache-2.0

package server

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"net/netip"
	"runtime/debug"
	"strings"
	"time"

	"github.com/shahzadarain/agent-governance-auditor/internal/storage"
)

// App holds the server state shared by all handlers.
type App struct {
	cfg     Config
	store   storage.Store
	log     *slog.Logger
	proxies []netip.Prefix
	metrics *metrics

	loginIP   *rateLimiter // login and setup attempts per client IP
	loginLock *lockouts    // failed logins per username and IP
	ingestRL  *rateLimiter // uploads per API token
	hashSlots chan struct{}
	dummyHash string // verified against when the user does not exist
}

// access says which credential a route accepts.
type access int

const (
	accessPublic  access = iota // no credential
	accessSession               // browser session cookie
	accessToken                 // project API token (Bearer)
	accessMetrics               // administrator session or loopback caller
)

// route is one entry of the route table. Authorization is declared here and
// enforced in one place (App.serveRoute) before the handler runs.
type route struct {
	Method string
	Path   string
	access access
	perm   permission
	scope  scopeFunc // resolves the project the request targets; may be nil
	h      func(a *App, w http.ResponseWriter, r *http.Request, rc *reqCtx)
}

// RouteInfo describes one public API route. The OpenAPI test compares this
// list with api/openapi.yaml.
type RouteInfo struct {
	Method string
	Path   string
}

// Routes returns every route the server registers, except the internal
// catch-all handlers for the dashboard and for unknown API paths.
func Routes() []RouteInfo {
	rs := routeTable()
	out := make([]RouteInfo, 0, len(rs))
	for _, r := range rs {
		out = append(out, RouteInfo{Method: r.Method, Path: r.Path})
	}
	return out
}

func routeTable() []route {
	return []route{
		{"GET", "/healthz", accessPublic, permNone, nil, (*App).handleHealthz},
		{"GET", "/readyz", accessPublic, permNone, nil, (*App).handleReadyz},
		{"GET", "/metrics", accessMetrics, permNone, nil, (*App).handleMetrics},
		{"GET", "/api/v1/version", accessPublic, permNone, nil, (*App).handleVersion},

		{"POST", "/api/v1/setup", accessPublic, permNone, nil, (*App).handleSetup},
		{"POST", "/api/v1/login", accessPublic, permNone, nil, (*App).handleLogin},
		{"POST", "/api/v1/logout", accessSession, permAuthenticated, nil, (*App).handleLogout},
		{"GET", "/api/v1/session", accessSession, permAuthenticated, nil, (*App).handleSession},

		{"GET", "/api/v1/users", accessSession, permAdmin, nil, (*App).handleListUsers},
		{"POST", "/api/v1/users", accessSession, permAdmin, nil, (*App).handleCreateUser},

		{"GET", "/api/v1/projects", accessSession, permAuthenticated, nil, (*App).handleListProjects},
		{"POST", "/api/v1/projects", accessSession, permAdmin, nil, (*App).handleCreateProject},
		{"GET", "/api/v1/projects/{projectId}", accessSession, permProjectRead, scopeProjectPath, (*App).handleGetProject},
		{"GET", "/api/v1/projects/{projectId}/agents", accessSession, permProjectRead, scopeProjectPath, (*App).handleListAgents},
		{"GET", "/api/v1/projects/{projectId}/tokens", accessSession, permProjectManage, scopeProjectPath, (*App).handleListTokens},
		{"POST", "/api/v1/projects/{projectId}/tokens", accessSession, permProjectManage, scopeProjectPath, (*App).handleCreateToken},
		{"DELETE", "/api/v1/projects/{projectId}/tokens/{tokenId}", accessSession, permProjectManage, scopeProjectPath, (*App).handleRevokeToken},
		{"GET", "/api/v1/projects/{projectId}/members", accessSession, permProjectManage, scopeProjectPath, (*App).handleListMembers},
		{"POST", "/api/v1/projects/{projectId}/members", accessSession, permProjectManage, scopeProjectPath, (*App).handleSetMember},
		{"DELETE", "/api/v1/projects/{projectId}/members", accessSession, permProjectManage, scopeProjectPath, (*App).handleRemoveMember},

		{"POST", "/api/v1/scans", accessToken, permNone, nil, (*App).handleIngest},
		{"GET", "/api/v1/agents/{agentId}", accessSession, permProjectRead, scopeAgentPath, (*App).handleGetAgent},
		{"GET", "/api/v1/agents/{agentId}/scans", accessSession, permProjectRead, scopeAgentPath, (*App).handleAgentScans},
		{"GET", "/api/v1/scans/{scanId}", accessSession, permProjectRead, scopeScanPath, (*App).handleGetScan},
		{"GET", "/api/v1/scans/{scanId}/findings", accessSession, permProjectRead, scopeScanPath, (*App).handleScanFindings},
		{"GET", "/api/v1/scans/{scanId}/controls", accessSession, permProjectRead, scopeScanPath, (*App).handleScanControls},
		{"GET", "/api/v1/scans/{scanId}/compare/{otherScanId}", accessSession, permProjectRead, scopeComparePath, (*App).handleCompare},

		{"GET", "/api/v1/controls", accessSession, permAuthenticated, nil, (*App).handleControls},
		{"GET", "/api/v1/policies", accessSession, permAuthenticated, nil, (*App).handlePolicies},
		{"POST", "/api/v1/evidence/verify", accessSession, permAuthenticated, nil, (*App).handleEvidenceVerify},
		{"GET", "/api/v1/audit-events", accessSession, permProjectAudit, scopeProjectQuery, (*App).handleAuditEvents},
		{"GET", "/api/v1/overview", accessSession, permAuthenticated, nil, (*App).handleOverview},
	}
}

// NewHandler builds the HTTP handler on an open store. When no user exists
// it generates the one-time bootstrap token and prints it to
// Config.BootstrapOut.
func NewHandler(cfg Config, store storage.Store) (http.Handler, error) {
	a, err := newApp(cfg, store)
	if err != nil {
		return nil, err
	}
	return a.handler(), nil
}

func newApp(cfg Config, store storage.Store) (*App, error) {
	if store == nil {
		return nil, errors.New("server: store is required")
	}
	cfg = cfg.withDefaults()
	proxies, err := parseTrustedProxies(cfg.TrustedProxies)
	if err != nil {
		return nil, err
	}
	a := &App{
		cfg:       cfg,
		store:     store,
		log:       cfg.Logger,
		proxies:   proxies,
		metrics:   newMetrics(),
		loginIP:   newRateLimiter(cfg.Now, 20, 20.0/60.0),
		loginLock: newLockouts(cfg.Now),
		ingestRL:  newRateLimiter(cfg.Now, float64(cfg.IngestRatePerMinute), float64(cfg.IngestRatePerMinute)/60.0),
		hashSlots: make(chan struct{}, 4),
	}
	// A real hash of a random password: login for an unknown user does the
	// same work as login for a known one.
	a.dummyHash, err = hashPassword(randomToken(16), cfg.Argon2MemoryKiB)
	if err != nil {
		return nil, err
	}
	if err := a.ensureBootstrap(context.Background()); err != nil {
		return nil, err
	}
	return a, nil
}

func (a *App) handler() http.Handler {
	mux := http.NewServeMux()
	for _, rt := range routeTable() {
		rt := rt
		mux.HandleFunc(rt.Method+" "+rt.Path, func(w http.ResponseWriter, r *http.Request) { a.serveRoute(rt, w, r) })
	}
	// Unknown API paths answer with the JSON error format, never with the
	// dashboard's index.html.
	mux.HandleFunc("/api/", func(w http.ResponseWriter, r *http.Request) {
		stateFrom(r).pattern = "/api/"
		writeError(w, http.StatusNotFound, "not_found", "The requested resource does not exist.")
	})
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		stateFrom(r).pattern = "/"
		a.serveUI(w, r)
	})
	return a.outer(mux)
}

// reqState is per-request data shared between the outer middleware and the
// route wrapper.
type reqState struct {
	id      string
	pattern string
	actor   string // "user:<id>", "token:<id>", or ""
}

type stateKey struct{}

func stateFrom(r *http.Request) *reqState {
	if s, ok := r.Context().Value(stateKey{}).(*reqState); ok {
		return s
	}
	return &reqState{}
}

type statusWriter struct {
	http.ResponseWriter
	status int
}

func (w *statusWriter) WriteHeader(code int) {
	if w.status == 0 {
		w.status = code
	}
	w.ResponseWriter.WriteHeader(code)
}

func (w *statusWriter) Write(b []byte) (int, error) {
	if w.status == 0 {
		w.status = http.StatusOK
	}
	return w.ResponseWriter.Write(b)
}

func isAPIPath(p string) bool {
	return strings.HasPrefix(p, "/api/") || p == "/healthz" || p == "/readyz" || p == "/metrics"
}

// uiCSP is the Content-Security-Policy of the dashboard.
const uiCSP = "default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; " +
	"connect-src 'self'; frame-ancestors 'none'; base-uri 'none'; form-action 'self'"

// outer applies security headers, the request ID, panic recovery, metrics,
// and structured request logging to every response.
//
// The log line holds the request ID, method, route pattern, status, duration,
// client IP, and actor ID. It never holds the raw path, query string,
// headers, cookies, tokens, passwords, or bodies.
func (a *App) outer(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()
		st := &reqState{id: randomHex(8)}
		r = r.WithContext(context.WithValue(r.Context(), stateKey{}, st))
		sw := &statusWriter{ResponseWriter: w}

		h := sw.Header()
		h.Set("X-Request-ID", st.id)
		h.Set("X-Content-Type-Options", "nosniff")
		h.Set("Referrer-Policy", "no-referrer")
		h.Set("X-Frame-Options", "DENY")
		h.Set("Cross-Origin-Opener-Policy", "same-origin")
		if isAPIPath(r.URL.Path) {
			h.Set("Cache-Control", "no-store")
			h.Set("Content-Security-Policy", "default-src 'none'; frame-ancestors 'none'")
		} else {
			h.Set("Content-Security-Policy", uiCSP)
		}

		defer func() {
			if rec := recover(); rec != nil {
				if rec == http.ErrAbortHandler {
					panic(rec)
				}
				// The stack goes to the server log only.
				a.log.Error("panic in handler", "request_id", st.id, "route", st.pattern,
					"panic", fmt.Sprint(rec), "stack", string(debug.Stack()))
				if sw.status == 0 {
					writeError(sw, http.StatusInternalServerError, "internal_error", "Internal server error.")
				}
			}
			status := sw.status
			if status == 0 {
				status = http.StatusOK
			}
			a.metrics.request(r.Method, status)
			a.log.Info("request", "request_id", st.id, "method", r.Method, "route", st.pattern, "status", status,
				"duration_ms", time.Since(start).Milliseconds(), "client_ip", a.clientIP(r), "actor", st.actor)
		}()
		next.ServeHTTP(sw, r)
	})
}

func isMutating(method string) bool {
	switch method {
	case http.MethodGet, http.MethodHead, http.MethodOptions:
		return false
	}
	return true
}

// serveRoute authenticates, applies CSRF defenses, authorizes, and then
// calls the handler. Every registered route passes through here.
func (a *App) serveRoute(rt route, w http.ResponseWriter, r *http.Request) {
	st := stateFrom(r)
	st.pattern = rt.Method + " " + rt.Path
	rc := &reqCtx{}

	// Browser-facing mutating routes must be same-origin, with or without a
	// session (this also covers login and setup).
	if isMutating(r.Method) && rt.access != accessToken {
		if !sameOrigin(r) {
			a.metrics.authFailure("csrf")
			writeError(w, http.StatusForbidden, "cross_origin", "Cross-origin requests are not allowed.")
			return
		}
	}

	switch rt.access {
	case accessSession:
		if err := a.authenticateSession(w, r, rc); err != nil {
			a.metrics.authFailure("session")
			writeAuthError(w, err)
			return
		}
		st.actor = "user:" + rc.user.ID
		if isMutating(r.Method) && !csrfTokenMatches(r, rc.session.CSRFToken) {
			a.metrics.authFailure("csrf")
			writeError(w, http.StatusForbidden, "csrf_failed", "Missing or invalid CSRF token.")
			return
		}
		projectID := ""
		if rt.scope != nil {
			var err error
			if projectID, err = rt.scope(a, r, rc); err != nil {
				writeAuthError(w, err)
				return
			}
		}
		if err := a.authorize(r.Context(), rc.user, rt.perm, projectID); err != nil {
			writeAuthError(w, err)
			return
		}
		rc.projectID = projectID
	case accessToken:
		if err := a.authenticateToken(r, rc); err != nil {
			a.metrics.authFailure("token")
			writeAuthError(w, err)
			return
		}
		st.actor = "token:" + rc.token.ID
	case accessMetrics:
		if !a.isDirectLoopback(r) {
			if err := a.authenticateSession(w, r, rc); err != nil || rc.user.Role != storage.RoleAdministrator {
				a.metrics.authFailure("session")
				writeError(w, http.StatusNotFound, "not_found", "The requested resource does not exist.")
				return
			}
			st.actor = "user:" + rc.user.ID
		}
	}
	rt.h(a, w, r, rc)
}

// Run opens the database, applies migrations, and serves until ctx is
// canceled. It then shuts down gracefully.
func Run(ctx context.Context, cfg Config) error {
	cfg = cfg.withDefaults()
	public, err := CheckListenAddress(cfg.Listen, cfg.AllowPublic)
	if err != nil {
		return err
	}
	if cfg.DatabaseURL == "" {
		return errors.New("server: DatabaseURL is required")
	}
	if public {
		cfg.Logger.Warn("SECURITY WARNING: the server listens on a non-loopback address. " +
			"It speaks plain HTTP. Put a reverse proxy that terminates TLS in front of it, " +
			"restrict the port with a firewall, and set TrustedProxies to the proxy address.")
	}
	store, err := storage.Open(ctx, cfg.DatabaseURL)
	if err != nil {
		return err
	}
	defer store.Close()
	if store.Dialect() == storage.DialectPostgres {
		cfg.Logger.Warn("PostgreSQL support is experimental and has not been tested against a real server.")
	}
	a, err := newApp(cfg, store)
	if err != nil {
		return err
	}

	srv := newHTTPServer(a.handler(), cfg.Logger)
	ln, err := net.Listen("tcp", cfg.Listen)
	if err != nil {
		return fmt.Errorf("server: listen: %w", err)
	}
	cfg.Logger.Info("server listening", "addr", ln.Addr().String(), "public", public, "database", store.Dialect(), "version", cfg.Version)
	if cfg.OnListening != nil {
		cfg.OnListening(ln.Addr())
	}

	// Expired sessions are also rejected at request time; this only keeps
	// the table small.
	janitorDone := make(chan struct{})
	go func() {
		defer close(janitorDone)
		t := time.NewTicker(15 * time.Minute)
		defer t.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-t.C:
				now := a.cfg.Now()
				if _, err := store.DeleteExpiredSessions(ctx, now, now.Add(-a.cfg.SessionIdleTTL)); err != nil && ctx.Err() == nil {
					cfg.Logger.Warn("session cleanup failed", "error", err.Error())
				}
			}
		}
	}()

	errc := make(chan error, 1)
	go func() { errc <- srv.Serve(ln) }()
	select {
	case err := <-errc:
		return err
	case <-ctx.Done():
	}
	cfg.Logger.Info("shutting down")
	sctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	err = srv.Shutdown(sctx)
	<-janitorDone
	if err != nil {
		return fmt.Errorf("server: shutdown: %w", err)
	}
	return nil
}

// newHTTPServer returns an http.Server with bounded timeouts and header
// size, so slow or oversized requests cannot hold connections open.
func newHTTPServer(h http.Handler, logger *slog.Logger) *http.Server {
	return &http.Server{
		Handler:           h,
		ReadHeaderTimeout: 10 * time.Second,
		ReadTimeout:       60 * time.Second,
		WriteTimeout:      120 * time.Second,
		IdleTimeout:       120 * time.Second,
		MaxHeaderBytes:    64 << 10,
		ErrorLog:          slog.NewLogLogger(logger.Handler(), slog.LevelWarn),
	}
}

func randomHex(n int) string {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		panic("server: crypto/rand failed: " + err.Error())
	}
	return hex.EncodeToString(b)
}

// clientIP returns the client address. X-Forwarded-For is honored only when
// the direct peer is a trusted proxy; the rightmost untrusted entry wins.
func (a *App) clientIP(r *http.Request) string {
	peer := peerAddr(r)
	if !peer.IsValid() || !a.isTrustedProxy(peer) {
		if peer.IsValid() {
			return peer.String()
		}
		return "unknown"
	}
	parts := strings.Split(strings.Join(r.Header.Values("X-Forwarded-For"), ","), ",")
	for i := len(parts) - 1; i >= 0; i-- {
		ip, err := netip.ParseAddr(strings.TrimSpace(parts[i]))
		if err != nil {
			break
		}
		ip = ip.Unmap()
		if !a.isTrustedProxy(ip) {
			return ip.String()
		}
	}
	return peer.String()
}

func peerAddr(r *http.Request) netip.Addr {
	ap, err := netip.ParseAddrPort(r.RemoteAddr)
	if err != nil {
		return netip.Addr{}
	}
	return ap.Addr().Unmap()
}

func (a *App) isTrustedProxy(ip netip.Addr) bool {
	for _, p := range a.proxies {
		if p.Contains(ip) {
			return true
		}
	}
	return false
}

// isHTTPS reports whether the client connection is HTTPS, either directly or
// as stated by a trusted proxy.
func (a *App) isHTTPS(r *http.Request) bool {
	if r.TLS != nil {
		return true
	}
	peer := peerAddr(r)
	return peer.IsValid() && a.isTrustedProxy(peer) && strings.EqualFold(r.Header.Get("X-Forwarded-Proto"), "https")
}

// isDirectLoopback reports whether the request comes straight from the local
// host. A request that carries proxy headers is never treated as local, so a
// reverse proxy on the same host does not expose loopback-only routes.
func (a *App) isDirectLoopback(r *http.Request) bool {
	peer := peerAddr(r)
	if !peer.IsValid() || !peer.IsLoopback() {
		return false
	}
	for _, h := range []string{"X-Forwarded-For", "Forwarded", "X-Real-Ip", "X-Forwarded-Host", "X-Forwarded-Proto"} {
		if r.Header.Get(h) != "" {
			return false
		}
	}
	return true
}
