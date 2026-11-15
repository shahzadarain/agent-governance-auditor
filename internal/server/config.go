// SPDX-License-Identifier: Apache-2.0

// Package server is the self-hosted AgentGov API. It ingests ScanResult
// documents uploaded by the CLI and serves them to the dashboard.
//
// Security posture in short:
//   - Binds to loopback unless Config.AllowPublic is set.
//   - No default credentials: the first administrator is created with a
//     one-time bootstrap token.
//   - Browser sessions use an opaque cookie, a CSRF token, and a same-origin
//     check. Project API tokens can upload scans and nothing else.
//   - Every project-scoped lookup goes through one authorization function;
//     data of a project the caller cannot see is reported as "not found".
//   - The server never fetches a URL supplied by a client. No endpoint
//     accepts a URL to retrieve, so there is no SSRF surface.
//   - The server stores scan metadata and the uploaded ScanResult. It does
//     not scan uploaded content for secrets; the CLI redacts before upload.
package server

import (
	"crypto/ed25519"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"log/slog"
	"net"
	"net/netip"
	"os"
	"strings"
	"time"

	"github.com/shahzadarain/agent-governance-auditor/internal/model"
)

// Defaults.
const (
	DefaultListen         = "127.0.0.1:8080"
	DefaultMaxUploadBytes = 5 << 20 // 5 MiB
	DefaultSessionTTL     = 12 * time.Hour
	DefaultSessionIdleTTL = 2 * time.Hour
	DefaultArgon2Memory   = 64 * 1024 // KiB
	DefaultIngestRate     = 60        // uploads per token per minute
	bootstrapTTL          = time.Hour
	minPasswordLength     = 12
	maxPasswordBytes      = 1024
	smallBodyLimit        = 64 << 10
)

// Config configures the server. The CLI maps flags and environment variables
// to this struct; the server itself reads no environment variable.
type Config struct {
	Listen      string // default 127.0.0.1:8080
	DatabaseURL string // "sqlite:///path/agentgov.db", a bare file path, or "postgres://..." (experimental)
	AllowPublic bool   // required to bind a non-loopback address

	// TrustedProxies lists CIDRs (or single IPs) of reverse proxies whose
	// X-Forwarded-For and X-Forwarded-Proto headers are honored.
	TrustedProxies []string

	MaxUploadBytes int64         // scan upload limit; default 5 MiB
	SessionTTL     time.Duration // absolute session lifetime; default 12 h
	SessionIdleTTL time.Duration // idle session lifetime; default 2 h

	UI      fs.FS // built dashboard; nil serves a minimal fallback page
	Version string
	Logger  *slog.Logger

	Catalog  *model.Catalog  // served by GET /api/v1/controls; nil gives 503
	Profiles []model.Profile // served by GET /api/v1/policies; empty gives 503

	// TrustedKeys maps a key ID to an Ed25519 public key that may verify
	// signed evidence in POST /api/v1/evidence/verify.
	TrustedKeys map[string]ed25519.PublicKey

	// BootstrapOut receives the one-time bootstrap token. Default os.Stderr.
	BootstrapOut io.Writer

	// IngestRatePerMinute limits uploads per API token. Default 60.
	IngestRatePerMinute int

	// OnListening, when set, is called once with the bound address.
	OnListening func(addr net.Addr)

	// Test hooks.
	Now             func() time.Time // default time.Now
	Argon2MemoryKiB uint32           // default 65536 (64 MiB); tests use less
}

func (c Config) withDefaults() Config {
	if c.Listen == "" {
		c.Listen = DefaultListen
	}
	if c.MaxUploadBytes <= 0 {
		c.MaxUploadBytes = DefaultMaxUploadBytes
	}
	if c.SessionTTL <= 0 {
		c.SessionTTL = DefaultSessionTTL
	}
	if c.SessionIdleTTL <= 0 {
		c.SessionIdleTTL = DefaultSessionIdleTTL
	}
	if c.SessionIdleTTL > c.SessionTTL {
		c.SessionIdleTTL = c.SessionTTL
	}
	if c.Version == "" {
		c.Version = "dev"
	}
	if c.Logger == nil {
		c.Logger = slog.New(slog.NewTextHandler(os.Stderr, nil))
	}
	if c.BootstrapOut == nil {
		c.BootstrapOut = os.Stderr
	}
	if c.IngestRatePerMinute <= 0 {
		c.IngestRatePerMinute = DefaultIngestRate
	}
	if c.Now == nil {
		c.Now = time.Now
	}
	// Every timestamp the server creates is UTC with microsecond precision,
	// which is what the database stores.
	clock := c.Now
	c.Now = func() time.Time { return clock().UTC().Truncate(time.Microsecond) }
	if c.Argon2MemoryKiB == 0 {
		c.Argon2MemoryKiB = DefaultArgon2Memory
	}
	return c
}

// ErrPublicBindRefused is returned when Listen is not a loopback address
// and AllowPublic is false.
var ErrPublicBindRefused = errors.New("server: refusing to listen on a non-loopback address without AllowPublic")

// CheckListenAddress validates a listen address. It returns public=true when
// the address is reachable from other hosts.
func CheckListenAddress(listen string, allowPublic bool) (public bool, err error) {
	host, port, err := net.SplitHostPort(listen)
	if err != nil {
		return false, fmt.Errorf("server: invalid listen address %q: %w", listen, err)
	}
	if port == "" {
		return false, fmt.Errorf("server: listen address %q has no port", listen)
	}
	loopback := false
	if strings.EqualFold(host, "localhost") {
		loopback = true
	} else if ip, perr := netip.ParseAddr(host); perr == nil {
		loopback = ip.IsLoopback()
	}
	// An empty host (":8080") binds every interface and is public.
	if loopback {
		return false, nil
	}
	if !allowPublic {
		return true, fmt.Errorf("%w (listen=%q)", ErrPublicBindRefused, listen)
	}
	return true, nil
}

func parseTrustedProxies(in []string) ([]netip.Prefix, error) {
	var out []netip.Prefix
	for _, raw := range in {
		s := strings.TrimSpace(raw)
		if s == "" {
			continue
		}
		if p, err := netip.ParsePrefix(s); err == nil {
			out = append(out, p.Masked())
			continue
		}
		ip, err := netip.ParseAddr(s)
		if err != nil {
			return nil, fmt.Errorf("server: invalid trusted proxy %q", raw)
		}
		out = append(out, netip.PrefixFrom(ip.Unmap(), ip.Unmap().BitLen()))
	}
	return out, nil
}
