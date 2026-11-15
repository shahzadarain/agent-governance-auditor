// SPDX-License-Identifier: Apache-2.0

package main

import (
	"context"
	"crypto/ed25519"
	"errors"
	"fmt"
	"io/fs"
	"log/slog"
	"net"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/spf13/cobra"

	"github.com/shahzadarain/agent-governance-auditor/internal/controls"
	"github.com/shahzadarain/agent-governance-auditor/internal/model"
	"github.com/shahzadarain/agent-governance-auditor/internal/policy"
	"github.com/shahzadarain/agent-governance-auditor/internal/server"
	"github.com/shahzadarain/agent-governance-auditor/web"
)

func envOr(name, def string) string {
	if v := strings.TrimSpace(os.Getenv(name)); v != "" {
		return v
	}
	return def
}

func newServeCmd() *cobra.Command {
	var listen, dbURL, dataDir, proxies string
	var allowPublic bool
	var maxUpload int64
	var trust []string
	cmd := &cobra.Command{
		Use:   "serve",
		Short: "Run the self-hosted dashboard on this machine",
		Long: `Run the self-hosted dashboard and evidence API.

By default the server listens only on this machine (127.0.0.1) and stores
data in a local SQLite file. On first start it prints a one-time setup
token. Open the address in a browser and use the token to create the first
administrator. There are no default passwords.

To expose the server to other machines, put it behind a reverse proxy that
terminates HTTPS, then pass --allow-public. See docs/self-hosting.md.`,
		Example: `  agentgov serve
  agentgov serve --listen 127.0.0.1:9090 --data-dir ./agentgov-data`,
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			if dbURL == "" {
				if err := os.MkdirAll(dataDir, 0o700); err != nil {
					return fmt.Errorf("create data folder: %w", err)
				}
				dbURL = filepath.Join(dataDir, "agentgov.db")
			}
			cat, err := controls.Load()
			if err != nil {
				return err
			}
			var profiles []model.Profile
			for _, name := range policy.ProfileNames() {
				p, err := policy.LoadProfile(name)
				if err != nil {
					return err
				}
				profiles = append(profiles, *p)
			}
			keys := map[string]ed25519.PublicKey{}
			for _, path := range trust {
				raw, err := readKeyFile(path, ed25519.PublicKeySize)
				if err != nil {
					return fmt.Errorf("trusted key %s: %w", path, err)
				}
				id := strings.TrimSuffix(filepath.Base(path), filepath.Ext(path))
				keys[id] = ed25519.PublicKey(raw)
			}
			var proxyList []string
			for _, p := range strings.Split(proxies, ",") {
				if p = strings.TrimSpace(p); p != "" {
					proxyList = append(proxyList, p)
				}
			}
			var ui fs.FS
			if sub, err := web.Dist(); err == nil {
				ui = sub
			}

			ctx, stop := signal.NotifyContext(cmd.Context(), os.Interrupt, syscall.SIGTERM)
			defer stop()

			out := cmd.ErrOrStderr()
			cfg := server.Config{
				Listen:         listen,
				DatabaseURL:    dbURL,
				AllowPublic:    allowPublic,
				TrustedProxies: proxyList,
				MaxUploadBytes: maxUpload,
				UI:             ui,
				Version:        version,
				Logger:         slog.New(slog.NewTextHandler(out, &slog.HandlerOptions{Level: slog.LevelInfo})),
				Catalog:        cat,
				Profiles:       profiles,
				TrustedKeys:    keys,
				BootstrapOut:   out,
				OnListening: func(addr net.Addr) {
					fmt.Fprintf(out, "\nAgentGov dashboard is running at http://%s\nPress Ctrl+C to stop.\n\n", addr)
				},
			}
			err = server.Run(ctx, cfg)
			if errors.Is(err, context.Canceled) || errors.Is(err, http.ErrServerClosed) {
				return nil
			}
			return err
		},
	}
	defUpload, _ := strconv.ParseInt(envOr("AGENTGOV_MAX_UPLOAD_BYTES", "0"), 10, 64)
	defPublic, _ := strconv.ParseBool(envOr("AGENTGOV_ALLOW_PUBLIC", "false"))
	fl := cmd.Flags()
	fl.StringVar(&listen, "listen", envOr("AGENTGOV_LISTEN", "127.0.0.1:8080"), "address to listen on")
	fl.StringVar(&dbURL, "database-url", envOr("AGENTGOV_DATABASE_URL", ""), "SQLite file path, or postgres:// URL (experimental)")
	fl.StringVar(&dataDir, "data-dir", envOr("AGENTGOV_DATA_DIR", "agentgov-data"), "folder for the SQLite database when --database-url is not set")
	fl.BoolVar(&allowPublic, "allow-public", defPublic, "allow listening on a non-local address (use only behind an HTTPS reverse proxy)")
	fl.StringVar(&proxies, "trusted-proxies", envOr("AGENTGOV_TRUSTED_PROXIES", ""), "comma-separated proxy addresses whose X-Forwarded headers are trusted")
	fl.Int64Var(&maxUpload, "max-upload-bytes", defUpload, "largest accepted scan upload (default 5 MiB)")
	fl.StringSliceVar(&trust, "trust-key", nil, "Ed25519 public key file for evidence verification (repeatable)")
	return cmd
}

func newHealthcheckCmd() *cobra.Command {
	var url string
	cmd := &cobra.Command{
		Use:    "healthcheck",
		Short:  "Check that a running AgentGov server answers",
		Hidden: true,
		Args:   cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			client := &http.Client{Timeout: 5 * time.Second}
			req, err := http.NewRequestWithContext(cmd.Context(), http.MethodGet, url, nil)
			if err != nil {
				return err
			}
			resp, err := client.Do(req)
			if err != nil {
				return err
			}
			defer resp.Body.Close()
			if resp.StatusCode != http.StatusOK {
				return fmt.Errorf("server answered %d", resp.StatusCode)
			}
			return nil
		},
	}
	cmd.Flags().StringVar(&url, "url", "http://127.0.0.1:8080/healthz", "health endpoint to call")
	return cmd
}
