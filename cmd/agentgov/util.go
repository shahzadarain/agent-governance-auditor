// SPDX-License-Identifier: Apache-2.0

package main

import (
	"bufio"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"

	"golang.org/x/term"

	"github.com/shahzadarain/agent-governance-auditor/internal/model"
)

// useColor decides whether ANSI color may be written to f.
func useColor(f *os.File, disabled bool) bool {
	if disabled {
		return false
	}
	if _, set := os.LookupEnv("NO_COLOR"); set {
		return false
	}
	// CLICOLOR_FORCE=1 keeps color when output is piped, for example into a
	// pager or a screenshot tool.
	if v := os.Getenv("CLICOLOR_FORCE"); v != "" && v != "0" {
		return true
	}
	if os.Getenv("TERM") == "dumb" {
		return false
	}
	if !term.IsTerminal(int(f.Fd())) {
		return false
	}
	return enableVirtualTerminal(f)
}

// terminalWidth returns the width of f, or a readable default.
func terminalWidth(f *os.File) int {
	if w, _, err := term.GetSize(int(f.Fd())); err == nil && w >= 60 {
		if w > 120 {
			return 120
		}
		return w
	}
	return 100
}

func isInteractive() bool {
	return term.IsTerminal(int(os.Stdin.Fd())) && term.IsTerminal(int(os.Stdout.Fd()))
}

// writeFileAtomic writes data next to path and renames it into place.
func writeFileAtomic(path string, data []byte) error {
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return err
	}
	tmp, err := os.CreateTemp(dir, ".agentgov-*")
	if err != nil {
		return err
	}
	name := tmp.Name()
	if _, err := tmp.Write(data); err != nil {
		tmp.Close()
		os.Remove(name)
		return err
	}
	if err := tmp.Close(); err != nil {
		os.Remove(name)
		return err
	}
	if err := os.Rename(name, path); err != nil {
		os.Remove(name)
		return err
	}
	return nil
}

// maxResultBytes bounds a results file read from disk.
const maxResultBytes = 64 << 20

// readResult loads a ScanResult JSON file produced by `agentgov scan`.
func readResult(path string) (*model.ScanResult, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	data, err := io.ReadAll(io.LimitReader(f, maxResultBytes+1))
	if err != nil {
		return nil, err
	}
	if len(data) > maxResultBytes {
		return nil, fmt.Errorf("%s is larger than %d MiB", path, maxResultBytes>>20)
	}
	var res model.ScanResult
	if err := json.Unmarshal(data, &res); err != nil {
		return nil, fmt.Errorf("%s is not a scan result: %w", path, err)
	}
	if res.SchemaVersion != model.SchemaVersion {
		return nil, fmt.Errorf("%s has schema_version %q; this build reads version %q", path, res.SchemaVersion, model.SchemaVersion)
	}
	return &res, nil
}

// confirm asks a yes/no question on the terminal. It returns def when the
// session is not interactive.
func confirm(question string, def bool) bool {
	if !isInteractive() {
		return def
	}
	hint := "y/N"
	if def {
		hint = "Y/n"
	}
	fmt.Fprintf(os.Stdout, "%s [%s] ", question, hint)
	line, _ := bufio.NewReader(os.Stdin).ReadString('\n')
	line = strings.ToLower(strings.TrimSpace(line))
	if line == "" {
		return def
	}
	return line == "y" || line == "yes"
}

// ask reads one line of input with a default value.
func ask(question, def string) string {
	if !isInteractive() {
		return def
	}
	if def != "" {
		fmt.Fprintf(os.Stdout, "%s [%s]: ", question, def)
	} else {
		fmt.Fprintf(os.Stdout, "%s: ", question)
	}
	line, _ := bufio.NewReader(os.Stdin).ReadString('\n')
	line = strings.TrimSpace(line)
	if line == "" {
		return def
	}
	return line
}

// openInBrowser opens a local file with the operating system's default
// handler. It is only called for files this tool just wrote.
func openInBrowser(path string) error {
	abs, err := filepath.Abs(path)
	if err != nil {
		return err
	}
	var cmd *exec.Cmd
	switch runtime.GOOS {
	case "windows":
		cmd = exec.Command("rundll32", "url.dll,FileProtocolHandler", abs)
	case "darwin":
		cmd = exec.Command("open", abs)
	default:
		cmd = exec.Command("xdg-open", abs)
	}
	return cmd.Start()
}

// loadPublicKeys reads Ed25519 public keys (base64, one per file) used to
// verify signed evidence.
func loadPublicKeys(paths []string) ([]ed25519.PublicKey, error) {
	var keys []ed25519.PublicKey
	for _, p := range paths {
		key, err := readKeyFile(p, ed25519.PublicKeySize)
		if err != nil {
			return nil, fmt.Errorf("trusted key %s: %w", p, err)
		}
		keys = append(keys, ed25519.PublicKey(key))
	}
	return keys, nil
}

func readKeyFile(path string, size int) ([]byte, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	raw, err := base64.StdEncoding.DecodeString(strings.TrimSpace(string(data)))
	if err != nil {
		return nil, fmt.Errorf("not valid base64: %w", err)
	}
	if len(raw) != size {
		return nil, fmt.Errorf("expected %d bytes, found %d", size, len(raw))
	}
	return raw, nil
}

func shortSHA(s string) string {
	if len(s) > 12 {
		return s[:12]
	}
	return s
}
