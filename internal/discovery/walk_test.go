// SPDX-License-Identifier: Apache-2.0

package discovery

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/shahzadarain/agent-governance-auditor/internal/model"
)

// writeTree creates files under a new temporary directory. Keys are
// forward-slash relative paths.
func writeTree(t *testing.T, files map[string]string) string {
	t.Helper()
	root := t.TempDir()
	for rel, content := range files {
		p := filepath.Join(root, filepath.FromSlash(rel))
		if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p, []byte(content), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	return root
}

func walk(t *testing.T, opts Options) *Inventory {
	t.Helper()
	inv, err := Walk(context.Background(), opts)
	if err != nil {
		t.Fatalf("Walk: %v", err)
	}
	return inv
}

func paths(inv *Inventory) []string {
	var out []string
	for _, f := range inv.Files {
		out = append(out, f.Path)
	}
	return out
}

func hasWarning(inv *Inventory, substr string) bool {
	for _, w := range inv.Warnings {
		if strings.Contains(w, substr) {
			return true
		}
	}
	return false
}

func TestWalkDefaultExcludes(t *testing.T) {
	files := map[string]string{"src/app.py": "x = 1\n", "README.md": "hi\n"}
	for _, d := range DefaultExcludes {
		files[d+"/inner/file.py"] = "secret = 1\n"
		files["pkg/"+d+"/file.js"] = "x\n"
	}
	inv := walk(t, Options{Root: writeTree(t, files)})
	got := strings.Join(paths(inv), ",")
	if got != "README.md,src/app.py" {
		t.Fatalf("unexpected inventory: %s", got)
	}
}

func TestWalkNeverReadsSecretStores(t *testing.T) {
	root := writeTree(t, map[string]string{
		".env": "API_KEY=super-secret-value\n", ".env.production": "X=1\n", ".env.example": "API_KEY=changeme\n",
		"deploy/server.pem": "-----BEGIN PRIVATE KEY-----\n", "id_rsa": "key\n", "id_rsa.pub": "pub\n",
		"certs/client.p12": "x", "certs/client.pfx": "x", "tls.key": "x", "app.py": "x = 1\n",
	})
	inv := walk(t, Options{Root: root})
	wantSecret := map[string]bool{".env": true, ".env.production": true, "deploy/server.pem": true, "id_rsa": true,
		"id_rsa.pub": true, "certs/client.p12": true, "certs/client.pfx": true, "tls.key": true}
	for _, f := range inv.Files {
		if wantSecret[f.Path] {
			if f.Skipped != SkipSecretStore || f.Content != nil {
				t.Errorf("%s: secret store content must not be read (skipped=%q, content=%d bytes)", f.Path, f.Skipped, len(f.Content))
			}
			delete(wantSecret, f.Path)
		} else if f.Skipped != "" {
			t.Errorf("%s: expected to be read, got skipped=%q", f.Path, f.Skipped)
		}
	}
	if len(wantSecret) != 0 {
		t.Errorf("secret stores must still be listed; missing: %v", wantSecret)
	}
	if f, ok := inv.Get(".env.example"); !ok || !bytes.Contains(f.Content, []byte("changeme")) {
		t.Errorf(".env.example should be readable")
	}
	for _, f := range inv.Files {
		if bytes.Contains(f.Content, []byte("super-secret-value")) {
			t.Fatalf("secret value was read from %s", f.Path)
		}
	}
}

func TestWalkBounds(t *testing.T) {
	t.Run("per-file size limit", func(t *testing.T) {
		root := writeTree(t, map[string]string{"big.py": strings.Repeat("a", 5000), "small.py": "x\n"})
		inv := walk(t, Options{Root: root, MaxFileSize: 1000})
		big, _ := inv.Get("big.py")
		if big.Skipped != SkipTooLarge || big.Content != nil {
			t.Fatalf("big file should be skipped, got %q", big.Skipped)
		}
		if !hasWarning(inv, "big.py") {
			t.Fatalf("expected a warning for the large file, got %v", inv.Warnings)
		}
		if inv.FilesScanned != 1 || inv.FilesSkipped != 1 {
			t.Fatalf("stats: scanned=%d skipped=%d", inv.FilesScanned, inv.FilesSkipped)
		}
	})
	t.Run("two MiB file with default limit", func(t *testing.T) {
		root := writeTree(t, map[string]string{"huge.json": strings.Repeat("[1,2,3]\n", (2<<20)/8), "ok.py": "x\n"})
		inv := walk(t, Options{Root: root})
		f, _ := inv.Get("huge.json")
		if f.Skipped != SkipTooLarge {
			t.Fatalf("2 MiB file should be skipped by the 1 MiB default, got %q", f.Skipped)
		}
	})
	t.Run("max files", func(t *testing.T) {
		files := map[string]string{}
		for _, n := range []string{"a", "b", "c", "d", "e", "f"} {
			files[n+".py"] = "x\n"
		}
		inv := walk(t, Options{Root: writeTree(t, files), MaxFiles: 3})
		if len(inv.Files) != 3 || !inv.Truncated || !hasWarning(inv, "scan stopped after 3 files") {
			t.Fatalf("files=%d truncated=%v warnings=%v", len(inv.Files), inv.Truncated, inv.Warnings)
		}
	})
	t.Run("max total bytes", func(t *testing.T) {
		root := writeTree(t, map[string]string{"a.py": strings.Repeat("a", 600), "b.py": strings.Repeat("b", 600)})
		inv := walk(t, Options{Root: root, MaxTotalBytes: 1000})
		b, _ := inv.Get("b.py")
		if b.Skipped != SkipByteBudget || !inv.Truncated {
			t.Fatalf("second file should exceed the byte budget, got %q", b.Skipped)
		}
	})
	t.Run("max depth", func(t *testing.T) {
		root := writeTree(t, map[string]string{"a/b/c/d/deep.py": "x\n", "a/top.py": "x\n"})
		inv := walk(t, Options{Root: root, MaxDepth: 2})
		if inv.Has("a/b/c/d/deep.py") || !inv.Has("a/top.py") || !hasWarning(inv, "maximum depth") {
			t.Fatalf("paths=%v warnings=%v", paths(inv), inv.Warnings)
		}
	})
	t.Run("cancelled context", func(t *testing.T) {
		ctx, cancel := context.WithCancel(context.Background())
		cancel()
		if _, err := Walk(ctx, Options{Root: writeTree(t, map[string]string{"a.py": "x\n"})}); err == nil {
			t.Fatal("expected an error from a cancelled context")
		}
	})
}

func TestWalkSkipsBinaryAndArchives(t *testing.T) {
	root := writeTree(t, map[string]string{
		"data.bin": "abc\x00def", "bundle.zip": "PK\x03\x04\x00\x00payload", "text.py": "x = 1\n",
	})
	inv := walk(t, Options{Root: root})
	for _, name := range []string{"data.bin", "bundle.zip"} {
		f, _ := inv.Get(name)
		if f.Skipped != SkipBinary || f.Content != nil {
			t.Errorf("%s should be skipped as binary and never unpacked, got %q", name, f.Skipped)
		}
	}
	if len(inv.Files) != 3 {
		t.Errorf("an archive must stay one file; got %v", paths(inv))
	}
}

func TestWalkSymlinkEscapeAndCycle(t *testing.T) {
	outside := writeTree(t, map[string]string{"secret.py": "TOP = 'outside'\n", "dir/inner.py": "x\n"})
	root := writeTree(t, map[string]string{"app.py": "x = 1\n", "sub/mod.py": "y = 2\n", "real.py": "z = 3\n"})
	if err := os.Symlink(filepath.Join(outside, "secret.py"), filepath.Join(root, "escape.py")); err != nil {
		t.Skipf("cannot create symlinks on this system: %v", err)
	}
	mustLink := func(target, link string) {
		t.Helper()
		if err := os.Symlink(target, link); err != nil {
			t.Skipf("cannot create symlinks on this system: %v", err)
		}
	}
	mustLink(filepath.Join(outside, "dir"), filepath.Join(root, "escape-dir"))
	mustLink(root, filepath.Join(root, "sub", "loop"))                              // cycle to an ancestor
	mustLink(filepath.Join(root, "real.py"), filepath.Join(root, "inside-link.py")) // allowed
	mustLink(filepath.Join(root, "missing.py"), filepath.Join(root, "broken.py"))   // dangling

	inv := walk(t, Options{Root: root})
	got := strings.Join(paths(inv), ",")
	if got != "app.py,inside-link.py,real.py,sub/mod.py" {
		t.Fatalf("unexpected inventory: %s", got)
	}
	for _, f := range inv.Files {
		if bytes.Contains(f.Content, []byte("outside")) {
			t.Fatalf("content from outside the root was read through %s", f.Path)
		}
	}
	for _, want := range []string{"escape.py: link skipped, it resolves outside", "escape-dir: link skipped, it resolves outside",
		"sub/loop: link skipped, it points at one of its own parent directories", "broken.py: link skipped"} {
		if !hasWarning(inv, want) {
			t.Errorf("missing warning %q in %v", want, inv.Warnings)
		}
	}
}

func TestGlobs(t *testing.T) {
	match := []struct {
		pattern, path string
		want          bool
	}{
		{"*.py", "a.py", true},
		{"*.py", "src/deep/a.py", true},
		{"*.py", "a.pyc", false},
		{"src/**", "src/a/b.py", true},
		{"src/**/*.py", "src/a.py", true},
		{"src/**/*.py", "src/a/b/c.py", true},
		{"src/**/*.py", "lib/a.py", false},
		{"**/tests/**", "pkg/tests/unit/a.py", true},
		{"docs", "docs/guide/a.md", true},
		{"docs/", "docs/guide/a.md", true},
		{"docs/*.md", "docs/guide/a.md", false},
		{"src/gen", "src/gen/x.py", true},
		{"./src/gen", "src/gen/x.py", true},
		{"a?.py", "ab.py", true},
		{"caf\u00e9/*", "caf\u00e9/x.py", true},
	}
	for _, c := range match {
		if got := MatchGlob(c.pattern, c.path); got != c.want {
			t.Errorf("MatchGlob(%q, %q) = %v, want %v", c.pattern, c.path, got, c.want)
		}
	}
	for _, bad := range []string{"../x", "a/../../b", "/etc/passwd", `C:\Windows`, "c:/x", `..\x`, "", "~/.ssh", "a/[", "x\x00y"} {
		if err := ValidatePattern(bad); err == nil {
			t.Errorf("ValidatePattern(%q) should fail", bad)
		}
	}
	for _, ok := range []string{"src/**", "*.py", "a/b/*.ts", "docs/"} {
		if err := ValidatePattern(ok); err != nil {
			t.Errorf("ValidatePattern(%q): %v", ok, err)
		}
	}
}

func TestWalkIncludeExclude(t *testing.T) {
	root := writeTree(t, map[string]string{"src/a.py": "x\n", "src/gen/b.py": "x\n", "docs/c.md": "x\n", "main.py": "x\n"})
	inv := walk(t, Options{Root: root, Include: []string{"src/**", "main.py"}, Exclude: []string{"src/gen"}})
	if got := strings.Join(paths(inv), ","); got != "main.py,src/a.py" {
		t.Fatalf("unexpected inventory: %s", got)
	}
	for _, bad := range [][]string{{"../outside/**"}, {"/abs"}} {
		if _, err := Walk(context.Background(), Options{Root: root, Include: bad}); err == nil {
			t.Errorf("include %v should be rejected", bad)
		}
		if _, err := Walk(context.Background(), Options{Root: root, Exclude: bad}); err == nil {
			t.Errorf("exclude %v should be rejected", bad)
		}
	}
}

func TestWalkDeterministicUnicodeForwardSlash(t *testing.T) {
	root := writeTree(t, map[string]string{
		"b/z.py": "x\n", "a/y.py": "x\n", "caf\u00e9/\u30a8\u30fc\u30b8\u30a7\u30f3\u30c8.py": "x\n", "a/b/c.py": "x\n", "Z.py": "x\n",
	})
	first := paths(walk(t, Options{Root: root}))
	second := paths(walk(t, Options{Root: root}))
	if strings.Join(first, "|") != strings.Join(second, "|") {
		t.Fatalf("order differs between runs: %v vs %v", first, second)
	}
	want := "Z.py|a/b/c.py|a/y.py|b/z.py|caf\u00e9/\u30a8\u30fc\u30b8\u30a7\u30f3\u30c8.py"
	if got := strings.Join(first, "|"); got != want {
		t.Fatalf("got %s, want %s", got, want)
	}
	for _, p := range first {
		if strings.Contains(p, `\`) {
			t.Errorf("path %q must use forward slashes", p)
		}
	}
}

func TestWalkRejectsBadRoot(t *testing.T) {
	root := writeTree(t, map[string]string{"file.txt": "x"})
	if _, err := Walk(context.Background(), Options{Root: filepath.Join(root, "file.txt")}); err == nil {
		t.Error("a file is not a valid scan root")
	}
	if _, err := Walk(context.Background(), Options{Root: filepath.Join(root, "missing")}); err == nil {
		t.Error("a missing directory is not a valid scan root")
	}
}

func TestReadCommit(t *testing.T) {
	const sha1 = "0123456789abcdef0123456789abcdef01234567"
	const sha2 = "89abcdef0123456789abcdef0123456789abcdef"
	cases := []struct {
		name  string
		files map[string]string
		want  string
	}{
		{"loose ref", map[string]string{".git/HEAD": "ref: refs/heads/main\n", ".git/refs/heads/main": sha1 + "\n"}, sha1},
		{"packed ref", map[string]string{".git/HEAD": "ref: refs/heads/feature/x\n",
			".git/packed-refs": "# pack-refs with: peeled fully-peeled sorted\n" + sha1 + " refs/heads/main\n" + sha2 + " refs/heads/feature/x\n^" + sha1 + "\n"}, sha2},
		{"detached head", map[string]string{".git/HEAD": sha2 + "\n"}, sha2},
		{"worktree git file", map[string]string{".git": "gitdir: /somewhere/else/.git/worktrees/x\n"}, model.Unknown},
		{"unborn branch", map[string]string{".git/HEAD": "ref: refs/heads/main\n"}, model.Unknown},
		{"garbage head", map[string]string{".git/HEAD": "not a ref\n"}, model.Unknown},
		{"ref escaping the git dir", map[string]string{".git/HEAD": "ref: refs/../../outside\n", "outside": sha1 + "\n"}, model.Unknown},
		{"malformed loose ref", map[string]string{".git/HEAD": "ref: refs/heads/main\n", ".git/refs/heads/main": "zzzz\n"}, model.Unknown},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			root := writeTree(t, c.files)
			if got := ReadCommit(root); got != c.want {
				t.Fatalf("ReadCommit = %q, want %q", got, c.want)
			}
		})
	}
	t.Run("subdirectory of a repository", func(t *testing.T) {
		root := writeTree(t, map[string]string{".git/HEAD": sha1 + "\n", "services/api/main.py": "x\n"})
		if got := ReadCommit(filepath.Join(root, "services", "api")); got != sha1 {
			t.Fatalf("ReadCommit from a subdirectory = %q, want %q", got, sha1)
		}
	})
	t.Run("not a repository", func(t *testing.T) {
		root := writeTree(t, map[string]string{"a.py": "x\n"})
		// The temporary directory is not expected to sit inside a repository.
		if got := ReadCommit(root); got != model.Unknown {
			t.Skipf("temporary directory appears to be inside a repository (commit %s)", got)
		}
	})
}
