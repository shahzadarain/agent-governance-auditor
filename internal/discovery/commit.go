// SPDX-License-Identifier: Apache-2.0

package discovery

import (
	"io"
	"os"
	"path/filepath"
	"regexp"
	"strings"

	"github.com/shahzadarain/agent-governance-auditor/internal/model"
)

var shaRe = regexp.MustCompile(`^[0-9a-f]{40}([0-9a-f]{24})?$`)
var refNameRe = regexp.MustCompile(`^refs/[A-Za-z0-9._/@+-]+$`)

// ReadCommit returns the commit SHA checked out in the repository that
// contains root. It never runs git: it parses .git/HEAD, loose refs, and
// packed-refs. It returns model.Unknown when root is not inside a repository,
// when .git is a file (a linked worktree or submodule), or when anything
// looks malformed.
func ReadCommit(root string) string {
	abs, err := filepath.Abs(root)
	if err != nil {
		return model.Unknown
	}
	dir := abs
	for i := 0; i < 64; i++ {
		gitPath := filepath.Join(dir, ".git")
		if fi, err := os.Lstat(gitPath); err == nil {
			if !fi.IsDir() || fi.Mode()&os.ModeSymlink != 0 {
				return model.Unknown
			}
			return readCommitFromGitDir(gitPath)
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			break
		}
		dir = parent
	}
	return model.Unknown
}

func readSmall(p string, limit int64) (string, bool) {
	fi, err := os.Lstat(p)
	if err != nil || !fi.Mode().IsRegular() {
		return "", false
	}
	f, err := os.Open(p)
	if err != nil {
		return "", false
	}
	defer f.Close()
	b, err := io.ReadAll(io.LimitReader(f, limit))
	if err != nil {
		return "", false
	}
	return string(b), true
}

func readCommitFromGitDir(gitDir string) string {
	head, ok := readSmall(filepath.Join(gitDir, "HEAD"), 4096)
	if !ok {
		return model.Unknown
	}
	head = strings.TrimSpace(head)
	if shaRe.MatchString(head) {
		return head
	}
	if !strings.HasPrefix(head, "ref:") {
		return model.Unknown
	}
	ref := strings.TrimSpace(strings.TrimPrefix(head, "ref:"))
	if !refNameRe.MatchString(ref) || strings.Contains(ref, "..") {
		return model.Unknown
	}
	if loose, ok := readSmall(filepath.Join(gitDir, filepath.FromSlash(ref)), 4096); ok {
		v := strings.TrimSpace(loose)
		if shaRe.MatchString(v) {
			return v
		}
		return model.Unknown
	}
	packed, ok := readSmall(filepath.Join(gitDir, "packed-refs"), 16<<20)
	if !ok {
		return model.Unknown
	}
	for _, line := range strings.Split(packed, "\n") {
		line = strings.TrimSpace(line)
		if line == "" || line[0] == '#' || line[0] == '^' {
			continue
		}
		parts := strings.Fields(line)
		if len(parts) == 2 && parts[1] == ref && shaRe.MatchString(parts[0]) {
			return parts[0]
		}
	}
	return model.Unknown
}
