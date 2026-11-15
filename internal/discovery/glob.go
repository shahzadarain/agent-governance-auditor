// SPDX-License-Identifier: Apache-2.0

package discovery

import (
	"fmt"
	"path"
	"strings"
)

// ValidatePattern rejects include and exclude patterns that could address
// anything outside the scan root.
func ValidatePattern(p string) error {
	if strings.TrimSpace(p) == "" {
		return fmt.Errorf("empty pattern")
	}
	if strings.ContainsRune(p, 0) {
		return fmt.Errorf("pattern %q contains a NUL byte", p)
	}
	n := strings.ReplaceAll(p, "\\", "/")
	if strings.HasPrefix(n, "/") || strings.HasPrefix(n, "~") {
		return fmt.Errorf("pattern %q is absolute; patterns must be relative to the scan root", p)
	}
	if len(n) >= 2 && n[1] == ':' {
		return fmt.Errorf("pattern %q names a drive; patterns must be relative to the scan root", p)
	}
	for _, seg := range strings.Split(n, "/") {
		if seg == ".." {
			return fmt.Errorf("pattern %q contains \"..\"; patterns cannot leave the scan root", p)
		}
	}
	if _, err := path.Match(strings.ReplaceAll(n, "**", "*"), "x"); err != nil {
		return fmt.Errorf("pattern %q is not a valid glob", p)
	}
	return nil
}

// normalizePattern converts a pattern to forward slashes and drops a leading
// "./" and a trailing "/".
func normalizePattern(p string) string {
	n := strings.ReplaceAll(strings.TrimSpace(p), "\\", "/")
	n = strings.TrimPrefix(n, "./")
	n = strings.TrimSuffix(n, "/")
	return n
}

// MatchGlob reports whether the repo-relative, forward-slash path matches the
// pattern. "**" matches any number of path segments. A pattern without a
// slash matches a file or directory name at any depth. A pattern that matches
// a directory also matches everything below it.
func MatchGlob(pattern, rel string) bool {
	pattern = normalizePattern(pattern)
	if pattern == "" {
		return false
	}
	segs := strings.Split(rel, "/")
	if !strings.Contains(pattern, "/") {
		for _, s := range segs {
			if ok, _ := path.Match(pattern, s); ok {
				return true
			}
		}
		return false
	}
	pat := strings.Split(pattern, "/")
	// A match of any leading part of the path covers the whole subtree.
	for end := len(segs); end >= 1; end-- {
		if matchSegs(pat, segs[:end]) {
			return true
		}
	}
	return false
}

func matchSegs(pat, segs []string) bool {
	for len(pat) > 0 {
		if pat[0] == "**" {
			if len(pat) == 1 {
				return true
			}
			for i := 0; i <= len(segs); i++ {
				if matchSegs(pat[1:], segs[i:]) {
					return true
				}
			}
			return false
		}
		if len(segs) == 0 {
			return false
		}
		if ok, _ := path.Match(pat[0], segs[0]); !ok {
			return false
		}
		pat, segs = pat[1:], segs[1:]
	}
	return len(segs) == 0
}
