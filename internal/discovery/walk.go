// SPDX-License-Identifier: Apache-2.0

// Package discovery builds a read-only, bounded inventory of a directory.
// It never executes anything, never follows a link out of the scan root,
// never unpacks archives, and never reads the content of files that look
// like secret stores.
package discovery

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
)

// Defaults for the walk bounds.
const (
	DefaultMaxFileSize   int64 = 1 << 20   // 1 MiB
	DefaultMaxFiles            = 50000     //
	DefaultMaxTotalBytes int64 = 256 << 20 // 256 MiB of content held in memory
	DefaultMaxDepth            = 40        //
	binarySniffLen             = 8 << 10   // 8 KiB
)

// DefaultExcludes are directory names that are never entered.
var DefaultExcludes = []string{
	".git", "node_modules", "vendor", ".venv", "venv", "__pycache__", "dist",
	"build", "target", ".next", ".tox", ".mypy_cache", "site-packages",
	".terraform", "coverage",
}

// Skip reasons recorded on File.Skipped.
const (
	SkipSecretStore = "secret-store"
	SkipTooLarge    = "too-large"
	SkipBinary      = "binary"
	SkipUnreadable  = "unreadable"
	SkipByteBudget  = "byte-budget"
)

// Options configures a walk. Zero values select the defaults.
type Options struct {
	Root          string
	MaxFileSize   int64
	MaxFiles      int
	MaxTotalBytes int64
	MaxDepth      int
	Include       []string // when set, only matching files are listed
	Exclude       []string // added to the default excludes
}

// File is one inventoried file. Content is nil when Skipped is set.
type File struct {
	Path    string // repo-relative, forward slashes
	Size    int64
	Content []byte
	Skipped string // "" when the content was read
}

// Inventory is the result of a walk. Files are sorted by Path.
type Inventory struct {
	Root         string // absolute, symlink-resolved root
	Files        []File
	Warnings     []string
	FilesScanned int
	FilesSkipped int
	BytesRead    int64
	Truncated    bool // a bound stopped the walk early
	byPath       map[string]int
}

// Get returns the file with the given repo-relative path.
func (inv *Inventory) Get(rel string) (*File, bool) {
	i, ok := inv.byPath[rel]
	if !ok {
		return nil, false
	}
	return &inv.Files[i], true
}

// Has reports whether a file with the given path exists in the inventory,
// whether or not its content was read.
func (inv *Inventory) Has(rel string) bool {
	_, ok := inv.byPath[rel]
	return ok
}

// IsSecretStoreName reports whether a file name looks like a secret store
// whose content must not be read.
func IsSecretStoreName(name string) bool {
	l := strings.ToLower(name)
	switch l {
	case ".env.example", ".env.sample", ".env.template", ".env.dist":
		return false
	case ".env", ".netrc", ".pgpass", "credentials.json", "secrets.json":
		return true
	}
	if strings.HasPrefix(l, ".env.") || strings.HasPrefix(l, "id_rsa") || strings.HasPrefix(l, "id_ed25519") ||
		strings.HasPrefix(l, "id_ecdsa") || strings.HasPrefix(l, "id_dsa") {
		return true
	}
	if strings.HasSuffix(l, ".env") && !strings.HasSuffix(l, ".example.env") {
		return true
	}
	for _, suf := range []string{".pem", ".key", ".p12", ".pfx", ".jks", ".keystore"} {
		if strings.HasSuffix(l, suf) {
			return true
		}
	}
	return false
}

type walker struct {
	ctx      context.Context
	opts     Options
	root     string
	inv      *Inventory
	excluded map[string]bool
	total    int64
}

// Walk inventories opts.Root. It returns an error only when the root cannot
// be used at all or a pattern is unsafe; everything else becomes a warning.
func Walk(ctx context.Context, opts Options) (*Inventory, error) {
	if opts.MaxFileSize <= 0 {
		opts.MaxFileSize = DefaultMaxFileSize
	}
	if opts.MaxFiles <= 0 {
		opts.MaxFiles = DefaultMaxFiles
	}
	if opts.MaxTotalBytes <= 0 {
		opts.MaxTotalBytes = DefaultMaxTotalBytes
	}
	if opts.MaxDepth <= 0 {
		opts.MaxDepth = DefaultMaxDepth
	}
	for _, p := range append(append([]string{}, opts.Include...), opts.Exclude...) {
		if err := ValidatePattern(p); err != nil {
			return nil, err
		}
	}
	abs, err := filepath.Abs(opts.Root)
	if err != nil {
		return nil, fmt.Errorf("resolve scan root: %w", err)
	}
	real, err := filepath.EvalSymlinks(abs)
	if err != nil {
		return nil, fmt.Errorf("resolve scan root: %w", err)
	}
	fi, err := os.Stat(real)
	if err != nil {
		return nil, fmt.Errorf("read scan root: %w", err)
	}
	if !fi.IsDir() {
		return nil, fmt.Errorf("scan root %q is not a directory", filepath.Base(real))
	}
	w := &walker{ctx: ctx, opts: opts, root: real, inv: &Inventory{Root: real}, excluded: map[string]bool{}}
	for _, d := range DefaultExcludes {
		w.excluded[d] = true
	}
	walkErr := w.dir(real, "", 0)
	sort.Slice(w.inv.Files, func(i, j int) bool { return w.inv.Files[i].Path < w.inv.Files[j].Path })
	w.inv.byPath = make(map[string]int, len(w.inv.Files))
	for i, f := range w.inv.Files {
		w.inv.byPath[f.Path] = i
	}
	sort.Strings(w.inv.Warnings)
	if walkErr != nil {
		return w.inv, walkErr
	}
	return w.inv, nil
}

func (w *walker) warn(format string, a ...any) {
	if len(w.inv.Warnings) < 500 {
		w.inv.Warnings = append(w.inv.Warnings, fmt.Sprintf(format, a...))
	}
}

func (w *walker) userExcluded(rel string) bool {
	for _, p := range w.opts.Exclude {
		if MatchGlob(p, rel) {
			return true
		}
	}
	return false
}

func (w *walker) included(rel string) bool {
	if len(w.opts.Include) == 0 {
		return true
	}
	for _, p := range w.opts.Include {
		if MatchGlob(p, rel) {
			return true
		}
	}
	return false
}

// inside reports whether the absolute path p is the root or below it.
func (w *walker) inside(p string) bool {
	rel, err := filepath.Rel(w.root, p)
	if err != nil {
		return false
	}
	return rel == "." || (rel != ".." && !strings.HasPrefix(rel, ".."+string(filepath.Separator)) && !filepath.IsAbs(rel))
}

func (w *walker) dir(abs, rel string, depth int) error {
	if err := w.ctx.Err(); err != nil {
		return err
	}
	if depth > w.opts.MaxDepth {
		w.warn("%s: skipped, deeper than the maximum depth of %d", rel, w.opts.MaxDepth)
		w.inv.Truncated = true
		return nil
	}
	entries, err := os.ReadDir(abs)
	if err != nil {
		w.warn("%s: directory is not readable", displayRel(rel))
		return nil
	}
	sort.Slice(entries, func(i, j int) bool { return entries[i].Name() < entries[j].Name() })
	for _, e := range entries {
		if err := w.ctx.Err(); err != nil {
			return err
		}
		name := e.Name()
		childRel := name
		if rel != "" {
			childRel = rel + "/" + name
		}
		childAbs := filepath.Join(abs, name)
		fi, err := os.Lstat(childAbs)
		if err != nil {
			w.warn("%s: not readable", childRel)
			continue
		}
		mode := fi.Mode()
		if mode&os.ModeSymlink != 0 || mode&os.ModeIrregular != 0 {
			w.link(childAbs, childRel, depth)
			continue
		}
		if mode.IsDir() {
			if w.excluded[name] || w.userExcluded(childRel) {
				continue
			}
			if err := w.dir(childAbs, childRel, depth+1); err != nil {
				return err
			}
			continue
		}
		if !mode.IsRegular() {
			continue // devices, sockets, pipes
		}
		if w.userExcluded(childRel) || !w.included(childRel) {
			continue
		}
		if stop := w.file(childAbs, childRel, fi.Size()); stop {
			return nil
		}
	}
	return nil
}

func displayRel(rel string) string {
	if rel == "" {
		return "."
	}
	return rel
}

// link handles a symbolic link or another reparse point. A link is used only
// when it resolves to a regular file inside the root. Directory links are
// never followed: a target inside the root is scanned at its real path, and
// following it could loop.
func (w *walker) link(abs, rel string, depth int) {
	target, err := filepath.EvalSymlinks(abs)
	if err != nil {
		w.warn("%s: link skipped, it is broken or forms a cycle", rel)
		w.inv.FilesSkipped++
		return
	}
	if !w.inside(target) {
		w.warn("%s: link skipped, it resolves outside the scan root", rel)
		w.inv.FilesSkipped++
		return
	}
	fi, err := os.Stat(target)
	if err != nil {
		w.warn("%s: link skipped, the target is not readable", rel)
		w.inv.FilesSkipped++
		return
	}
	if fi.IsDir() {
		linkParent := filepath.Dir(abs)
		if realParent, err := filepath.EvalSymlinks(linkParent); err == nil {
			if r, err := filepath.Rel(target, realParent); err == nil && (r == "." || !strings.HasPrefix(r, "..")) {
				w.warn("%s: link skipped, it points at one of its own parent directories (cycle)", rel)
				w.inv.FilesSkipped++
				return
			}
		}
		w.warn("%s: directory link not followed; the target is scanned at its real path", rel)
		w.inv.FilesSkipped++
		return
	}
	if !fi.Mode().IsRegular() {
		return
	}
	if w.userExcluded(rel) || !w.included(rel) {
		return
	}
	w.file(target, rel, fi.Size())
}

// file records one regular file. It returns true when the file-count bound
// stopped the walk.
func (w *walker) file(abs, rel string, size int64) (stop bool) {
	if len(w.inv.Files) >= w.opts.MaxFiles {
		if !w.inv.Truncated {
			w.warn("scan stopped after %d files; the remaining files were not scanned", w.opts.MaxFiles)
		}
		w.inv.Truncated = true
		return true
	}
	f := File{Path: rel, Size: size}
	name := rel[strings.LastIndex(rel, "/")+1:]
	switch {
	case IsSecretStoreName(name):
		f.Skipped = SkipSecretStore
	case size > w.opts.MaxFileSize:
		f.Skipped = SkipTooLarge
		w.warn("%s: skipped, larger than the per-file limit of %d bytes", rel, w.opts.MaxFileSize)
	case w.total+size > w.opts.MaxTotalBytes:
		f.Skipped = SkipByteBudget
		if !w.inv.Truncated {
			w.warn("%s: skipped, the total byte budget of %d bytes is used up; later files were not read", rel, w.opts.MaxTotalBytes)
		}
		w.inv.Truncated = true
	default:
		data, err := readBounded(abs, w.opts.MaxFileSize)
		switch {
		case err != nil:
			f.Skipped = SkipUnreadable
			w.warn("%s: skipped, not readable", rel)
		case isBinary(data):
			f.Skipped = SkipBinary
		default:
			f.Content = data
			w.total += int64(len(data))
		}
	}
	if f.Skipped != "" {
		w.inv.FilesSkipped++
	} else {
		w.inv.FilesScanned++
		w.inv.BytesRead += int64(len(f.Content))
	}
	w.inv.Files = append(w.inv.Files, f)
	return false
}

func readBounded(abs string, limit int64) ([]byte, error) {
	fh, err := os.Open(abs)
	if err != nil {
		return nil, err
	}
	defer fh.Close()
	data, err := io.ReadAll(io.LimitReader(fh, limit+1))
	if err != nil {
		return nil, err
	}
	if int64(len(data)) > limit {
		return nil, fmt.Errorf("file grew past the size limit")
	}
	if data == nil {
		data = []byte{}
	}
	return data, nil
}

func isBinary(data []byte) bool {
	n := len(data)
	if n > binarySniffLen {
		n = binarySniffLen
	}
	return bytes.IndexByte(data[:n], 0) >= 0
}
