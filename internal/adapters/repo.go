// SPDX-License-Identifier: Apache-2.0

package adapters

import (
	"context"
	"path"
	"regexp"
	"sort"
	"strings"

	"github.com/shahzadarain/agent-governance-auditor/internal/discovery"
)

// Repo is the analyzed form of an inventory: sources, structured documents,
// manifests, and infrastructure files.
type Repo struct {
	Inv         *discovery.Inventory
	Sources     []*Source          // sorted by path
	Docs        []*Doc             // sorted by path, then index
	Deps        []Dependency       // from dependency manifests
	Lockfiles   []string           // lockfile paths present
	LockVersion map[string]string  // "dir|package" -> version from a lockfile
	MCP         []MCPServer        //
	Dockerfiles []*Dockerfile      //
	Malformed   map[string]string  // path -> reason
	Warnings    []string           //
	srcByPath   map[string]*Source //
	docsByPath  map[string][]*Doc  //
}

// Dependency is one declared package dependency.
type Dependency struct {
	Name   string // normalized: lower case, "_" and "." become "-" for Python
	Spec   string
	Pinned bool
	Hashed bool
	Dev    bool
	Eco    string // pypi | npm
	Path   string // manifest path
	Line   int
}

// MCPServer is one server entry from an MCP client configuration file. Only
// the command name and package are kept; arguments and environment values
// are never stored.
type MCPServer struct {
	Name      string
	Transport string // stdio | http | sse | unknown
	Target    string // command name plus package, or host
	Package   string // registry package without version; "" when not a registry package
	Version   string
	Pinned    bool
	Registry  bool // launched from a package registry or image registry
	Path      string
	Line      int
	Allowed   bool // the entry carries an allowedTools-style restriction
}

// Dockerfile is the parsed form of a Dockerfile.
type Dockerfile struct {
	Path     string
	Froms    []DockerFrom
	User     string // last USER instruction of the final stage; "" when none
	UserLine int
	Lines    []DockerInstr
}

// DockerFrom is one FROM instruction.
type DockerFrom struct {
	Image  string
	Line   int
	Digest bool
	Tag    string
}

// DockerInstr is one instruction line.
type DockerInstr struct {
	Op   string
	Args string
	Line int
}

var lockfileNames = map[string]bool{
	"poetry.lock": true, "uv.lock": true, "package-lock.json": true, "pnpm-lock.yaml": true,
	"yarn.lock": true, "Pipfile.lock": true, "pdm.lock": true, "bun.lockb": true, "bun.lock": true,
	"npm-shrinkwrap.json": true,
}

// Source returns the analyzed source at path.
func (r *Repo) Source(p string) *Source { return r.srcByPath[p] }

// DocsAt returns the parsed documents of the file at path.
func (r *Repo) DocsAt(p string) []*Doc { return r.docsByPath[p] }

// Analyze runs the language and configuration adapters over an inventory.
func Analyze(ctx context.Context, inv *discovery.Inventory) *Repo {
	r := &Repo{Inv: inv, Malformed: map[string]string{}, srcByPath: map[string]*Source{},
		docsByPath: map[string][]*Doc{}, LockVersion: map[string]string{}}
	py, js := PythonAnalyzer{}, JSAnalyzer{}
	for i := range inv.Files {
		if ctx.Err() != nil {
			r.Warnings = append(r.Warnings, "analysis stopped early: the scan was cancelled or timed out")
			break
		}
		f := &inv.Files[i]
		base := path.Base(f.Path)
		ext := strings.ToLower(path.Ext(base))
		if lockfileNames[base] {
			r.Lockfiles = append(r.Lockfiles, f.Path)
		}
		if f.Skipped != "" {
			continue
		}
		func() {
			defer func() {
				if rec := recover(); rec != nil {
					r.Malformed[f.Path] = "analyzer failure"
					r.Warnings = append(r.Warnings, f.Path+": could not be analyzed; the file was skipped")
				}
			}()
			switch {
			case ext == ".py" || ext == ".pyi":
				r.addSource(py.Analyze(f.Path, f.Content))
			case hasExt(ext, js.Extensions()):
				if !strings.HasSuffix(base, ".min.js") && !strings.HasSuffix(base, ".d.ts") {
					r.addSource(js.Analyze(f.Path, f.Content))
				}
			case ext == ".yml" || ext == ".yaml":
				docs, err := ParseYAML(f.Path, f.Content)
				if err != nil {
					r.malformed(f.Path, "malformed YAML")
					return
				}
				r.addDocs(f.Path, docs)
			case ext == ".json":
				d, err := ParseJSON(f.Path, f.Content)
				if err != nil {
					r.malformed(f.Path, "malformed JSON")
					return
				}
				r.addDocs(f.Path, []*Doc{d})
			case ext == ".toml" || base == "poetry.lock" || base == "uv.lock":
				d, err := ParseTOML(f.Path, f.Content)
				if err != nil {
					r.malformed(f.Path, "malformed TOML")
					return
				}
				r.addDocs(f.Path, []*Doc{d})
			case IsDockerfileName(base):
				r.Dockerfiles = append(r.Dockerfiles, parseDockerfile(f.Path, f.Content))
			}
			if isRequirementsName(base) {
				r.Deps = append(r.Deps, parseRequirements(f.Path, f.Content)...)
			}
		}()
	}
	for _, d := range r.Docs {
		base := path.Base(d.Path)
		switch {
		case base == "pyproject.toml":
			r.Deps = append(r.Deps, pyprojectDeps(d)...)
		case base == "package.json":
			r.Deps = append(r.Deps, packageJSONDeps(d)...)
		case base == "poetry.lock" || base == "uv.lock":
			dir := path.Dir(d.Path)
			for _, e := range d.Match(lockNameRe) {
				if v, ok := d.Get(strings.TrimSuffix(e.Path, ".name") + ".version"); ok {
					r.LockVersion[dir+"|"+NormalizePyName(e.Value)] = v
				}
			}
		case base == "package-lock.json":
			dir := path.Dir(d.Path)
			for _, e := range d.Entries {
				if e.Kind == 's' && strings.HasPrefix(e.Path, "packages.node_modules/") && strings.HasSuffix(e.Path, ".version") {
					name := strings.TrimSuffix(strings.TrimPrefix(e.Path, "packages.node_modules/"), ".version")
					if !strings.Contains(name, "node_modules/") {
						r.LockVersion[dir+"|"+name] = e.Value
					}
				}
			}
		}
		if IsMCPConfigPath(d.Path) {
			r.MCP = append(r.MCP, mcpServers(d)...)
		}
	}
	sort.Strings(r.Lockfiles)
	sort.Strings(r.Warnings)
	sort.SliceStable(r.Deps, func(i, j int) bool {
		if r.Deps[i].Path != r.Deps[j].Path {
			return r.Deps[i].Path < r.Deps[j].Path
		}
		return r.Deps[i].Line < r.Deps[j].Line
	})
	return r
}

var lockNameRe = regexp.MustCompile(`^package\[\d+\]\.name$`)

func hasExt(ext string, list []string) bool {
	for _, e := range list {
		if e == ext {
			return true
		}
	}
	return false
}

func (r *Repo) malformed(p, why string) {
	r.Malformed[p] = why
	r.Warnings = append(r.Warnings, p+": "+why+"; the file was not used as evidence")
}

func (r *Repo) addSource(s *Source) {
	r.Sources = append(r.Sources, s)
	r.srcByPath[s.Path] = s
	r.Warnings = append(r.Warnings, s.Warnings...)
}

func (r *Repo) addDocs(p string, docs []*Doc) {
	r.Docs = append(r.Docs, docs...)
	r.docsByPath[p] = docs
}

// IsDockerfileName reports whether a base name is a Dockerfile.
func IsDockerfileName(base string) bool {
	l := strings.ToLower(base)
	return l == "dockerfile" || strings.HasPrefix(l, "dockerfile.") || strings.HasSuffix(l, ".dockerfile") || l == "containerfile"
}

func isRequirementsName(base string) bool {
	l := strings.ToLower(base)
	return strings.HasPrefix(l, "requirements") && (strings.HasSuffix(l, ".txt") || strings.HasSuffix(l, ".in"))
}

// IsMCPConfigPath reports whether a path is a known MCP client configuration.
func IsMCPConfigPath(p string) bool {
	base := path.Base(p)
	switch base {
	case ".mcp.json", "mcp.json", "claude_desktop_config.json", "mcp_config.json":
		return true
	}
	return false
}

// NormalizePyName normalizes a Python distribution name.
func NormalizePyName(n string) string {
	return strings.ToLower(strings.NewReplacer("_", "-", ".", "-").Replace(strings.TrimSpace(n)))
}

var (
	reqLineRe   = regexp.MustCompile(`^([A-Za-z0-9][A-Za-z0-9._-]*)\s*(?:\[[^\]]*\])?\s*(.*)$`)
	exactVerRe  = regexp.MustCompile(`^={2,3}\s*[0-9][^*,;\s]*$`)
	npmExactRe  = regexp.MustCompile(`^v?\d+\.\d+\.\d+(?:[-+][0-9A-Za-z.-]+)?$`)
	bareVerRe   = regexp.MustCompile(`^\d+(?:\.\d+)*(?:[-+.]?[0-9A-Za-z]+)*$`)
	commitRefRe = regexp.MustCompile(`@[0-9a-f]{40}\b`)
)

func parseRequirements(p string, content []byte) []Dependency {
	var out []Dependency
	lines := strings.Split(strings.ReplaceAll(string(content), "\r\n", "\n"), "\n")
	for i := 0; i < len(lines); i++ {
		lineNo := i + 1
		line := lines[i]
		for strings.HasSuffix(strings.TrimRight(line, " \t"), "\\") && i+1 < len(lines) {
			i++
			line = strings.TrimSuffix(strings.TrimRight(line, " \t"), "\\") + " " + lines[i]
		}
		if j := strings.Index(line, " #"); j >= 0 {
			line = line[:j]
		}
		line = strings.TrimSpace(line)
		if line == "" || line[0] == '#' || line[0] == '-' {
			continue
		}
		hashed := strings.Contains(line, "--hash=")
		if j := strings.Index(line, "--hash="); j >= 0 {
			line = strings.TrimSpace(line[:j])
		}
		if j := strings.Index(line, ";"); j >= 0 {
			line = strings.TrimSpace(line[:j])
		}
		m := reqLineRe.FindStringSubmatch(line)
		if m == nil {
			continue
		}
		spec := strings.TrimSpace(m[2])
		pinned := exactVerRe.MatchString(spec) || (strings.HasPrefix(spec, "@") && commitRefRe.MatchString(spec))
		out = append(out, Dependency{Name: NormalizePyName(m[1]), Spec: spec, Pinned: pinned, Hashed: hashed, Eco: "pypi", Path: p, Line: lineNo})
	}
	return out
}

var (
	pyprojDepRe   = regexp.MustCompile(`^(project\.dependencies|project\.optional-dependencies\.[^.\[]+|dependency-groups\.[^.\[]+)\[\d+\]$`)
	poetryDepRe   = regexp.MustCompile(`^tool\.poetry\.(?:dev-)?dependencies\.([^.\[]+)(\.version)?$`)
	poetryGroupRe = regexp.MustCompile(`^tool\.poetry\.group\.[^.]+\.dependencies\.([^.\[]+)(\.version)?$`)
)

func pyprojectDeps(d *Doc) []Dependency {
	var out []Dependency
	for _, e := range d.Entries {
		if e.Kind != 's' {
			continue
		}
		if pyprojDepRe.MatchString(e.Path) {
			line := e.Value
			if j := strings.Index(line, ";"); j >= 0 {
				line = strings.TrimSpace(line[:j])
			}
			if m := reqLineRe.FindStringSubmatch(strings.TrimSpace(line)); m != nil {
				spec := strings.TrimSpace(m[2])
				out = append(out, Dependency{Name: NormalizePyName(m[1]), Spec: spec, Pinned: exactVerRe.MatchString(spec), Eco: "pypi", Path: d.Path, Line: e.Line,
					Dev: !strings.HasPrefix(e.Path, "project.dependencies")})
			}
			continue
		}
		m := poetryDepRe.FindStringSubmatch(e.Path)
		dev := strings.Contains(e.Path, "dev-dependencies")
		if m == nil {
			m = poetryGroupRe.FindStringSubmatch(e.Path)
			dev = true
		}
		if m != nil && m[1] != "python" {
			spec := strings.TrimSpace(e.Value)
			pinned := exactVerRe.MatchString(spec) || bareVerRe.MatchString(spec)
			out = append(out, Dependency{Name: NormalizePyName(m[1]), Spec: spec, Pinned: pinned, Eco: "pypi", Path: d.Path, Line: e.Line, Dev: dev})
		}
	}
	return out
}

func packageJSONDeps(d *Doc) []Dependency {
	var out []Dependency
	for _, e := range d.Entries {
		if e.Kind != 's' {
			continue
		}
		for _, sec := range []string{"dependencies.", "devDependencies.", "optionalDependencies.", "peerDependencies."} {
			if strings.HasPrefix(e.Path, sec) {
				name := e.Path[len(sec):]
				out = append(out, Dependency{Name: name, Spec: e.Value, Pinned: npmExactRe.MatchString(strings.TrimSpace(e.Value)), Eco: "npm",
					Path: d.Path, Line: e.Line, Dev: sec != "dependencies."})
			}
		}
	}
	return out
}

var (
	mcpServerRe   = regexp.MustCompile(`^(?:mcpServers|servers|mcp\.servers)\.([^.\[]+)$`)
	npmPkgRe      = regexp.MustCompile(`^((?:@[A-Za-z0-9._-]+/)?[A-Za-z0-9._-]+)(?:@([A-Za-z0-9._^~-]+))?$`)
	pyPkgRe       = regexp.MustCompile(`^([A-Za-z0-9._-]+)(?:\[[^\]]*\])?(?:==([A-Za-z0-9._-]+))?$`)
	imageRe       = regexp.MustCompile(`^([a-z0-9._/-]+(?::[0-9]+/[a-z0-9._/-]+)?)(?::([A-Za-z0-9._-]+))?(@sha256:[0-9a-f]{64})?$`)
	hostRe        = regexp.MustCompile("^[a-z][a-z0-9+.-]*://(?:[^/?#@]*@)?([^/:?#@]+)")
	dockerValFlag = map[string]bool{"-e": true, "--env": true, "-v": true, "--volume": true, "--name": true, "--network": true,
		"-p": true, "--publish": true, "--mount": true, "-w": true, "--workdir": true, "-u": true, "--user": true, "--env-file": true,
		"--entrypoint": true, "-l": true, "--label": true, "--memory": true, "-m": true, "--cpus": true}
)

func mcpServers(d *Doc) []MCPServer {
	var out []MCPServer
	for _, e := range d.Entries {
		m := mcpServerRe.FindStringSubmatch(e.Path)
		if m == nil || e.Kind != 'm' {
			continue
		}
		srv := MCPServer{Name: m[1], Transport: "unknown", Target: "unknown", Path: d.Path, Line: e.Line}
		base := e.Path
		for _, k := range []string{"allowedTools", "allowed_tools", "tools", "includeTools", "autoApprove"} {
			if d.Has(base+"."+k) && k != "autoApprove" {
				srv.Allowed = true
			}
		}
		if url, ok := d.Get(base + ".url"); ok {
			srv.Transport = "http"
			if t, ok := d.Get(base + ".type"); ok && strings.Contains(strings.ToLower(t), "sse") {
				srv.Transport = "sse"
			} else if strings.HasSuffix(strings.TrimRight(url, "/"), "/sse") {
				srv.Transport = "sse"
			}
			if hm := hostRe.FindStringSubmatch(strings.ToLower(url)); hm != nil {
				srv.Target = hm[1]
			}
			out = append(out, srv)
			continue
		}
		cmd, ok := d.Get(base + ".command")
		if !ok {
			out = append(out, srv)
			continue
		}
		srv.Transport = "stdio"
		cmdFields := strings.Fields(cmd)
		if len(cmdFields) == 0 {
			out = append(out, srv)
			continue
		}
		name := strings.ToLower(path.Base(strings.ReplaceAll(cmdFields[0], "\\", "/")))
		name = strings.TrimSuffix(strings.TrimSuffix(name, ".exe"), ".cmd")
		var args []string
		args = append(args, cmdFields[1:]...)
		for _, a := range d.List(base + ".args") {
			args = append(args, a.Value)
		}
		srv.Target = name
		srv.Pinned = true // a local command is versioned with its repository
		switch name {
		case "npx", "bunx", "pnpm", "yarn", "bun":
			srv.Registry, srv.Pinned = true, false
			for _, a := range args {
				if strings.HasPrefix(a, "-") || a == "dlx" || a == "x" || a == "exec" {
					continue
				}
				if pm := npmPkgRe.FindStringSubmatch(a); pm != nil {
					srv.Package, srv.Target = pm[1], name+" "+pm[1]
					if pm[2] != "" && pm[2][0] >= '0' && pm[2][0] <= '9' && npmExactRe.MatchString(pm[2]) {
						srv.Pinned, srv.Version = true, pm[2]
					}
				}
				break
			}
		case "uvx", "pipx", "uv":
			srv.Registry, srv.Pinned = true, false
			for _, a := range args {
				if a == "run" || a == "tool" || strings.HasPrefix(a, "-") {
					continue
				}
				if pm := pyPkgRe.FindStringSubmatch(a); pm != nil {
					srv.Package, srv.Target = NormalizePyName(pm[1]), name+" "+NormalizePyName(pm[1])
					if pm[2] != "" {
						srv.Pinned, srv.Version = true, pm[2]
					}
				}
				break
			}
		case "docker", "podman":
			srv.Registry, srv.Pinned = true, false
			for i := 0; i < len(args); i++ {
				a := args[i]
				if a == "run" {
					continue
				}
				if strings.HasPrefix(a, "-") {
					if dockerValFlag[a] {
						i++
					}
					continue
				}
				if im := imageRe.FindStringSubmatch(a); im != nil {
					srv.Package, srv.Target = im[1], name+" "+im[1]
					if im[3] != "" {
						srv.Pinned, srv.Version = true, "sha256 digest"
					} else if im[2] != "" && im[2] != "latest" {
						srv.Pinned, srv.Version = true, im[2]
					}
				}
				break
			}
		}
		out = append(out, srv)
	}
	return out
}

func parseDockerfile(p string, content []byte) *Dockerfile {
	df := &Dockerfile{Path: p}
	lines := strings.Split(strings.ReplaceAll(string(content), "\r\n", "\n"), "\n")
	for i := 0; i < len(lines); i++ {
		lineNo := i + 1
		line := strings.TrimSpace(lines[i])
		if line == "" || line[0] == '#' {
			continue
		}
		for strings.HasSuffix(line, "\\") && i+1 < len(lines) {
			i++
			next := strings.TrimSpace(lines[i])
			if strings.HasPrefix(next, "#") {
				continue
			}
			line = strings.TrimSuffix(line, "\\") + " " + next
		}
		fields := strings.Fields(line)
		if len(fields) == 0 {
			continue
		}
		op := strings.ToUpper(fields[0])
		args := strings.TrimSpace(line[len(fields[0]):])
		df.Lines = append(df.Lines, DockerInstr{Op: op, Args: args, Line: lineNo})
		switch op {
		case "FROM":
			img := ""
			for _, f := range fields[1:] {
				if !strings.HasPrefix(f, "--") {
					img = f
					break
				}
			}
			from := DockerFrom{Image: img, Line: lineNo, Digest: strings.Contains(img, "@sha256:")}
			noDigest := strings.SplitN(img, "@", 2)[0]
			if j := strings.LastIndex(noDigest, ":"); j >= 0 && !strings.Contains(noDigest[j:], "/") {
				from.Tag = noDigest[j+1:]
			}
			df.Froms = append(df.Froms, from)
			df.User, df.UserLine = "", 0 // a new stage resets the user
		case "USER":
			if len(fields) > 1 {
				df.User, df.UserLine = fields[1], lineNo
			}
		}
	}
	return df
}
