# Implementation plan

This plan is the working contract for building AgentGov Auditor. It records the
assumptions, the package boundaries, and the function signatures that let the
parts be built and tested independently.

## Assumptions

- Module path: `github.com/shahzadarain/agent-governance-auditor`. Owner taken
  from the authenticated GitHub account on the build machine.
- Go 1.27 toolchain. No cgo anywhere, so every platform cross-compiles from one
  machine.
- Deviation from the specification: tree-sitter needs cgo, which would break
  single-command cross-compilation and `go install`. Python and
  JavaScript/TypeScript are analyzed by purpose-built lexers in pure Go that
  strip comments and string literals before matching, resolve import aliases,
  and sit behind an adapter interface so a full parser can replace them later.
  The limitation is documented in `docs/known-limitations.md`.
- SQLite through `modernc.org/sqlite` (pure Go). PostgreSQL through `pgx` is
  wired but labeled experimental until it is tested against a real database.
- The build machine has no Docker and no Make. Compose files ship untested and
  are labeled so. `scripts/check.ps1` and `scripts/check-all.sh` mirror
  `make check`.

## Dependencies (fixed; do not add others without review)

`spf13/cobra`, `gopkg.in/yaml.v3`, `santhosh-tekuri/jsonschema/v6`,
`modernc.org/sqlite`, `jackc/pgx/v5`, `golang.org/x/crypto`,
`golang.org/x/term`, and the Go standard library.

## Data flow

```text
repository -> detect.Run -> model.Detection
                              |  agents, evidence, findings
catalog + profile + config -> policy.Evaluate -> assessments, score, decision
                              |
                        scanner.Scan -> model.ScanResult -> reporting.Render
                                                         -> server ingestion
```

## Package ownership and public signatures

All shared types live in `internal/model` and `internal/config/types.go`. Those
two files are frozen; a change request goes to the lead.

### Detection engine

Packages: `internal/discovery`, `internal/adapters`, `internal/rules`,
`internal/evidence`, `internal/detect`, plus `examples/` and `tests/fixtures/`.

```go
package detect

type Options struct {
    Root           string            // directory to scan
    Config         *config.Config    // may be nil
    ScannerVersion string
    PolicyVersion  string
    MaxFileSize    int64             // bytes; 0 means default (1 MiB)
    Include        []string
    Exclude        []string
    Now            time.Time         // injected clock for determinism
    TrustedKeys    []ed25519.PublicKey // keys that may verify signed evidence
}

func Run(ctx context.Context, opts Options) (*model.Detection, error)
```

```go
package evidence

// SubjectDigest returns the lowercase hex SHA-256 binding for the given
// repo-relative paths (sorted; each contributes path, NUL, content hash).
func SubjectDigest(root string, paths []string) (string, error)

// LoadDir reads external evidence JSON files and sets Validity and Integrity.
func LoadDir(root, dir string, commit string, now time.Time, keys []ed25519.PublicKey) ([]model.Evidence, []string)

// Sign and Verify implement detached Ed25519 signatures over canonical JSON.
func Sign(ev model.Evidence, key ed25519.PrivateKey) (string, error)
func Verify(ev model.Evidence, sig string, keys []ed25519.PublicKey) bool
```

### Governance logic

Packages: `policies/` (embedded YAML and JSON Schema), `internal/controls`,
`internal/config` (loader), `internal/scoring`, `internal/policy`.

```go
package controls
func Load() (*model.Catalog, error)                 // embedded builtin/v1
func Find(cat *model.Catalog, id string) (model.Control, bool)

package config
func Load(root, explicitPath string) (*Config, []string, error) // nil config when absent
func Validate(data []byte) []string                             // human-readable diagnostics

package policy
func LoadProfile(name string) (*model.Profile, error)
func ProfileNames() []string
func LoadBaseline(path string) (*model.Profile, error) // organization baseline from outside the repo
func Effective(base *model.Profile, cfg *config.Config, baseline *model.Profile) *model.Profile // can only tighten

type Input struct {
    Detection *model.Detection
    Catalog   *model.Catalog
    Profile   *model.Profile
    Config    *config.Config
    Now       time.Time
}
func Evaluate(in Input) (assessments []model.AgentAssessment, score model.Score, decision model.Decision)
```

Status derivation, in precedence order, for each agent and control, using only
evidence with `validity == valid`:

1. Any `signal: error` gives `error`.
2. Any `signal: violation` gives `failed`.
3. Approved exception in configuration gives `not-applicable` or
   `accepted-risk`.
4. Capability-mode control with no triggering capability detected gives
   `not-applicable` with basis `inferred`.
5. Strongest `signal: present` evidence gives `verified-operational`,
   `verified-tested`, or `verified-implementation`. Levels 3 and 4 need
   `integrity: verified` when the profile sets `require_signed_evidence`.
6. Only `signal: declared` gives `declared-only`.
7. Only `signal: absent` gives `missing`.
8. Nothing gives `unknown`. When evidence existed but was not valid, the reason
   names the cause (expired, commit mismatch, digest mismatch, bad signature).

Decision: `BLOCK` when a mandatory applicable control is `failed`, `error`,
`missing`, `unknown`, or below the minimum maturity. `REVIEW_REQUIRED` when the
only shortfalls are accepted risks or inferred not-applicable on mandatory
controls, when no agent was detected, or when the profile enables a review
workflow for non-failure shortfalls. Otherwise `ALLOW`. The score never changes
the decision.

### Reporting

Package: `internal/reporting`, plus `policies/schema/scan-result.schema.json`.

```go
package reporting

type Options struct {
    Color       bool
    Full        bool // full control matrix in terminal output
    SummaryOnly bool
    Width       int
}
func Formats() []string // terminal, json, markdown, html, sarif
func Render(w io.Writer, res *model.ScanResult, format string, opts Options) error
func Compare(before, after *model.ScanResult) *model.Comparison
func RenderComparison(w io.Writer, c *model.Comparison, format string, opts Options) error // terminal, json, markdown
```

### Server and storage

Packages: `internal/server`, `internal/storage`, plus `api/openapi.yaml`.

```go
package server

type Config struct {
    Listen       string // default 127.0.0.1:8080
    DatabaseURL  string // sqlite file path or postgres:// URL
    AllowPublic  bool   // required to bind a non-loopback address
    UI           fs.FS  // built dashboard; nil serves a minimal fallback page
    Version      string
    Logger       *slog.Logger
}
func Run(ctx context.Context, cfg Config) error
func NewHandler(cfg Config, store storage.Store) (http.Handler, error) // for tests
```

### Lead

`cmd/agentgov`, `internal/scanner`, `action.yml`, workflows, release
packaging, integration, verification, and documentation review.

## Sequence

1. Contract: module, model, configuration types (done first).
2. Parallel: detection engine, governance logic, reporting, server.
3. Integrate: scanner and CLI; run fixtures; fix what the real output shows.
4. Parallel: dashboard, documentation and community files, CI and release.
5. Verify end to end; record status in `docs/IMPLEMENTATION_STATUS.md`.
