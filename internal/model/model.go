// SPDX-License-Identifier: Apache-2.0

// Package model defines the single normalized data model for AgentGov
// Auditor. Every detector, the policy engine, every report format, and the
// self-hosted server exchange these types. The JSON form of ScanResult is the
// stable, schema-versioned scan output.
//
// Rules for all producers:
//   - Unknown values stay explicitly unknown (use the Unknown constant for
//     strings); never guess.
//   - Never place secret values, prompt contents, or full file contents in any
//     field. Locations and short redacted summaries only.
//   - Slices are sorted deterministically before a result is returned.
//   - Paths are repository-relative with forward slashes.
package model

import "time"

// SchemaVersion is the version of the ScanResult JSON document.
const SchemaVersion = "1"

// Unknown is the explicit marker for a string value that could not be
// established from the available evidence.
const Unknown = "unknown"

// AllAgents is the agent_id used by evidence and findings that apply to every
// agent in the repository (for example a repository-level CI check).
const AllAgents = "*"

// ---------------------------------------------------------------------------
// Enumerations
// ---------------------------------------------------------------------------

// Status is the assessment status of one control for one agent.
type Status string

const (
	StatusVerifiedOperational    Status = "verified-operational"    // maturity 4
	StatusVerifiedTested         Status = "verified-tested"         // maturity 3
	StatusVerifiedImplementation Status = "verified-implementation" // maturity 2
	StatusDeclaredOnly           Status = "declared-only"           // maturity 1
	StatusMissing                Status = "missing"                 // looked for and not found
	StatusFailed                 Status = "failed"                  // negative evidence (violation or failed test)
	StatusUnknown                Status = "unknown"                 // could not be assessed
	StatusNotApplicable          Status = "not-applicable"          // excluded from the denominator
	StatusAcceptedRisk           Status = "accepted-risk"           // recorded exception, not a pass
	StatusError                  Status = "error"                   // collector or assessment error
)

// Severity of a finding or the default severity of a control.
type Severity string

const (
	SeverityCritical Severity = "critical"
	SeverityHigh     Severity = "high"
	SeverityMedium   Severity = "medium"
	SeverityLow      Severity = "low"
	SeverityInfo     Severity = "info"
)

// Confidence of a detection or finding.
type Confidence string

const (
	ConfidenceHigh   Confidence = "high"
	ConfidenceMedium Confidence = "medium"
	ConfidenceLow    Confidence = "low"
)

// DetectionState distinguishes how sure discovery is that an agent exists.
type DetectionState string

const (
	Detected    DetectionState = "detected"
	Suspected   DetectionState = "suspected"
	NotDetected DetectionState = "not-detected"
)

// SourceType is where an evidence item came from.
type SourceType string

const (
	SourceStatic        SourceType = "static"
	SourceConfiguration SourceType = "configuration"
	SourceTest          SourceType = "test"
	SourceRuntime       SourceType = "runtime"
	SourceAttestation   SourceType = "external-attestation"
	SourceManualReview  SourceType = "manual-review"
)

// Integrity is the cryptographic integrity state of an evidence item.
type Integrity string

const (
	IntegrityVerified     Integrity = "verified"      // signature checked against a trusted key
	IntegrityUnsigned     Integrity = "unsigned"      // no signature supplied
	IntegrityInvalid      Integrity = "invalid"       // signature present but did not verify
	IntegrityNotAvailable Integrity = "not-available" // integrity does not apply (scanner-observed facts)
)

// Result is the outcome recorded by one evidence item.
type Result string

const (
	ResultPass         Result = "pass"
	ResultFail         Result = "fail"
	ResultInconclusive Result = "inconclusive"
)

// Signal says what an evidence item observed. The policy engine derives the
// control status from signals, never from file names alone.
type Signal string

const (
	SignalPresent   Signal = "present"   // the control mechanism was observed (Result pass)
	SignalAbsent    Signal = "absent"    // a capable detector looked and found no mechanism (Result inconclusive)
	SignalViolation Signal = "violation" // a concrete breach or failed test was observed (Result fail)
	SignalDeclared  Signal = "declared"  // only a declaration exists (Result inconclusive)
	SignalError     Signal = "error"     // the collector failed (Result inconclusive)
)

// Strength is the highest maturity an evidence item can support on its own.
type Strength string

const (
	StrengthDeclared       Strength = "declared"       // maturity 1
	StrengthImplementation Strength = "implementation" // maturity 2
	StrengthTested         Strength = "tested"         // maturity 3
	StrengthOperational    Strength = "operational"    // maturity 4
)

// Validity says whether an evidence item may be credited for this scan.
type Validity string

const (
	ValidityValid            Validity = "valid"
	ValidityExpired          Validity = "expired"           // valid_until is in the past
	ValidityCommitMismatch   Validity = "commit-mismatch"   // bound to a different commit
	ValidityDigestMismatch   Validity = "digest-mismatch"   // subject files changed since collection
	ValidityUnbound          Validity = "unbound"           // external evidence with no commit or digest binding
	ValidityInvalidSignature Validity = "invalid-signature" // signature failed verification
	ValidityMalformed        Validity = "malformed"         // failed schema validation
)

// Outcome is the release decision.
type Outcome string

const (
	OutcomeAllow          Outcome = "ALLOW"
	OutcomeBlock          Outcome = "BLOCK"
	OutcomeReviewRequired Outcome = "REVIEW_REQUIRED"
)

// Capability names describe what a detected agent can do. Control
// applicability is decided from these, not from framework names.
const (
	CapTools            = "tools"             // exposes or calls tools
	CapSensitiveActions = "sensitive-actions" // tools that move money, delete, send, or change records
	CapMutatingActions  = "mutating-actions"  // tools that write state
	CapShellExec        = "shell-exec"        // runs shell commands
	CapCodeExec         = "code-exec"         // evaluates generated code
	CapFilesystem       = "filesystem"        // reads or writes files through tools
	CapNetwork          = "network"           // makes outbound requests through tools
	CapBrowser          = "browser"           // drives a browser
	CapDataAccess       = "data-access"       // retrieval or database access
	CapMemory           = "memory"            // persistent memory or vector store writes
	CapMultiAgent       = "multi-agent"       // agent-to-agent messaging or handoffs
	CapMCP              = "mcp"               // MCP client or server
	CapCredentials      = "credentials"       // handles API keys, tokens, or passwords
	CapContainer        = "container"         // ships container or orchestration manifests
)

// Applicability basis values for ControlResult.ApplicabilityBasis.
const (
	BasisAlways   = "always"   // the control applies to every agent
	BasisDetected = "detected" // a triggering capability was detected
	BasisDeclared = "declared" // the configuration declares the capability
	BasisInferred = "inferred" // no triggering capability was detected; N/A is an inference, not an approval
	BasisApproved = "approved" // N/A approved with a recorded reason in configuration
)

// ---------------------------------------------------------------------------
// Discovery
// ---------------------------------------------------------------------------

// Location points at a place in the scanned repository.
type Location struct {
	Path    string `json:"path" yaml:"path"`                             // repo-relative, forward slashes
	Line    int    `json:"line,omitempty" yaml:"line,omitempty"`         // 1-based; 0 when unknown
	EndLine int    `json:"end_line,omitempty" yaml:"end_line,omitempty"` // 0 when unknown
}

// Fact is one normalized observation made by a discovery adapter.
type Fact struct {
	Kind          string     `json:"kind"`           // e.g. "framework-import", "tool-definition", "mcp-server", "model-client"
	Detail        string     `json:"detail"`         // short, redacted explanation
	Location      Location   `json:"location"`       //
	Confidence    Confidence `json:"confidence"`     //
	Collector     string     `json:"collector"`      // adapter ID, e.g. "python.langgraph"
	ParserVersion string     `json:"parser_version"` // version of the adapter's parser
}

// Tool is a tool or action an agent can invoke.
type Tool struct {
	Name         string   `json:"name"`
	Kind         string   `json:"kind"`      // function | mcp | shell | http | filesystem | browser | code | database | unknown
	Location     Location `json:"location"`  //
	Sensitive    bool     `json:"sensitive"` // changes state, moves value, deletes, sends, or executes
	SensitiveWhy string   `json:"sensitive_why,omitempty"`
	Capabilities []string `json:"capabilities"` // Cap* names this tool contributes
	Declared     bool     `json:"declared"`     // listed in .agentgov.yaml declared_tools
}

// MCPConnection is a configured MCP server or client connection.
type MCPConnection struct {
	Name      string   `json:"name"`
	Transport string   `json:"transport"`         // stdio | http | sse | unknown
	Target    string   `json:"target"`            // command name or host only; never arguments that may hold secrets
	Pinned    bool     `json:"pinned"`            // version or digest pinned
	Version   string   `json:"version,omitempty"` //
	Location  Location `json:"location"`
}

// Agent is one detected or suspected AI agent.
type Agent struct {
	ID                  string          `json:"id"`                   // declared ID, or a stable derived ID
	Name                string          `json:"name"`                 //
	Root                string          `json:"root"`                 // repo-relative directory, "." for the repo root
	Detection           DetectionState  `json:"detection"`            //
	Confidence          Confidence      `json:"confidence"`           //
	Framework           string          `json:"framework"`            // langgraph | langchain | openai-agents | crewai | autogen | pydantic-ai | mcp | generic-tool-calling | unknown
	FrameworkVersion    string          `json:"framework_version"`    // Unknown when not established
	Language            string          `json:"language"`             // python | typescript | javascript | unknown
	Entrypoint          string          `json:"entrypoint"`           // Unknown when not established
	Owner               string          `json:"owner"`                // declared owner; Unknown when not declared
	RiskTier            string          `json:"risk_tier"`            // declared tier; Unknown when not declared
	InferredRiskTier    string          `json:"inferred_risk_tier"`   // tier suggested by detected capabilities
	Tools               []Tool          `json:"tools"`                //
	PermissionsDeclared []string        `json:"permissions_declared"` //
	DataAccessPaths     []string        `json:"data_access_paths"`    //
	MCPConnections      []MCPConnection `json:"mcp_connections"`      //
	Capabilities        []string        `json:"capabilities"`         // sorted Cap* names
	Facts               []Fact          `json:"facts"`                //
}

// ---------------------------------------------------------------------------
// Evidence and findings
// ---------------------------------------------------------------------------

// Subject binds external evidence to exact file content. Digest is the
// lowercase hex SHA-256 computed by evidence.SubjectDigest over Paths.
type Subject struct {
	Paths  []string `json:"paths"`
	Digest string   `json:"digest"`
}

// Evidence is one typed evidence item for one control.
type Evidence struct {
	EvidenceID      string     `json:"evidence_id"`                // stable hash-derived ID
	ControlID       string     `json:"control_id"`                 //
	AgentID         string     `json:"agent_id"`                   // AllAgents for repository-level evidence
	CommitSHA       string     `json:"commit_sha"`                 // Unknown when the repo commit could not be read
	ArtifactDigest  string     `json:"artifact_digest,omitempty"`  //
	Subject         *Subject   `json:"subject,omitempty"`          // content binding for external evidence
	PolicyVersion   string     `json:"policy_version"`             //
	ScannerVersion  string     `json:"scanner_version"`            //
	SourceType      SourceType `json:"source_type"`                //
	SourceLocation  string     `json:"source_location"`            // "path:line" or an evidence reference
	Location        *Location  `json:"location,omitempty"`         // structured form when a file location exists
	Collector       string     `json:"collector"`                  // detector or integration ID
	ObservedAt      time.Time  `json:"observed_at"`                //
	ValidUntil      *time.Time `json:"valid_until"`                // nil means no expiry was stated
	IdentityContext string     `json:"identity_context,omitempty"` // non-sensitive reference only
	Integrity       Integrity  `json:"integrity"`                  //
	Result          Result     `json:"result"`                     //
	Signal          Signal     `json:"signal"`                     //
	Strength        Strength   `json:"strength"`                   //
	Validity        Validity   `json:"validity"`                   //
	ValidityReason  string     `json:"validity_reason,omitempty"`  //
	Summary         string     `json:"summary"`                    // human-readable, redacted
	Limitations     []string   `json:"limitations"`                //
}

// Mapping links a finding or control to a published external standard.
type Mapping struct {
	Standard      string `json:"standard" yaml:"standard"`
	Version       string `json:"version" yaml:"version"`
	RequirementID string `json:"requirement_id" yaml:"requirement_id"`
	URL           string `json:"url" yaml:"url"`
	Rationale     string `json:"rationale" yaml:"rationale"`
}

// Finding is one actionable issue.
type Finding struct {
	FindingID    string     `json:"finding_id"`             // stable; derived from Fingerprint
	Fingerprint  string     `json:"fingerprint"`            // stable dedup key; never built from secret values
	RuleID       string     `json:"rule_id"`                // e.g. "AGC-008.hardcoded-secret"
	ControlID    string     `json:"control_id"`             //
	AgentID      string     `json:"agent_id"`               //
	Severity     Severity   `json:"severity"`               //
	Confidence   Confidence `json:"confidence"`             //
	Title        string     `json:"title"`                  // short description
	Description  string     `json:"description"`            // what was observed, redacted
	WhyItMatters string     `json:"why_it_matters"`         // plain language
	Remediation  []string   `json:"remediation"`            // ordered steps
	Reproduction string     `json:"reproduction,omitempty"` // safe steps to confirm
	Location     *Location  `json:"location,omitempty"`     // nil for findings with no code location
	EvidenceRefs []string   `json:"evidence_refs"`          //
	Mappings     []Mapping  `json:"mappings"`               //
}

// Detection is the output of the detection engine (discovery plus rules),
// before any policy is applied.
type Detection struct {
	CommitSHA   string     `json:"commit_sha"`  // Unknown when not readable
	Agents      []Agent    `json:"agents"`      //
	Evidence    []Evidence `json:"evidence"`    //
	Findings    []Finding  `json:"findings"`    //
	Stats       Stats      `json:"stats"`       //
	Warnings    []string   `json:"warnings"`    // non-fatal problems (malformed files, skipped paths)
	Limitations []string   `json:"limitations"` // what this scan could not see
}

// Stats describes the work a scan performed.
type Stats struct {
	FilesScanned  int   `json:"files_scanned"`
	FilesSkipped  int   `json:"files_skipped"`
	BytesRead     int64 `json:"bytes_read"`
	DurationMilli int64 `json:"duration_ms"` // excluded from determinism comparisons
}

// ---------------------------------------------------------------------------
// Assessment
// ---------------------------------------------------------------------------

// ControlResult is the assessment of one control for one agent. It carries
// enough catalog text to make a report self-contained.
type ControlResult struct {
	ControlID           string   `json:"control_id"`
	AgentID             string   `json:"agent_id"`
	Title               string   `json:"title"`
	Domain              string   `json:"domain"`               // e.g. "A: Accountability"
	PlainLanguage       string   `json:"plain_language"`       // one-sentence explanation for non-specialists
	Status              Status   `json:"status"`               //
	StatusReason        string   `json:"status_reason"`        // exact reason, e.g. "evidence expired on 2026-01-01"
	Maturity            int      `json:"maturity"`             // 0..4
	MaxStaticMaturity   int      `json:"max_static_maturity"`  // the highest level static scanning alone can support
	Applicable          bool     `json:"applicable"`           //
	ApplicabilityBasis  string   `json:"applicability_basis"`  // Basis* constant
	ApplicabilityReason string   `json:"applicability_reason"` //
	Mandatory           bool     `json:"mandatory"`            // mandatory under the effective profile
	MinMaturity         int      `json:"min_maturity"`         // required maturity when mandatory
	Weight              int      `json:"weight"`               //
	Severity            Severity `json:"severity"`             // control default severity
	EvidenceRefs        []string `json:"evidence_refs"`        //
	FindingRefs         []string `json:"finding_refs"`         //
	NextAction          string   `json:"next_action"`          // the single most useful next step
	Remediation         []string `json:"remediation"`          //
	Limitations         []string `json:"limitations"`          //
}

// Score is the transparent maturity score and its companion measures.
// Value is nil when there are no applicable controls; Label is then
// "insufficient-evidence". The score is illustrative only and is never a
// certification or a probability of safety.
type Score struct {
	Value                *int           `json:"value"`                  // 0..100 or nil
	Label                string         `json:"label"`                  // "NN/100" or "insufficient-evidence"
	ApplicableControls   int            `json:"applicable_controls"`    //
	ControlsWithEvidence int            `json:"controls_with_evidence"` // coverage numerator
	CoveragePercent      int            `json:"coverage_percent"`       //
	TestedPercent        int            `json:"tested_percent"`         // maturity >= 3
	OperationalPercent   int            `json:"operational_percent"`    // maturity 4
	FindingsBySeverity   map[string]int `json:"findings_by_severity"`   //
	UnresolvedMandatory  []string       `json:"unresolved_mandatory"`   // control IDs
	StatusCounts         map[string]int `json:"status_counts"`          // status -> count over all 24 controls
}

// Reason is one machine-readable reason behind a decision.
type Reason struct {
	Code      string `json:"code"`                 // e.g. "mandatory-control-failed", "no-agent-detected"
	ControlID string `json:"control_id,omitempty"` //
	AgentID   string `json:"agent_id,omitempty"`   //
	Message   string `json:"message"`              //
}

// Decision is the definitive policy decision.
type Decision struct {
	Outcome Outcome  `json:"outcome"`
	Reasons []Reason `json:"reasons"`
}

// AgentAssessment is the complete assessment of one agent.
type AgentAssessment struct {
	AgentID  string          `json:"agent_id"`
	Score    Score           `json:"score"`
	Decision Decision        `json:"decision"`
	Controls []ControlResult `json:"controls"` // always all catalog controls, in ID order
}

// ScanMeta is scan-level metadata.
type ScanMeta struct {
	ScanID        string    `json:"scan_id"`        // derived from content; stable for identical inputs
	StartedAt     time.Time `json:"started_at"`     // timestamp; excluded from determinism comparisons
	FinishedAt    time.Time `json:"finished_at"`    // timestamp; excluded from determinism comparisons
	Target        string    `json:"target"`         // display name of the scanned path (base name only)
	CommitSHA     string    `json:"commit_sha"`     //
	Profile       string    `json:"profile"`        // baseline | standard | high-risk | custom name
	ProfileSource string    `json:"profile_source"` // flag | config | baseline-lock | inferred | default
	PolicyPack    string    `json:"policy_pack"`    // e.g. "builtin/v1"
	PolicyVersion string    `json:"policy_version"` //
	ConfigPath    string    `json:"config_path"`    // "" when no config was found
	Offline       bool      `json:"offline"`        //
}

// ToolInfo identifies the scanner build.
type ToolInfo struct {
	Name    string `json:"name"`
	Version string `json:"version"`
}

// ScanResult is the normalized scan output. All report formats render from
// this one value.
type ScanResult struct {
	SchemaVersion string            `json:"schema_version"`
	Tool          ToolInfo          `json:"tool"`
	Scan          ScanMeta          `json:"scan"`
	Agents        []Agent           `json:"agents"`
	Assessments   []AgentAssessment `json:"assessments"` // one per agent; empty when no agent was detected
	Evidence      []Evidence        `json:"evidence"`
	Findings      []Finding         `json:"findings"`
	Score         Score             `json:"score"`    // repository-level: the lowest-scoring agent's score
	Decision      Decision          `json:"decision"` // repository-level: the most restrictive agent decision
	Stats         Stats             `json:"stats"`
	Warnings      []string          `json:"warnings"`
	Limitations   []string          `json:"limitations"`
}

// ---------------------------------------------------------------------------
// Catalog and profiles (versioned policy data)
// ---------------------------------------------------------------------------

// Applicability says when a control applies.
type Applicability struct {
	Mode            string   `json:"mode" yaml:"mode"`                                             // "always" | "capability"
	CapabilitiesAny []string `json:"capabilities_any,omitempty" yaml:"capabilities_any,omitempty"` // Cap* names
	Rationale       string   `json:"rationale" yaml:"rationale"`
}

// VerificationRules documents what each maturity level requires.
type VerificationRules struct {
	Implementation    string `json:"implementation" yaml:"implementation"`
	Tested            string `json:"tested" yaml:"tested"`
	Operational       string `json:"operational" yaml:"operational"`
	MaxStaticMaturity int    `json:"max_static_maturity" yaml:"max_static_maturity"` // 0..2
}

// Examples gives one positive and one negative evidence example.
type Examples struct {
	Positive string `json:"positive" yaml:"positive"`
	Negative string `json:"negative" yaml:"negative"`
}

// Control is one versioned control definition from the catalog.
type Control struct {
	ID                string            `json:"id" yaml:"id"` // AGC-001 .. AGC-024
	Title             string            `json:"title" yaml:"title"`
	Domain            string            `json:"domain" yaml:"domain"` // "A: Accountability" etc.
	Intent            string            `json:"intent" yaml:"intent"` //
	PlainLanguage     string            `json:"plain_language" yaml:"plain_language"`
	Applicability     Applicability     `json:"applicability" yaml:"applicability"`
	EvidenceTypes     []string          `json:"evidence_types" yaml:"evidence_types"`
	Detectors         []string          `json:"detectors" yaml:"detectors"`         // rule IDs that can produce evidence; may be empty
	DynamicTests      []string          `json:"dynamic_tests" yaml:"dynamic_tests"` //
	VerificationRules VerificationRules `json:"verification_rules" yaml:"verification_rules"`
	Remediation       []string          `json:"remediation" yaml:"remediation"`
	Severity          Severity          `json:"severity" yaml:"severity"`
	DefaultWeight     int               `json:"default_weight" yaml:"default_weight"`
	StandardsMappings []Mapping         `json:"standards_mappings" yaml:"standards_mappings"`
	Limitations       []string          `json:"limitations" yaml:"limitations"`
	Examples          Examples          `json:"examples" yaml:"examples"`
}

// Catalog is a loaded, validated policy pack.
type Catalog struct {
	Pack     string    `json:"pack"`    // "builtin/v1"
	Version  string    `json:"version"` // policy version, e.g. "1.0"
	Controls []Control `json:"controls"`
}

// Profile is a versioned risk profile: which controls are mandatory and how
// mature they must be.
type Profile struct {
	Name                  string         `json:"name" yaml:"name"`
	Version               string         `json:"version" yaml:"version"`
	Description           string         `json:"description" yaml:"description"`
	MandatoryControls     []string       `json:"mandatory_controls" yaml:"mandatory_controls"`
	MinMaturity           int            `json:"min_maturity" yaml:"min_maturity"`                       // required maturity for mandatory controls
	RequireSignedEvidence bool           `json:"require_signed_evidence" yaml:"require_signed_evidence"` // levels 3 and 4 need integrity "verified"
	ReviewWorkflow        bool           `json:"review_workflow" yaml:"review_workflow"`                 // when true, shortfalls that are not failures yield REVIEW_REQUIRED
	Weights               map[string]int `json:"weights,omitempty" yaml:"weights,omitempty"`             // per-control overrides of default_weight
	// ControlMinMaturity is a per-control override of MinMaturity for mandatory
	// controls; may be lower or higher than MinMaturity.
	ControlMinMaturity map[string]int `json:"control_min_maturity,omitempty" yaml:"control_min_maturity,omitempty"`
}

// ---------------------------------------------------------------------------
// Comparison
// ---------------------------------------------------------------------------

// ControlChange is a control whose status or maturity differs between scans.
type ControlChange struct {
	ControlID      string `json:"control_id"`
	AgentID        string `json:"agent_id"`
	BeforeStatus   Status `json:"before_status"`
	AfterStatus    Status `json:"after_status"`
	BeforeMaturity int    `json:"before_maturity"`
	AfterMaturity  int    `json:"after_maturity"`
}

// Comparison is the difference between two scan results.
type Comparison struct {
	Comparable       bool            `json:"comparable"` // false when policy pack, version, or profile differ
	NotComparableWhy string          `json:"not_comparable_why,omitempty"`
	BeforeCommit     string          `json:"before_commit"`
	AfterCommit      string          `json:"after_commit"`
	BeforeScore      Score           `json:"before_score"`
	AfterScore       Score           `json:"after_score"`
	BeforeDecision   Outcome         `json:"before_decision"`
	AfterDecision    Outcome         `json:"after_decision"`
	NewFindings      []Finding       `json:"new_findings"`
	ResolvedFindings []Finding       `json:"resolved_findings"`
	UnchangedCount   int             `json:"unchanged_count"`
	ControlChanges   []ControlChange `json:"control_changes"`
}
