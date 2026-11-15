// SPDX-License-Identifier: Apache-2.0

// Package storage is the persistence layer of the self-hosted AgentGov
// server. One SQL implementation over database/sql serves both SQLite
// (modernc.org/sqlite, pure Go) and PostgreSQL (pgx stdlib driver).
//
// Test status: the SQLite path is covered by automated tests. The PostgreSQL
// path compiles and shares every query with SQLite, but it is EXPERIMENTAL
// and UNTESTED: no PostgreSQL instance was available when it was written.
//
// Conventions:
//   - Every query is parameterized. No SQL text is built from caller input.
//   - Every write runs in a transaction.
//   - Timestamps are stored as Unix microseconds in UTC.
//   - The store keeps scan metadata and the uploaded ScanResult document. It
//     never receives source files; the CLI redacts before upload.
package storage

import (
	"context"
	"errors"
	"io"
	"time"
)

// Sentinel errors returned by Store implementations.
var (
	ErrNotFound     = errors.New("storage: not found")
	ErrConflict     = errors.New("storage: conflict")
	ErrSchemaTooNew = errors.New("storage: database schema is newer than this binary")
)

// Global user roles.
const (
	RoleAdministrator = "administrator"
	RoleUser          = "user"
)

// Per-project member roles.
const (
	ProjectOwner    = "owner"
	ProjectReviewer = "reviewer"
	ProjectViewer   = "viewer"
)

// Audit actor types.
const (
	ActorUser   = "user"
	ActorToken  = "token"
	ActorSystem = "system"
)

// User is a local account. PasswordHash is an encoded argon2id string with a
// per-user salt and parameters; it never leaves the server.
type User struct {
	ID           string    `json:"id"`
	Username     string    `json:"username"`
	PasswordHash string    `json:"-"`
	Role         string    `json:"role"`
	CreatedAt    time.Time `json:"created_at"`
	Disabled     bool      `json:"disabled"`
}

// Session is a browser session. Only the SHA-256 of the session ID is stored.
type Session struct {
	IDHash    string
	UserID    string
	CSRFToken string
	CreatedAt time.Time
	ExpiresAt time.Time
	LastSeen  time.Time
}

// Project groups agents, scans, tokens, and members.
type Project struct {
	ID        string    `json:"id"`
	Slug      string    `json:"slug"`
	Name      string    `json:"name"`
	CreatedBy string    `json:"created_by"`
	CreatedAt time.Time `json:"created_at"`
	// Role is the caller's role in the project. It is filled by
	// ListProjectsForUser only.
	Role string `json:"role,omitempty"`
}

// Member is one project membership.
type Member struct {
	ProjectID string `json:"project_id"`
	UserID    string `json:"user_id"`
	Username  string `json:"username"`
	Role      string `json:"role"`
}

// APIToken is a project-scoped upload token. TokenHash is the hex SHA-256 of
// the full token string; the token itself is shown once and never stored.
type APIToken struct {
	ID         string     `json:"id"`
	ProjectID  string     `json:"project_id"`
	Name       string     `json:"name"`
	TokenHash  string     `json:"-"`
	Prefix     string     `json:"prefix"`
	Scopes     []string   `json:"scopes"`
	CreatedBy  string     `json:"created_by"`
	CreatedAt  time.Time  `json:"created_at"`
	LastUsedAt *time.Time `json:"last_used_at"`
	ExpiresAt  *time.Time `json:"expires_at"`
	RevokedAt  *time.Time `json:"revoked_at"`
}

// Scan is the server-side record of one uploaded ScanResult.
type Scan struct {
	ID              string    `json:"id"` // server-generated row ID, used in URLs
	ProjectID       string    `json:"project_id"`
	ScanID          string    `json:"scan_id"` // scan.scan_id from the payload
	Target          string    `json:"target"`
	CommitSHA       string    `json:"commit_sha"`
	Profile         string    `json:"profile"`
	PolicyPack      string    `json:"policy_pack"`
	PolicyVersion   string    `json:"policy_version"`
	ToolVersion     string    `json:"tool_version"`
	Decision        string    `json:"decision"`
	Score           *int      `json:"score"`
	ScoreLabel      string    `json:"score_label"`
	ReceivedAt      time.Time `json:"received_at"`
	UploadedByToken string    `json:"uploaded_by_token"` // token ID (collector provenance)
	PayloadBytes    int       `json:"payload_bytes"`
	PayloadSHA256   string    `json:"payload_sha256"`
}

// Agent is the latest known state of one agent in a project. Key is a
// server-generated opaque identifier that is unique across projects.
type Agent struct {
	Key          string    `json:"key"`
	ProjectID    string    `json:"project_id"`
	AgentID      string    `json:"agent_id"`
	Name         string    `json:"name"`
	Framework    string    `json:"framework"`
	Language     string    `json:"language"`
	Owner        string    `json:"owner"`
	RiskTier     string    `json:"risk_tier"`
	LastScanID   string    `json:"last_scan_id"`
	LastDecision string    `json:"last_decision"`
	LastScore    *int      `json:"last_score"`
	FirstSeen    time.Time `json:"first_seen"`
	LastSeen     time.Time `json:"last_seen"`
}

// AgentScan is one point in the score and decision history of an agent.
type AgentScan struct {
	ScanRowID     string    `json:"id"`
	ScanID        string    `json:"scan_id"`
	ReceivedAt    time.Time `json:"received_at"`
	CommitSHA     string    `json:"commit_sha"`
	Profile       string    `json:"profile"`
	PolicyPack    string    `json:"policy_pack"`
	PolicyVersion string    `json:"policy_version"`
	ToolVersion   string    `json:"tool_version"`
	Decision      string    `json:"decision"`
	Score         *int      `json:"score"`
	ScoreLabel    string    `json:"score_label"`
}

// IngestAgent is the per-agent row written by IngestScan.
type IngestAgent struct {
	NewKey     string // key to assign when the agent is new in this project
	AgentID    string
	Name       string
	Framework  string
	Language   string
	Owner      string
	RiskTier   string
	Decision   string
	Score      *int
	ScoreLabel string
}

// IngestFinding is the indexed summary of one finding.
type IngestFinding struct {
	FindingID   string
	Fingerprint string
	ControlID   string
	AgentID     string
	Severity    string
	Title       string
	Path        string
	Line        int
}

// IngestControl is the indexed summary of one control result.
type IngestControl struct {
	AgentID   string
	ControlID string
	Status    string
	Maturity  int
	Mandatory bool
}

// IngestInput is everything IngestScan writes in one transaction.
type IngestInput struct {
	Scan     Scan   // ID, ProjectID, and metadata set by the caller
	Payload  []byte // validated ScanResult JSON
	Agents   []IngestAgent
	Findings []IngestFinding
	Controls []IngestControl
	Audit    *AuditEvent // written only when a new scan row is created
}

// AuditEvent is one entry of the tamper-evident audit log. Hash is
// sha256(prev_hash || canonical event); see canonicalAudit.
type AuditEvent struct {
	Seq       int64     `json:"id"`
	At        time.Time `json:"at"`
	ActorType string    `json:"actor_type"`
	ActorID   string    `json:"actor_id"`
	Action    string    `json:"action"`
	Target    string    `json:"target"`
	ProjectID string    `json:"project_id"`
	Detail    string    `json:"-"` // JSON object text; "{}" when empty
	PrevHash  string    `json:"prev_hash"`
	Hash      string    `json:"hash"`
}

// AuditFilter selects audit events, newest first.
type AuditFilter struct {
	ProjectID string // "" means every project
	BeforeSeq int64  // 0 means from the newest
	Limit     int    // 0 means 100
}

// Overview is the dashboard summary of one project. Open findings are the
// findings of the project's most recent scan.
type Overview struct {
	ProjectID      string         `json:"project_id"`
	AgentCount     int            `json:"agent_count"`
	ScanCount      int            `json:"scan_count"`
	Decisions      map[string]int `json:"decisions"` // agent last decision -> count
	OpenCritical   int            `json:"open_critical"`
	OpenHigh       int            `json:"open_high"`
	LatestScanID   string         `json:"latest_scan_id"`
	LatestDecision string         `json:"latest_decision"`
	LatestScanAt   *time.Time     `json:"latest_scan_at"`
}

// Store is the persistence contract used by the server.
//
// Mutating methods accept an optional audit event. When it is not nil the
// event is appended to the hash chain in the same transaction as the write.
type Store interface {
	Ping(ctx context.Context) error
	// MigrationStatus returns the highest applied migration and the highest
	// migration this binary knows.
	MigrationStatus(ctx context.Context) (applied, known int, err error)
	Dialect() string
	Close() error

	GetSetting(ctx context.Context, key string) (string, bool, error)
	SetSettings(ctx context.Context, values map[string]string, ev *AuditEvent) error

	CountUsers(ctx context.Context) (int, error)
	// CreateFirstUser creates the first account and deletes the given
	// settings keys. It returns ErrConflict when a user already exists or
	// when requireSetting is no longer present with the expected value.
	CreateFirstUser(ctx context.Context, u User, requireSetting, requireValue string, clearSettings []string, ev *AuditEvent) error
	CreateUser(ctx context.Context, u User, ev *AuditEvent) error
	GetUserByID(ctx context.Context, id string) (User, error)
	GetUserByUsername(ctx context.Context, username string) (User, error)
	ListUsers(ctx context.Context) ([]User, error)

	CreateSession(ctx context.Context, s Session, ev *AuditEvent) error
	GetSession(ctx context.Context, idHash string) (Session, error)
	TouchSession(ctx context.Context, idHash string, at time.Time) error
	DeleteSession(ctx context.Context, idHash string, ev *AuditEvent) error
	DeleteExpiredSessions(ctx context.Context, now, idleCutoff time.Time) (int64, error)

	CreateProject(ctx context.Context, p Project, ev *AuditEvent) error
	GetProject(ctx context.Context, id string) (Project, error)
	ListProjects(ctx context.Context) ([]Project, error)
	ListProjectsForUser(ctx context.Context, userID string) ([]Project, error)
	DeleteProject(ctx context.Context, id string, ev *AuditEvent) error
	MemberRole(ctx context.Context, projectID, userID string) (string, error)
	ListMembers(ctx context.Context, projectID string) ([]Member, error)
	SetMember(ctx context.Context, m Member, ev *AuditEvent) error
	RemoveMember(ctx context.Context, projectID, userID string, ev *AuditEvent) error

	CreateToken(ctx context.Context, t APIToken, ev *AuditEvent) error
	ListTokens(ctx context.Context, projectID string) ([]APIToken, error)
	GetTokenByHash(ctx context.Context, tokenHash string) (APIToken, error)
	RevokeToken(ctx context.Context, projectID, tokenID string, at time.Time, ev *AuditEvent) error
	TouchToken(ctx context.Context, tokenID string, at time.Time) error

	// IngestScan stores a scan. It is idempotent on (project, payload
	// SHA-256): a repeated upload returns the existing row and created=false.
	IngestScan(ctx context.Context, in IngestInput) (scan Scan, created bool, err error)
	GetScan(ctx context.Context, id string) (Scan, error)
	GetScanPayload(ctx context.Context, id string) ([]byte, error)
	ListScans(ctx context.Context, projectID string, limit int) ([]Scan, error)
	ListAgents(ctx context.Context, projectID string) ([]Agent, error)
	GetAgent(ctx context.Context, key string) (Agent, error)
	ListAgentScans(ctx context.Context, projectID, agentID string, limit int) ([]AgentScan, error)
	ProjectOverview(ctx context.Context, projectID string) (Overview, error)

	AppendAudit(ctx context.Context, ev AuditEvent) error
	ListAudit(ctx context.Context, f AuditFilter) ([]AuditEvent, error)
	// VerifyAuditChain recomputes every hash. It returns the number of
	// events checked and an error that names the first broken entry.
	VerifyAuditChain(ctx context.Context) (int, error)

	// PruneScans deletes scans of a project received before olderThan. It
	// keeps the latest scan of every agent and the latest scan of the
	// project.
	PruneScans(ctx context.Context, projectID string, olderThan time.Time, ev *AuditEvent) (int64, error)
	// ExportProject writes a JSON dump of one project for backups.
	ExportProject(ctx context.Context, projectID string, w io.Writer) error
}
