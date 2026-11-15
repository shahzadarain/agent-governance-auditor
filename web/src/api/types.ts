// SPDX-License-Identifier: Apache-2.0
//
// Types of the AgentGov server API. Field names follow the Go structs in
// internal/server, internal/storage, and internal/model exactly.

export type Status =
  | "verified-operational"
  | "verified-tested"
  | "verified-implementation"
  | "declared-only"
  | "missing"
  | "failed"
  | "unknown"
  | "not-applicable"
  | "accepted-risk"
  | "error";

export type Severity = "critical" | "high" | "medium" | "low" | "info";
export type Outcome = "ALLOW" | "BLOCK" | "REVIEW_REQUIRED";

export interface Location {
  path: string;
  line?: number;
  end_line?: number;
}

export interface Tool {
  name: string;
  kind: string;
  location: Location;
  sensitive: boolean;
  sensitive_why?: string;
  capabilities: string[] | null;
  declared: boolean;
}

export interface McpConnection {
  name: string;
  transport: string;
  target: string;
  pinned: boolean;
  version?: string;
  location: Location;
}

export interface ScanAgent {
  id: string;
  name: string;
  root: string;
  detection: string;
  confidence: string;
  framework: string;
  framework_version: string;
  language: string;
  entrypoint: string;
  owner: string;
  risk_tier: string;
  inferred_risk_tier: string;
  tools: Tool[] | null;
  permissions_declared: string[] | null;
  data_access_paths: string[] | null;
  mcp_connections: McpConnection[] | null;
  capabilities: string[] | null;
}

export interface Evidence {
  evidence_id: string;
  control_id: string;
  agent_id: string;
  commit_sha: string;
  source_type: string;
  source_location: string;
  location?: Location;
  collector: string;
  observed_at: string;
  valid_until: string | null;
  integrity: string;
  result: string;
  signal: string;
  strength: string;
  validity: string;
  validity_reason?: string;
  summary: string;
  limitations: string[] | null;
}

export interface Mapping {
  standard: string;
  version: string;
  requirement_id: string;
  url: string;
  rationale: string;
}

export interface Finding {
  finding_id: string;
  fingerprint: string;
  rule_id: string;
  control_id: string;
  agent_id: string;
  severity: Severity | string;
  confidence: string;
  title: string;
  description: string;
  why_it_matters: string;
  remediation: string[] | null;
  reproduction?: string;
  location?: Location | null;
  evidence_refs: string[] | null;
  mappings: Mapping[] | null;
}

export interface ControlResult {
  control_id: string;
  agent_id: string;
  title: string;
  domain: string;
  plain_language: string;
  status: Status | string;
  status_reason: string;
  maturity: number;
  max_static_maturity: number;
  applicable: boolean;
  applicability_basis: string;
  applicability_reason: string;
  mandatory: boolean;
  min_maturity: number;
  weight: number;
  severity: Severity | string;
  evidence_refs: string[] | null;
  finding_refs: string[] | null;
  next_action: string;
  remediation: string[] | null;
  limitations: string[] | null;
}

export interface Score {
  value: number | null;
  label: string;
  applicable_controls: number;
  controls_with_evidence: number;
  coverage_percent: number;
  tested_percent: number;
  operational_percent: number;
  findings_by_severity: Record<string, number> | null;
  unresolved_mandatory: string[] | null;
  status_counts: Record<string, number> | null;
}

export interface Reason {
  code: string;
  control_id?: string;
  agent_id?: string;
  message: string;
}

export interface Decision {
  outcome: Outcome | string;
  reasons: Reason[] | null;
}

export interface AgentAssessment {
  agent_id: string;
  score: Score;
  decision: Decision;
  controls: ControlResult[] | null;
}

export interface ScanMeta {
  scan_id: string;
  started_at: string;
  finished_at: string;
  target: string;
  commit_sha: string;
  profile: string;
  profile_source: string;
  policy_pack: string;
  policy_version: string;
  config_path: string;
  offline: boolean;
}

export interface ScanResult {
  schema_version: string;
  tool: { name: string; version: string };
  scan: ScanMeta;
  agents: ScanAgent[] | null;
  assessments: AgentAssessment[] | null;
  evidence: Evidence[] | null;
  findings: Finding[] | null;
  score: Score;
  decision: Decision;
  stats: { files_scanned: number; files_skipped: number; bytes_read: number; duration_ms: number };
  warnings: string[] | null;
  limitations: string[] | null;
}

// --- Catalog and profiles ---------------------------------------------------

export interface Control {
  id: string;
  title: string;
  domain: string;
  intent: string;
  plain_language: string;
  applicability: { mode: string; capabilities_any?: string[]; rationale: string };
  evidence_types: string[] | null;
  detectors: string[] | null;
  dynamic_tests: string[] | null;
  verification_rules: { implementation: string; tested: string; operational: string; max_static_maturity: number };
  remediation: string[] | null;
  severity: Severity | string;
  default_weight: number;
  standards_mappings: Mapping[] | null;
  limitations: string[] | null;
  examples: { positive: string; negative: string };
}

export interface Catalog {
  pack: string;
  version: string;
  controls: Control[];
}

export interface Profile {
  name: string;
  version: string;
  description: string;
  mandatory_controls: string[] | null;
  min_maturity: number;
  require_signed_evidence: boolean;
  review_workflow: boolean;
  weights?: Record<string, number>;
  control_min_maturity?: Record<string, number>;
}

// --- Server records ---------------------------------------------------------

export type GlobalRole = "administrator" | "user";
export type ProjectRole = "administrator" | "owner" | "reviewer" | "viewer";

export interface User {
  id: string;
  username: string;
  role: GlobalRole | string;
  created_at: string;
  disabled: boolean;
}

export interface Session {
  user: User;
  csrf_token: string;
  expires_at: string;
  idle_expires_at: string;
}

export interface VersionInfo {
  name: string;
  version: string;
  api_version: string;
  schema_version: string;
  setup_required: boolean;
}

export interface Project {
  id: string;
  slug: string;
  name: string;
  created_by: string;
  created_at: string;
  role?: ProjectRole | string;
}

export interface ProjectOverview {
  project_id: string;
  agent_count: number;
  scan_count: number;
  decisions: Record<string, number> | null;
  open_critical: number;
  open_high: number;
  latest_scan_id: string;
  latest_decision: string;
  latest_scan_at: string | null;
}

export interface Scan {
  id: string;
  project_id: string;
  scan_id: string;
  target: string;
  commit_sha: string;
  profile: string;
  policy_pack: string;
  policy_version: string;
  tool_version: string;
  decision: string;
  score: number | null;
  score_label: string;
  received_at: string;
  uploaded_by_token: string;
  payload_bytes: number;
  payload_sha256: string;
}

export interface Agent {
  key: string;
  project_id: string;
  agent_id: string;
  name: string;
  framework: string;
  language: string;
  owner: string;
  risk_tier: string;
  last_scan_id: string;
  last_decision: string;
  last_score: number | null;
  first_seen: string;
  last_seen: string;
}

export interface AgentScan {
  id: string;
  scan_id: string;
  received_at: string;
  commit_sha: string;
  profile: string;
  policy_pack: string;
  policy_version: string;
  tool_version: string;
  decision: string;
  score: number | null;
  score_label: string;
}

export interface Member {
  project_id: string;
  user_id: string;
  username: string;
  role: string;
}

export interface ApiToken {
  id: string;
  project_id: string;
  name: string;
  prefix: string;
  scopes: string[] | null;
  created_by: string;
  created_at: string;
  last_used_at: string | null;
  expires_at: string | null;
  revoked_at: string | null;
}

export interface CreatedToken {
  token: string;
  record: ApiToken;
}

export interface AuditEvent {
  id: number;
  at: string;
  actor_type: string;
  actor_id: string;
  action: string;
  target: string;
  project_id: string;
  detail: Record<string, unknown>;
  prev_hash: string;
  hash: string;
}

export interface ProjectDetail {
  project: Project;
  overview: ProjectOverview;
  recent_scans: Scan[] | null;
}

export interface AgentDetail {
  agent: Agent;
  scan: Scan | null;
  detail: ScanAgent | null;
  assessment: AgentAssessment | null;
}

export interface ScanDetail {
  scan: Scan;
  result: ScanResult;
}

export interface Page<T> {
  items: T[];
  total: number;
  limit: number;
  offset: number;
}

export interface ControlChange {
  control_id: string;
  agent_id: string;
  before_status: string;
  after_status: string;
  before_maturity: number;
  after_maturity: number;
}

export interface Comparison {
  comparable: boolean;
  not_comparable_why?: string;
  before_commit: string;
  after_commit: string;
  before_score: Score;
  after_score: Score;
  before_decision: string;
  after_decision: string;
  new_findings: Finding[] | null;
  resolved_findings: Finding[] | null;
  unchanged_count: number;
  control_changes: ControlChange[] | null;
}

export interface CompareResponse {
  before: Scan;
  after: Scan;
  comparison: Comparison;
}

export interface OverviewResponse {
  projects: { project: Project; overview: ProjectOverview }[];
  totals: {
    projects: number;
    agents: number;
    scans: number;
    open_critical: number;
    open_high: number;
    decisions: Record<string, number> | null;
    latest_scan_at: string | null;
  };
}
