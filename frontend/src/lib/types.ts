export type Role = "OWNER" | "ADMIN" | "SECURITY_ANALYST" | "DEVELOPER" | "VIEWER";
export type Severity = "CRITICAL" | "HIGH" | "MEDIUM" | "LOW" | "INFO";
export type Confidence = "CONFIRMED" | "HIGH" | "MEDIUM" | "LOW";
export type FindingStatus = "OPEN" | "IN_PROGRESS" | "RESOLVED" | "REOPENED" | "FALSE_POSITIVE" | "ACCEPTED_RISK";
export type Verification = "DETECTED" | "AI_SUGGESTED" | "CONFIRMED" | "FALSE_POSITIVE" | "NOT_TESTED";
export type ScanStatus = "QUEUED" | "RUNNING" | "COMPLETED" | "FAILED" | "CANCELLED";

export interface Page<T> {
  items: T[];
  total: number;
  page: number;
  page_size: number;
}

export interface User {
  id: string;
  email: string;
  display_name: string;
  is_active: boolean;
  last_login_at: string | null;
  created_at: string;
}

export interface Membership {
  organization_id: string;
  organization_name: string;
  organization_slug: string;
  role: Role;
  permissions: string[];
}

export interface Me {
  user: User | null;
  api_key_prefix: string | null;
  memberships: Membership[];
  csrf_token: string | null;
}

export interface LoginResponse {
  user: User;
  memberships: Membership[];
  csrf_token: string;
  expires_at: string;
}

export interface GatePolicy {
  fail_on: Severity[];
  min_confidence: Confidence;
  include_ai_suggested: boolean;
  fail_on_regression: boolean;
  max_findings: number | null;
}

export interface Project {
  id: string;
  organization_id: string;
  name: string;
  slug: string;
  description: string;
  business_criticality: string | null;
  exposure: string;
  gate_policy: GatePolicy | null;
  created_at: string;
  updated_at: string;
  open_findings: number;
  critical_open: number;
  high_open: number;
  last_scan_at: string | null;
  last_scan_status: ScanStatus | null;
  risk_index: number | null;
}

export interface Repository {
  id: string;
  project_id: string;
  name: string;
  source_type: "GIT" | "UPLOAD";
  url: string | null;
  default_branch: string | null;
  created_at: string;
}

export interface ScannerRun {
  scanner: string;
  status: "ran" | "skipped" | "unavailable" | "failed";
  detail: string | null;
  findings: number;
  duration_ms: number;
  languages: string[];
}

export interface RetestSummary {
  previous_findings: number;
  resolved: number;
  still_open: number;
  not_reproduced: number;
  not_tested: number;
  new: number;
  regressions: number;
  remaining: number;
  regression_check: "PASS" | "FAIL";
}

export interface GateResult {
  status: "PASS" | "FAIL";
  reasons: string[];
  blocking: { id: string; title: string; severity: Severity; confidence: Confidence; location: string | null }[];
  counts: Record<Severity, number>;
  policy: GatePolicy;
}

export interface ScanStats {
  files_total?: number;
  files_analyzed?: number;
  lines_analyzed?: number;
  languages?: Record<string, { files: number; lines: number; sast: number }>;
  findings_total?: number;
  findings_by_severity?: Partial<Record<Severity, number>>;
  findings_by_source?: Record<string, number>;
  dependencies_total?: number;
  dependencies_by_status?: Record<string, number>;
  scanners?: ScannerRun[];
  errors?: string[];
  gate?: GateResult;
  risk?: { index: number; total: number };
  retest?: RetestSummary;
  analysis_ms?: number;
}

export interface Scan {
  id: string;
  project_id: string;
  repository_id: string | null;
  snapshot_id: string | null;
  status: ScanStatus;
  trigger: string;
  scope: "FULL" | "PARTIAL";
  baseline_scan_id: string | null;
  config: Record<string, unknown>;
  progress: { stage?: string; percent?: number };
  stats: ScanStats;
  risk_index: number | null;
  gate_status: "PASS" | "FAIL" | null;
  gate_reasons: string[];
  error: string | null;
  queued_at: string | null;
  started_at: string | null;
  finished_at: string | null;
  created_at: string;
  repository_name?: string | null;
}

export interface ScanFile {
  path: string;
  language: string | null;
  size_bytes: number;
  line_count: number;
  status: string;
  detail: string | null;
}

export interface FileMarker {
  finding_id: string;
  public_id: string;
  title: string;
  severity: Severity;
  confidence: Confidence;
  line: number | null;
  end_line: number | null;
  status: FindingStatus;
  verification: Verification;
}

export interface FileContent {
  path: string;
  language: string | null;
  content: string;
  redacted: boolean;
  findings: FileMarker[];
}

export interface Dependency {
  id: string;
  ecosystem: string;
  name: string;
  version: string | null;
  version_spec: string | null;
  manifest_path: string;
  direct: boolean;
  dev: boolean;
  vuln_status: "VULNERABLE" | "NO_KNOWN_VULNERABILITIES" | "NOT_VERIFIED";
  advisory_ids: string[];
  source: string | null;
}

export interface Finding {
  id: string;
  project_id: string;
  repository_id: string | null;
  target_id: string | null;
  public_id: string;
  engine: "APPSEC" | "AISEC";
  source_kind: string;
  rule_id: string;
  vuln_class: string;
  title: string;
  category: string;
  severity: Severity;
  confidence: Confidence;
  verification: Verification;
  status: FindingStatus;
  exploitability: string;
  cwe: string[];
  owasp: string[];
  file_path: string | null;
  line: number | null;
  risk_score: number;
  first_seen_at: string;
  last_seen_at: string;
  resolved_at: string | null;
  status_reason: string | null;
}

export interface Evidence {
  id: string;
  kind: string;
  source: string;
  summary: string;
  location: Record<string, unknown> | null;
  data: Record<string, unknown>;
}

export interface Occurrence {
  id: string;
  scan_id: string | null;
  test_run_id: string | null;
  file_path: string | null;
  start_line: number | null;
  end_line: number | null;
  function_name: string | null;
  snippet: string | null;
  severity: Severity;
  confidence: Confidence;
  scanners: string[];
  correlation: Record<string, unknown>;
  created_at: string;
  evidence: Evidence[];
}

export interface ExplanationStep {
  number: number;
  title: string;
  detail?: string;
  code?: string;
}

export interface Explanation {
  steps: ExplanationStep[];
  root_cause: string;
  impact: string;
  prevention: string;
  example: { language: string; insecure: string; secure: string } | null;
  language: string | null;
  basis: string;
}

export interface FindingDetail extends Finding {
  description: string;
  impact: string;
  recommendation: string;
  remediation_guidance: string;
  references: string[];
  occurrences: Occurrence[];
  retests: {
    retest_id: string;
    result: string;
    match_method: string;
    notes: string | null;
    created_at: string;
    retest_scan_id: string | null;
    retest_run_id: string | null;
  }[];
  explanation: Explanation;
  learning: { lesson_id: string; title: string; language: string } | null;
}

export interface Retest {
  id: string;
  project_id: string;
  kind: string;
  baseline_scan_id: string | null;
  retest_scan_id: string | null;
  status: string;
  summary: RetestSummary;
  gate_status: string | null;
  created_at: string;
}

export interface RetestDetail extends Retest {
  results: {
    finding_id: string;
    public_id: string;
    title: string;
    vuln_class: string;
    result: string;
    match_method: string;
    before: Record<string, unknown> | null;
    after: Record<string, unknown> | null;
    notes: string | null;
  }[];
}

export interface DashboardSummary {
  projects: {
    id: string;
    name: string;
    slug: string;
    risk_index: number | null;
    gate_status: string | null;
    last_scan_at: string | null;
    open_by_severity: Record<Severity, number>;
  }[];
  open_by_severity: Record<Severity, number>;
  open_by_source: Record<string, number>;
  by_status: Record<string, number>;
  open_by_verification: Record<string, number>;
  top_classes: { vuln_class: string; count: number }[];
  trend: { date: string; new: number; resolved: number }[];
  mttr_days: number | null;
  risk_history: { scan_id: string; project_id: string; finished_at: string | null; risk_index: number; gate_status: string | null }[];
  top_findings: {
    id: string;
    project_id: string;
    project_name: string;
    public_id: string;
    title: string;
    severity: Severity;
    confidence: Confidence;
    verification: Verification;
    risk_score: number;
    file_path: string | null;
    line: number | null;
  }[];
  recent_scans: {
    id: string;
    project_id: string;
    project_name: string;
    repository_name: string | null;
    status: ScanStatus;
    trigger: string;
    gate_status: string | null;
    risk_index: number | null;
    findings: number | null;
    created_at: string;
    finished_at: string | null;
  }[];
  generated_at: string;
}

export interface ProjectMetrics extends DashboardSummary {
  latest_scan_id: string | null;
  languages: Record<string, { files: number; lines: number; sast: number }>;
  hotspots: { path: string; count: number; worst: Severity }[];
}

export interface Member {
  membership_id: string;
  user_id: string;
  email: string;
  display_name: string;
  role: Role;
  is_active: boolean;
  created_at: string;
}

export interface ApiKey {
  id: string;
  name: string;
  prefix: string;
  role: Role;
  project_id: string | null;
  created_at: string;
  last_used_at: string | null;
  expires_at: string | null;
  revoked_at: string | null;
}

export interface AuditEntry {
  id: string;
  organization_id: string | null;
  actor_label: string | null;
  action: string;
  outcome: string;
  target_type: string | null;
  target_id: string | null;
  ip: string | null;
  details: Record<string, unknown>;
  created_at: string;
}

export interface SystemStatus {
  version: string;
  environment: string;
  ai: { provider: string; available: boolean; model: string | null; endpoint_host: string | null; detail: string };
  dependency_intelligence: { osv_enabled: boolean; osv_api_url: string | null; offline_database: string | null };
  external_scanners: { name: string; enabled: boolean; installed: boolean; detail: string | null }[];
  limits: Record<string, number>;
  git_allowed_hosts: string[];
  insecure_default_key: boolean;
}

export interface OrgSettings {
  risk_weights: Record<string, Record<string, number> | number>;
  risk_overrides: Record<string, unknown>;
  risk_defaults: Record<string, Record<string, number> | number>;
  risk_methodology: string;
  gate_policy: GatePolicy;
}
