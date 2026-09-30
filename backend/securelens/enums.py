"""Domain enumerations shared by the database, the API and the engines.

Values are stored as strings; validation happens in the application layer so
that adding a value never requires a database migration of a CHECK constraint.
"""

from __future__ import annotations

from enum import StrEnum


class Role(StrEnum):
    OWNER = "OWNER"
    ADMIN = "ADMIN"
    SECURITY_ANALYST = "SECURITY_ANALYST"
    DEVELOPER = "DEVELOPER"
    VIEWER = "VIEWER"


ROLE_RANK = {
    Role.VIEWER: 0,
    Role.DEVELOPER: 1,
    Role.SECURITY_ANALYST: 2,
    Role.ADMIN: 3,
    Role.OWNER: 4,
}


class Engine(StrEnum):
    APPSEC = "APPSEC"
    AISEC = "AISEC"


class SourceKind(StrEnum):
    SAST = "SAST"
    SECRET = "SECRET"  # noqa: S105
    DEPENDENCY = "DEPENDENCY"
    AI_CODE = "AI_CODE"  # static analysis of AI-application code
    LLM_TEST = "LLM_TEST"  # dynamic AI security evaluation


class Severity(StrEnum):
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    INFO = "INFO"


SEVERITY_ORDER = {
    Severity.CRITICAL: 4,
    Severity.HIGH: 3,
    Severity.MEDIUM: 2,
    Severity.LOW: 1,
    Severity.INFO: 0,
}


class Confidence(StrEnum):
    CONFIRMED = "CONFIRMED"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"


CONFIDENCE_ORDER = {
    Confidence.CONFIRMED: 3,
    Confidence.HIGH: 2,
    Confidence.MEDIUM: 1,
    Confidence.LOW: 0,
}


class Verification(StrEnum):
    """How a finding is known — kept separate from its lifecycle status."""

    DETECTED = "DETECTED"  # deterministic scanner or failing deterministic test
    AI_SUGGESTED = "AI_SUGGESTED"  # supported only by an AI-based signal
    CONFIRMED = "CONFIRMED"  # human-confirmed, or direct dynamic evidence
    FALSE_POSITIVE = "FALSE_POSITIVE"
    NOT_TESTED = "NOT_TESTED"


class FindingStatus(StrEnum):
    OPEN = "OPEN"
    IN_PROGRESS = "IN_PROGRESS"
    RESOLVED = "RESOLVED"
    REOPENED = "REOPENED"
    FALSE_POSITIVE = "FALSE_POSITIVE"
    ACCEPTED_RISK = "ACCEPTED_RISK"


ACTIVE_STATUSES = frozenset({FindingStatus.OPEN, FindingStatus.IN_PROGRESS, FindingStatus.REOPENED})


class Exploitability(StrEnum):
    PROVEN_DATAFLOW = "PROVEN_DATAFLOW"  # untrusted source reaches the sink
    LIKELY = "LIKELY"
    POSSIBLE = "POSSIBLE"  # dangerous construct, origin of data unknown
    THEORETICAL = "THEORETICAL"  # pattern only


class ScanStatus(StrEnum):
    QUEUED = "QUEUED"
    RUNNING = "RUNNING"
    COMPLETED = "COMPLETED"
    FAILED = "FAILED"
    CANCELLED = "CANCELLED"


class ScanTrigger(StrEnum):
    MANUAL = "MANUAL"
    API = "API"
    RETEST = "RETEST"
    REMEDIATION = "REMEDIATION"
    WEBHOOK = "WEBHOOK"
    CLI_IMPORT = "CLI_IMPORT"


class ScanScope(StrEnum):
    FULL = "FULL"
    PARTIAL = "PARTIAL"


class SnapshotOrigin(StrEnum):
    UPLOAD_ARCHIVE = "UPLOAD_ARCHIVE"
    UPLOAD_FILE = "UPLOAD_FILE"
    GIT = "GIT"
    PATCH = "PATCH"


class SnapshotStatus(StrEnum):
    PENDING = "PENDING"
    READY = "READY"
    FAILED = "FAILED"


class RepositorySourceType(StrEnum):
    GIT = "GIT"
    UPLOAD = "UPLOAD"


class FileStatus(StrEnum):
    ANALYZED = "ANALYZED"
    SKIPPED_BINARY = "SKIPPED_BINARY"
    SKIPPED_SIZE = "SKIPPED_SIZE"
    SKIPPED_UNSUPPORTED = "SKIPPED_UNSUPPORTED"
    PARSE_ERROR = "PARSE_ERROR"
    EXCLUDED = "EXCLUDED"


class DependencyVulnStatus(StrEnum):
    VULNERABLE = "VULNERABLE"
    NO_KNOWN_VULNERABILITIES = "NO_KNOWN_VULNERABILITIES"
    NOT_VERIFIED = "NOT_VERIFIED"


class RetestResultKind(StrEnum):
    RESOLVED = "RESOLVED"
    STILL_OPEN = "STILL_OPEN"
    REGRESSION = "REGRESSION"
    NOT_REPRODUCED = "NOT_REPRODUCED"
    NOT_TESTED = "NOT_TESTED"
    NEW = "NEW"


class MatchMethod(StrEnum):
    FINGERPRINT = "FINGERPRINT"
    FUZZY = "FUZZY"
    NONE = "NONE"


class AnalysisStatus(StrEnum):
    QUEUED = "QUEUED"
    RUNNING = "RUNNING"
    COMPLETED = "COMPLETED"
    FAILED = "FAILED"
    INVALID_OUTPUT = "INVALID_OUTPUT"


class AIVerdict(StrEnum):
    LIKELY_TRUE_POSITIVE = "LIKELY_TRUE_POSITIVE"
    LIKELY_FALSE_POSITIVE = "LIKELY_FALSE_POSITIVE"
    UNCERTAIN = "UNCERTAIN"


class RemediationOrigin(StrEnum):
    AI = "AI"
    TEMPLATE = "TEMPLATE"


class RemediationStatus(StrEnum):
    PROPOSED = "PROPOSED"
    APPLIED = "APPLIED"  # applied to a new snapshot; awaiting retest
    REJECTED = "REJECTED"
    SUPERSEDED = "SUPERSEDED"
    VERIFIED = "VERIFIED"  # retest confirmed the finding no longer reproduces
    NOT_VERIFIED = "NOT_VERIFIED"  # retest still found the issue


class TargetKind(StrEnum):
    HTTP = "HTTP"
    REFERENCE = "REFERENCE"
    HARNESS = "HARNESS"


class TestCategory(StrEnum):
    PROMPT_SECURITY = "PROMPT_SECURITY"
    DATA_SECURITY = "DATA_SECURITY"
    RAG_SECURITY = "RAG_SECURITY"
    AGENT_SECURITY = "AGENT_SECURITY"


class TestOutcome(StrEnum):
    PASS = "PASS"  # noqa: S105
    FAIL = "FAIL"
    INCONCLUSIVE = "INCONCLUSIVE"
    ERROR = "ERROR"
    NOT_TESTED = "NOT_TESTED"


class FailureLayer(StrEnum):
    RETRIEVAL = "RETRIEVAL"
    AUTHORIZATION = "AUTHORIZATION"
    PROMPT_HANDLING = "PROMPT_HANDLING"
    MODEL_BEHAVIOR = "MODEL_BEHAVIOR"
    TOOL_EXECUTION = "TOOL_EXECUTION"


class RunStatus(StrEnum):
    QUEUED = "QUEUED"
    RUNNING = "RUNNING"
    COMPLETED = "COMPLETED"
    FAILED = "FAILED"
    CANCELLED = "CANCELLED"


class JobStatus(StrEnum):
    QUEUED = "QUEUED"
    RUNNING = "RUNNING"
    SUCCEEDED = "SUCCEEDED"
    FAILED = "FAILED"
    CANCELLED = "CANCELLED"


class JobKind(StrEnum):
    SCAN = "SCAN"
    TEST_RUN = "TEST_RUN"
    AI_ANALYSIS = "AI_ANALYSIS"
    REMEDIATION = "REMEDIATION"
    PR_COMMENT = "PR_COMMENT"


class ReportFormat(StrEnum):
    JSON = "JSON"
    SARIF = "SARIF"
    HTML = "HTML"
    MARKDOWN = "MARKDOWN"


class GateStatus(StrEnum):
    PASS = "PASS"  # noqa: S105
    FAIL = "FAIL"


class IntegrationKind(StrEnum):
    GITHUB = "GITHUB"


class BusinessCriticality(StrEnum):
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"


class Exposure(StrEnum):
    INTERNET_FACING = "INTERNET_FACING"
    INTERNAL = "INTERNAL"
    UNKNOWN = "UNKNOWN"
