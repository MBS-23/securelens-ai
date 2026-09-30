"""SQLAlchemy models. Importing this package registers every table."""

from securelens.models.aisec import AITarget, SecurityTest, TestResult, TestRun
from securelens.models.base import Base
from securelens.models.finding import (
    AIAnalysis,
    Evidence,
    Finding,
    FindingOccurrence,
    Remediation,
    Retest,
    RetestResult,
    SecretFinding,
)
from securelens.models.identity import APIKey, Membership, Organization, User, UserSession
from securelens.models.ops import AuditLog, Integration, Job, Report
from securelens.models.project import Project, ProjectMember, Repository, Snapshot
from securelens.models.scan import Dependency, Scan, ScanFile

__all__ = [
    "AIAnalysis",
    "AITarget",
    "APIKey",
    "AuditLog",
    "Base",
    "Dependency",
    "Evidence",
    "Finding",
    "FindingOccurrence",
    "Integration",
    "Job",
    "Membership",
    "Organization",
    "Project",
    "ProjectMember",
    "Remediation",
    "Report",
    "Repository",
    "Retest",
    "RetestResult",
    "Scan",
    "ScanFile",
    "SecretFinding",
    "SecurityTest",
    "Snapshot",
    "TestResult",
    "TestRun",
    "User",
    "UserSession",
]
