"""
CodeGuard AI 2.0 - Core Schemas
Extended structured models for issues, reviews, benchmarks, and evaluation metrics.
Supports standardized categories:
- Syntax Errors
- Runtime Errors
- Logical Errors
- Security Vulnerabilities
- Performance Issues
- Code Quality Issues
- Exception Handling
- Resource Management
"""
from __future__ import annotations
import uuid
from typing import List, Optional, Dict, Any
from pydantic import BaseModel, Field, field_validator


SUPPORTED_LANGUAGES = [
    "Python",
    "Java",
    "JavaScript",
    "TypeScript",
    "C++",
    "C",
    "C#",
    "Go",
    "Rust",
    "PHP",
    "Ruby",
    "SQL",
]

STANDARD_CATEGORIES = [
    "Syntax Errors",
    "Runtime Errors",
    "Logical Errors",
    "Security Vulnerabilities",
    "Performance Issues",
    "Code Quality Issues",
    "Exception Handling",
    "Resource Management",
]


class CodeIssue(BaseModel):
    """
    Represents a single detected code issue or vulnerability with full provenance,
    evidence, confidence ratings, and actionable remediation details.
    """
    issue_id: str = Field(default_factory=lambda: f"ISSUE-{uuid.uuid4().hex[:8].upper()}")
    issue_type: str = Field(..., description="Normalized issue category identifier (e.g., sql_injection)")
    category: str = Field(default="Code Quality Issues", description="Standardized classification category")
    title: str = Field(..., description="Short human-readable summary")
    description: str = Field(..., description="Detailed explanation of the flaw and why it occurs")
    severity: str = Field(..., description="Critical | High | Medium | Low | Informational")
    line_number: Optional[int] = Field(None, description="Starting source line number where issue occurs")
    end_line_number: Optional[int] = Field(None, description="Ending source line number if applicable")
    evidence: Optional[str] = Field(None, description="Exact or problematic code line/token snippet")
    suggested_fix: Optional[str] = Field(None, description="Actionable remediation advice")
    corrected_code: Optional[str] = Field(None, description="Safe replacement code snippet")
    impact: Optional[str] = Field(None, description="Security or operational impact if left unresolved")
    confidence: float = Field(default=0.85, ge=0.0, le=1.0, description="Confidence score 0.0 to 1.0")
    confidence_explanation: Optional[str] = Field(
        default=None,
        description="Explanation distinguishing deterministic static/AST proof from statistical LLM estimate."
    )
    detection_sources: List[str] = Field(default_factory=lambda: ["rule_engine"], description="Engines that identified this issue")
    source: str = Field(default="rule_engine", description="Primary/original source engine")
    rule_id: Optional[str] = Field(None, description="Static linter rule or engine ID (e.g. C0114, B602)")
    status: str = Field(default="Open", description="Open | Resolved | False Positive | Ignored")

    @field_validator("severity")
    @classmethod
    def validate_severity(cls, v: str) -> str:
        mapping = {
            "critical": "Critical",
            "high": "High",
            "medium": "Medium",
            "low": "Low",
            "info": "Informational",
            "informational": "Informational",
        }
        val = str(v).strip().lower()
        if val in mapping:
            return mapping[val]
        if v in ("Critical", "High", "Medium", "Low", "Info", "Informational"):
            return "Informational" if v == "Info" else v
        return "Info"

    @field_validator("category")
    @classmethod
    def normalize_category(cls, v: str) -> str:
        v_clean = str(v).strip()
        cat_map = {
            "security": "Security Vulnerabilities",
            "security vulnerabilities": "Security Vulnerabilities",
            "bug": "Logical Errors",
            "logical errors": "Logical Errors",
            "logic errors": "Logical Errors",
            "runtime errors": "Runtime Errors",
            "runtime": "Runtime Errors",
            "syntax errors": "Syntax Errors",
            "syntax": "Syntax Errors",
            "performance": "Performance Issues",
            "performance issues": "Performance Issues",
            "style": "Code Quality Issues",
            "code quality issues": "Code Quality Issues",
            "code quality": "Code Quality Issues",
            "reliability": "Code Quality Issues",
            "exception handling": "Exception Handling",
            "exception": "Exception Handling",
            "resource management": "Resource Management",
            "resource": "Resource Management",
        }
        return cat_map.get(v_clean.lower(), "Code Quality Issues")

    @field_validator("issue_type")
    @classmethod
    def normalise_issue_type(cls, v: str) -> str:
        return str(v).strip().lower().replace(" ", "_").replace("-", "_")

    @field_validator("confidence")
    @classmethod
    def validate_confidence(cls, v: Optional[float]) -> float:
        if v is None:
            return 0.8
        return max(0.0, min(1.0, float(v)))


class ReviewResult(BaseModel):
    """Aggregated result of multi-engine code analysis."""
    review_id: str = Field(default_factory=lambda: f"REV-{uuid.uuid4().hex[:8].upper()}")
    summary: str = Field(default="", description="High-level executive assessment")
    language: str = Field(default="", description="Programming language inspected")
    overall_quality: str = Field(default="Fair", description="Good | Fair | Poor")
    issues: List[CodeIssue] = Field(default_factory=list)
    recommendations: List[str] = Field(default_factory=list)
    analysis_mode: str = Field(default="rule_based", description="rule_based | ast | static | llm | hybrid")
    analyzer_statuses: Dict[str, str] = Field(default_factory=dict, description="Execution status for each engine")
    analysis_duration_sec: float = Field(default=0.0, description="Duration in seconds")
    error: Optional[str] = Field(None, description="Error note if an engine failed")

    @field_validator("overall_quality")
    @classmethod
    def validate_quality(cls, v: str) -> str:
        allowed = {"Good", "Fair", "Poor"}
        return v if v in allowed else "Fair"


class ReviewRecord(BaseModel):
    """Database record stored in review history."""
    review_id: str
    timestamp: str
    language: str
    filename: Optional[str] = None
    lines_of_code: int = 0
    total_issues: int = 0
    critical_count: int = 0
    high_count: int = 0
    overall_quality: str = "Fair"
    analysis_mode: str = "rule_based"
    summary: str = ""
    source_hash: Optional[str] = None
    duration_sec: Optional[float] = 0.0


class AnalysisRequest(BaseModel):
    """Input submission for analysis."""
    code: str = Field(..., min_length=1)
    language: str = Field(default="Python")
    filename: Optional[str] = None
    enabled_engines: Optional[List[str]] = Field(
        default_factory=lambda: ["rule_engine", "ast_analyzer", "static_analyzer", "llm_service"]
    )

    @field_validator("language")
    @classmethod
    def validate_language(cls, v: str) -> str:
        for lang in SUPPORTED_LANGUAGES:
            if lang.lower() == v.lower():
                return lang
        return v if v else "Python"


class BenchmarkSample(BaseModel):
    """Verified ground-truth benchmark item."""
    sample_id: str
    programming_language: str
    source_code: str
    buggy_code: str
    corrected_code: str
    bug_category: str
    bug_subcategory: str
    severity: str
    expected_line_number: Optional[int] = None
    expected_behavior: str
    actual_behavior: str
    ground_truth_label: int = Field(default=1, description="1 if buggy, 0 if clean")
    source: str = "manually_verified"
    verification_status: str = "Verified"
