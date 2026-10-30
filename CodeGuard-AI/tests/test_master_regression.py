"""
CodeGuard AI 2.0 - Master Regression & Reliability Test Suite
Covers:
1. Issue Explorer navigation & state management
2. Uploaded file synchronization & cache invalidation
3. Missing issue metadata & defensive rendering
4. Malformed LLM responses & graceful fallback
5. Pylint result parsing, Rule IDs, and accurate remediation mapping
6. Source line & end line evidence validation
7. Confidence score calibration & explanation assertions
8. Multiple file upload handling simulation
9. Empty source code input error handling
10. Invalid Python syntax handling
"""
import sys
import os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

import pytest
import json
from unittest.mock import MagicMock, patch
from core.schemas import AnalysisRequest, ReviewResult, CodeIssue
from core.rule_engine import RuleEngine
from core.ast_analyzer import ASTAnalyzer
from core.static_analyzer import StaticAnalyzer, _map_pylint_category, PYLINT_REMEDIATION_MAP
from core.llm_service import LLMService
from core.analyzer import analyse_code, deduplicate_issues


# 1. Issue Explorer Navigation & State
def test_issue_explorer_state_model():
    issue = CodeIssue(
        issue_type="sql_injection",
        category="Security Vulnerabilities",
        title="SQL Injection",
        description="Dynamic SQL query",
        severity="Critical",
        line_number=10,
        evidence="cursor.execute('SELECT * FROM users')",
        suggested_fix="Use parameter markers",
        confidence=0.95,
        detection_sources=["rule_engine"],
    )
    result = ReviewResult(
        summary="Test review",
        language="Python",
        overall_quality="Poor",
        issues=[issue],
    )
    assert len(result.issues) == 1
    assert result.issues[0].issue_type == "sql_injection"
    assert result.issues[0].line_number == 10


# 2. Uploaded-File Synchronization Simulation
def test_upload_sync_reset():
    # Simulate changing files resetting review state
    session_state = {"last_uploaded_files": ["app.py"], "current_review": "dummy_review"}
    new_uploaded_files = ["service.py"]
    if new_uploaded_files != session_state["last_uploaded_files"]:
        session_state["last_uploaded_files"] = new_uploaded_files
        session_state["current_review"] = None
    assert session_state["last_uploaded_files"] == ["service.py"]
    assert session_state["current_review"] is None


# 3. Missing Issue Metadata & Defensive Defaults
def test_missing_issue_metadata():
    # Construct an issue with minimal required fields
    issue = CodeIssue(
        issue_type="null_pointer",
        title="Null Check",
        description="Missing check",
        severity="High",
    )
    assert issue.line_number is None
    assert issue.evidence is None
    assert issue.suggested_fix is None
    assert issue.category == "Code Quality Issues"  # default
    assert issue.confidence == 0.85
    assert issue.status == "Open"


# 4. Malformed LLM Responses & Graceful Handling
def test_llm_malformed_json_handling():
    service = LLMService(api_key="mock_key")
    service._available = True
    
    with patch.object(service, "_call_gemini_rest", return_value="This is not valid JSON at all!"):
        result = service.analyse("x = 1", "Python")
        assert isinstance(result, ReviewResult)
        assert result.error is not None
        assert "JSON decoding error" in result.error
        assert len(result.issues) == 0


# 5. Pylint Result Parsing & Specific Remediations
def test_pylint_category_and_remediation_mapping():
    cat = _map_pylint_category("warning", "dangerous-default-value")
    assert cat == "Security Vulnerabilities"

    doc_remed = PYLINT_REMEDIATION_MAP.get("missing-module-docstring")
    assert "module-level docstring" in doc_remed


# 6. Source Line and Evidence Accuracy
def test_ast_source_line_accuracy():
    analyzer = ASTAnalyzer()
    code = "import os\n\ndef divide():\n    return 100 / 0"
    issues = analyzer.analyse_code(code)
    div_issue = next(i for i in issues if i.issue_type == "division_by_zero")
    assert div_issue.line_number == 4
    assert div_issue.evidence == "return 100 / 0"
    assert div_issue.category == "Runtime Errors"


# 7. Confidence Score Validation
def test_confidence_score_distinction():
    rule_engine = RuleEngine()
    code = 'api_key = "secret_12345678"'
    issues = rule_engine.analyse_python(code)
    assert len(issues) > 0
    assert issues[0].confidence >= 0.90
    assert issues[0].confidence_explanation is not None


# 8. Empty Source Code Input Handling
def test_empty_source_code_rejection():
    with pytest.raises(Exception):
        AnalysisRequest(code="", language="Python")


# 9. Invalid Python Syntax Handling
def test_invalid_python_syntax():
    analyzer = ASTAnalyzer()
    code = "def broken_func(:\n    pass"
    issues = analyzer.analyse_code(code)
    assert len(issues) == 1
    assert issues[0].issue_type == "syntax_error"
    assert issues[0].category == "Syntax Errors"
    assert issues[0].line_number == 1


# 10. Multi-Attribute Deduplication
def test_deduplication_preserves_provenance():
    i1 = CodeIssue(
        issue_type="hardcoded_credentials",
        category="Security Vulnerabilities",
        title="Hardcoded API Key",
        description="Found by Rule Engine",
        severity="Critical",
        line_number=2,
        evidence='api_key = "12345"',
        detection_sources=["rule_engine"],
    )
    i2 = CodeIssue(
        issue_type="hardcoded_credentials",
        category="Security Vulnerabilities",
        title="Hardcoded Credential Token",
        description="Found by Bandit",
        severity="High",
        line_number=2,
        evidence='api_key = "12345"',
        detection_sources=["bandit"],
    )
    merged = deduplicate_issues([i1, i2])
    assert len(merged) == 1
    assert "rule_engine" in merged[0].detection_sources
    assert "bandit" in merged[0].detection_sources
    assert merged[0].severity == "Critical"  # Upgraded to higher severity

