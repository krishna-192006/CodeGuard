"""
CodeGuard AI - Test Suite: Analyzer Orchestrator
Tests for the full analysis pipeline including error handling.
"""
import sys
import os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

import pytest
from unittest.mock import patch, MagicMock
from core.schemas import AnalysisRequest, ReviewResult
from core.analyzer import analyse_code


def test_python_analysis_returns_result():
    req = AnalysisRequest(code='password = "secret123"', language="Python")
    result = analyse_code(req)
    assert isinstance(result, ReviewResult)
    assert result.language == "Python"
    assert len(result.issues) > 0


def test_java_analysis_returns_result():
    req = AnalysisRequest(code='String pwd = "pw123";', language="Java")
    result = analyse_code(req)
    assert isinstance(result, ReviewResult)
    assert result.language == "Java"


def test_empty_code_raises():
    with pytest.raises(Exception):
        AnalysisRequest(code="", language="Python")


def test_analysis_mode_set():
    req = AnalysisRequest(code='x = 1', language="Python")
    result = analyse_code(req)
    assert result.analysis_mode in ("rule_based", "llm", "hybrid")


def test_result_overall_quality_valid():
    req = AnalysisRequest(code='password = "test"', language="Python")
    result = analyse_code(req)
    assert result.overall_quality in ("Good", "Fair", "Poor")


def test_issue_schema_valid():
    from core.schemas import CodeIssue
    issue = CodeIssue(
        issue_type="sql_injection",
        title="Test Issue",
        description="Test desc",
        line_number=5,
        severity="High",
        source="rule_based",
    )
    assert issue.severity == "High"
    assert issue.issue_type == "sql_injection"


def test_severity_validator():
    from core.schemas import CodeIssue
    issue = CodeIssue(
        issue_type="test",
        title="T",
        description="D",
        severity="INVALID",
        source="rule_based",
    )
    assert issue.severity == "Info"  # Falls back to Info


def test_language_validator():
    req = AnalysisRequest(code="x=1", language="Python")
    assert req.language == "Python"
    req_js = AnalysisRequest(code="x=1", language="JavaScript")
    assert req_js.language == "JavaScript"
    req_unknown = AnalysisRequest(code="x=1", language="UnknownLang123")
    assert req_unknown.language == "UnknownLang123"


def test_analysis_no_crash_on_complex_code():
    complex_code = '''
import os
import sys

def process_data(db_conn, user_input):
    password = "hardcoded"
    query = "SELECT * FROM users WHERE name = " + user_input
    result = eval(user_input)
    try:
        db_conn.execute(query)
    except:
        pass
    return result
'''
    req = AnalysisRequest(code=complex_code, language="Python")
    result = analyse_code(req)
    assert result is not None
    assert len(result.issues) > 0


def test_clean_code_produces_no_critical():
    clean_code = '''
def add_numbers(a: int, b: int) -> int:
    """Add two integers and return the result."""
    return a + b

def main():
    result = add_numbers(3, 4)
    return result
'''
    req = AnalysisRequest(code=clean_code, language="Python")
    result = analyse_code(req)
    critical = [i for i in result.issues if i.severity == "Critical"]
    assert len(critical) == 0
