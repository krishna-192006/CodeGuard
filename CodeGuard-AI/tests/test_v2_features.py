"""
CodeGuard AI 2.0 - Comprehensive Unit & Integration Test Suite
Validates AST visitors, Rule engine, Static analyzer gracefully degrading,
Deduplication logic, Evaluation metrics, and Export functionality.
"""
import sys
import os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

import pytest
import pandas as pd
from core.schemas import AnalysisRequest, ReviewResult, CodeIssue
from core.rule_engine import RuleEngine
from core.ast_analyzer import ASTAnalyzer
from core.analyzer import analyse_code, deduplicate_issues
from core.evaluation import calculate_metrics, evaluate_engines_on_benchmark
from core.test_generator import generate_pytest_suite
from core.report_exporter import export_as_json, export_as_csv, export_as_pdf


# ─── AST Tests ───────────────────────────────────────────────────────────────

def test_ast_mutable_default():
    analyzer = ASTAnalyzer()
    code = "def process(items=[]):\n    items.append(1)\n    return items"
    issues = analyzer.analyse_code(code)
    types = [i.issue_type for i in issues]
    assert "mutable_default_argument" in types
    assert issues[0].line_number == 1
    assert issues[0].severity == "High"


def test_ast_division_by_zero():
    analyzer = ASTAnalyzer()
    code = "x = 100 / 0"
    issues = analyzer.analyse_code(code)
    types = [i.issue_type for i in issues]
    assert "division_by_zero" in types
    assert issues[0].severity == "Critical"


def test_ast_suspicious_comparison_none():
    analyzer = ASTAnalyzer()
    code = "if val == None:\n    pass"
    issues = analyzer.analyse_code(code)
    types = [i.issue_type for i in issues]
    assert "suspicious_comparison" in types


def test_ast_syntax_error_graceful():
    analyzer = ASTAnalyzer()
    code = "def invalid syntax ("
    issues = analyzer.analyse_code(code)
    assert len(issues) == 1
    assert issues[0].issue_type == "syntax_error"


# ─── Rule Engine Tests ───────────────────────────────────────────────────────

def test_rule_hardcoded_credentials():
    engine = RuleEngine()
    code = 'api_key = "secret_token_12345"'
    issues = engine.analyse_python(code)
    types = [i.issue_type for i in issues]
    assert "hardcoded_credentials" in types


def test_rule_sql_injection_python():
    engine = RuleEngine()
    code = 'cursor.execute("SELECT * FROM users WHERE id = " + user_id)'
    issues = engine.analyse_python(code)
    types = [i.issue_type for i in issues]
    assert "sql_injection" in types


def test_rule_comments_ignored():
    engine = RuleEngine()
    # A comment should not trigger a hardcoded credential finding
    code = '# Note: password = "password_sample"'
    issues = engine.analyse_python(code)
    types = [i.issue_type for i in issues]
    assert "hardcoded_credentials" not in types


def test_rule_multi_language_cpp():
    engine = RuleEngine()
    code = 'char buf[10];\ngets(buf);'
    issues = engine.analyse_by_language(code, "C++")
    types = [i.issue_type for i in issues]
    assert "buffer_overflow" in types


def test_rule_multi_language_sql():
    engine = RuleEngine()
    code = 'DELETE FROM users;'
    issues = engine.analyse_by_language(code, "SQL")
    types = [i.issue_type for i in issues]
    assert "dangerous_query" in types


# ─── Orchestrator & Deduplication Tests ──────────────────────────────────────

def test_orchestrator_python_pipeline():
    code = 'def test_fn(items=[]):\n    return 10 / 0'
    req = AnalysisRequest(code=code, language="Python", enabled_engines=["rule_engine", "ast_analyzer"])
    result = analyse_code(req)
    assert isinstance(result, ReviewResult)
    types = [i.issue_type for i in result.issues]
    assert "mutable_default_argument" in types
    assert "division_by_zero" in types


def test_deduplication_merges_sources():
    issue1 = CodeIssue(
        issue_type="sql_injection",
        category="Security",
        title="SQL Injection",
        description="Found by rules",
        severity="Critical",
        line_number=5,
        detection_sources=["rule_engine"],
        source="rule_engine"
    )
    issue2 = CodeIssue(
        issue_type="sql_injection",
        category="Security",
        title="SQL Injection",
        description="Found by static",
        severity="Critical",
        line_number=5,
        detection_sources=["bandit"],
        source="bandit"
    )
    merged = deduplicate_issues([issue1, issue2])
    assert len(merged) == 1
    assert "rule_engine" in merged[0].detection_sources
    assert "bandit" in merged[0].detection_sources


# ─── Evaluation Metrics Tests ────────────────────────────────────────────────

def test_calculate_metrics_perfect():
    y_true = [1, 1, 0, 0]
    y_pred = [1, 1, 0, 0]
    metrics = calculate_metrics(y_true, y_pred)
    assert metrics["accuracy"] == 1.0
    assert metrics["precision"] == 1.0
    assert metrics["recall"] == 1.0
    assert metrics["f1"] == 1.0
    assert metrics["fpr"] == 0.0


def test_calculate_metrics_with_fp_fn():
    y_true = [1, 0, 1, 0]
    y_pred = [1, 1, 0, 0]
    metrics = calculate_metrics(y_true, y_pred)
    assert metrics["TP"] == 1
    assert metrics["FP"] == 1
    assert metrics["FN"] == 1
    assert metrics["TN"] == 1
    assert metrics["accuracy"] == 0.5


# ─── Report Exporter & Test Generator Tests ──────────────────────────────────

def test_generate_pytest_suite():
    issue = CodeIssue(
        issue_type="division_by_zero",
        category="Bug",
        title="Division by Zero",
        description="test",
        severity="Critical",
        line_number=2,
    )
    test_code = generate_pytest_suite("def f(): return 1/0", "Python", [issue])
    assert "pytest" in test_code
    assert "ZeroDivisionError" in test_code


def test_report_exporters():
    res = ReviewResult(
        summary="Test summary",
        language="Python",
        overall_quality="Good",
        issues=[],
    )
    json_out = export_as_json(res)
    assert "Test summary" in json_out
    csv_out = export_as_csv(res)
    assert "issue_id" in csv_out
    pdf_out = export_as_pdf(res, "test.py")
    assert isinstance(pdf_out, bytes)
    assert len(pdf_out) > 500

