"""
CodeGuard AI - Test Suite: Rule Engine
Tests that pattern-based rules correctly detect known code issues.
"""
import sys
import os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

import pytest
from core.rule_engine import RuleEngine


@pytest.fixture
def engine():
    return RuleEngine()


# ─── Python Tests ──────────────────────────────────────────────────────────

def test_hardcoded_password_detected(engine):
    code = 'password = "super_secret_123"'
    issues = engine.analyse_python(code)
    types = [i.issue_type for i in issues]
    assert "hardcoded_credentials" in types


def test_eval_detected(engine):
    code = "result = eval(user_input)"
    issues = engine.analyse_python(code)
    types = [i.issue_type for i in issues]
    assert "dangerous_eval" in types


def test_sql_injection_python(engine):
    code = 'cursor.execute("SELECT * FROM users WHERE id = " + user_id)'
    issues = engine.analyse_python(code)
    types = [i.issue_type for i in issues]
    assert "sql_injection" in types


def test_bare_except(engine):
    code = "try:\n    pass\nexcept:\n    pass"
    issues = engine.analyse_python(code)
    types = [i.issue_type for i in issues]
    assert "empty_exception_handler" in types


def test_pickle_usage(engine):
    code = "data = pickle.loads(raw)"
    issues = engine.analyse_python(code)
    types = [i.issue_type for i in issues]
    assert "security_flaw" in types


def test_shell_true(engine):
    code = 'subprocess.run(cmd, shell=True)'
    issues = engine.analyse_python(code)
    assert any(i.issue_type == "security_flaw" for i in issues)


def test_clean_python_code(engine):
    code = "def add(a, b):\n    return a + b\n\nresult = add(1, 2)\nprint(result)"
    issues = engine.analyse_python(code)
    # print() may flag style, but no critical/high issues
    critical = [i for i in issues if i.severity in ("Critical", "High")]
    assert len(critical) == 0


# ─── Java Tests ────────────────────────────────────────────────────────────

def test_java_string_comparison(engine):
    code = 'if (userName == "admin") {'
    issues = engine.analyse_java(code)
    types = [i.issue_type for i in issues]
    assert "null_pointer" in types


def test_java_hardcoded_credential(engine):
    code = 'String password = "secret123";'
    issues = engine.analyse_java(code)
    types = [i.issue_type for i in issues]
    assert "hardcoded_credentials" in types


def test_java_empty_catch(engine):
    code = "try {\n  doSomething();\n} catch (Exception e) {}"
    issues = engine.analyse_java(code)
    types = [i.issue_type for i in issues]
    assert "empty_exception_handler" in types


def test_java_runtime_exec(engine):
    code = 'Runtime.getRuntime().exec("cmd /c " + input);'
    issues = engine.analyse_java(code)
    types = [i.issue_type for i in issues]
    assert "security_flaw" in types


def test_empty_code_python(engine):
    issues = engine.analyse_python("")
    assert issues == []


def test_empty_code_java(engine):
    issues = engine.analyse_java("")
    assert issues == []


def test_issue_severity_valid(engine):
    code = 'password = "test123"'
    issues = engine.analyse_python(code)
    valid_severities = {"Critical", "High", "Medium", "Low", "Info"}
    for issue in issues:
        assert issue.severity in valid_severities


def test_issue_has_suggested_fix(engine):
    code = 'password = "test123"'
    issues = engine.analyse_python(code)
    cred_issues = [i for i in issues if i.issue_type == "hardcoded_credentials"]
    assert all(i.suggested_fix is not None for i in cred_issues)


# ─── Multi-Language Tests ──────────────────────────────────────────────────

def test_javascript_rules(engine):
    code = 'const apiKey = "12345abcdef";\neval(userInput);\nelement.innerHTML = "<p>test</p>";'
    issues = engine.analyse_by_language(code, "JavaScript")
    types = [i.issue_type for i in issues]
    assert "hardcoded_credentials" in types
    assert "dangerous_eval" in types
    assert "xss_vulnerability" in types


def test_cpp_rules(engine):
    code = 'char buf[10];\ngets(buf);\nsystem("rm -rf /");'
    issues = engine.analyse_by_language(code, "C++")
    types = [i.issue_type for i in issues]
    assert "buffer_overflow" in types
    assert "command_injection" in types


def test_go_rules(engine):
    code = 'query := fmt.Sprintf("SELECT * FROM users WHERE id = %s", id)'
    issues = engine.analyse_by_language(code, "Go")
    types = [i.issue_type for i in issues]
    assert "sql_injection" in types


def test_sql_rules(engine):
    code = 'DELETE FROM accounts;'
    issues = engine.analyse_by_language(code, "SQL")
    types = [i.issue_type for i in issues]
    assert "dangerous_query" in types
