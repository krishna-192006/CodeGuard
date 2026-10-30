# Test Cases — CodeGuard AI

## Test Environment
- Python 3.10+
- pytest
- No API key required (rule-based mode)

## Running Tests

```bash
cd CodeGuard-AI
pytest tests/ -v
```

---

## TC-01: Python Hardcoded Credential Detection
**Component:** Rule Engine  
**Input:** `password = "super_secret_123"`  
**Expected:** Issue with `issue_type="hardcoded_credentials"` and `severity="Critical"` detected.  
**File:** `tests/test_rules.py::test_hardcoded_password_detected`

---

## TC-02: eval() Usage Detection
**Component:** Rule Engine  
**Input:** `result = eval(user_input)`  
**Expected:** Issue with `issue_type="dangerous_eval"` and `severity="High"` detected.  
**File:** `tests/test_rules.py::test_eval_detected`

---

## TC-03: Python SQL Injection Detection
**Component:** Rule Engine  
**Input:** `cursor.execute("SELECT * FROM users WHERE id = " + user_id)`  
**Expected:** Issue with `issue_type="sql_injection"` and `severity="Critical"` detected.  
**File:** `tests/test_rules.py::test_sql_injection_python`

---

## TC-04: Empty except Block Detection
**Component:** Rule Engine  
**Input:**
```python
try:
    pass
except:
    pass
```
**Expected:** Issue with `issue_type="empty_exception_handler"` detected.  
**File:** `tests/test_rules.py::test_bare_except`

---

## TC-05: Java String == Comparison Detection
**Component:** Rule Engine  
**Input:** `if (userName == "admin") {`  
**Expected:** Issue with `issue_type="null_pointer"` detected.  
**File:** `tests/test_rules.py::test_java_string_comparison`

---

## TC-06: Java Hardcoded Credential Detection
**Component:** Rule Engine  
**Input:** `String password = "secret123";`  
**Expected:** Issue with `issue_type="hardcoded_credentials"` detected.  
**File:** `tests/test_rules.py::test_java_hardcoded_credential`

---

## TC-07: Clean Python Code — No Critical Issues
**Component:** Rule Engine  
**Input:** Simple, correct `add(a, b)` function.  
**Expected:** No Critical or High severity issues.  
**File:** `tests/test_rules.py::test_clean_python_code`

---

## TC-08: Empty Code Input
**Component:** Rule Engine  
**Input:** Empty string `""`  
**Expected:** Returns empty list (no crash).  
**File:** `tests/test_rules.py::test_empty_code_python`

---

## TC-09: Dataset Loads Successfully
**Component:** Dataset / Config  
**Input:** `dataset.csv`  
**Expected:** 500 rows and 8 expected columns present.  
**File:** `tests/test_dataset.py::test_dataset_row_count`

---

## TC-10: LLM Confidence Values in Range
**Component:** Dataset  
**Input:** `dataset.csv`  
**Expected:** All `llm_confidence` values are between 0.0 and 1.0.  
**File:** `tests/test_dataset.py::test_llm_confidence_range`

---

## TC-11: Severity Values Valid
**Component:** Dataset  
**Input:** `dataset.csv`  
**Expected:** `severity` column contains only: Critical, High, Medium, Low, Info.  
**File:** `tests/test_dataset.py::test_severity_values`

---

## TC-12: Analysis Returns ReviewResult
**Component:** Analyzer Orchestrator  
**Input:** Python code with hardcoded password.  
**Expected:** Returns `ReviewResult` with at least one issue.  
**File:** `tests/test_analyzer.py::test_python_analysis_returns_result`

---

## TC-13: Invalid Language Normalised
**Component:** Pydantic Schema  
**Input:** `AnalysisRequest(code="x=1", language="Ruby")`  
**Expected:** `language` normalised to `"Python"` without error.  
**File:** `tests/test_analyzer.py::test_language_validator`

---

## TC-14: Invalid Severity Normalised
**Component:** Pydantic Schema  
**Input:** `CodeIssue(severity="INVALID", ...)`  
**Expected:** `severity` normalised to `"Info"`.  
**File:** `tests/test_analyzer.py::test_severity_validator`

---

## TC-15: Complex Buggy Code — Multiple Issues Detected
**Component:** Analyzer Orchestrator  
**Input:** Code containing hardcoded password, SQL injection, eval(), bare except.  
**Expected:** Multiple issues detected, result is not None.  
**File:** `tests/test_analyzer.py::test_analysis_no_crash_on_complex_code`

---

## TC-16: File Extension Validation — Reject Unknown Type
**Component:** Security Module  
**Input:** `filename = "script.php"`  
**Expected:** `validate_file_extension()` returns `(False, error_msg)`.  
**Manual test in:** `core/security.py::validate_file_extension`

---

## TC-17: File Extension Validation — Accept .py
**Component:** Security Module  
**Input:** `filename = "script.py"`  
**Expected:** `validate_file_extension()` returns `(True, "")`

---

## TC-18: Database Save and Retrieve
**Component:** History Database  
**Input:** `ReviewResult` object.  
**Expected:** `save_review()` returns a review ID; `get_all_reviews()` includes the saved record.  
**Manual / integration test**

---

## TC-19: Analysis Mode Correctly Set
**Component:** Analyzer Orchestrator  
**Input:** Any Python code, no API key set.  
**Expected:** `result.analysis_mode == "rule_based"`.  
**File:** `tests/test_analyzer.py::test_analysis_mode_set`

---

## TC-20: Pickle Usage Detection
**Component:** Rule Engine  
**Input:** `data = pickle.loads(raw)`  
**Expected:** Issue with `issue_type="security_flaw"` detected.  
**File:** `tests/test_rules.py::test_pickle_usage`
