# Methodology — CodeGuard AI

## 1. Input Processing

Source code is received via two channels:
- **Paste**: Direct text entry in the Streamlit text area.
- **Upload**: `.py` or `.java` file upload (validated for extension and size).

The code string is passed to `AnalysisRequest` (Pydantic model) which validates language and minimum length.

## 2. Static Analysis

### Bandit (Python only)
Bandit performs security-focused AST analysis. CodeGuard AI writes code to a temporary file, invokes `bandit -f json`, parses output, and maps findings to `CodeIssue` objects. The temporary file is deleted immediately after analysis.

### Pylint (Python only)
Pylint inspects code for errors, conventions, and refactoring opportunities. JSON output is parsed and categorised by message type (error → High, warning → Medium, convention → Low, refactor → Info).

### Radon (Python only)
Radon measures cyclomatic complexity (CC). Functions with CC ≥ 10 are flagged as Medium severity; CC ≥ 15 as High severity.

All static tools degrade gracefully — if a tool is not installed, the analysis continues with remaining tools.

## 3. Rule-Based Detection

The rule engine applies compiled regex patterns line-by-line to the source code:
- **16 Python rules**: hardcoded credentials, eval/exec, SQL injection, bare except, pickle, shell=True, mutable defaults, etc.
- **12 Java rules**: string == comparison, null pointer patterns, empty catch, unclosed resources, Runtime.exec(), etc.

Each rule specifies: issue type, title, severity, description, suggested fix, and impact.

## 4. LLM Analysis (Optional)

When `GEMINI_API_KEY` is configured:

1. A carefully crafted system prompt instructs Gemini to output **only** a JSON object matching the `ReviewResult` schema.
2. The code is appended to the prompt inside a fenced code block.
3. The response is stripped of any markdown fences and parsed with `json.loads()`.
4. The parsed object is validated with Pydantic. Validation errors are caught and reported without crashing.
5. All LLM-sourced issues are tagged with `source="llm"`.

### Error Handling
| Error | Response |
|---|---|
| No API key | Rule-based mode, no LLM banner |
| Rate limit | Error message shown; rule results still displayed |
| Timeout | Timeout message; rule results still displayed |
| Malformed JSON | Parse error shown; rule results still displayed |
| Schema mismatch | Validation error shown; rule results still displayed |

## 5. Result Merging (Hybrid Mode)

When LLM is available, results from all three layers are merged:
1. LLM issues take priority.
2. Rule/static issues not already covered (matched by `issue_type + line_number`) are appended.
3. Deduplication prevents the same finding appearing twice.

## 6. Severity Classification

| Level | Meaning |
|---|---|
| Critical | Immediate security or data risk (e.g., SQL injection, hardcoded credential) |
| High | Likely bug causing crashes or security issues (e.g., null dereference, eval) |
| Medium | Risk under certain conditions (e.g., bare except, open without context manager) |
| Low | Code quality or maintenance concern (e.g., None comparison using ==) |
| Info | Informational / style finding (e.g., print statements, global variables) |

## 7. Human Approval Workflow

1. Analysis results are displayed with explanations and suggested fixes.
2. A disclaimer is shown prominently on every results page.
3. Side-by-side comparison shows the original code context and the suggested fix.
4. An explicit **"Human approval required"** notice appears below every fix.
5. The application **never** automatically applies, commits, or merges any change.
6. Users are instructed to review suggestions with domain knowledge before acting.

## 8. Dataset Analytics

The historical dataset (`dataset.csv`, 500 rows) is loaded with Pandas:
- Cleaned (duplicates removed, values clipped/normalised).
- Saved as `processed_dataset.csv`.
- Visualised with 7 interactive Plotly charts and 7 static Matplotlib/Seaborn charts.

Dashboard statistics are clearly labelled as **historical dataset metrics** and are never mixed with live analysis results.

## 9. Review History

Each completed analysis is stored in SQLite with:
- Unique review ID, timestamp, language, filename
- Issue counts by severity
- Overall quality rating
- Full issues JSON

History can be browsed and individual records deleted after confirmation.
