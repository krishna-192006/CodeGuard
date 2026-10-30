"""
CodeGuard AI 2.0 - Rule Engine
Pattern-based security flaw and bug detection across multiple programming languages.
Extracts code evidence, filters comments, and provides detailed remediation guidance.
"""
from __future__ import annotations
import re
from typing import List, Dict, Any, Optional
from core.schemas import CodeIssue


def _strip_comment(line: str, lang: str) -> str:
    """Strip single-line comments so regex rules don't trigger on documentation."""
    l_strip = line.strip()
    if lang in ("python", "py", "ruby", "rb"):
        if l_strip.startswith("#"):
            return ""
        return line.split("#")[0]
    elif lang in ("javascript", "typescript", "java", "c++", "cpp", "c", "c#", "cs", "go", "rust", "php"):
        if l_strip.startswith("//") or l_strip.startswith("/*") or l_strip.startswith("*"):
            return ""
        return line.split("//")[0]
    elif lang == "sql":
        if l_strip.startswith("--") or l_strip.startswith("/*"):
            return ""
        return line.split("--")[0]
    return line


# ─── PYTHON RULES ────────────────────────────────────────────────────────────

PYTHON_RULES: list[dict] = [
    {
        "id": "py_eval_usage",
        "issue_type": "dangerous_eval",
        "category": "Security Vulnerabilities",
        "title": "Dangerous eval() Usage",
        "severity": "High",
        "pattern": re.compile(r'\beval\s*\('),
        "description": "eval() executes arbitrary code and creates serious security vulnerabilities.",
        "suggested_fix": "Replace eval() with safer alternatives like ast.literal_eval() for data parsing.",
        "impact": "Arbitrary code execution if input is user-controlled.",
        "confidence": 0.98,
        "confidence_explanation": "Deterministic regex pattern match on built-in dangerous dynamic execution call.",
    },
    {
        "id": "py_shell_true",
        "issue_type": "security_flaw",
        "category": "Security Vulnerabilities",
        "title": "Subprocess shell=True Detected",
        "severity": "High",
        "pattern": re.compile(r'subprocess\.[a-zA-Z_]+\(.*shell\s*=\s*True', re.IGNORECASE),
        "description": "Invoking subprocess with shell=True invites command injection vulnerabilities.",
        "suggested_fix": "Pass arguments as a sequence without shell=True.",
        "impact": "OS command execution.",
        "confidence": 0.95,
        "confidence_explanation": "Deterministic regex pattern match on unsafe subprocess configuration.",
    },
    {
        "id": "py_hardcoded_cred",
        "issue_type": "hardcoded_credentials",
        "category": "Security Vulnerabilities",
        "title": "Hardcoded Credential Detected",
        "severity": "Critical",
        "pattern": re.compile(
            r'(?:password|passwd|secret|api_key|apikey|token|auth)\s*=\s*["\'][^"\']{4,}["\']',
            re.IGNORECASE,
        ),
        "description": "A secret token, password, or API key appears hardcoded directly into the Python source code.",
        "suggested_fix": "Extract the credential into an environment variable and load it securely using os.environ or os.getenv().",
        "corrected_code": "import os\napi_key = os.getenv('API_KEY')",
        "impact": "Exposes credentials in version control systems and build logs, leading to account compromise.",
        "confidence": 0.95,
        "confidence_explanation": "Pattern match on credential variable assignment containing private token literal.",
    },
    {
        "id": "py_sql_injection",
        "issue_type": "sql_injection",
        "category": "Security Vulnerabilities",
        "title": "SQL Injection via String Concatenation",
        "severity": "Critical",
        "pattern": re.compile(
            r'(?:execute|cursor\.execute)\s*\(\s*(?:f["\']|["\'].*?(?:\+|%s|%d|\{))',
            re.IGNORECASE,
        ),
        "description": "SQL statement is assembled using dynamic string concatenation, f-strings, or formatting.",
        "suggested_fix": "Use parameterized queries or ORM query builders to safely bind values.",
        "corrected_code": "cursor.execute('SELECT * FROM users WHERE id = ?', (user_id,))",
        "impact": "Enables attackers to bypass authentication, extract sensitive records, or drop tables.",
        "confidence": 0.92,
        "confidence_explanation": "Static regex match on string concatenation in database execute statements.",
    },
    {
        "id": "py_command_injection",
        "issue_type": "command_injection",
        "category": "Security Vulnerabilities",
        "title": "Command Injection Vulnerability (shell=True)",
        "severity": "Critical",
        "pattern": re.compile(
            r'(?:os\.system\s*\(|subprocess\.(?:Popen|call|run)\s*\(.*?shell\s*=\s*True)',
            re.IGNORECASE,
        ),
        "description": "Executing system shell commands with user inputs or shell=True allows arbitrary OS command injection.",
        "suggested_fix": "Pass command arguments as a list with shell=False, or use dedicated high-level Python libraries.",
        "corrected_code": "subprocess.run(['ls', '-la'], check=True, shell=False)",
        "impact": "Full server compromise through remote shell execution.",
        "confidence": 0.94,
        "confidence_explanation": "Pattern detection of unescaped shell invocations.",
    },
    {
        "id": "py_insecure_deserialization",
        "issue_type": "security_flaw",
        "category": "Security Vulnerabilities",
        "title": "Insecure Deserialization via pickle",
        "severity": "Critical",
        "pattern": re.compile(r'\bpickle\.(?:loads|load)\s*\('),
        "description": "Python's pickle module is not secure against erroneous or maliciously constructed data.",
        "suggested_fix": "Use safe data serialization formats like JSON, MessagePack, or Protocol Buffers.",
        "corrected_code": "import json\ndata = json.loads(payload)",
        "impact": "Arbitrary code execution during object unpickling.",
        "confidence": 0.98,
        "confidence_explanation": "Direct invocation of Python's pickle deserializer.",
    },
    {
        "id": "py_open_no_with",
        "issue_type": "resource_leak",
        "category": "Resource Management",
        "title": "Unmanaged File Handle (Missing Context Manager)",
        "severity": "Medium",
        "pattern": re.compile(r'=\s*open\s*\((?!.*with\b)'),
        "description": "File handle is opened without a context manager ('with' block), risking unclosed file descriptors.",
        "suggested_fix": "Wrap file interactions with 'with open(...) as handle:' to guarantee file closure.",
        "corrected_code": "with open(filepath, 'r', encoding='utf-8') as f:\n    data = f.read()",
        "impact": "OS file descriptor exhaustion and data corruption on abrupt termination.",
        "confidence": 0.88,
        "confidence_explanation": "Direct assignment from open() call without enclosing context manager.",
    },
    {
        "id": "py_bare_except",
        "issue_type": "empty_exception_handler",
        "category": "Exception Handling",
        "title": "Indiscriminate Bare except Clause",
        "severity": "Medium",
        "pattern": re.compile(r'except\s*:'),
        "description": "A bare except statement catches SystemExit, KeyboardInterrupt, and all errors indiscriminately.",
        "suggested_fix": "Specify the exact exceptions you anticipate, such as 'except (ValueError, KeyError) as e:'.",
        "corrected_code": "except SpecificException as err:\n    logger.error('Operation failed: %s', err)",
        "impact": "Masks bugs, prevents process termination, and complicates troubleshooting.",
        "confidence": 0.96,
        "confidence_explanation": "Syntax pattern match for non-specific exception handler.",
    },
]

# ─── JAVA RULES ──────────────────────────────────────────────────────────────

JAVA_RULES: list[dict] = [
    {
        "id": "java_string_comparison",
        "issue_type": "null_pointer",
        "category": "Logical Errors",
        "title": "String Comparison Using ==",
        "severity": "High",
        "pattern": re.compile(r'==\s*"[^\"]*"|"[^\"]*"\s*=='),
        "description": "Comparing strings with == checks reference equality instead of value equality.",
        "suggested_fix": "Use .equals() for string value comparison.",
        "confidence": 0.95,
        "confidence_explanation": "Reference equality comparison detected on string literal.",
    },
    {
        "id": "java_sql_concat",
        "issue_type": "sql_injection",
        "category": "Security Vulnerabilities",
        "title": "SQL Injection in Statement Execution",
        "severity": "Critical",
        "pattern": re.compile(r'(?:executeQuery|executeUpdate)\s*\(\s*["\'].*\+', re.IGNORECASE),
        "description": "SQL query built with string concatenation in JDBC statement.",
        "suggested_fix": "Use PreparedStatement with positional parameter markers (?).",
        "corrected_code": "PreparedStatement ps = conn.prepareStatement(\"SELECT * FROM users WHERE id = ?\");\nps.setInt(1, userId);",
        "impact": "Unauthorized database reads, data loss, or schema manipulation.",
        "confidence": 0.94,
        "confidence_explanation": "JDBC query concatenation pattern.",
    },
    {
        "id": "java_hardcoded_cred",
        "issue_type": "hardcoded_credentials",
        "category": "Security Vulnerabilities",
        "title": "Hardcoded Credential in Java",
        "severity": "Critical",
        "pattern": re.compile(
            r'(?:String|char\[\])\s+(?:password|secret|apiKey|api_key|token)\s*=\s*["\'][^"\']{4,}["\']',
            re.IGNORECASE,
        ),
        "description": "Hardcoded secret string detected in Java class declaration or method body.",
        "suggested_fix": "Load secrets from environment variables using System.getenv().",
        "corrected_code": "String apiKey = System.getenv(\"API_KEY\");",
        "impact": "Secrets leaks through compiled bytecode or decompilation.",
        "confidence": 0.92,
        "confidence_explanation": "Java variable declaration holding secret literal.",
    },
    {
        "id": "java_runtime_exec",
        "issue_type": "security_flaw",
        "category": "Security Vulnerabilities",
        "title": "Unsafe Runtime.getRuntime().exec()",
        "severity": "High",
        "pattern": re.compile(r'Runtime\.getRuntime\(\)\.exec\s*\('),
        "description": "Invoking system commands via Runtime.exec without rigorous arguments sanitization.",
        "suggested_fix": "Use ProcessBuilder with argument list and avoid shell interpreters.",
        "corrected_code": "ProcessBuilder pb = new ProcessBuilder(\"safe_command\", \"arg1\");\nProcess p = pb.start();",
        "impact": "Remote command execution vulnerabilities.",
        "confidence": 0.90,
        "confidence_explanation": "Invocation of dangerous Java Runtime.exec call.",
    },
    {
        "id": "java_empty_catch",
        "issue_type": "empty_exception_handler",
        "category": "Exception Handling",
        "title": "Empty catch Block",
        "severity": "Medium",
        "pattern": re.compile(r'catch\s*\([^)]+\)\s*\{\s*\}'),
        "description": "Exception caught but block contains no handling or logging logic.",
        "suggested_fix": "Log the exception using a logger (e.g., SLF4J / Log4j2) or rethrow.",
        "corrected_code": "catch (Exception e) {\n    LOGGER.error(\"Operation failed\", e);\n}",
        "impact": "Suppresses critical application failures.",
        "confidence": 0.95,
        "confidence_explanation": "Syntactic check for empty exception block body.",
    },
]

# ─── JAVASCRIPT / TYPESCRIPT RULES ───────────────────────────────────────────

JS_TS_RULES: list[dict] = [
    {
        "id": "js_hardcoded_cred",
        "issue_type": "hardcoded_credentials",
        "category": "Security Vulnerabilities",
        "title": "Hardcoded Credential in JS/TS",
        "severity": "Critical",
        "pattern": re.compile(
            r'(?:const|let|var)\s+(?:password|passwd|secret|apiKey|api_key|token|auth)\s*=\s*["\'][^"\']{4,}["\']',
            re.IGNORECASE,
        ),
        "description": "A secret token or password appears hardcoded in JavaScript/TypeScript.",
        "suggested_fix": "Load secrets via process.env or secret manager.",
        "corrected_code": "const apiKey = process.env.API_KEY;",
        "impact": "Exposing secrets in client-side bundles or source code.",
        "confidence": 0.92,
        "confidence_explanation": "Pattern match on credential assignment.",
    },
    {
        "id": "js_eval",
        "issue_type": "dangerous_eval",
        "category": "Security Vulnerabilities",
        "title": "eval() Usage in JS/TS",
        "severity": "High",
        "pattern": re.compile(r'\beval\s*\('),
        "description": "eval() executes arbitrary JavaScript strings, enabling Cross-Site Scripting (XSS) or RCE.",
        "suggested_fix": "Use JSON.parse() for structured data or standard function dispatch.",
        "corrected_code": "const data = JSON.parse(jsonString);",
        "impact": "Arbitrary JavaScript execution in client or server (Node.js) context.",
        "confidence": 0.98,
        "confidence_explanation": "Direct eval() invocation.",
    },
    {
        "id": "js_inner_html",
        "issue_type": "xss_vulnerability",
        "category": "Security Vulnerabilities",
        "title": "Potential DOM XSS via innerHTML",
        "severity": "High",
        "pattern": re.compile(r'\.innerHTML\s*='),
        "description": "Directly assigning raw strings to innerHTML allows Cross-Site Scripting (XSS).",
        "suggested_fix": "Use textContent or sanitize HTML with DOMPurify.",
        "corrected_code": "element.textContent = safeText;",
        "impact": "Session cookie theft and browser compromise.",
        "confidence": 0.88,
        "confidence_explanation": "Direct DOM innerHTML assignment.",
    },
    {
        "id": "js_loose_equality",
        "issue_type": "type_coercion_bug",
        "category": "Logical Errors",
        "title": "Loose Equality Operator (==)",
        "severity": "Low",
        "pattern": re.compile(r'\s==\s(?!=)|!=[^=]'),
        "description": "Using loose equality (== or !=) causes unintended type coercion.",
        "suggested_fix": "Use strict equality (=== or !==) instead.",
        "corrected_code": "if (a === b) { ... }",
        "impact": "Subtle logic bugs due to unexpected type casting.",
        "confidence": 0.85,
        "confidence_explanation": "Syntactic check for non-strict equality operators.",
    },
]

# ─── C / C++ RULES ───────────────────────────────────────────────────────────

CPP_RULES: list[dict] = [
    {
        "id": "cpp_gets",
        "issue_type": "buffer_overflow",
        "category": "Security Vulnerabilities",
        "title": "Insecure gets() Function Call",
        "severity": "Critical",
        "pattern": re.compile(r'\bgets\s*\('),
        "description": "gets() does not check buffer limits and is inherently vulnerable to stack buffer overflows.",
        "suggested_fix": "Use fgets() or std::string / std::getline() instead.",
        "corrected_code": "std::string line;\nstd::getline(std::cin, line);",
        "impact": "Classic stack buffer overflow and remote code execution.",
        "confidence": 0.99,
        "confidence_explanation": "Deprecated unsafe C runtime function call.",
    },
    {
        "id": "cpp_strcpy",
        "issue_type": "buffer_overflow",
        "category": "Security Vulnerabilities",
        "title": "Unbounded strcpy / strcat Operation",
        "severity": "High",
        "pattern": re.compile(r'\b(?:strcpy|strcat|sprintf)\s*\('),
        "description": "Unbounded string functions copy data without verifying destination buffer capacities.",
        "suggested_fix": "Use safer bounded alternatives (strncpy, snprintf) or std::string.",
        "corrected_code": "snprintf(dest, sizeof(dest), \"%s\", src);",
        "impact": "Memory corruption, crashes, and arbitrary execution.",
        "confidence": 0.90,
        "confidence_explanation": "Invocation of unbounded buffer function.",
    },
    {
        "id": "cpp_system_call",
        "issue_type": "command_injection",
        "category": "Security Vulnerabilities",
        "title": "Direct system() Command Invocation",
        "severity": "High",
        "pattern": re.compile(r'\bsystem\s*\('),
        "description": "system() passes command strings directly to the shell, exposing the process to command injection.",
        "suggested_fix": "Use posix_spawn or execvp without a shell interpreter.",
        "corrected_code": "# Use execvp or posix_spawn with argument vectors",
        "impact": "Arbitrary OS command injection.",
        "confidence": 0.90,
        "confidence_explanation": "Invocation of shell interpreter.",
    },
]

# ─── GO RULES ────────────────────────────────────────────────────────────────

GO_RULES: list[dict] = [
    {
        "id": "go_hardcoded_cred",
        "issue_type": "hardcoded_credentials",
        "category": "Security Vulnerabilities",
        "title": "Hardcoded Credential in Go",
        "severity": "Critical",
        "pattern": re.compile(r'(?:apiKey|password|secret|token)\s*(?::=|=)\s*["\'][^"\']{4,}["\']', re.IGNORECASE),
        "description": "Hardcoded secret or credential found in Go source.",
        "suggested_fix": "Load secrets via os.Getenv().",
        "corrected_code": "apiKey := os.Getenv(\"API_KEY\")",
        "impact": "Credential exposure in binary artifacts.",
        "confidence": 0.92,
        "confidence_explanation": "Go variable holding secret token.",
    },
    {
        "id": "go_sql_concat",
        "issue_type": "sql_injection",
        "category": "Security Vulnerabilities",
        "title": "SQL Injection in Query Formatting",
        "severity": "Critical",
        "pattern": re.compile(r'(?:fmt\.Sprintf\s*\(\s*["\'].*(?:SELECT|INSERT|UPDATE|DELETE)|(?:Query|Exec)\s*\(\s*fmt\.Sprintf)', re.IGNORECASE),
        "description": "SQL query formed using fmt.Sprintf string interpolation.",
        "suggested_fix": "Pass parameters using db.Query(query, param1, param2) placeholders.",
        "corrected_code": "rows, err := db.Query(\"SELECT * FROM users WHERE id = $1\", id)",
        "impact": "Database manipulation and SQL injection.",
        "confidence": 0.94,
        "confidence_explanation": "Sprintf SQL formatting pattern.",
    },
]

# ─── SQL RULES ───────────────────────────────────────────────────────────────

SQL_RULES: list[dict] = [
    {
        "id": "sql_missing_where",
        "issue_type": "dangerous_query",
        "category": "Logical Errors",
        "title": "UPDATE / DELETE Without WHERE Clause",
        "severity": "Critical",
        "pattern": re.compile(r'\b(DELETE\s+FROM|UPDATE\s+[a-zA-Z0-9_]+)\b(?!.*\bWHERE\b)', re.IGNORECASE),
        "description": "UPDATE or DELETE statement without a WHERE clause will modify or wipe every row in the table.",
        "suggested_fix": "Add a WHERE clause specifying the target rows.",
        "corrected_code": "DELETE FROM users WHERE user_id = :id;",
        "impact": "Mass accidental data deletion.",
        "confidence": 0.95,
        "confidence_explanation": "Destructive query statement lacking WHERE predicate.",
    },
    {
        "id": "sql_drop_table",
        "issue_type": "destructive_query",
        "category": "Resource Management",
        "title": "Destructive DROP/TRUNCATE Statement",
        "severity": "High",
        "pattern": re.compile(r'\b(DROP\s+TABLE|TRUNCATE\s+TABLE)\b', re.IGNORECASE),
        "description": "Destructive statement permanently removes tables or clears data.",
        "suggested_fix": "Guard schema migrations with backup procedures and transaction wrappers.",
        "corrected_code": "# Verify before running drop migrations",
        "impact": "Irreversible data destruction.",
        "confidence": 0.98,
        "confidence_explanation": "DDL drop statement detected.",
    },
]

# ─── GENERIC FALLBACK RULES ──────────────────────────────────────────────────

GENERIC_RULES: list[dict] = [
    {
        "id": "gen_hardcoded_cred",
        "issue_type": "hardcoded_credentials",
        "category": "Security Vulnerabilities",
        "title": "Hardcoded Secret / Token Detected",
        "severity": "Critical",
        "pattern": re.compile(r'(?:password|secret|api[_-]?key|token)\s*[:=]\s*["\'][^"\']{4,}["\']', re.IGNORECASE),
        "description": "Hardcoded API key, token, or secret string found.",
        "suggested_fix": "Extract into environment variables or secrets store.",
        "corrected_code": "# Store in .env or secrets manager",
        "impact": "Exposure of sensitive credentials.",
        "confidence": 0.88,
        "confidence_explanation": "Token pattern matched in source text.",
    },
    {
        "id": "gen_todo_fixme",
        "issue_type": "code_debt",
        "category": "Code Quality Issues",
        "title": "Unresolved TODO / FIXME Marker",
        "severity": "Informational",
        "pattern": re.compile(r'(?://|#|/\*|--)\s*(TODO|FIXME|HACK|XXX)\b', re.IGNORECASE),
        "description": "Unresolved technical debt marker left in source code.",
        "suggested_fix": "Resolve the pending task before deploying to production.",
        "corrected_code": "# Complete pending implementation",
        "impact": "Unfinished logic or lingering work items.",
        "confidence": 0.90,
        "confidence_explanation": "Comment marker match.",
    }
]


class RuleEngine:
    """Configurable, multi-language pattern matching engine with evidence extraction."""

    def analyse_by_language(self, code: str, language: str) -> List[CodeIssue]:
        lang = language.lower().strip()
        if lang in ("python", "py"):
            return self._apply_rules(code, PYTHON_RULES, lang)
        elif lang in ("java",):
            return self._apply_rules(code, JAVA_RULES, lang)
        elif lang in ("javascript", "js", "typescript", "ts"):
            return self._apply_rules(code, JS_TS_RULES, lang)
        elif lang in ("c++", "cpp", "c"):
            return self._apply_rules(code, CPP_RULES, lang)
        elif lang in ("go", "golang"):
            return self._apply_rules(code, GO_RULES, lang)
        elif lang in ("sql",):
            return self._apply_rules(code, SQL_RULES, lang)
        else:
            return self._apply_rules(code, GENERIC_RULES, lang)

    def analyse_python(self, code: str) -> List[CodeIssue]:
        return self.analyse_by_language(code, "Python")

    def analyse_java(self, code: str) -> List[CodeIssue]:
        return self.analyse_by_language(code, "Java")

    def _apply_rules(self, code: str, rules: list[dict], lang: str) -> List[CodeIssue]:
        issues: List[CodeIssue] = []
        lines = code.splitlines()

        for rule in rules:
            for line_no, raw_line in enumerate(lines, start=1):
                clean_line = _strip_comment(raw_line, lang)
                if not clean_line.strip() and rule["issue_type"] != "code_debt":
                    continue

                target_text = raw_line if rule["issue_type"] == "code_debt" else clean_line
                if rule["pattern"].search(target_text):
                    issues.append(
                        CodeIssue(
                            issue_type=rule["issue_type"],
                            category=rule.get("category", "Security Vulnerabilities"),
                            title=rule["title"],
                            description=rule["description"],
                            line_number=line_no,
                            end_line_number=line_no,
                            severity=rule["severity"],
                            evidence=raw_line.strip(),
                            suggested_fix=rule.get("suggested_fix"),
                            corrected_code=rule.get("corrected_code"),
                            impact=rule.get("impact"),
                            confidence=rule.get("confidence", 0.90),
                            confidence_explanation=rule.get("confidence_explanation"),
                            rule_id=rule.get("id"),
                            detection_sources=["rule_engine"],
                            source="rule_engine",
                        )
                    )

        return issues
