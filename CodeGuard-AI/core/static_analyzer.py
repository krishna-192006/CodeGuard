"""
CodeGuard AI 2.0 - Static Analysis Wrapper
Integrates Bandit (security), Pylint (style/bugs), and Radon (complexity).
Normalizes all findings into the standard CodeIssue schema with accurate line evidence and specific remediations.
"""
from __future__ import annotations
import subprocess
import json
import sys
import tempfile
import os
from typing import List, Tuple, Dict, Optional
from core.schemas import CodeIssue

# Specific, helpful remediation messages for common Pylint message IDs and symbols
PYLINT_REMEDIATION_MAP = {
    "missing-module-docstring": "Add a module-level docstring at the top of the file describing the module's architecture and purpose.",
    "missing-class-docstring": "Add a class docstring detailing the class responsibility and key attributes.",
    "missing-function-docstring": "Add a docstring to this function describing parameters, return types, and potential exceptions.",
    "unused-variable": "Remove this unused variable or prefix with '_' if required by an unpacking interface.",
    "unused-import": "Remove the unused import to keep the namespace clean and avoid unnecessary overhead.",
    "undefined-variable": "Verify variable declaration and scoping; this variable appears undefined in current context.",
    "broad-exception-caught": "Replace broad Exception catch block with specific exception classes (e.g. ValueError, KeyError).",
    "bare-except": "Specify the exact exception type (e.g. 'except Exception as e:') instead of using bare 'except:'.",
    "line-too-long": "Split the line or refactor expressions to adhere to the PEP 8 standard maximum line length (88-100 chars).",
    "invalid-name": "Rename identifier to comply with PEP 8 naming conventions (snake_case for functions/variables, PascalCase for classes).",
    "pointless-statement": "Remove or assign the expression; this statement does not produce side-effects or bind state.",
    "unspecified-encoding": "Explicitly specify encoding (e.g. encoding='utf-8') in open() to avoid platform-dependent bugs.",
    "no-member": "Verify that the attribute exists on this class or instance; check for typos or dynamic bindings.",
    "dangerous-default-value": "Change default container parameter to None and instantiate fresh container inside the function.",
    "redefined-outer-name": "Rename inner variable to prevent shadowing the variable defined in outer scope.",
}

# Categorize Pylint message types to standard CodeGuard categories
def _map_pylint_category(msg_type: str, symbol: str) -> str:
    sym = symbol.lower()
    if "syntax" in sym or msg_type == "fatal":
        return "Syntax Errors"
    elif "undefined" in sym or "no-member" in sym or msg_type == "error":
        return "Runtime Errors"
    elif "exception" in sym:
        return "Exception Handling"
    elif "encoding" in sym or "resource" in sym or "open" in sym:
        return "Resource Management"
    elif "dangerous" in sym or "eval" in sym or "exec" in sym:
        return "Security Vulnerabilities"
    elif "complexity" in sym:
        return "Performance Issues"
    elif msg_type == "warning":
        return "Logical Errors"
    return "Code Quality Issues"


class StaticAnalyzer:
    """Wraps external CLI linters and security scanners with isolation and error handling."""

    def __init__(self) -> None:
        self.tool_statuses: Dict[str, str] = {
            "bandit": "Ready",
            "pylint": "Ready",
            "radon": "Ready",
        }

    def get_statuses(self) -> Dict[str, str]:
        return dict(self.tool_statuses)

    def analyse_python(self, code: str) -> List[CodeIssue]:
        issues: List[CodeIssue] = []
        issues += self._run_bandit(code)
        issues += self._run_pylint(code)
        issues += self._run_radon(code)
        return issues

    def analyse_java(self, code: str) -> List[CodeIssue]:
        return []

    def _run_bandit(self, code: str) -> List[CodeIssue]:
        issues: List[CodeIssue] = []
        tmp_path = None
        code_lines = code.splitlines()
        try:
            with tempfile.NamedTemporaryFile(mode="w", suffix=".py", delete=False, encoding="utf-8") as f:
                f.write(code)
                tmp_path = f.name

            result = subprocess.run(
                [sys.executable, "-m", "bandit", "-f", "json", "-q", tmp_path],
                capture_output=True,
                text=True,
                timeout=15,
            )

            if result.stdout:
                try:
                    data = json.loads(result.stdout)
                    for finding in data.get("results", []):
                        sev_raw = finding.get("issue_severity", "LOW").capitalize()
                        sev = sev_raw if sev_raw in ("Critical", "High", "Medium", "Low") else "Low"

                        code_snippet = finding.get("code", "").strip()
                        line_no = finding.get("line_number")
                        if not code_snippet and line_no and 1 <= line_no <= len(code_lines):
                            code_snippet = code_lines[line_no - 1].strip()

                        # Deterministic confidence for static analyzer
                        conf_str = finding.get("issue_confidence", "HIGH")
                        confidence = 0.95 if conf_str == "HIGH" else (0.85 if conf_str == "MEDIUM" else 0.75)

                        issues.append(
                            CodeIssue(
                                issue_type=f"bandit_{finding.get('test_id', 'vuln').lower()}",
                                category="Security Vulnerabilities",
                                title=f"[Bandit] {finding.get('test_name', 'Security Vulnerability')}",
                                description=finding.get("issue_text", ""),
                                line_number=line_no,
                                severity=sev,
                                evidence=code_snippet,
                                confidence=confidence,
                                suggested_fix=f"Refer to Bandit security guidance: {finding.get('more_info', '')}",
                                impact=f"Identified with Bandit confidence: {conf_str}",
                                detection_sources=["bandit"],
                                source="bandit",
                            )
                        )
                    self.tool_statuses["bandit"] = "Active"
                except json.JSONDecodeError:
                    self.tool_statuses["bandit"] = "Malformed Output"
            else:
                self.tool_statuses["bandit"] = "Active"
        except FileNotFoundError:
            self.tool_statuses["bandit"] = "Not Installed"
        except subprocess.TimeoutExpired:
            self.tool_statuses["bandit"] = "Timeout (>15s)"
        except Exception as e:
            self.tool_statuses["bandit"] = f"Error: {e}"
        finally:
            if tmp_path and os.path.exists(tmp_path):
                try:
                    os.unlink(tmp_path)
                except Exception:
                    pass

        return issues

    def _run_pylint(self, code: str) -> List[CodeIssue]:
        issues: List[CodeIssue] = []
        tmp_path = None
        code_lines = code.splitlines()
        try:
            with tempfile.NamedTemporaryFile(mode="w", suffix=".py", delete=False, encoding="utf-8") as f:
                f.write(code)
                tmp_path = f.name

            result = subprocess.run(
                [sys.executable, "-m", "pylint", "--output-format=json", tmp_path],
                capture_output=True,
                text=True,
                timeout=15,
            )

            if result.stdout.strip().startswith("["):
                try:
                    messages = json.loads(result.stdout)
                    for msg in messages:
                        msg_type = msg.get("type", "convention")
                        symbol = msg.get("symbol", "lint-warning")
                        msg_id = msg.get("message-id", "")
                        line_no = msg.get("line")
                        end_line = msg.get("end_line")

                        sev_map = {
                            "fatal": "Critical",
                            "error": "High",
                            "warning": "Medium",
                            "convention": "Low",
                            "refactor": "Informational",
                            "info": "Informational",
                        }
                        sev = sev_map.get(msg_type, "Low")
                        category = _map_pylint_category(msg_type, symbol)

                        # Specific remediation lookup
                        remediation = PYLINT_REMEDIATION_MAP.get(
                            symbol,
                            f"Refactor according to Pylint rule {msg_id} ({symbol})."
                        )

                        # Extract exact line evidence
                        evidence_str = None
                        if line_no and 1 <= line_no <= len(code_lines):
                            evidence_str = code_lines[line_no - 1].strip()

                        issues.append(
                            CodeIssue(
                                issue_type=f"pylint_{symbol.lower().replace('-', '_')}",
                                category=category,
                                title=f"[Pylint] {symbol.replace('-', ' ').title()} ({msg_id})",
                                description=msg.get("message", ""),
                                line_number=line_no,
                                end_line_number=end_line,
                                severity=sev,
                                evidence=evidence_str,
                                confidence=0.92,  # Deterministic AST rule
                                suggested_fix=remediation,
                                impact=f"Pylint {msg_type.upper()} finding (Rule ID: {msg_id})",
                                detection_sources=["pylint"],
                                source="pylint",
                            )
                        )
                    self.tool_statuses["pylint"] = "Active"
                except json.JSONDecodeError:
                    self.tool_statuses["pylint"] = "Malformed Output"
            else:
                self.tool_statuses["pylint"] = "Active"
        except FileNotFoundError:
            self.tool_statuses["pylint"] = "Not Installed"
        except subprocess.TimeoutExpired:
            self.tool_statuses["pylint"] = "Timeout (>15s)"
        except Exception as e:
            self.tool_statuses["pylint"] = f"Error: {e}"
        finally:
            if tmp_path and os.path.exists(tmp_path):
                try:
                    os.unlink(tmp_path)
                except Exception:
                    pass

        return issues

    def _run_radon(self, code: str) -> List[CodeIssue]:
        issues: List[CodeIssue] = []
        tmp_path = None
        code_lines = code.splitlines()
        try:
            with tempfile.NamedTemporaryFile(mode="w", suffix=".py", delete=False, encoding="utf-8") as f:
                f.write(code)
                tmp_path = f.name

            result = subprocess.run(
                [sys.executable, "-m", "radon", "cc", "-j", tmp_path],
                capture_output=True,
                text=True,
                timeout=10,
            )

            if result.stdout:
                try:
                    data = json.loads(result.stdout)
                    for _file, blocks in data.items():
                        for block in blocks:
                            complexity = block.get("complexity", 0)
                            if complexity >= 10:
                                sev = "High" if complexity >= 15 else "Medium"
                                lineno = block.get("lineno")
                                endlineno = block.get("endline")
                                evidence = f"def/class {block.get('name')}() (CC={complexity})"
                                if lineno and 1 <= lineno <= len(code_lines):
                                    evidence = code_lines[lineno - 1].strip()

                                issues.append(
                                    CodeIssue(
                                        issue_type="high_cyclomatic_complexity",
                                        category="Performance Issues",
                                        title=f"[Radon] High Complexity in '{block.get('name', 'function')}' (CC={complexity})",
                                        description=f"Cyclomatic complexity of {complexity} exceeds threshold (10). High cyclomatic complexity indicates code that branches heavily and is difficult to maintain and test.",
                                        line_number=lineno,
                                        end_line_number=endlineno,
                                        severity=sev,
                                        evidence=evidence,
                                        confidence=0.95,
                                        suggested_fix="Decompose this function into smaller, single-purpose helper functions to reduce decision branching.",
                                        impact="Elevated cognitive overhead, high test burden, and greater probability of hidden regression bugs.",
                                        detection_sources=["radon"],
                                        source="radon",
                                    )
                                )
                    self.tool_statuses["radon"] = "Active"
                except json.JSONDecodeError:
                    self.tool_statuses["radon"] = "Malformed Output"
            else:
                self.tool_statuses["radon"] = "Active"
        except FileNotFoundError:
            self.tool_statuses["radon"] = "Not Installed"
        except subprocess.TimeoutExpired:
            self.tool_statuses["radon"] = "Timeout (>10s)"
        except Exception as e:
            self.tool_statuses["radon"] = f"Error: {e}"
        finally:
            if tmp_path and os.path.exists(tmp_path):
                try:
                    os.unlink(tmp_path)
                except Exception:
                    pass

        return issues
