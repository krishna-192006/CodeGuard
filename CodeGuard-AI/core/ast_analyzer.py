"""
CodeGuard AI 2.0 - AST Python Code Analyzer
Uses Python's ast module to statically inspect code syntax trees without execution.
Comprehensive detection of logical errors, runtime exceptions, security flaws, and performance anti-patterns.
"""
from __future__ import annotations
import ast
from typing import List, Set, Dict, Optional
from core.schemas import CodeIssue


class _ASTVisitor(ast.NodeVisitor):
    def __init__(self, code_lines: List[str]):
        self.code_lines = code_lines
        self.issues: List[CodeIssue] = []
        self.defined_names: Set[str] = set()
        self.used_names: Set[str] = set()
        self.function_scoped_assigns: List[Dict[str, int]] = []
        self.function_scoped_used: List[Set[str]] = []
        self.current_function_name: Optional[str] = None
        self.loop_depth = 0

    def _get_evidence(self, node: ast.AST) -> Optional[str]:
        lineno = getattr(node, "lineno", None)
        if lineno is not None and 1 <= lineno <= len(self.code_lines):
            return self.code_lines[lineno - 1].strip()
        return None

    def visit_FunctionDef(self, node: ast.FunctionDef) -> None:
        prev_fn = self.current_function_name
        self.current_function_name = node.name
        self.function_scoped_assigns.append({})
        self.function_scoped_used.append(set())

        # 1. Mutable Default Arguments
        for default in node.args.defaults + node.args.kw_defaults:
            if default is not None and isinstance(default, (ast.List, ast.Dict, ast.Set)):
                evidence = self._get_evidence(default)
                end_lineno = getattr(node, "end_lineno", node.lineno)
                self.issues.append(
                    CodeIssue(
                        issue_type="mutable_default_argument",
                        category="Logical Errors",
                        title=f"Mutable Default Argument in '{node.name}'",
                        description=f"Function '{node.name}' uses a mutable container (list/dict/set) as a default parameter. Python binds default arguments once at definition time, causing shared state between invocations.",
                        severity="High",
                        line_number=node.lineno,
                        end_line_number=end_lineno,
                        evidence=evidence,
                        suggested_fix="Use None as the default argument value and initialize the mutable container inside the function body.",
                        corrected_code=f"def {node.name}(..., arg=None):\n    if arg is None:\n        arg = []",
                        impact="State mutation leaks across multiple function calls, leading to hard-to-debug data corruption.",
                        confidence=0.98,
                        confidence_explanation="Deterministic AST inspection of function argument default AST nodes.",
                        detection_sources=["ast_analyzer"],
                        source="ast_analyzer",
                    )
                )

        self.generic_visit(node)

        # Check for unused local variables in this function scope
        local_assigns = self.function_scoped_assigns.pop()
        local_used = self.function_scoped_used.pop()

        for var_name, lineno in local_assigns.items():
            if var_name not in local_used and not var_name.startswith("_") and var_name not in ("self", "cls"):
                evidence = self.code_lines[lineno - 1].strip() if 1 <= lineno <= len(self.code_lines) else None
                self.issues.append(
                    CodeIssue(
                        issue_type="unused_variable",
                        category="Code Quality Issues",
                        title=f"Unused Local Variable '{var_name}'",
                        description=f"Local variable '{var_name}' in function '{node.name}' is assigned but never referenced.",
                        severity="Low",
                        line_number=lineno,
                        end_line_number=lineno,
                        evidence=evidence,
                        suggested_fix=f"Remove variable '{var_name}' or prefix with an underscore if required by an API.",
                        corrected_code=f"# Remove or rename to '_{var_name}'",
                        impact="Dead code reduces readability and wastes memory.",
                        confidence=0.88,
                        confidence_explanation="Scoped variable tracking detected assignment without subsequent Load context.",
                        detection_sources=["ast_analyzer"],
                        source="ast_analyzer",
                    )
                )

        self.current_function_name = prev_fn

    def visit_AsyncFunctionDef(self, node: ast.AsyncFunctionDef) -> None:
        self.visit_FunctionDef(node)  # type: ignore

    def visit_For(self, node: ast.For) -> None:
        self.loop_depth += 1
        if self.loop_depth >= 3:
            evidence = self._get_evidence(node)
            self.issues.append(
                CodeIssue(
                    issue_type="deeply_nested_loop",
                    category="Performance Issues",
                    title="Deeply Nested Loops (O(N^3) or Greater)",
                    description="Loop is nested 3 or more levels deep, leading to polynomial or exponential time complexity.",
                    severity="Medium",
                    line_number=node.lineno,
                    end_line_number=getattr(node, "end_lineno", node.lineno),
                    evidence=evidence,
                    suggested_fix="Refactor with dictionaries, sets, or vectorized operations (e.g. NumPy/Pandas) to lower complexity.",
                    impact="Severe execution latency on non-trivial dataset inputs.",
                    confidence=0.95,
                    confidence_explanation="AST loop nesting counter reached >= 3 levels.",
                    detection_sources=["ast_analyzer"],
                    source="ast_analyzer",
                )
            )
        self.generic_visit(node)
        self.loop_depth -= 1

    def visit_While(self, node: ast.While) -> None:
        # Potential infinite loop if while True has no break
        if isinstance(node.test, ast.Constant) and node.test.value is True:
            has_break = any(isinstance(n, ast.Break) for n in ast.walk(node))
            if not has_break:
                evidence = self._get_evidence(node)
                self.issues.append(
                    CodeIssue(
                        issue_type="potential_infinite_loop",
                        category="Logical Errors",
                        title="Unbounded 'while True' Loop (No break Detected)",
                        description="A 'while True' loop construct does not contain any 'break' statement, creating an infinite loop risk.",
                        severity="Critical",
                        line_number=node.lineno,
                        end_line_number=getattr(node, "end_lineno", node.lineno),
                        evidence=evidence,
                        suggested_fix="Add termination condition with 'break' or a timeout guard.",
                        corrected_code="while condition:\n    # perform work\n    if termination_condition:\n        break",
                        impact="Hangs the execution thread and triggers high CPU utilization.",
                        confidence=0.92,
                        confidence_explanation="AST traversal of while True block confirmed zero break AST nodes.",
                        detection_sources=["ast_analyzer"],
                        source="ast_analyzer",
                    )
                )
        self.generic_visit(node)

    def visit_Name(self, node: ast.Name) -> None:
        if isinstance(node.ctx, ast.Store):
            if self.function_scoped_assigns:
                self.function_scoped_assigns[-1][node.id] = node.lineno
        elif isinstance(node.ctx, ast.Load):
            if self.function_scoped_used:
                self.function_scoped_used[-1].add(node.id)
        self.generic_visit(node)

    def visit_BinOp(self, node: ast.BinOp) -> None:
        # 2. Division by Zero (literal constant)
        if isinstance(node.op, (ast.Div, ast.FloorDiv, ast.Mod)):
            if isinstance(node.right, ast.Constant) and node.right.value == 0:
                evidence = self._get_evidence(node)
                self.issues.append(
                    CodeIssue(
                        issue_type="division_by_zero",
                        category="Runtime Errors",
                        title="Literal Division or Modulo by Zero",
                        description="An arithmetic division or modulo operation is performed with a constant divisor of zero, which will immediately raise a ZeroDivisionError.",
                        severity="Critical",
                        line_number=node.lineno,
                        end_line_number=getattr(node, "end_lineno", node.lineno),
                        evidence=evidence,
                        suggested_fix="Validate that the denominator is non-zero before dividing.",
                        corrected_code="if divisor != 0:\n    result = numerator / divisor",
                        impact="Causes an unhandled ZeroDivisionError exception, terminating execution.",
                        confidence=1.0,
                        confidence_explanation="Syntactic proof: divisor operand is constant integer literal 0.",
                        detection_sources=["ast_analyzer"],
                        source="ast_analyzer",
                    )
                )
        self.generic_visit(node)

    def visit_Compare(self, node: ast.Compare) -> None:
        # 3. Suspicious comparisons (e.g. `x == None` or `x is 10`)
        for op, comparator in zip(node.ops, node.comparators):
            if isinstance(comparator, ast.Constant):
                # Using == or != with None
                if comparator.value is None and isinstance(op, (ast.Eq, ast.NotEq)):
                    evidence = self._get_evidence(node)
                    op_str = "==" if isinstance(op, ast.Eq) else "!="
                    suggested_op = "is None" if isinstance(op, ast.Eq) else "is not None"
                    self.issues.append(
                        CodeIssue(
                            issue_type="suspicious_comparison",
                            category="Code Quality Issues",
                            title=f"Comparison with None Using '{op_str}'",
                            description=f"Comparing an expression with None using '{op_str}' can yield incorrect results if the object overrides __eq__.",
                            severity="Low",
                            line_number=node.lineno,
                            end_line_number=getattr(node, "end_lineno", node.lineno),
                            evidence=evidence,
                            suggested_fix=f"Use identity check '{suggested_op}' instead.",
                            corrected_code=f"if expr {suggested_op}:",
                            impact="Logic bug if custom objects evaluate equality unexpectedly.",
                            confidence=0.95,
                            confidence_explanation="Syntactic proof: operator is equality with None singleton.",
                            detection_sources=["ast_analyzer"],
                            source="ast_analyzer",
                        )
                    )
                # Using `is` with numeric or string literals
                elif isinstance(comparator.value, (int, float, str)) and isinstance(op, (ast.Is, ast.IsNot)):
                    evidence = self._get_evidence(node)
                    self.issues.append(
                        CodeIssue(
                            issue_type="suspicious_comparison",
                            category="Logical Errors",
                            title="Identity Comparison ('is') With Literal",
                            description="Comparing literals using 'is' tests for memory identity rather than value equality, leading to undefined results across Python runtimes.",
                            severity="Medium",
                            line_number=node.lineno,
                            end_line_number=getattr(node, "end_lineno", node.lineno),
                            evidence=evidence,
                            suggested_fix="Use equality operator '==' or '!=' instead of 'is'/'is not' for literal values.",
                            corrected_code="if value == literal:",
                            impact="Flaky comparisons depending on Python's internal string/integer interning.",
                            confidence=0.95,
                            confidence_explanation="Identity comparison against literal value.",
                            detection_sources=["ast_analyzer"],
                            source="ast_analyzer",
                        )
                    )
        self.generic_visit(node)

    def visit_Call(self, node: ast.Call) -> None:
        # Dangerous Function Calls (eval, exec)
        func_name = None
        if isinstance(node.func, ast.Name):
            func_name = node.func.id
        elif isinstance(node.func, ast.Attribute):
            func_name = node.func.attr

        if func_name in ("eval", "exec"):
            evidence = self._get_evidence(node)
            self.issues.append(
                CodeIssue(
                    issue_type=f"dangerous_{func_name}",
                    category="Security Vulnerabilities",
                    title=f"Direct Invocation of Dynamic Code Execution '{func_name}()'",
                    description=f"Using '{func_name}()' dynamically evaluates code strings, introducing severe arbitrary Remote Code Execution (RCE) vulnerabilities if user input is supplied.",
                    severity="Critical" if func_name == "eval" else "High",
                    line_number=node.lineno,
                    end_line_number=getattr(node, "end_lineno", node.lineno),
                    evidence=evidence,
                    suggested_fix="Replace with ast.literal_eval() for safe literal evaluation or refactor logic using structured dictionaries or match statements.",
                    corrected_code="import ast\nsafe_data = ast.literal_eval(untrusted_str)",
                    impact="Allows an attacker to run arbitrary system commands or extract secrets.",
                    confidence=0.99,
                    confidence_explanation="Direct AST call node to built-in eval/exec.",
                    detection_sources=["ast_analyzer"],
                    source="ast_analyzer",
                )
            )

        # Insecure random usage in security context
        if isinstance(node.func, ast.Attribute) and isinstance(node.func.value, ast.Name):
            if node.func.value.id == "random" and node.func.attr in ("randint", "choice", "random", "randrange"):
                evidence = self._get_evidence(node)
                self.issues.append(
                    CodeIssue(
                        issue_type="insecure_random",
                        category="Security Vulnerabilities",
                        title=f"Standard Pseudo-Random Function 'random.{node.func.attr}()'",
                        description="The standard 'random' module utilizes the Mersenne Twister PRNG, which is completely deterministic and cryptographically insecure.",
                        severity="Low",
                        line_number=node.lineno,
                        end_line_number=getattr(node, "end_lineno", node.lineno),
                        evidence=evidence,
                        suggested_fix="If generating tokens, nonces, passwords, or encryption keys, use Python's 'secrets' module instead.",
                        corrected_code="import secrets\ntoken = secrets.token_hex(16)",
                        impact="Tokens generated with predictable PRNGs can be guessed by adversaries.",
                        confidence=0.80,
                        confidence_explanation="Call to Mersenne Twister random function.",
                        detection_sources=["ast_analyzer"],
                        source="ast_analyzer",
                    )
                )

        self.generic_visit(node)

    def visit_ExceptHandler(self, node: ast.ExceptHandler) -> None:
        evidence = self._get_evidence(node)
        is_bare = node.type is None
        is_broad = False
        if isinstance(node.type, ast.Name) and node.type.id in ("Exception", "BaseException"):
            is_broad = True

        is_pass_only = len(node.body) == 1 and isinstance(node.body[0], ast.Pass)

        if is_bare or (is_broad and is_pass_only):
            self.issues.append(
                CodeIssue(
                    issue_type="empty_exception_handler",
                    category="Exception Handling",
                    title="Silenced or Overly Broad Exception Handler",
                    description="The exception block catches exceptions indiscriminately or silently discards them with 'pass'. This suppresses unexpected runtime errors and prevents proper diagnosis.",
                    severity="Medium",
                    line_number=node.lineno,
                    end_line_number=getattr(node, "end_lineno", node.lineno),
                    evidence=evidence,
                    suggested_fix="Catch specific expected exception types (e.g., ValueError, KeyError) and log error details.",
                    corrected_code="except SpecificError as err:\n    logger.error('Failed: %s', err)\n    raise",
                    impact="Masks critical application bugs, crash loops, and system termination signals.",
                    confidence=0.94,
                    confidence_explanation="Exception handler AST node has no specific exception type or only contains pass.",
                    detection_sources=["ast_analyzer"],
                    source="ast_analyzer",
                )
            )

        self.generic_visit(node)

    def visit_If(self, node: ast.If) -> None:
        if isinstance(node.test, ast.Constant):
            evidence = self._get_evidence(node)
            self.issues.append(
                CodeIssue(
                    issue_type="constant_condition",
                    category="Logical Errors",
                    title=f"Static Condition 'if {node.test.value}:'",
                    description="The condition expression evaluates to a static boolean constant, meaning one branch is permanently dead or always executed.",
                    severity="Low",
                    line_number=node.lineno,
                    end_line_number=getattr(node, "end_lineno", node.lineno),
                    evidence=evidence,
                    suggested_fix="Remove the condition and unreachable branch or verify intended logic.",
                    corrected_code="# Remove static condition",
                    impact="Dead code and redundant branch instructions.",
                    confidence=0.96,
                    confidence_explanation="If condition is a literal constant AST node.",
                    detection_sources=["ast_analyzer"],
                    source="ast_analyzer",
                )
            )
        self.generic_visit(node)


class ASTAnalyzer:
    """Statically analyzes Python code using Abstract Syntax Trees."""

    def analyse_code(self, code: str) -> List[CodeIssue]:
        """Parse and run AST visitors on code string without execution."""
        if not code or not code.strip():
            return []

        try:
            tree = ast.parse(code)
        except SyntaxError as e:
            return [
                CodeIssue(
                    issue_type="syntax_error",
                    category="Syntax Errors",
                    title=f"Python Syntax Error: {e.msg}",
                    description=f"The code cannot be parsed: '{e.msg}'. Syntax errors prevent compilation and execution.",
                    severity="High",
                    line_number=e.lineno,
                    end_line_number=getattr(e, "end_lineno", e.lineno),
                    evidence=e.text.strip() if e.text else None,
                    suggested_fix="Correct the syntax at the highlighted line before proceeding.",
                    impact="Code will fail immediately at load time with SyntaxError.",
                    confidence=1.0,
                    confidence_explanation="Python core compiler ast.parse() raised SyntaxError.",
                    detection_sources=["ast_analyzer"],
                    source="ast_analyzer",
                )
            ]
        except Exception:
            return []

        visitor = _ASTVisitor(code.splitlines())
        visitor.visit(tree)
        return visitor.issues
