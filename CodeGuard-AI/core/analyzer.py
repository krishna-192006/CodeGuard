"""
CodeGuard AI 2.0 - Analysis Orchestrator
Coordinates AST, Rule-Based, Static Linters, and Google Gemini LLM.
Performs multi-attribute finding deduplication, provenance tracking, and quality metrics.
"""
from __future__ import annotations
import time
from typing import List, Dict, Tuple, Optional
from core.schemas import ReviewResult, CodeIssue, AnalysisRequest
from core.rule_engine import RuleEngine
from core.ast_analyzer import ASTAnalyzer
from core.static_analyzer import StaticAnalyzer
from core.llm_service import LLMService

_rule_engine = RuleEngine()
_ast_analyzer = ASTAnalyzer()
_static_analyzer = StaticAnalyzer()
_llm_service = LLMService()


def get_llm_status() -> Tuple[bool, str]:
    return _llm_service.is_available, _llm_service.status_message


def get_analyzer_statuses() -> Dict[str, str]:
    statuses = {
        "rule_engine": "Active",
        "ast_analyzer": "Active",
        "llm_service": "Connected" if _llm_service.is_available else "Not Configured",
    }
    statuses.update(_static_analyzer.get_statuses())
    return statuses


def deduplicate_issues(issues: List[CodeIssue]) -> List[CodeIssue]:
    """
    Intelligently merge overlapping findings across multiple engines.
    Correlates issues based on (line_number, issue_type/category) or identical titles.
    Preserves all detection sources without discarding provenance.
    """
    merged: List[CodeIssue] = []

    for issue in issues:
        matched = False
        for existing in merged:
            # Check for line match and issue correlation
            same_line = (issue.line_number is not None and existing.line_number is not None and abs(issue.line_number - existing.line_number) <= 1)
            same_type = (issue.issue_type == existing.issue_type)
            similar_cat = (issue.category == existing.category and ("sql" in issue.issue_type and "sql" in existing.issue_type or "cred" in issue.issue_type and "cred" in existing.issue_type))
            
            if (same_line and (same_type or similar_cat)) or (same_type and issue.evidence and existing.evidence and issue.evidence == existing.evidence):
                # Merge sources
                for src in issue.detection_sources:
                    if src not in existing.detection_sources:
                        existing.detection_sources.append(src)
                
                # Upgrade severity if the incoming issue is more severe
                sev_order = {"Critical": 4, "High": 3, "Medium": 2, "Low": 1, "Informational": 0}
                if sev_order.get(issue.severity, 2) > sev_order.get(existing.severity, 2):
                    existing.severity = issue.severity
                    existing.title = issue.title
                    existing.description = issue.description

                # Confidence handling
                existing.confidence = max(existing.confidence, issue.confidence)
                if not existing.confidence_explanation and issue.confidence_explanation:
                    existing.confidence_explanation = issue.confidence_explanation

                # Keep richer suggested fix or corrected code
                if not existing.suggested_fix and issue.suggested_fix:
                    existing.suggested_fix = issue.suggested_fix
                if not existing.corrected_code and issue.corrected_code:
                    existing.corrected_code = issue.corrected_code
                if not existing.evidence and issue.evidence:
                    existing.evidence = issue.evidence
                if not existing.rule_id and issue.rule_id:
                    existing.rule_id = issue.rule_id
                if not existing.end_line_number and issue.end_line_number:
                    existing.end_line_number = issue.end_line_number

                matched = True
                break

        if not matched:
            merged.append(issue)

    return merged


def analyse_code(request: AnalysisRequest) -> ReviewResult:
    """
    Unified analysis pipeline:
    1. Validation and language routing
    2. Rule Engine analysis
    3. AST Analysis (Python)
    4. Static Analysis (Python linters: Bandit, Pylint, Radon)
    5. Google Gemini LLM Contextual Analysis (if active)
    6. Multi-attribute Deduplication & Provenance Merging
    7. Overall Quality Calculation & Executive Summary
    """
    start_time = time.time()
    code = request.code
    language = request.language
    enabled = request.enabled_engines or ["rule_engine", "ast_analyzer", "static_analyzer", "llm_service"]

    all_raw_issues: List[CodeIssue] = []
    statuses = get_analyzer_statuses()
    error_notes: List[str] = []

    # 1. Rule Engine (Runs for all supported languages)
    if "rule_engine" in enabled:
        try:
            r_issues = _rule_engine.analyse_by_language(code, language)
            all_raw_issues.extend(r_issues)
        except Exception as e:
            statuses["rule_engine"] = f"Error: {e}"
            error_notes.append(f"Rule engine encountered: {e}")

    # 2. AST Analyzer (Python only)
    if "ast_analyzer" in enabled and language.lower() in ("python", "py"):
        try:
            ast_issues = _ast_analyzer.analyse_code(code)
            all_raw_issues.extend(ast_issues)
        except Exception as e:
            statuses["ast_analyzer"] = f"Error: {e}"
            error_notes.append(f"AST analyzer error: {e}")

    # 3. Static Linters (Python only)
    if "static_analyzer" in enabled and language.lower() in ("python", "py"):
        try:
            static_issues = _static_analyzer.analyse_python(code)
            all_raw_issues.extend(static_issues)
        except Exception as e:
            statuses["static_analyzer"] = f"Error: {e}"
            error_notes.append(f"Static analyzer error: {e}")

    # 4. LLM Analysis (Gemini)
    llm_summary = ""
    llm_quality = None
    llm_recs: List[str] = []

    if "llm_service" in enabled and _llm_service.is_available:
        try:
            llm_result = _llm_service.analyse(code, language)
            if llm_result.issues:
                all_raw_issues.extend(llm_result.issues)
            if llm_result.summary:
                llm_summary = llm_result.summary
            if llm_result.overall_quality:
                llm_quality = llm_result.overall_quality
            if llm_result.recommendations:
                llm_recs = llm_result.recommendations
            if llm_result.error:
                error_notes.append(llm_result.error)
        except Exception as e:
            statuses["llm_service"] = f"Error: {e}"
            error_notes.append(f"LLM service error: {e}")

    # 5. Intelligent Deduplication
    final_issues = deduplicate_issues(all_raw_issues)

    # 6. Overall Quality & Summary Computation
    crit_count = sum(1 for i in final_issues if i.severity == "Critical")
    high_count = sum(1 for i in final_issues if i.severity == "High")
    med_count = sum(1 for i in final_issues if i.severity == "Medium")

    if llm_quality and _llm_service.is_available:
        quality = llm_quality
    elif crit_count > 0 or high_count >= 2:
        quality = "Poor"
    elif high_count == 1 or med_count >= 3:
        quality = "Fair"
    else:
        quality = "Good"

    if llm_summary and _llm_service.is_available:
        summary = llm_summary
    else:
        if not final_issues:
            summary = f"Clean review: No defects or vulnerabilities identified in {language} code."
        else:
            summary = (
                f"Analysis detected {len(final_issues)} issue(s) "
                f"({crit_count} Critical, {high_count} High, {med_count} Medium). "
                f"Prioritize remediation of high-severity flaws before production release."
            )

    # Recommendations
    recommendations = list(llm_recs)
    rule_recs = _generate_recommendations(final_issues)
    for rec in rule_recs:
        if rec not in recommendations:
            recommendations.append(rec)

    # Determine analysis mode
    active_sources = set()
    for i in final_issues:
        for s in i.detection_sources:
            active_sources.add(s)

    if "llm_gemini" in active_sources and len(active_sources) > 1:
        mode = "hybrid"
    elif "llm_gemini" in active_sources:
        mode = "llm"
    elif "ast_analyzer" in active_sources and len(active_sources) > 1:
        mode = "hybrid"
    else:
        mode = "rule_based"

    duration = round(time.time() - start_time, 2)

    return ReviewResult(
        summary=summary,
        language=language,
        overall_quality=quality,
        issues=final_issues,
        recommendations=recommendations,
        analysis_mode=mode,
        analyzer_statuses=statuses,
        analysis_duration_sec=duration,
        error="; ".join(error_notes) if error_notes else None,
    )


def _generate_recommendations(issues: List[CodeIssue]) -> List[str]:
    recs: List[str] = []
    types = {i.issue_type for i in issues}

    if any("sql" in t for t in types):
        recs.append("Adopt parameterized statements, prepared queries, or safe ORM mappings to prevent SQL injection.")
    if any("cred" in t for t in types):
        recs.append("Store secrets and API tokens in environment variables or a vault (e.g. AWS Secrets Manager, HashiCorp Vault).")
    if any("eval" in t for t in types):
        recs.append("Avoid dynamic code evaluation with eval/exec; replace with structured parsers like ast.literal_eval().")
    if any("buffer" in t for t in types):
        recs.append("Replace unbounded memory functions (gets, strcpy) with bounds-checked alternatives or safe string classes.")
    if any("exception" in t for t in types):
        recs.append("Ensure every try-except/catch block handles specific exception types and logs meaningful diagnostics.")
    if any("mutable_default" in t for t in types):
        recs.append("Use None as the default argument value in Python functions instead of mutable containers like lists or dicts.")
    if any("division_by_zero" in t for t in types):
        recs.append("Perform defensive bounds and zero-denominator validation before dividing.")
    return recs
