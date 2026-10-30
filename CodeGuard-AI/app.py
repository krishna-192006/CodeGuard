"""
CodeGuard AI 2.0 - Next-Gen Code Audit Dashboard
Comprehensive multi-engine review platform with state persistence,
side-by-side remediation comparison, SQLite telemetry, and network diagnostics.
"""
from __future__ import annotations
import sys
import os
import html
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import streamlit as st
import pandas as pd
from datetime import datetime
from pathlib import Path

from config.settings import ALLOWED_EXTENSIONS, APP_NAME, APP_TAGLINE, APP_VERSION, DATASET_PATH
from core.schemas import AnalysisRequest, ReviewResult, CodeIssue, SUPPORTED_LANGUAGES, STANDARD_CATEGORIES
from core.security import validate_file_extension, validate_file_size, DISCLAIMER
from core.analyzer import analyse_code, get_llm_status, get_analyzer_statuses, _llm_service
from core.test_generator import generate_pytest_suite
from core.report_exporter import export_as_json, export_as_csv, export_as_pdf
from core.evaluation import evaluate_engines_on_benchmark, calculate_metrics
from core.connection_tester import run_gemini_diagnostics
import database.history as db
from components.charts import (
    severity_bar_chart, language_donut_chart, issue_type_bar,
    accepted_pie, fix_time_by_severity, confidence_histogram,
    evaluation_comparison_bar, confusion_matrix_heatmap, issues_by_category_chart
)

# ── Page Config ───────────────────────────────────────────────────────────────
st.set_page_config(
    page_title="CodeGuard AI 2.0",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded",
)

def safe_text(val: any) -> str:
    """Escape untrusted strings before rendering in HTML badges or cards."""
    if val is None:
        return ""
    return html.escape(str(val))


# ── SaaS Dark Theme CSS ───────────────────────────────────────────────────────
st.markdown("""
<style>
  @import url('https://fonts.googleapis.com/css2?family=Inter:wght@300;400;500;600;700&family=JetBrains+Mono:wght@400;500&display=swap');

  html, body, [class*="css"] {
    font-family: 'Inter', -apple-system, BlinkMacSystemFont, sans-serif;
    background-color: #0b0f19;
    color: #f1f5f9;
  }

  /* Sidebar styling */
  [data-testid="stSidebar"] {
    background: #0f172a;
    border-right: 1px solid rgba(255, 255, 255, 0.08);
  }

  /* Metric cards */
  [data-testid="metric-container"] {
    background: #1e293b;
    border: 1px solid rgba(255, 255, 255, 0.08);
    border-radius: 8px;
    padding: 16px;
    box-shadow: 0 4px 6px -1px rgba(0, 0, 0, 0.1);
  }
  [data-testid="stMetricValue"] {
    color: #f8fafc !important;
    font-weight: 700 !important;
    font-size: 1.8rem !important;
  }
  [data-testid="stMetricLabel"] {
    color: #94a3b8 !important;
    font-size: 0.85rem !important;
    font-weight: 500 !important;
  }

  /* Primary Button */
  .stButton > button {
    background: #4f46e5;
    color: #ffffff;
    border: 1px solid #6366f1;
    border-radius: 6px;
    font-weight: 600;
    padding: 8px 20px;
    transition: all 0.15s ease-in-out;
  }
  .stButton > button:hover {
    background: #4338ca;
    border-color: #4f46e5;
    box-shadow: 0 4px 12px rgba(79, 70, 229, 0.3);
  }

  /* Textarea Code Input */
  .stTextArea > div > div > textarea {
    background: #090d16 !important;
    color: #e2e8f0 !important;
    border: 1px solid rgba(255, 255, 255, 0.12) !important;
    border-radius: 6px !important;
    font-family: 'JetBrains Mono', monospace !important;
    font-size: 13px !important;
    line-height: 1.5 !important;
  }

  /* Badges */
  .badge-crit { background: rgba(239, 68, 68, 0.15); color: #f87171; border: 1px solid rgba(239, 68, 68, 0.3); padding: 2px 8px; border-radius: 4px; font-size: 11px; font-weight: 600; }
  .badge-high { background: rgba(249, 115, 22, 0.15); color: #fb923c; border: 1px solid rgba(249, 115, 22, 0.3); padding: 2px 8px; border-radius: 4px; font-size: 11px; font-weight: 600; }
  .badge-med  { background: rgba(234, 179, 8, 0.15);  color: #facc15; border: 1px solid rgba(234, 179, 8, 0.3);  padding: 2px 8px; border-radius: 4px; font-size: 11px; font-weight: 600; }
  .badge-low  { background: rgba(59, 130, 246, 0.15); color: #60a5fa; border: 1px solid rgba(59, 130, 246, 0.3); padding: 2px 8px; border-radius: 4px; font-size: 11px; font-weight: 600; }
  .badge-info { background: rgba(139, 92, 246, 0.15); color: #c084fc; border: 1px solid rgba(139, 92, 246, 0.3); padding: 2px 8px; border-radius: 4px; font-size: 11px; font-weight: 600; }
  .source-pill { background: rgba(255, 255, 255, 0.06); color: #94a3b8; border: 1px solid rgba(255, 255, 255, 0.1); padding: 2px 6px; border-radius: 4px; font-size: 11px; margin-right: 4px; }
  .confidence-pill { background: rgba(16, 185, 129, 0.12); color: #34d399; border: 1px solid rgba(16, 185, 129, 0.25); padding: 2px 6px; border-radius: 4px; font-size: 11px; margin-right: 4px; }

  /* File Uploader Redesign */
  [data-testid="stFileUploader"] {
    background: #111827;
    border: 1px dashed rgba(99, 102, 241, 0.4);
    border-radius: 10px;
    padding: 12px;
    transition: all 0.2s ease;
  }
  [data-testid="stFileUploader"]:hover {
    border-color: #6366f1;
    background: #151d30;
  }
  [data-testid="stFileUploader"] section {
    padding: 0 !important;
  }
  [data-testid="stFileUploader"] section button {
    background: #1f2937 !important;
    border: 1px solid rgba(255, 255, 255, 0.15) !important;
    color: #e2e8f0 !important;
    font-size: 12px !important;
    border-radius: 6px !important;
    padding: 4px 12px !important;
  }
  [data-testid="stFileUploader"] section button:hover {
    background: #4f46e5 !important;
    color: #ffffff !important;
    border-color: #6366f1 !important;
  }
  /* Hide file uploader subtext instructions / extension list */
  [data-testid="stFileUploader"] section > div > div > small {
    display: none !important;
  }
  [data-testid="stFileUploader"] section small {
    display: none !important;
  }
  [data-testid="stFileUploaderDropzoneInstructions"] small {
    display: none !important;
  }
  [data-testid="stFileUploaderDropzoneInstructions"] div:last-child {
    display: none !important;
  }
  .upload-card {
    background: #111827;
    border: 1px solid rgba(255, 255, 255, 0.08);
    border-radius: 8px;
    padding: 14px;
    margin-top: 10px;
  }
  .file-badge {
    background: #1e293b;
    border: 1px solid rgba(255, 255, 255, 0.1);
    border-radius: 6px;
    padding: 6px 10px;
    font-size: 12px;
    color: #cbd5e1;
    display: inline-flex;
    align-items: center;
    gap: 6px;
    margin: 3px;
  }
</style>
""", unsafe_allow_html=True)


@st.cache_data
def load_historical_dataset() -> pd.DataFrame:
    if os.path.exists(DATASET_PATH):
        return pd.read_csv(DATASET_PATH)
    return pd.DataFrame()


@st.cache_data
def load_benchmark_dataset() -> pd.DataFrame:
    bench_path = Path(__file__).parent / "data" / "benchmark_dataset.csv"
    if bench_path.exists():
        return pd.read_csv(bench_path)
    return pd.DataFrame()


# ── Navigation State Handling ────────────────────────────────────────────────
if "current_page" not in st.session_state:
    st.session_state["current_page"] = "📊 Dashboard"

def navigate_to(page_name: str):
    st.session_state["current_page"] = page_name
    st.rerun()


# ── Sidebar ───────────────────────────────────────────────────────────────────
with st.sidebar:
    st.markdown("### 🛡️ **CodeGuard AI 2.0**")
    st.caption("Intelligent Automated Code Review & Bug Detection")
    st.markdown("<hr style='border-color: rgba(255,255,255,0.08); margin: 10px 0;'>", unsafe_allow_html=True)

    nav_pages = [
        "📊 Dashboard",
        "🔍 Code Review",
        "🔎 Issue Explorer",
        "📈 Evaluation & Analytics",
        "📁 Dataset Explorer",
        "🕒 Review History",
        "⚙️ Settings",
    ]

    selected_page = st.radio(
        "Navigation",
        nav_pages,
        index=nav_pages.index(st.session_state["current_page"]) if st.session_state["current_page"] in nav_pages else 0,
        key="main_nav_radio",
        label_visibility="collapsed",
    )
    if selected_page != st.session_state["current_page"]:
        st.session_state["current_page"] = selected_page
        st.rerun()

    page = st.session_state["current_page"]

    st.markdown("<hr style='border-color: rgba(255,255,255,0.08); margin: 15px 0;'>", unsafe_allow_html=True)

    # Truthful Engine Status Indicators
    st.markdown("##### **Analyzer Statuses**")
    statuses = get_analyzer_statuses()
    for engine, stat in statuses.items():
        icon = "🟢" if "Active" in stat or "Ready" in stat or "Connected" in stat else "⚪"
        st.markdown(f"<span style='font-size:12px; color:#94a3b8;'>{icon} <b>{safe_text(engine)}:</b> {safe_text(stat)}</span>", unsafe_allow_html=True)

    st.markdown("<br>", unsafe_allow_html=True)
    st.caption(f"Version: {APP_VERSION} | LLM: {_llm_service.model_name}")


# ══════════════════════════════════════════════════════════════════════════════
# 1. DASHBOARD PAGE
# ══════════════════════════════════════════════════════════════════════════════
if page == "📊 Dashboard":
    st.markdown("## 📊 Executive Code Review Dashboard")
    st.caption("Real-time telemetry and aggregate defect intelligence computed from database records.")

    hist_reviews = db.get_all_reviews()
    total_db_reviews = len(hist_reviews)
    total_db_issues = sum(r.total_issues for r in hist_reviews)
    total_crit = sum(r.critical_count for r in hist_reviews)
    total_high = sum(r.high_count for r in hist_reviews)
    avg_dur = round(sum(r.duration_sec or 0.0 for r in hist_reviews) / total_db_reviews, 2) if total_db_reviews else 0.0

    if total_db_reviews > 0:
        penalty = (total_crit * 15 + total_high * 8) / total_db_reviews
        quality_score = max(0, min(100, int(100 - penalty)))
    else:
        quality_score = 100

    col1, col2, col3, col4, col5 = st.columns(5)
    with col1:
        st.metric("Total Reviews Executed", f"{total_db_reviews:,}")
    with col2:
        st.metric("Total Issues Identified", f"{total_db_issues:,}")
    with col3:
        st.metric("Critical Security Flaws", f"{total_crit:,}")
    with col4:
        st.metric("Average Review Latency", f"{avg_dur}s")
    with col5:
        st.metric("Code Quality Score", f"{quality_score}/100")

    st.markdown("---")

    active_rev: ReviewResult = st.session_state.get("current_review")
    if active_rev and active_rev.issues:
        st.markdown("### 🔍 Active Review: Issues by Category")
        st.plotly_chart(issues_by_category_chart(active_rev.issues), use_container_width=True)

    df_hist = load_historical_dataset()
    if not df_hist.empty:
        st.markdown("### 📈 Historical Defect Intelligence")
        c1, c2 = st.columns(2)
        with c1:
            st.plotly_chart(severity_bar_chart(df_hist), use_container_width=True)
        with c2:
            st.plotly_chart(language_donut_chart(df_hist), use_container_width=True)

        c3, c4 = st.columns(2)
        with c3:
            st.plotly_chart(issue_type_bar(df_hist), use_container_width=True)
        with c4:
            st.plotly_chart(accepted_pie(df_hist), use_container_width=True)
    else:
        st.info("No historical dataset found. Run a code review to populate telemetry.")

    st.markdown("### 🕒 Recent Review Activity")
    if hist_reviews:
        table_rows = []
        for r in hist_reviews[:10]:
            table_rows.append({
                "Review ID": r.review_id,
                "File": r.filename or "snippet",
                "Language": r.language,
                "Timestamp": r.timestamp,
                "Lines": r.lines_of_code,
                "Issues": r.total_issues,
                "Quality": r.overall_quality,
                "Mode": r.analysis_mode.upper(),
            })
        st.dataframe(pd.DataFrame(table_rows), use_container_width=True)
    else:
        st.info("No previous reviews recorded in SQLite database.")


# ══════════════════════════════════════════════════════════════════════════════
# 2. CODE REVIEW PAGE
# ══════════════════════════════════════════════════════════════════════════════
elif page == "🔍 Code Review":
    st.markdown("## 🔍 Deep Code Review & Vulnerability Audit")
    st.caption("Select your language, paste or upload source code, and run multi-engine inspection.")

    col_left, col_right = st.columns([3, 1])

    with col_right:
        st.markdown("#### **Audit Options**")
        language = st.selectbox("Programming Language", SUPPORTED_LANGUAGES, key="lang_selector")
        
        if language == "Python":
            st.caption("🟢 Full support: AST + Rules + Bandit + Pylint + Radon + Gemini")
        elif language in ("Java", "JavaScript", "C++", "SQL", "Go"):
            st.caption("🟡 Specialized pattern rule engine + Gemini LLM")
        else:
            st.caption("⚪ Polyglot heuristic patterns + Gemini LLM")

        st.markdown("**Enabled Analyzers**")
        chk_rules = st.checkbox("Rule Engine", value=True)
        chk_ast = st.checkbox("AST Analyzer (Python)", value=(language == "Python"))
        chk_static = st.checkbox("Linters (Bandit/Pylint/Radon)", value=(language == "Python"))
        chk_llm = st.checkbox("Google Gemini LLM", value=_llm_service.is_available)

        selected_engines = []
        if chk_rules: selected_engines.append("rule_engine")
        if chk_ast: selected_engines.append("ast_analyzer")
        if chk_static: selected_engines.append("static_analyzer")
        if chk_llm: selected_engines.append("llm_service")

        st.markdown("---")
        st.markdown("#### 📂 **Source Files**")
        st.caption("Upload code files for automated loading & auditing")
        
        uploaded_files = st.file_uploader(
            "Upload Code Files",
            accept_multiple_files=True,
            key="file_uploader",
            label_visibility="collapsed",
        )
        
        uploaded_file_names = [f.name for f in uploaded_files] if uploaded_files else []
        last_uploaded_names = st.session_state.get("last_uploaded_files", [])
        
        if uploaded_file_names != last_uploaded_names:
            st.session_state["last_uploaded_files"] = uploaded_file_names
            st.session_state["current_review"] = None
            st.session_state["selected_issue_id"] = None
            if uploaded_files:
                st.toast(f"✅ Loaded {len(uploaded_files)} file(s) into session.", icon="📂")

        if uploaded_files:
            st.markdown(f"**Loaded Files ({len(uploaded_files)}):**")
            file_pills = " ".join([f'<span class="file-badge">📄 {safe_text(f.name)} ({len(f.getvalue())//1024 + 1}KB)</span>' for f in uploaded_files[:4]])
            if len(uploaded_files) > 4:
                file_pills += f'<span class="file-badge">+{len(uploaded_files)-4} more</span>'
            st.markdown(file_pills, unsafe_allow_html=True)

    with col_left:
        loaded_code = ""
        current_active_file = "pasted_snippet"

        if uploaded_files:
            if len(uploaded_files) > 1:
                selected_fname = st.selectbox(
                    "Choose uploaded file to inspect",
                    [f.name for f in uploaded_files],
                    key="multi_file_selector"
                )
                target_f = next(f for f in uploaded_files if f.name == selected_fname)
            else:
                target_f = uploaded_files[0]

            val_ext, ext_err = validate_file_extension(target_f.name)
            val_sz, sz_err = validate_file_size(target_f.getvalue())
            if not val_ext:
                st.error(ext_err)
            elif not val_sz:
                st.error(sz_err)
            else:
                try:
                    loaded_code = target_f.getvalue().decode("utf-8")
                    current_active_file = target_f.name
                except Exception:
                    st.error("Error decoding uploaded file as UTF-8.")

        code_input = st.text_area(
            "Source Code Input",
            value=loaded_code if loaded_code else st.session_state.get("current_code", ""),
            height=420,
            placeholder=f"# Paste {language} source code here for inspection...",
            key="code_area",
        )

        c_btn, c_clr = st.columns([1, 5])
        with c_btn:
            run_audit = st.button("🚀 Analyze Code", type="primary")

    if run_audit:
        if not code_input.strip():
            st.error("Please provide non-empty source code before launching analysis.")
        else:
            with st.spinner("Executing multi-engine audit (Rules, AST, Linters, LLM)..."):
                req = AnalysisRequest(
                    code=code_input,
                    language=language,
                    filename=current_active_file,
                    enabled_engines=selected_engines,
                )
                res = analyse_code(req)
                
                review_id = db.save_review(
                    res,
                    filename=current_active_file,
                    lines=len([l for l in code_input.splitlines() if l.strip()]),
                    source_code=code_input,
                )
                
                st.session_state["current_review"] = res
                st.session_state["current_code"] = code_input
                st.session_state["current_filename"] = current_active_file
                st.session_state["selected_issue_id"] = None

            st.success(f"Audit completed in {res.analysis_duration_sec}s! Review ID: **{res.review_id}**")
            st.rerun()

    curr_res: ReviewResult = st.session_state.get("current_review")
    if curr_res:
        st.markdown("---")
        st.markdown("### 📋 Latest Audit Findings")
        
        col1, col2, col3, col4, col5 = st.columns(5)
        with col1:
            st.metric("Overall Quality", curr_res.overall_quality)
        with col2:
            st.metric("Total Issues", len(curr_res.issues))
        with col3:
            st.metric("Critical", sum(1 for i in curr_res.issues if i.severity == "Critical"))
        with col4:
            st.metric("High", sum(1 for i in curr_res.issues if i.severity == "High"))
        with col5:
            st.metric("Engine Mode", curr_res.analysis_mode.upper())

        st.info(f"**Executive Summary:** {curr_res.summary}")

        ca1, ca2, ca3, ca4 = st.columns(4)
        with ca1:
            if st.button("🔎 Open in Issue Explorer", key="goto_explorer_btn"):
                navigate_to("🔎 Issue Explorer")
        with ca2:
            json_data = export_as_json(curr_res)
            st.download_button("📥 Export JSON", json_data, file_name=f"{curr_res.review_id}.json", mime="application/json")
        with ca3:
            csv_data = export_as_csv(curr_res)
            st.download_button("📥 Export CSV", csv_data, file_name=f"{curr_res.review_id}.csv", mime="text/csv")
        with ca4:
            try:
                pdf_bytes = export_as_pdf(curr_res, st.session_state.get("current_filename"))
                st.download_button("📑 Export PDF Report", pdf_bytes, file_name=f"{curr_res.review_id}.pdf", mime="application/pdf")
            except Exception as e:
                st.caption(f"PDF Export unavailable: {e}")


# ══════════════════════════════════════════════════════════════════════════════
# 3. ISSUE EXPLORER PAGE (ADVANCED REMEDIATION & BEFORE/AFTER)
# ══════════════════════════════════════════════════════════════════════════════
elif page == "🔎 Issue Explorer":
    st.markdown("## 🔎 Detailed Issue Explorer & Remediation")
    st.caption("Inspect identified defects, view correlated provenance, copy fixes, and generate unit tests.")

    res: ReviewResult = st.session_state.get("current_review")
    if not res:
        st.info("No active code review in memory. Go to **Code Review** or restore a previous review from **Review History**.")
        col_c, col_h = st.columns([1, 1])
        with col_c:
            if st.button("⬅️ Go to Code Review"):
                navigate_to("🔍 Code Review")
        with col_h:
            if st.button("🕒 Browse Review History"):
                navigate_to("🕒 Review History")
    else:
        f_col1, f_col2, f_col3, f_col4 = st.columns(4)
        with f_col1:
            all_sevs = ["All"] + sorted(list({i.severity for i in res.issues if i.severity}))
            sel_sev = st.selectbox("Filter by Severity", all_sevs, key="flt_sev")
        with f_col2:
            all_cats = ["All"] + sorted(list({i.category for i in res.issues if i.category}))
            sel_cat = st.selectbox("Filter by Category", all_cats, key="flt_cat")
        with f_col3:
            all_srcs = ["All"]
            for i in res.issues:
                for s in i.detection_sources:
                    if s not in all_srcs:
                        all_srcs.append(s)
            sel_src = st.selectbox("Filter by Engine", all_srcs, key="flt_src")
        with f_col4:
            search_query = st.text_input("Search issues by title/keyword", "", key="flt_search")

        filtered_issues = res.issues
        if sel_sev != "All":
            filtered_issues = [i for i in filtered_issues if i.severity == sel_sev]
        if sel_cat != "All":
            filtered_issues = [i for i in filtered_issues if i.category == sel_cat]
        if sel_src != "All":
            filtered_issues = [i for i in filtered_issues if sel_src in i.detection_sources]
        if search_query.strip():
            q = search_query.lower()
            filtered_issues = [
                i for i in filtered_issues
                if (i.title and q in i.title.lower()) or (i.description and q in i.description.lower())
            ]

        filtered_issues = sorted(filtered_issues, key=lambda x: x.line_number or 0)

        st.markdown(f"Displaying **{len(filtered_issues)}** of **{len(res.issues)}** issues (File: `{st.session_state.get('current_filename', 'source')}`)")

        for idx, issue in enumerate(filtered_issues, start=1):
            badge_class = (
                "badge-crit" if issue.severity == "Critical"
                else "badge-high" if issue.severity == "High"
                else "badge-med" if issue.severity == "Medium"
                else "badge-low" if issue.severity == "Low"
                else "badge-info"
            )
            
            line_str = f"Line {issue.line_number}" if issue.line_number else "Global Scope"
            if issue.end_line_number and issue.end_line_number != issue.line_number:
                line_str += f"-{issue.end_line_number}"

            rule_tag = f"[{safe_text(issue.rule_id)}] " if issue.rule_id else ""
            title_text = f"[{safe_text(issue.severity.upper())}] {rule_tag}{safe_text(issue.title)} ({line_str})"

            with st.expander(title_text, expanded=(idx == 1)):
                conf_pct = int((issue.confidence or 0.8) * 100)
                st.markdown(f"""
                <div style="margin-bottom: 8px;">
                  <span class="{badge_class}">{safe_text(issue.severity)}</span>
                  <span class="source-pill" style="margin-left: 8px;">Category: {safe_text(issue.category)}</span>
                  <span class="confidence-pill">Confidence: {conf_pct}%</span>
                  <span class="source-pill">Rule ID: {safe_text(issue.rule_id or 'General')}</span>
                </div>
                """, unsafe_allow_html=True)

                st.markdown(f"**Description:** {safe_text(issue.description)}")
                if issue.impact:
                    st.markdown(f"**Impact:** {safe_text(issue.impact)}")

                if issue.confidence_explanation:
                    st.caption(f"ℹ️ **Confidence Basis:** {safe_text(issue.confidence_explanation)}")

                sources_html = "".join([f'<span class="source-pill">🔍 {safe_text(s)}</span>' for s in issue.detection_sources])
                st.markdown(f"**Detected by Engines:** {sources_html}", unsafe_allow_html=True)

                if issue.evidence or issue.corrected_code:
                    st.markdown("#### **Side-by-Side Code Comparison**")
                    col_orig, col_fix = st.columns(2)
                    with col_orig:
                        st.markdown("**Original / Problematic Code:**")
                        st.code(issue.evidence or "# [Evidence snippet not captured]", language=res.language.lower() if res.language else "python")
                    with col_fix:
                        st.markdown("**Suggested Corrected Code:**")
                        st.code(issue.corrected_code or "# [Refer to recommended remediation]", language=res.language.lower() if res.language else "python")

                if issue.suggested_fix:
                    st.markdown(f"**Recommended Remediation:** {safe_text(issue.suggested_fix)}")

        st.markdown("---")
        st.markdown("### 🧪 Automated Pytest Test Suite Generation")
        st.caption("Generate an isolated test suite to reproduce identified defects and guard against regressions.")
        
        current_code = st.session_state.get("current_code", "")
        test_suite_code = generate_pytest_suite(current_code, res.language, res.issues)
        st.code(test_suite_code, language="python")
        st.download_button(
            "📥 Download Generated Test Suite (test_reproduction.py)",
            test_suite_code,
            file_name="test_reproduction.py",
            mime="text/x-python",
            key="download_test_suite_btn",
        )


# ══════════════════════════════════════════════════════════════════════════════
# 4. EVALUATION & ANALYTICS PAGE (RESEARCH-GRADE)
# ══════════════════════════════════════════════════════════════════════════════
elif page == "📈 Evaluation & Analytics":
    st.markdown("## 📈 Empirical Evaluation & Model Comparison")
    st.caption("Rigorous benchmark assessment against verified ground-truth labels. (No fabricated scores).")

    bench_df = load_benchmark_dataset()
    if bench_df.empty:
        st.error("Ground-truth benchmark dataset not found in data/benchmark_dataset.csv.")
    else:
        st.markdown(f"Loaded **{len(bench_df)}** verified benchmark test samples across Python, Java, JS, C++, and SQL.")
        
        if st.button("🚀 Run Live Benchmark Evaluation", type="primary", key="run_benchmark_btn"):
            with st.spinner("Evaluating Rule Engine, AST, Static Linters, and Hybrid detectors across benchmark samples..."):
                eval_results = evaluate_engines_on_benchmark(bench_df)
                st.session_state["benchmark_results"] = eval_results
            st.success("Benchmark evaluation complete!")

        eval_res = st.session_state.get("benchmark_results")
        if eval_res:
            comp_table = eval_res["comparison_table"]
            st.markdown("### 🏆 Performance Comparison Table")
            st.dataframe(comp_table, use_container_width=True)

            st.plotly_chart(evaluation_comparison_bar(comp_table), use_container_width=True)

            hybrid_m = eval_res["metrics_by_method"]["Hybrid"]
            st.markdown("### 🎯 Hybrid Model Confusion Matrix")
            col_cm, col_kpi = st.columns([2, 1])
            with col_cm:
                st.plotly_chart(
                    confusion_matrix_heatmap(hybrid_m["TP"], hybrid_m["FP"], hybrid_m["TN"], hybrid_m["FN"], "Hybrid Model Matrix"),
                    use_container_width=True,
                )
            with col_kpi:
                st.metric("Hybrid Accuracy", f"{hybrid_m['accuracy'] * 100:.1f}%")
                st.metric("Hybrid Precision", f"{hybrid_m['precision'] * 100:.1f}%")
                st.metric("Hybrid Recall", f"{hybrid_m['recall'] * 100:.1f}%")
                st.metric("Hybrid F1-Score", f"{hybrid_m['f1']:.3f}")
                st.metric("False Positive Rate", f"{hybrid_m['fpr'] * 100:.1f}%")


# ══════════════════════════════════════════════════════════════════════════════
# 5. DATASET EXPLORER PAGE (PROPER MULTILINE SYNTAX RENDERING)
# ══════════════════════════════════════════════════════════════════════════════
elif page == "📁 Dataset Explorer":
    st.markdown("## 📁 Benchmark & Dataset Explorer")
    st.caption("Inspect and export the ground-truth benchmark and historical review data with multiline code view.")

    tab1, tab2 = st.tabs(["🔬 Ground-Truth Benchmark", "📊 Historical Review Logs"])

    with tab1:
        bench_df = load_benchmark_dataset()
        if not bench_df.empty:
            st.markdown(f"**Total Samples:** {len(bench_df)} | **Verification:** 100% Manually Verified Ground Truth")
            
            sel_sample_id = st.selectbox("Inspect individual benchmark sample code", bench_df["sample_id"].tolist())
            sample_row = bench_df[bench_df["sample_id"] == sel_sample_id].iloc[0]

            col_b1, col_b2 = st.columns(2)
            with col_b1:
                st.markdown(f"**Category:** `{sample_row['bug_category']}` | **Severity:** `{sample_row['severity']}`")
                st.markdown(f"**Expected Line:** `{sample_row['expected_line_number']}`")
                st.markdown("**Source Code:**")
                st.code(str(sample_row['source_code']), language=str(sample_row['programming_language']).lower())
            with col_b2:
                st.markdown(f"**Expected:** {sample_row['expected_behavior']}")
                st.markdown(f"**Actual Bug:** {sample_row['actual_behavior']}")
                st.markdown("**Corrected Code:**")
                st.code(str(sample_row['corrected_code']), language=str(sample_row['programming_language']).lower())

            st.markdown("---")
            st.dataframe(bench_df, use_container_width=True)
            csv_bench = bench_df.to_csv(index=False)
            st.download_button("📥 Export Benchmark CSV", csv_bench, "benchmark_dataset.csv", "text/csv", key="export_bench_btn")
        else:
            st.info("Benchmark dataset is empty.")

    with tab2:
        hist_df = load_historical_dataset()
        if not hist_df.empty:
            st.markdown(f"**Total Records:** {len(hist_df):,} historical code reviews.")
            st.dataframe(hist_df, use_container_width=True)
            csv_hist = hist_df.to_csv(index=False)
            st.download_button("📥 Export Historical CSV", csv_hist, "historical_reviews.csv", "text/csv", key="export_hist_btn")
        else:
            st.info("Historical dataset is empty.")


# ══════════════════════════════════════════════════════════════════════════════
# 6. REVIEW HISTORY PAGE (ROBUST RESTORE & FILTERING)
# ══════════════════════════════════════════════════════════════════════════════
elif page == "🕒 Review History":
    st.markdown("## 🕒 Persistent Review History (SQLite)")
    st.caption("Browse previous code reviews, reload past audits, or remove legacy records.")

    reviews = db.get_all_reviews()
    if not reviews:
        st.info("No saved reviews found in the SQLite database.")
    else:
        col_s1, col_s2 = st.columns(2)
        with col_s1:
            search_rev = st.text_input("Search reviews by ID or Filename", "", key="search_rev_kw")
        with col_s2:
            rev_langs = ["All"] + sorted(list({r.language for r in reviews if r.language}))
            sel_rev_lang = st.selectbox("Filter by Language", rev_langs, key="sel_rev_lang")

        displayed_revs = reviews
        if search_rev.strip():
            sr = search_rev.lower()
            displayed_revs = [r for r in displayed_revs if sr in r.review_id.lower() or (r.filename and sr in r.filename.lower())]
        if sel_rev_lang != "All":
            displayed_revs = [r for r in displayed_revs if r.language == sel_rev_lang]

        st.markdown(f"Total stored records: **{len(displayed_revs)}**")
        for rev in displayed_revs:
            with st.expander(f"Review {safe_text(rev.review_id)} | {safe_text(rev.language)} | {safe_text(rev.timestamp)} ({rev.total_issues} issues)"):
                st.markdown(f"**Summary:** {safe_text(rev.summary)}")
                st.markdown(f"**File:** `{safe_text(rev.filename)}` &nbsp;|&nbsp; **Lines:** {rev.lines_of_code} &nbsp;|&nbsp; **Mode:** {safe_text(rev.analysis_mode)}")
                
                col_view, col_del = st.columns([1, 1])
                with col_view:
                    if st.button("🔄 Restore into Issue Explorer", key=f"load_{rev.review_id}"):
                        full_rev = db.get_review_by_id(rev.review_id)
                        if full_rev:
                            st.session_state["current_review"] = ReviewResult(**full_rev)
                            st.session_state["current_filename"] = rev.filename or "restored_review"
                            navigate_to("🔎 Issue Explorer")
                with col_del:
                    if st.button("🗑️ Delete Review", key=f"del_{rev.review_id}"):
                        db.delete_review(rev.review_id)
                        st.warning(f"Deleted review {rev.review_id}")
                        st.rerun()


# ══════════════════════════════════════════════════════════════════════════════
# 7. SETTINGS PAGE (NETWORK DIAGNOSTICS & API VALIDATION)
# ══════════════════════════════════════════════════════════════════════════════
elif page == "⚙️ Settings":
    st.markdown("## ⚙️ Application & Engine Settings")
    st.caption("Configure API keys, execute live network diagnostics, and verify tool integrations.")

    st.markdown("#### **Google Gemini API Configuration**")
    avail, msg = get_llm_status()
    if avail:
        st.success(f"🟢 Gemini API is active! Model: `{safe_text(_llm_service.model_name)}`")
    else:
        st.warning(f"⚪ Gemini API is currently inactive: {safe_text(msg)}")

    # API Configuration Panel
    with st.expander("🔑 Configure & Test API Key", expanded=True):
        st.markdown(f"**Configured Model:** `{safe_text(_llm_service.model_name)}`")
        
        has_configured_key = bool(_llm_service._api_key and _llm_service._api_key != "your_gemini_api_key_here")
        if has_configured_key:
            masked_display = _llm_service._api_key[:4] + "••••••••" + _llm_service._api_key[-4:]
            st.info(f"Active Key Loaded: `{masked_display}`")

        new_key = st.text_input("Enter or Update Gemini API Key (Masked)", type="password", key="gemini_key_input")
        custom_model = st.text_input("Gemini Model Identifier", value=_llm_service.model_name, key="model_name_input")

        col_v1, col_v2, col_v3 = st.columns([1, 1, 1])
        with col_v1:
            validate_btn = st.button("🧪 Validate & Test Connection", type="primary")
        with col_v2:
            diag_btn = st.button("🔍 Run Full Network Diagnostics")
        with col_v3:
            clear_btn = st.button("🗑️ Clear Active Key")

        if validate_btn:
            test_key = new_key.strip() if new_key.strip() else _llm_service._api_key
            if not test_key:
                st.error("Please enter a valid Gemini API key.")
            else:
                with st.spinner(f"Validating connection with {custom_model}..."):
                    success, test_msg = _llm_service.configure_key(test_key, custom_model)
                if success:
                    st.success(f"✅ Connection successful: {test_msg}")
                    st.rerun()
                else:
                    st.error(f"❌ Connection failed: {test_msg}")

        if diag_btn:
            target_k = new_key.strip() if new_key.strip() else _llm_service._api_key
            with st.spinner("Executing network diagnostics (DNS, TCP, HTTPS, Auth, Model)..."):
                st.session_state["diag_results"] = run_gemini_diagnostics(target_k, custom_model)

        if clear_btn:
            _llm_service.clear_key()
            st.session_state["diag_results"] = None
            st.warning("API key cleared for this session.")
            st.rerun()

        # Render Diagnostics Panel
        diag_res = st.session_state.get("diag_results") or _llm_service._last_diagnostics
        if diag_res:
            st.markdown("---")
            st.markdown("##### **📊 Network & API Diagnostic Results**")
            
            steps = [
                ("DNS Resolution", diag_res["dns"]),
                ("TCP Port 443 Connection", diag_res["tcp"]),
                ("HTTPS / TLS Handshake", diag_res["https"]),
                ("API Key Authentication", diag_res["auth"]),
                (f"Model Availability ({diag_res['model']['model']})", diag_res["model"]),
            ]

            for label, data in steps:
                s = data.get("status")
                icon = "🟢" if s == "passed" else ("🔴" if s == "failed" else "🟡")
                color = "#34d399" if s == "passed" else ("#f87171" if s == "failed" else "#facc15")
                st.markdown(f"""
                <div class="diag-card">
                  <b>{icon} {label}:</b> <span style="color:{color}; font-weight:600;">{s.upper()}</span><br/>
                  <span style="font-size:12px; color:#cbd5e1;">{safe_text(data.get('message'))}</span>
                </div>
                """, unsafe_allow_html=True)

            if diag_res.get("troubleshooting"):
                st.warning(f"ℹ️ **Troubleshooting Guidance:** {diag_res['troubleshooting']}")

        st.markdown("""
        ---
        **Persistent Credentials Setup (.env):**
        To avoid entering your key each time, add it to `.env` in the `CodeGuard-AI` directory:
        ```ini
        GEMINI_API_KEY=AIzaSy...your_actual_key
        GEMINI_MODEL=gemini-3.8-flash
        ```
        """)

    st.markdown("---")
    st.markdown("#### **Local Static Analysis Diagnostics**")
    st_statuses = get_analyzer_statuses()
    for tool, stat in st_statuses.items():
        st.markdown(f"- **{safe_text(tool)}:** `{safe_text(stat)}`")

    st.markdown("---")
    st.warning(DISCLAIMER)
