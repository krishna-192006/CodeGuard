"""
Create Project_Synopsis_Krishna_Pandey.docx from a template.
Run: python create_synopsis.py
"""
import sys
import os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from pathlib import Path

BASE_DIR = Path(__file__).parent.parent
WORKSPACE = BASE_DIR.parent  # Parent of CodeGuard-AI
OUTPUT = WORKSPACE / "Project_Synopsis_Krishna_Pandey.docx"

try:
    from docx import Document
    from docx.shared import Pt, RGBColor, Inches
    from docx.enum.text import WD_ALIGN_PARAGRAPH

    def add_heading(doc, text, level=1):
        h = doc.add_heading(text, level=level)
        h.runs[0].font.color.rgb = RGBColor(0x63, 0x66, 0xF1)
        return h

    def add_para(doc, text, bold=False):
        p = doc.add_paragraph()
        run = p.add_run(text)
        run.bold = bold
        run.font.size = Pt(11)
        return p

    doc = Document()

    # Title
    title = doc.add_paragraph()
    title.alignment = WD_ALIGN_PARAGRAPH.CENTER
    run = title.add_run("PROJECT SYNOPSIS")
    run.bold = True
    run.font.size = Pt(18)
    run.font.color.rgb = RGBColor(0x63, 0x66, 0xF1)

    doc.add_paragraph()
    subtitle = doc.add_paragraph()
    subtitle.alignment = WD_ALIGN_PARAGRAPH.CENTER
    subtitle.add_run("HCLTech Career Shaper Programme — Project No. 74").bold = True

    doc.add_paragraph()

    # Table: Basic Info
    table = doc.add_table(rows=8, cols=2)
    table.style = 'Table Grid'
    fields = [
        ("Project Title", "Automated Code Review and Bug Detection Using LLM"),
        ("Project Number", "74"),
        ("Domain", "Artificial Intelligence / Software Engineering"),
        ("Learner Name", "Krishna Pandey"),
        ("Roll Number", "[Roll Number — fill in]"),
        ("Mentor/Guide", "[Mentor Name — fill in]"),
        ("Submission Date", "[Submission Date — fill in]"),
        ("Institution", "[Institution Name — fill in]"),
    ]
    for i, (label, value) in enumerate(fields):
        cell_l = table.rows[i].cells[0]
        cell_r = table.rows[i].cells[1]
        cell_l.text = label
        cell_r.text = value
        cell_l.paragraphs[0].runs[0].bold = True

    doc.add_paragraph()

    sections = [
        ("1. Problem Statement",
         "Modern software development teams encounter significant challenges in identifying bugs, security vulnerabilities, and coding standard violations before code is deployed. Manual code review is time-consuming, inconsistent, and often insufficient, especially in fast-paced Agile environments. There is a need for an automated system that can analyse source code, detect common and critical issues, and support developers with actionable, human-reviewable suggestions."
        ),
        ("2. Proposed Solution",
         "CodeGuard AI is an AI-powered code review application that analyses Python and Java source code using a three-layer approach:\n\n1. Rule-Based Detection — 28 pattern-based rules covering hardcoded credentials, SQL injection, dangerous eval/exec, empty exception handlers, shell injection, mutable defaults, and more.\n\n2. Static Analysis — Bandit (security), Pylint (quality), and Radon (complexity) are integrated for Python, degrading gracefully if tools are unavailable.\n\n3. LLM Analysis (Optional) — When a Google Gemini API key is configured, the code is submitted to the Gemini model with a structured system prompt. The response is validated against a Pydantic schema before display.\n\nAll results are labelled by source (rule-based, static analysis, or LLM). No fix is applied automatically — every suggestion requires human developer review and approval."
        ),
        ("3. Technology Stack",
         "Frontend: Streamlit, Plotly, Custom CSS\nBackend: Python 3.10+, Pydantic v2, Pandas\nAI/LLM: Google Gemini API (google-generativeai)\nStatic Analysis: Bandit, Pylint, Radon\nDatabase: SQLite (review history)\nData Analysis: Pandas, NumPy, Matplotlib, Seaborn\nEnvironment: python-dotenv"
        ),
        ("4. Dataset Details",
         "The project uses a code review dataset containing 500 records with 8 features:\n- review_id: Unique review identifier\n- file_type: Programming language (Python, Java, JavaScript, TypeScript)\n- lines_of_code: Number of lines reviewed\n- issue_type: Category (null_pointer, sql_injection, unused_variable, off_by_one, security_flaw, style_violation)\n- severity: Critical > High > Medium > Low > Info\n- llm_confidence: Model confidence score (0.0–1.0)\n- accepted: Whether fix was accepted (0/1)\n- fix_time_min: Time taken to fix the issue (minutes)\n\nThe dataset is preserved as-is. A processed copy (processed_dataset.csv) is generated after cleaning. EDA produces 7 visualisations."
        ),
        ("5. Architecture Description",
         "The application follows a modular architecture:\n\nUser → Streamlit UI (app.py) → Analyzer Orchestrator (core/analyzer.py)\n→ [Rule Engine | Static Analyzer | LLM Service] → ReviewResult\n→ SQLite History (database/history.py)\n→ Dataset Analytics (Pandas + Plotly)\n\nSecurity: Uploaded code is never executed. API keys are stored in environment variables. File uploads are validated for extension and size. All LLM suggestions require human approval."
        ),
        ("6. Evaluation Methodology",
         "The project evaluation uses the following methodology:\n\n(a) Dataset Metrics — Historical statistics computed from dataset.csv: severity distribution, acceptance rate (overall ~75.6%), average fix time, confidence distribution.\n\n(b) Application Testing — 20+ unit tests cover rule detection accuracy, schema validation, dataset integrity, and error handling.\n\n(c) Qualitative Evaluation — Rule engine effectiveness tested with 5 sample code snippets containing known bugs across Python and Java.\n\nNote: Ground-truth labelling of detected vs missed bugs in production code is not available. Precision, recall, and F1 metrics cannot be reliably calculated without a labelled benchmark. These metrics are therefore not reported."
        ),
        ("7. Challenges and Resolutions",
         "Challenge 1 — LLM unavailability: Resolved with a complete rule-based fallback so the app works offline without any API key.\n\nChallenge 2 — JSON output validation: LLM may return malformed JSON. Resolved with try/except parsing and Pydantic validation with clear error messages.\n\nChallenge 3 — Static tool compatibility: Bandit/Pylint/Radon are Python-only. Resolved with graceful degradation — tools checked at runtime.\n\nChallenge 4 — False positives: Rule-based patterns can flag non-issues. Resolved with clear labelling, confidence scores, and mandatory human review."
        ),
        ("8. References",
         "1. Google AI — Gemini API Documentation: https://ai.google.dev\n2. Streamlit Documentation: https://docs.streamlit.io\n3. Bandit Security Linter: https://bandit.readthedocs.io\n4. Pylint Documentation: https://pylint.pycqa.org\n5. Pydantic v2 Documentation: https://docs.pydantic.dev\n6. Plotly Python: https://plotly.com/python\n7. HCLTech Career Shaper Programme — Project Brief No. 74"
        ),
        ("9. Ethical Compliance Declaration",
         "I confirm that:\n- The application never executes uploaded user code.\n- No automatic code modifications are applied without human review.\n- LLM-generated suggestions are clearly labelled as AI-generated and require human verification.\n- API credentials are stored only in local environment variables and are not exposed in logs or the UI.\n- The dataset used is the provided project dataset and no fabricated experimental results are claimed.\n- Synthetic data, if generated, would be explicitly labelled.\n\nLearner Signature: _________________________ Date: _____________"
        ),
    ]

    for heading, content in sections:
        add_heading(doc, heading, level=1)
        add_para(doc, content)
        doc.add_paragraph()

    doc.save(str(OUTPUT))
    print(f"✅ Synopsis saved: {OUTPUT}")

except ImportError:
    # Fallback: create a text synopsis if python-docx is not installed
    text_output = OUTPUT.with_suffix(".txt")
    content = """PROJECT SYNOPSIS
================
HCLTech Career Shaper Programme — Project No. 74

Project Title: Automated Code Review and Bug Detection Using LLM
Learner Name: Krishna Pandey
Roll Number: [Fill in]
Mentor: [Fill in]
Date: [Fill in]

1. Problem Statement
Modern software teams struggle to identify bugs and security issues before deployment.
Manual review is slow and inconsistent. CodeGuard AI automates this first pass.

2. Proposed Solution
CodeGuard AI uses three analysis layers:
- Rule-based patterns (28 rules, Python + Java)
- Static analysis (Bandit, Pylint, Radon)
- Google Gemini LLM (optional)

3. Technology Stack
Streamlit, Python, Pydantic, Pandas, Plotly, Bandit, Pylint, Radon, SQLite, Gemini API

4. Dataset: 500 rows, 8 columns (review_id, file_type, lines_of_code, issue_type,
   severity, llm_confidence, accepted, fix_time_min)

5. Ethics: No code executed. No automatic fixes. Human approval required.

Learner Signature: _________________________ Date: _____________
"""
    text_output.write_text(content)
    print(f"[Note] python-docx not installed. Saved plain text synopsis: {text_output}")
