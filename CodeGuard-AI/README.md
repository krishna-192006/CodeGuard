# CodeGuard AI 2.0: Intelligent Automated Code Review and Bug Detection Using LLM

[![Python 3.10+](https://img.shields.io/badge/python-3.10+-blue.svg)](https://www.python.org/downloads/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Tests: 81 Passing](https://img.shields.io/badge/tests-81%20passed-brightgreen.svg)]()
[![Model: Gemini 3.8 Flash](https://img.shields.io/badge/model-gemini--3.8--flash-orange.svg)]()
[![Frontend: Streamlit](https://img.shields.io/badge/frontend-streamlit-red.svg)]()

> **CodeGuard AI 2.0** is an enterprise-grade hybrid code auditing and defect detection platform developed as part of the HCLTech Career Shaper Programme. It couples deterministic multi-language rule engines, static Abstract Syntax Tree (AST) analysis, production linters (Bandit, Pylint, Radon), and Google Gemini Large Language Models into a unified, explainable review system with side-by-side remediations, ground-truth benchmarking, and automated unit test generation.

---

## 📑 Table of Contents
1. [Core Modules Overview](#-core-modules-overview)
2. [Architectural Layers & Detection Engines](#-architectural-layers--detection-engines)
3. [Gemini Integration & Diagnostic Pipeline](#-gemini-integration--diagnostic-pipeline)
4. [Modern Dark UI & File Ingestion](#-modern-dark-ui--file-ingestion)
5. [Benchmark Dataset & Scientific Evaluation](#-benchmark-dataset--scientific-evaluation)
6. [Technology Stack](#-technology-stack)
7. [Repository Structure](#-repository-structure)
8. [Installation & Quick Start](#-installation--quick-start)
9. [Automated Test Suite](#-automated-test-suite)
10. [Security & Isolation Principles](#-security--isolation-principles)

---

## 🏛️ Core Modules Overview

CodeGuard AI 2.0 is structured into seven primary functional modules accessible via the navigation sidebar:

### 1. 📊 Executive Dashboard
- **Quality & Severity Telemetry:** Live KPIs displaying total code reviews executed, average code health score, critical/high/medium defect distribution, and fix acceptance rate.
- **Interactive Visualizations:** Severity breakdown bar charts, language distribution donuts, defect category distributions, and review activity timelines.
- **Recent Activity Table:** Displays historical audit logs directly populated from SQLite with quick-restore capabilities.

### 2. 🔍 Code Review & Vulnerability Audit
- **Multi-Language Selector:** Python, Java, JavaScript, TypeScript, C/C++, Go, SQL, C#, PHP, Ruby, HTML, CSS.
- **Engine Toggles:** Granular control over which engines execute (Rule Engine, AST Analyzer, Linters, Gemini LLM).
- **Clean File Ingestion Dropzone:** Minimalist, clutter-free drag-and-drop file upload supporting single or multi-file batches with size validation and active file switching.
- **Multi-Attribute Deduplication:** Merges overlapping findings from static and LLM engines with preserved provenance (`Detected by: Rule Engine, Bandit, Gemini`).
- **Export Options:** Instant downloads for audit reports in JSON, CSV, and formal Academic PDF formats.

### 3. 🔎 Issue Explorer & Remediation Lab
- **State Synchronization:** Fully synchronized with active code review state; allows viewing findings immediately after review or restoring any past review from SQLite.
- **Filter & Search:** Real-time filtering by Severity, Category, Detection Engine, and keyword search.
- **Confidence Scoring & Basis:** Transparent confidence percentage with explainable reasoning basis for every finding.
- **Side-by-Side Code Comparison:** Visual diff comparing original vulnerable snippets against suggested corrected remediation code.
- **Automated Pytest Reproduction:** Automatically drafts targeted, isolated Pytest unit test suites that reproduce detected vulnerabilities to guard against regressions.

### 4. 📈 Evaluation & Analytics (Research-Grade)
- **Zero Fabricated Metrics:** Benchmarks detection engines against a 100% verified ground-truth dataset (`data/benchmark_dataset.csv`).
- **Head-to-Head Comparison:** Computes Precision, Recall, F1-Score, False Positive Rate (FPR), and Total Detection counts across Rule-Based, AST, Static Linters, and Hybrid approaches.
- **Confusion Matrix Heatmap:** Live interactive confusion matrix comparing True Positives, False Positives, True Negatives, and False Negatives.

### 5. 📁 Dataset Explorer
- **Telemetry Inspection:** Browse the full historical code review telemetry dataset (`data/dataset.csv`).
- **Descriptive Statistics:** Inspect feature distributions, severity correlations, and accepted fix rates.
- **Search & Download:** Filter historical dataset records and export filtered views as CSV.

### 6. 🕒 Review History & Audit Trail
- **Persistent Storage:** Backed by SQLite3 (`database/codeguard_history.db`).
- **State Restoration:** Click **"Load Review"** on any past record to instantly restore the full audit state into the Code Review and Issue Explorer modules.
- **Database Telemetry:** Inspect file names, lines of code, analysis duration, and quality ratings over time.

### 7. ⚙️ Application & Engine Settings
- **Safe API Key Management:** Masked input field with local environment fallback; keys are never logged, printed, or committed.
- **Multi-Stage Network Diagnostics:** Live pipeline inspecting DNS, TCP 443, TLS, API authentication, and model reachability.
- **Real-Time Status Badges:** Visual indicators reflecting actual Google Gemini availability.

---

## 🌟 Architectural Layers & Detection Engines

```
                           +--------------------------------------+
                           |       Source Code / File Upload      |
                           +--------------------------------------+
                                              |
               +------------------------------+------------------------------+
               |                              |                              |
               v                              v                              v
    +--------------------+        +--------------------+        +--------------------+
    | AST Python Parser  |        | Polyglot Rules     |        | Static Linters     |
    | (ast.NodeVisitor)  |        | (Regex & Patterns) |        | (Bandit/Pylint/Radon)
    +--------------------+        +--------------------+        +--------------------+
               |                              |                              |
               +------------------------------+------------------------------+
                                              |
                                              v
                              +--------------------------------+
                              | Contextual Google Gemini LLM   |
                              | (Direct REST over Port 443)    |
                              +--------------------------------+
                                              |
                                              v
                              +--------------------------------+
                              | Deduplication & Provenance     |
                              | (Multi-attribute matching)     |
                              +--------------------------------+
                                              |
                                              v
                              +--------------------------------+
                              | ReviewResult & SQLite History  |
                              +--------------------------------+
```

1. **AST Structural Parser (`core/ast_analyzer.py`)**:
   - Parses Python syntax trees without executing untrusted code.
   - Detects mutable default arguments, constant division by zero, `eval()`/`exec()` usage, suspicious literal identity checks (`is None` vs `== None`), and overly broad `except:` clauses.

2. **Polyglot Rule Engine (`core/rule_engine.py`)**:
   - High-throughput pattern matching across Python, Java, JavaScript, TypeScript, C/C++, Go, and SQL.
   - Intelligent multi-line comment stripping to prevent false positives in docstrings and comments.
   - Outputs exact line spans, severity ratings, and concrete remediation snippets.

3. **Production Static Linters (`core/static_analyzer.py`)**:
   - **Bandit:** Discovers hardcoded secrets, weak cryptographic hashes (MD5, SHA1), SQL injections, and insecure configurations.
   - **Pylint:** Flags coding standard violations, undefined variables, and logic bugs.
   - **Radon:** Measures cyclomatic complexity and maintainability index.
   - Process sandboxing with strict timeouts prevents runaway processes.

4. **Contextual LLM Reasoning (`core/llm_service.py`)**:
   - Leverages Google Gemini (`gemini-3.8-flash`) for deep semantic bug analysis, architectural anti-patterns, and contextual patches.
   - Structured JSON schema deserialization with validation and graceful degradation when offline.

---

## ⚡ Gemini Integration & Diagnostic Pipeline

CodeGuard AI 2.0 features an enterprise-grade Google Gemini integration designed to eliminate timeout deadlocks and provide full diagnostic visibility:

### 1. Direct REST Architecture over Port 443
- Bypasses gRPC HTTP/2 stream deadlocks common on Windows firewall and proxy environments.
- Uses standard HTTPS REST endpoints: `https://generativelanguage.googleapis.com/v1beta/...`.
- Supported Model: **`gemini-3.8-flash`** (configured via `.env` or Settings UI).

### 2. Five-Stage Network Diagnostics (`core/connection_tester.py`)
Provides independent, isolated diagnostic checks with distinct status indicators:
- **DNS Resolution:** Resolves `generativelanguage.googleapis.com` to target Google IPs.
- **TCP Port 443 Handshake:** Establishes a raw socket connection within a dedicated 15-second timeout.
- **HTTPS / TLS Validation:** Validates SSL/TLS certificate chains and cipher negotiation.
- **API Key Authentication:** Verifies API key validity with Google without triggering long reasoning token queues.
- **Model Availability:** Probes the target model (`gemini-3.8-flash`) and distinguishes between `404 Model Not Found`, `429 Rate Limit/Quota Exceeded`, and `503 Service Unavailable`.

### 3. Fault Tolerance & Exponential Backoff
- Differentiates transient errors (HTTP 429, 500, 502, 503, 504) from fatal errors (HTTP 400 Invalid Key, HTTP 404 Model Not Found).
- Automatic retry loop with jittered exponential backoff for transient conditions.
- **Graceful Fallback:** If Gemini is offline, unconfigured, or timed out, all AST, Rule, and Static analysis engines continue to operate completely and report findings accurately.

---

## 🎨 Modern Dark UI & File Ingestion

- **SaaS Dark Palette:** Deep slate background (`#0b0f19` / `#0f172a`), crisp contrast typography using *Inter* and *JetBrains Mono*, and accessible status badges.
- **Minimalist Dropzone:** Removed messy language extension listings and cluttered text; features a clean, responsive dropzone with styled browse buttons.
- **File Chips:** Uploaded files render as compact metadata pills (`📄 filename.py (4KB)`) with multi-file management and active file switcher.
- **State Preservation:** Navigating between Dashboard, Code Review, Issue Explorer, and Settings preserves all uploaded code and review results in Streamlit session state.

---

## 📊 Benchmark Dataset & Scientific Evaluation

CodeGuard AI includes a scientific evaluation framework with verified ground truth:

- **Benchmark Dataset (`data/benchmark_dataset.csv`):** Verified code samples across 5 languages categorized into:
  - Logic & Arithmetic Flaws
  - SQL & Command Injection
  - Hardcoded Secrets & Credentials
  - Deserialization & Memory Safety
  - Clean / Reference Implementations
- **Data Dictionary (`data/data_dictionary.csv`):** Comprehensive schema definition describing ground-truth labels and evaluation metrics.
- **Historical Telemetry (`data/dataset.csv`):** 500 realistic code review records with defect telemetry, quality ratings, and resolution times.
- **Scientific Metrics:** Computes Precision, Recall, F1-Score, and False Positive Rate across all engines without simulated or hardcoded results.

---

## 🛠️ Technology Stack

| Layer | Technologies |
| :--- | :--- |
| **Language & Runtime** | Python 3.10+, SQLite3 |
| **LLM Provider** | Google Gemini API (`gemini-3.8-flash` via Direct REST) |
| **Static Analysis** | Python `ast`, Bandit, Pylint, Radon |
| **Web Frontend** | Streamlit, HTML5, CSS3, JetBrains Mono font |
| **Data & Charts** | Pandas, NumPy, Scikit-learn, Plotly Express & Graph Objects |
| **Report Generation** | ReportLab (Academic PDF), JSON, CSV |
| **Automated Testing** | Pytest, Unittest Mock |

---

## 📂 Repository Structure

```
CodeGuard-AI/
├── .env.example                  # Template environment configuration
├── .gitignore                     # Git ignore rules (secrets, venvs, DBs)
├── README.md                      # Comprehensive project documentation
├── requirements.txt               # Locked production dependencies
├── app.py                         # Streamlit multi-page frontend application
│
├── config/                        # Configuration module
│   ├── __init__.py
│   └── settings.py                # Environment parser & system settings
│
├── core/                          # Core analysis and detection engines
│   ├── __init__.py
│   ├── analyzer.py                # Central orchestrator & finding deduplication
│   ├── ast_analyzer.py            # Structural Python AST NodeVisitor
│   ├── rule_engine.py             # Polyglot pattern vulnerability detector
│   ├── static_analyzer.py         # Bandit, Pylint, and Radon linter wrappers
│   ├── llm_service.py             # Gemini client with REST execution & backoff
│   ├── connection_tester.py       # 5-stage network diagnostic pipeline
│   ├── schemas.py                 # Pydantic v2 data models & type definitions
│   ├── security.py                # File size, path, and extension sanitizers
│   ├── test_generator.py          # Automated Pytest reproduction suite builder
│   ├── report_exporter.py         # JSON, CSV, and Academic PDF report generators
│   └── evaluation.py              # Scientific benchmark evaluator & confusion matrix
│
├── components/                    # UI visualization components
│   ├── __init__.py
│   └── charts.py                  # Plotly charts (Severity, Language, Confusion Matrix)
│
├── database/                      # Telemetry persistence layer
│   ├── __init__.py
│   └── history.py                 # SQLite database models & query interfaces
│
├── data/                          # Ground-truth datasets & benchmarks
│   ├── benchmark_dataset.csv      # Verified ground-truth benchmark suite
│   ├── data_dictionary.csv        # Schema definition & data dictionary
│   └── dataset.csv                # 500 historical code review telemetry records
│
├── outputs/                       # Export and artifact storage
│   ├── eda/                       # Generated exploratory charts
│   └── reports/                   # Saved review reports
│
└── tests/                         # Comprehensive unit & regression test suite
    ├── __init__.py
    ├── test_analyzer.py           # Core orchestrator and deduplication tests
    ├── test_dataset.py            # Benchmark dataset integrity tests
    ├── test_gemini_connection.py  # Network diagnostics & mock API tests
    ├── test_master_regression.py  # End-to-end regression audit tests
    ├── test_rules.py              # Polyglot rule engine pattern tests
    └── test_v2_features.py        # PDF exporter, test generator, & SQLite tests
```

---

## 🚀 Installation & Quick Start

### 1. Clone & Set Up Virtual Environment
```bash
git clone https://github.com/<your-username>/CodeGuard-AI.git
cd CodeGuard-AI
python -m venv venv

# On Windows:
.\venv\Scripts\activate
# On Linux/macOS:
source venv/bin/activate
```

### 2. Install Dependencies
```bash
pip install -r requirements.txt
```

### 3. Configure Environment Variables
Copy `.env.example` to `.env` and set your configuration:
```bash
cp .env.example .env
```
Inside `.env`:
```ini
GEMINI_API_KEY=your_gemini_api_key_here
GEMINI_MODEL=gemini-3.8-flash
LLM_TIMEOUT=60
MAX_FILE_SIZE_KB=500
```
*(Note: CodeGuard AI runs in deterministic local mode using Rules + AST + Linters even without an API key).*

### 4. Launch the Streamlit Dashboard
```bash
streamlit run app.py
```
Open **`http://localhost:8501`** in your browser.

---

## 🧪 Automated Test Suite

CodeGuard AI 2.0 maintains a 100% passing test suite with zero external network dependencies (all external APIs are cleanly mocked):

```bash
pytest tests/ -v
```

### Test Suite Coverage (**81 Passing Tests**):
- **Gemini Connection & Network Diagnostics (`test_gemini_connection.py` - 16 tests):** Validates DNS failure handling, TCP timeouts, SSL certificate errors, HTTP 400 (Invalid Key), HTTP 404 (Model Not Found), HTTP 429 (Rate Limit), HTTP 503 (Server Error), and dynamic key configuration.
- **Polyglot Rule Engine (`test_rules.py` - 19 tests):** Validates comment stripping and defect pattern recognition across Python, Java, JS, C++, Go, and SQL.
- **AST Structural Parser (`test_analyzer.py` - 10 tests):** Asserts node visitor detection for mutable arguments, constant division, and broad exceptions.
- **Dataset & Benchmark (`test_dataset.py` - 11 tests):** Ensures benchmark integrity, ground-truth label validity, and metric calculation consistency.
- **Master Regression Suite (`test_master_regression.py` - 10 tests):** End-to-end regression covering JSON parsing, graceful degradation, and provenance tracking.
- **V2 Platform Features (`test_v2_features.py` - 15 tests):** Validates PDF report compilation, Pytest suite generation, SQLite persistence, and state retrieval.

---

## 🔒 Security & Isolation Principles

- **No Host Code Execution:** Source code submitted for analysis is statically parsed and never executed on the host server.
- **Subprocess Isolation:** External linters (Bandit, Pylint, Radon) execute within isolated subprocesses with mandatory execution timeouts and temporary directory scoping.
- **Credential Protection:** API keys and environment variables are strictly excluded via `.gitignore`, masked in UI inputs, and omitted from application logs and exported reports.
- **Input Sanitization:** Multi-stage validation rejects path traversals, unsupported file formats, and payloads exceeding size thresholds.
