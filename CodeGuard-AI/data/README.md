# CodeGuard AI 2.0 - Benchmark Dataset Documentation

This directory contains the verified benchmark ground-truth dataset and historical code review datasets used to evaluate the accuracy, recall, and false positive rates of static analysis, rule-based engines, and LLM reviewers.

---

## 1. `benchmark_dataset.csv`
A curated, research-grade evaluation benchmark with **verified ground-truth labels**. Used in `core/evaluation.py` to calculate True Positive, False Positive, True Negative, False Negative, Accuracy, Precision, Recall, and F1-Scores.

### Columns Specification:
| Column Name | Data Type | Nullable | Description |
| :--- | :--- | :--- | :--- |
| `sample_id` | String (Identifier) | No | Unique test sample identifier (e.g., `BENCH-001`). |
| `programming_language` | String | No | Target programming language (`Python`, `Java`, `JavaScript`, `C++`, `SQL`). |
| `source_code` | String (Multiline) | No | Exact source code block under evaluation. |
| `buggy_code` | String | Yes | Problematic snippet or token causing the defect. |
| `corrected_code` | String | No | Verified remediation snippet resolving the bug. |
| `bug_category` | String | No | Major defect class (`division_by_zero`, `sql_injection`, `command_injection`, `hardcoded_credentials`, `none`). |
| `bug_subcategory` | String | No | Detailed classification (e.g. `literal_zero_division`, `container_default`). |
| `severity` | String | No | Severity impact (`Critical`, `High`, `Medium`, `Low`, `Informational`). |
| `expected_line_number` | Integer | Yes | 1-based source code line where defect occurs (0 if clean). |
| `expected_behavior` | String | No | Intended functional or security behavior. |
| `actual_behavior` | String | No | Observable defect behavior or failure mode. |
| `ground_truth_label` | Integer (0 or 1) | No | `1` if the code contains a genuine defect, `0` if the code is clean. |
| `source` | String | No | Provenance of the sample (`manually_verified`). |
| `verification_status` | String | No | Verification state (`Verified`). |

---

## 2. `dataset.csv`
Historical review logs containing 500 review samples for exploratory data analysis (EDA), correlation matrix calculations, and reviewer acceptance modeling.

### Columns Specification:
| Column Name | Data Type | Nullable | Description |
| :--- | :--- | :--- | :--- |
| `review_id` | String | No | Unique review identifier (e.g., `REV00001`). |
| `file_type` | String | No | Source programming language / file type. |
| `lines_of_code` | Integer | No | Count of non-empty source lines reviewed. |
| `issue_type` | String | No | Primary issue identified during the review. |
| `severity` | String | No | Assigned severity (`Critical`, `High`, `Medium`, `Low`, `Info`). |
| `llm_confidence` | Float | No | Reviewer / LLM confidence score between 0.0 and 1.0. |
| `accepted` | Binary (0 or 1) | No | Whether developer accepted and applied the finding. |
| `fix_time_min` | Integer | No | Time in minutes spent addressing and closing the finding. |

