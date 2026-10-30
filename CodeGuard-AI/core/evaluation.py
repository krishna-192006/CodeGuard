"""
CodeGuard AI 2.0 - Evaluation & Metrics Engine
Evaluates detection models (Rule-Based, AST, Pylint, Bandit, Gemini LLM, Hybrid)
against verified ground-truth benchmarks.
Calculates Accuracy, Precision, Recall, F1-Score, and Confusion Matrix.
"""
from __future__ import annotations
import pandas as pd
from typing import Dict, List, Any, Tuple
from core.schemas import AnalysisRequest
from core.analyzer import analyse_code


def calculate_metrics(y_true: List[int], y_pred: List[int]) -> Dict[str, float]:
    """
    Computes classification metrics strictly from ground truth (1=Buggy, 0=Clean).
    TP, FP, TN, FN, Accuracy, Precision, Recall, F1-score, False Positive Rate.
    """
    tp = sum(1 for yt, yp in zip(y_true, y_pred) if yt == 1 and yp == 1)
    fp = sum(1 for yt, yp in zip(y_true, y_pred) if yt == 0 and yp == 1)
    tn = sum(1 for yt, yp in zip(y_true, y_pred) if yt == 0 and yp == 0)
    fn = sum(1 for yt, yp in zip(y_true, y_pred) if yt == 1 and yp == 0)

    total = len(y_true) if len(y_true) > 0 else 1
    accuracy = (tp + tn) / total
    precision = tp / (tp + fp) if (tp + fp) > 0 else 0.0
    recall = tp / (tp + fn) if (tp + fn) > 0 else 0.0
    f1 = (2 * precision * recall) / (precision + recall) if (precision + recall) > 0 else 0.0
    fpr = fp / (fp + tn) if (fp + tn) > 0 else 0.0

    return {
        "TP": tp,
        "FP": fp,
        "TN": tn,
        "FN": fn,
        "accuracy": round(accuracy, 4),
        "precision": round(precision, 4),
        "recall": round(recall, 4),
        "f1": round(f1, 4),
        "fpr": round(fpr, 4),
        "total_samples": len(y_true),
    }


def evaluate_engines_on_benchmark(benchmark_df: pd.DataFrame) -> Dict[str, Any]:
    """
    Runs live evaluation of detection engines on the verified ground-truth benchmark:
    1. Rule Engine
    2. AST Analyzer
    3. Static Linters (Bandit + Pylint + Radon)
    4. Hybrid Analysis Engine (All local tools combined)
    """
    y_true = benchmark_df["ground_truth_label"].astype(int).tolist()

    preds_rule: List[int] = []
    preds_ast: List[int] = []
    preds_static: List[int] = []
    preds_hybrid: List[int] = []

    for _, row in benchmark_df.iterrows():
        code = str(row["source_code"])
        lang = str(row["programming_language"])

        # 1. Rule Engine only
        req_rule = AnalysisRequest(code=code, language=lang, enabled_engines=["rule_engine"])
        res_rule = analyse_code(req_rule)
        preds_rule.append(1 if len(res_rule.issues) > 0 else 0)

        # 2. AST Analyzer only
        req_ast = AnalysisRequest(code=code, language=lang, enabled_engines=["ast_analyzer"])
        res_ast = analyse_code(req_ast)
        preds_ast.append(1 if len(res_ast.issues) > 0 else 0)

        # 3. Static linters only
        req_static = AnalysisRequest(code=code, language=lang, enabled_engines=["static_analyzer"])
        res_static = analyse_code(req_static)
        preds_static.append(1 if len(res_static.issues) > 0 else 0)

        # 4. Hybrid (All local engines combined)
        req_hybrid = AnalysisRequest(code=code, language=lang, enabled_engines=["rule_engine", "ast_analyzer", "static_analyzer"])
        res_hybrid = analyse_code(req_hybrid)
        preds_hybrid.append(1 if len(res_hybrid.issues) > 0 else 0)

    metrics_rule = calculate_metrics(y_true, preds_rule)
    metrics_ast = calculate_metrics(y_true, preds_ast)
    metrics_static = calculate_metrics(y_true, preds_static)
    metrics_hybrid = calculate_metrics(y_true, preds_hybrid)

    comparison_df = pd.DataFrame([
        {"Method": "Rule Engine", **metrics_rule},
        {"Method": "AST Analyzer", **metrics_ast},
        {"Method": "Static Linters", **metrics_static},
        {"Method": "Hybrid (Combined)", **metrics_hybrid},
    ])

    return {
        "comparison_table": comparison_df,
        "metrics_by_method": {
            "Rule Engine": metrics_rule,
            "AST Analyzer": metrics_ast,
            "Static Linters": metrics_static,
            "Hybrid": metrics_hybrid,
        },
        "y_true": y_true,
        "predictions": {
            "Rule Engine": preds_rule,
            "AST Analyzer": preds_ast,
            "Static Linters": preds_static,
            "Hybrid": preds_hybrid,
        }
    }
