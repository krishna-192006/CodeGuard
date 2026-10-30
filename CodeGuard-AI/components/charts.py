"""
CodeGuard AI 2.0 - Plotly Visualization Components
Production dark-theme charts for Dashboard, EDA, Evaluation, and Comparison.
"""
from __future__ import annotations
import pandas as pd
import plotly.express as px
import plotly.graph_objects as go
from typing import Dict, List, Any


SEVERITY_COLORS = {
    "Critical": "#ef4444",
    "High": "#f97316",
    "Medium": "#eab308",
    "Low": "#3b82f6",
    "Informational": "#8b5cf6",
    "Info": "#8b5cf6",
}

LANG_COLORS = {
    "Python": "#3b82f6",
    "Java": "#f97316",
    "JavaScript": "#eab308",
    "TypeScript": "#8b5cf6",
    "C++": "#06b6d4",
    "C": "#64748b",
    "C#": "#10b981",
    "Go": "#00add8",
    "SQL": "#ec4899",
}

CATEGORY_COLORS = {
    "Security Vulnerabilities": "#ef4444",
    "Runtime Errors": "#f97316",
    "Logical Errors": "#eab308",
    "Syntax Errors": "#ec4899",
    "Exception Handling": "#8b5cf6",
    "Resource Management": "#06b6d4",
    "Performance Issues": "#10b981",
    "Code Quality Issues": "#3b82f6",
}

PAPER_BG = "rgba(15,23,42,0)"
PLOT_BG = "rgba(30,41,59,0.5)"


def _base_layout(title: str) -> dict:
    return dict(
        title=dict(text=title, font=dict(size=15, color="#f1f5f9", family="Inter")),
        paper_bgcolor=PAPER_BG,
        plot_bgcolor=PLOT_BG,
        font=dict(color="#94a3b8", family="Inter"),
        margin=dict(t=50, b=35, l=40, r=30),
        legend=dict(bgcolor="rgba(0,0,0,0)", font=dict(color="#cbd5e1")),
    )


def severity_bar_chart(df: pd.DataFrame) -> go.Figure:
    order = ["Critical", "High", "Medium", "Low", "Info", "Informational"]
    counts = df["severity"].value_counts().reindex(order, fill_value=0).reset_index()
    counts.columns = ["Severity", "Count"]
    counts = counts[counts["Count"] > 0]
    colors = [SEVERITY_COLORS.get(s, "#64748b") for s in counts["Severity"]]

    fig = go.Figure(
        go.Bar(
            x=counts["Severity"],
            y=counts["Count"],
            marker=dict(color=colors, line=dict(color="rgba(255,255,255,0.1)", width=1)),
            text=counts["Count"],
            textposition="auto",
        )
    )
    fig.update_layout(
        **_base_layout("Issue Distribution by Severity"),
        xaxis=dict(gridcolor="rgba(255,255,255,0.05)"),
        yaxis=dict(gridcolor="rgba(255,255,255,0.05)"),
    )
    return fig


def issues_by_category_chart(issues_list: list) -> go.Figure:
    """Builds horizontal bar chart for category frequency."""
    cats = [getattr(i, "category", "Code Quality Issues") for i in issues_list]
    df = pd.Series(cats).value_counts().reset_index()
    df.columns = ["Category", "Count"]

    colors = [CATEGORY_COLORS.get(c, "#6366f1") for c in df["Category"]]
    fig = go.Figure(
        go.Bar(
            x=df["Count"],
            y=df["Category"],
            orientation="h",
            marker=dict(color=colors, line=dict(color="rgba(255,255,255,0.1)", width=1)),
            text=df["Count"],
            textposition="auto",
        )
    )
    fig.update_layout(
        **_base_layout("Issues by Category"),
        xaxis=dict(gridcolor="rgba(255,255,255,0.05)"),
        yaxis=dict(autorange="reversed", gridcolor="rgba(255,255,255,0.05)"),
    )
    return fig


def language_donut_chart(df: pd.DataFrame) -> go.Figure:
    col = "file_type" if "file_type" in df.columns else "language"
    counts = df[col].value_counts().reset_index()
    counts.columns = ["Language", "Count"]
    colors = [LANG_COLORS.get(l, "#94a3b8") for l in counts["Language"]]

    fig = go.Figure(
        go.Pie(
            labels=counts["Language"],
            values=counts["Count"],
            hole=0.55,
            marker=dict(colors=colors, line=dict(color="#0f172a", width=2)),
            textinfo="label+percent",
        )
    )
    fig.update_layout(**_base_layout("Reviews by Programming Language"))
    return fig


def issue_type_bar(df: pd.DataFrame, top_n: int = 8) -> go.Figure:
    top = df["issue_type"].value_counts().head(top_n).reset_index()
    top.columns = ["Issue Type", "Count"]

    fig = go.Figure(
        go.Bar(
            x=top["Count"],
            y=top["Issue Type"],
            orientation="h",
            marker=dict(
                color=top["Count"],
                colorscale="Purples",
                line=dict(color="rgba(255,255,255,0.1)", width=1),
            ),
            text=top["Count"],
            textposition="auto",
        )
    )
    fig.update_layout(
        **_base_layout(f"Top {top_n} Issue Types Detected"),
        yaxis=dict(autorange="reversed", gridcolor="rgba(255,255,255,0.05)"),
        xaxis=dict(gridcolor="rgba(255,255,255,0.05)"),
    )
    return fig


def accepted_pie(df: pd.DataFrame) -> go.Figure:
    counts = df["accepted"].value_counts().reset_index()
    counts.columns = ["Accepted", "Count"]
    counts["Label"] = counts["Accepted"].map({1: "Accepted", 0: "Rejected"})

    fig = go.Figure(
        go.Pie(
            labels=counts["Label"],
            values=counts["Count"],
            hole=0.45,
            marker=dict(
                colors=["#10b981", "#ef4444"],
                line=dict(color="#0f172a", width=2),
            ),
            textinfo="label+percent",
        )
    )
    fig.update_layout(**_base_layout("Developer Suggestion Acceptance Rate"))
    return fig


def fix_time_by_severity(df: pd.DataFrame) -> go.Figure:
    order = ["Critical", "High", "Medium", "Low", "Info", "Informational"]
    filtered = df[df["severity"].isin(order)]

    fig = px.box(
        filtered,
        x="severity",
        y="fix_time_min",
        category_orders={"severity": order},
        color="severity",
        color_discrete_map=SEVERITY_COLORS,
        template="plotly_dark",
    )
    fig.update_layout(
        **_base_layout("Remediation Time by Severity (Minutes)"),
        showlegend=False,
        xaxis=dict(gridcolor="rgba(255,255,255,0.05)", title=""),
        yaxis=dict(gridcolor="rgba(255,255,255,0.05)", title="Minutes"),
    )
    return fig


def confidence_histogram(df: pd.DataFrame) -> go.Figure:
    fig = px.histogram(
        df,
        x="llm_confidence",
        nbins=20,
        color_discrete_sequence=["#6366f1"],
        template="plotly_dark",
    )
    fig.update_layout(
        **_base_layout("LLM Confidence Score Distribution"),
        xaxis=dict(gridcolor="rgba(255,255,255,0.05)", title="Confidence (0-1)"),
        yaxis=dict(gridcolor="rgba(255,255,255,0.05)", title="Count"),
    )
    return fig


def evaluation_comparison_bar(comparison_df: pd.DataFrame) -> go.Figure:
    """Grouped bar chart comparing Accuracy, Precision, Recall, and F1 across methods."""
    metrics = ["accuracy", "precision", "recall", "f1"]
    fig = go.Figure()
    palette = {"accuracy": "#3b82f6", "precision": "#10b981", "recall": "#f59e0b", "f1": "#8b5cf6"}

    for m in metrics:
        fig.add_trace(
            go.Bar(
                name=m.capitalize(),
                x=comparison_df["Method"],
                y=comparison_df[m],
                marker_color=palette[m],
                text=[f"{v:.2f}" for v in comparison_df[m]],
                textposition="auto",
            )
        )

    fig.update_layout(
        **_base_layout("Model Evaluation Metric Comparison (Benchmark)"),
        barmode="group",
        yaxis=dict(range=[0, 1.1], gridcolor="rgba(255,255,255,0.05)"),
        xaxis=dict(gridcolor="rgba(255,255,255,0.05)"),
    )
    return fig


def confusion_matrix_heatmap(tp: int, fp: int, tn: int, fn: int, title: str = "Confusion Matrix") -> go.Figure:
    """Plots a 2x2 confusion matrix heatmap."""
    z = [[tp, fn], [fp, tn]]
    x = ["Predicted Buggy", "Predicted Clean"]
    y = ["Actual Buggy", "Actual Clean"]

    fig = px.imshow(
        z,
        x=x,
        y=y,
        text_auto=True,
        color_continuous_scale="Blues",
        template="plotly_dark",
    )
    fig.update_layout(
        **_base_layout(title),
        xaxis=dict(side="bottom"),
    )
    return fig
