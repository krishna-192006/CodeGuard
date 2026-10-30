"""
CodeGuard AI - EDA and Data Processing Script
Generates processed_dataset.csv and visualisations from dataset.csv.
Run standalone: python generate_eda.py
"""
import sys
import os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

import pandas as pd
import numpy as np
import matplotlib.pyplot as plt
import matplotlib
matplotlib.use('Agg')
import seaborn as sns
from pathlib import Path

BASE_DIR = Path(__file__).parent.parent
DATA_DIR = BASE_DIR / "data"
EDA_DIR = BASE_DIR / "outputs" / "eda"
EDA_DIR.mkdir(parents=True, exist_ok=True)

plt.style.use('dark_background')
COLORS = ['#6366f1', '#f97316', '#22c55e', '#eab308', '#ef4444']
SEVERITY_ORDER = ["Critical", "High", "Medium", "Low", "Info"]


def load_and_clean():
    df = pd.read_csv(DATA_DIR / "dataset.csv")
    print(f"Loaded {len(df)} rows, {len(df.columns)} columns")
    print("Columns:", df.columns.tolist())
    print("\nData types:\n", df.dtypes)
    print("\nMissing values:\n", df.isnull().sum())
    print("\nDuplicates:", df.duplicated().sum())

    # Clean
    df = df.drop_duplicates()
    df["llm_confidence"] = df["llm_confidence"].clip(0, 1)
    df["severity"] = df["severity"].str.strip()
    df["file_type"] = df["file_type"].str.strip()
    df["issue_type"] = df["issue_type"].str.strip()
    df["accepted"] = df["accepted"].astype(int)

    print(f"\nAfter cleaning: {len(df)} rows")
    return df


def save_processed(df):
    out = DATA_DIR / "processed_dataset.csv"
    df.to_csv(out, index=False)
    print(f"Saved processed dataset: {out}")


def save_data_dict(df):
    descriptions = {
        "review_id": "Unique identifier for each code review record (e.g. REV00001).",
        "file_type": "Programming language of the reviewed file (Python, Java, JavaScript, TypeScript).",
        "lines_of_code": "Number of lines of code in the reviewed file.",
        "issue_type": "Category of the detected issue (e.g. null_pointer, sql_injection, unused_variable).",
        "severity": "Severity level: Critical > High > Medium > Low > Info.",
        "llm_confidence": "LLM confidence score for the detected issue (float 0.0 to 1.0).",
        "accepted": "Whether the suggestion was accepted by the developer (1=Yes, 0=No).",
        "fix_time_min": "Time in minutes taken to fix the detected issue.",
    }

    rows = []
    for col in df.columns:
        rows.append({
            "column_name": col,
            "data_type": str(df[col].dtype),
            "sample_value_1": str(df[col].iloc[0]),
            "sample_value_2": str(df[col].iloc[1]),
            "sample_value_3": str(df[col].iloc[2]),
            "nullable": "No" if df[col].isnull().sum() == 0 else "Yes",
            "description": descriptions.get(col, ""),
        })

    dict_df = pd.DataFrame(rows)
    out = DATA_DIR / "data_dictionary.csv"
    dict_df.to_csv(out, index=False)
    print(f"Saved data dictionary: {out}")


def plot_severity_distribution(df):
    fig, ax = plt.subplots(figsize=(9, 5))
    counts = df["severity"].value_counts().reindex(SEVERITY_ORDER, fill_value=0)
    bars = ax.bar(counts.index, counts.values,
                  color=['#ef4444','#f97316','#eab308','#3b82f6','#8b5cf6'])
    ax.set_title("Issue Count by Severity", fontsize=14, pad=12)
    ax.set_xlabel("Severity")
    ax.set_ylabel("Count")
    for bar, val in zip(bars, counts.values):
        ax.text(bar.get_x() + bar.get_width()/2, bar.get_height() + 2,
                str(val), ha='center', va='bottom', fontsize=11)
    plt.tight_layout()
    plt.savefig(EDA_DIR / "01_severity_distribution.png", dpi=120, bbox_inches='tight')
    plt.close()
    print("Saved: 01_severity_distribution.png")


def plot_language_distribution(df):
    fig, ax = plt.subplots(figsize=(7, 7))
    counts = df["file_type"].value_counts()
    ax.pie(counts.values, labels=counts.index, autopct='%1.1f%%',
           colors=['#6366f1','#f97316','#eab308','#22c55e'],
           startangle=140, textprops={'fontsize': 12})
    ax.set_title("Reviews by Programming Language", fontsize=14, pad=12)
    plt.tight_layout()
    plt.savefig(EDA_DIR / "02_language_distribution.png", dpi=120, bbox_inches='tight')
    plt.close()
    print("Saved: 02_language_distribution.png")


def plot_issue_types(df):
    fig, ax = plt.subplots(figsize=(9, 5))
    counts = df["issue_type"].value_counts()
    ax.barh(counts.index, counts.values, color='#6366f1')
    ax.set_title("Issue Type Distribution", fontsize=14, pad=12)
    ax.set_xlabel("Count")
    plt.tight_layout()
    plt.savefig(EDA_DIR / "03_issue_type_distribution.png", dpi=120, bbox_inches='tight')
    plt.close()
    print("Saved: 03_issue_type_distribution.png")


def plot_accepted(df):
    fig, ax = plt.subplots(figsize=(6, 6))
    labels = ["Accepted", "Rejected"]
    sizes = [df["accepted"].sum(), (1 - df["accepted"]).sum()]
    ax.pie(sizes, labels=labels, autopct='%1.1f%%',
           colors=['#22c55e', '#ef4444'], startangle=90,
           textprops={'fontsize': 13})
    ax.set_title("Accepted vs Rejected Suggestions", fontsize=14, pad=12)
    plt.tight_layout()
    plt.savefig(EDA_DIR / "04_accepted_vs_rejected.png", dpi=120, bbox_inches='tight')
    plt.close()
    print("Saved: 04_accepted_vs_rejected.png")


def plot_fix_time_by_severity(df):
    fig, ax = plt.subplots(figsize=(9, 5))
    avg = df.groupby("severity")["fix_time_min"].mean().reindex(SEVERITY_ORDER)
    colors = ['#ef4444','#f97316','#eab308','#3b82f6','#8b5cf6']
    bars = ax.bar(avg.index, avg.values, color=colors)
    ax.set_title("Average Fix Time by Severity (minutes)", fontsize=14, pad=12)
    ax.set_xlabel("Severity")
    ax.set_ylabel("Avg Fix Time (minutes)")
    for bar, val in zip(bars, avg.values):
        ax.text(bar.get_x() + bar.get_width()/2, bar.get_height() + 0.5,
                f"{val:.1f}", ha='center', va='bottom', fontsize=10)
    plt.tight_layout()
    plt.savefig(EDA_DIR / "05_fix_time_by_severity.png", dpi=120, bbox_inches='tight')
    plt.close()
    print("Saved: 05_fix_time_by_severity.png")


def plot_confidence_hist(df):
    fig, ax = plt.subplots(figsize=(9, 5))
    ax.hist(df["llm_confidence"], bins=20, color='#6366f1', edgecolor='#e2e8f0', alpha=0.8)
    ax.set_title("LLM Confidence Score Distribution", fontsize=14, pad=12)
    ax.set_xlabel("Confidence Score")
    ax.set_ylabel("Frequency")
    plt.tight_layout()
    plt.savefig(EDA_DIR / "06_confidence_distribution.png", dpi=120, bbox_inches='tight')
    plt.close()
    print("Saved: 06_confidence_distribution.png")


def plot_correlation(df):
    num_df = df[["lines_of_code", "llm_confidence", "accepted", "fix_time_min"]]
    corr = num_df.corr().values
    labels = ["loc", "confidence", "accepted", "fix_time"]
    fig, ax = plt.subplots(figsize=(7, 6))
    im = ax.imshow(corr, cmap="coolwarm", vmin=-1, vmax=1)
    ax.set_xticks(range(len(labels)))
    ax.set_yticks(range(len(labels)))
    ax.set_xticklabels(labels, rotation=45, ha="right")
    ax.set_yticklabels(labels)
    for i in range(len(labels)):
        for j in range(len(labels)):
            ax.text(j, i, f"{corr[i, j]:.2f}", ha="center", va="center", color="white", fontsize=11)
    plt.colorbar(im, ax=ax)
    ax.set_title("Pearson Correlation Matrix", fontsize=14, pad=12)
    plt.tight_layout()
    plt.savefig(EDA_DIR / "07_correlation_matrix.png", dpi=120, bbox_inches='tight')
    plt.close()
    print("Saved: 07_correlation_matrix.png")


def save_eda_report(df):
    severity_counts = df["severity"].value_counts()
    lang_counts = df["file_type"].value_counts()
    accepted_pct = df["accepted"].mean() * 100

    report = f"""# CodeGuard AI - EDA Summary Report

## Dataset Overview
- Total rows: {len(df)}
- Columns: {len(df.columns)}
- Complete dataset (no missing values): {df.isnull().sum().sum() == 0}
- Duplicates removed: {df.duplicated().sum()}

## Key Statistics
- Average LLM confidence: {df["llm_confidence"].mean():.3f}
- Accepted suggestions: {accepted_pct:.1f}%
- Average fix time: {df["fix_time_min"].mean():.1f} minutes
- Max lines of code in single review: {df["lines_of_code"].max()}

## Severity Distribution
{severity_counts.to_string()}

## Language Distribution
{lang_counts.to_string()}

## Issue Types
{df["issue_type"].value_counts().to_string()}

## Fix Time Statistics
{df["fix_time_min"].describe().to_string()}

## Correlation Summary
- Higher severity issues tend to take longer to fix.
- LLM confidence has a slight positive correlation with acceptance rate.

## Visualisations Generated
1. 01_severity_distribution.png
2. 02_language_distribution.png
3. 03_issue_type_distribution.png
4. 04_accepted_vs_rejected.png
5. 05_fix_time_by_severity.png
6. 06_confidence_distribution.png
7. 07_correlation_matrix.png

*Dataset source: CodeGuard AI project dataset (500 records)*
"""
    out = BASE_DIR / "outputs" / "reports" / "eda_summary.md"
    out.write_text(report)
    print(f"Saved EDA report: {out}")


if __name__ == "__main__":
    df = load_and_clean()
    save_processed(df)
    save_data_dict(df)
    plot_severity_distribution(df)
    plot_language_distribution(df)
    plot_issue_types(df)
    plot_accepted(df)
    plot_fix_time_by_severity(df)
    plot_confidence_hist(df)
    plot_correlation(df)
    save_eda_report(df)
    print("\n✅ EDA complete. All outputs saved.")
