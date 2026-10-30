"""
CodeGuard AI - Test Suite: Dataset
Validates dataset loading, types, and data quality.
"""
import sys
import os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

import pytest
import pandas as pd
from config.settings import DATASET_PATH, PROCESSED_DATASET_PATH


@pytest.fixture
def df():
    path = PROCESSED_DATASET_PATH if PROCESSED_DATASET_PATH.exists() else DATASET_PATH
    return pd.read_csv(path)


EXPECTED_COLUMNS = [
    "review_id", "file_type", "lines_of_code", "issue_type",
    "severity", "llm_confidence", "accepted", "fix_time_min",
]


def test_dataset_loads(df):
    assert df is not None
    assert len(df) > 0


def test_dataset_row_count(df):
    assert len(df) >= 500


def test_dataset_columns(df):
    for col in EXPECTED_COLUMNS:
        assert col in df.columns, f"Missing column: {col}"


def test_no_missing_review_id(df):
    assert df["review_id"].isnull().sum() == 0


def test_severity_values(df):
    valid = {"Critical", "High", "Medium", "Low", "Info"}
    actual = set(df["severity"].unique())
    assert actual.issubset(valid), f"Unexpected severity values: {actual - valid}"


def test_llm_confidence_range(df):
    assert df["llm_confidence"].min() >= 0.0
    assert df["llm_confidence"].max() <= 1.0


def test_accepted_binary(df):
    assert set(df["accepted"].unique()).issubset({0, 1})


def test_fix_time_positive(df):
    assert (df["fix_time_min"] > 0).all()


def test_lines_of_code_positive(df):
    assert (df["lines_of_code"] > 0).all()


def test_file_types(df):
    # Dataset also contains JS and TS — all are present
    assert df["file_type"].nunique() >= 2


def test_no_duplicate_review_ids(df):
    assert df["review_id"].duplicated().sum() == 0
