"""
Model Metrics Verification Tests against actual datasets and evaluation notebook benchmarks.
"""

from __future__ import annotations

from pathlib import Path
import pandas as pd
import pytest

DATA_DIR = Path(__file__).resolve().parent.parent.parent / "data"
Y_TRAIN_PATH = DATA_DIR / "y_train.csv"
Y_TEST_PATH = DATA_DIR / "y_test.csv"


def test_dataset_split_sample_counts():
    """Verify that training and testing splits match the documented 69,767 and 17,442 samples."""
    assert Y_TRAIN_PATH.exists(), f"y_train.csv must exist at {Y_TRAIN_PATH}"
    assert Y_TEST_PATH.exists(), f"y_test.csv must exist at {Y_TEST_PATH}"

    y_train = pd.read_csv(Y_TRAIN_PATH)
    y_test = pd.read_csv(Y_TEST_PATH)

    assert len(y_train) == 69767, f"Expected 69,767 training samples, got {len(y_train)}"
    assert len(y_test) == 17442, f"Expected 17,442 testing samples, got {len(y_test)}"

    total = len(y_train) + len(y_test)
    assert total == 87209, f"Expected 87,209 total deduplicated rows, got {total}"

    test_ratio = len(y_test) / total
    assert round(test_ratio, 2) == 0.20, f"Expected 20% test split, got {test_ratio:.4f}"


def test_metric_values_match_evaluation_notebook(client):
    """
    Verify that the metrics surfaced by /model-metrics match the true values
    computed in notebook/model_evaluation.ipynb:
      - Accuracy: 0.970072 -> 97.01%
      - Precision: 0.955414 -> 95.54%
      - Recall: 0.959174 -> 95.92%
      - F1 Score: 0.957290 -> 95.73%
      - ROC-AUC: 0.995049 -> 0.995
    """
    res = client.get("/model-metrics")
    assert res.status_code == 200
    data = res.get_json()

    rf = next(m for m in data["models"] if m["name"] == "Random Forest")
    assert rf["accuracy"] == 0.9701
    assert rf["precision"] == 0.9554
    assert rf["recall"] == 0.9592
    assert rf["f1_score"] == 0.9573
    assert rf["roc_auc"] == 0.995
    assert rf["training_samples"] == 69767
    assert data["testSamples"] == 17442
