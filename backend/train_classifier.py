"""Reproducible grouped training for SentinelLLM v4.2.

The included 52k corpus is synthetic. The trainer separates entire template families
into train/validation/test groups, tunes the threshold on validation only, and reports
final metrics on an untouched grouped test set. This is not a substitute for a real-world benchmark.
"""
from pathlib import Path
import json
import hashlib
import pandas as pd
import joblib
import numpy as np
import sklearn
from sklearn.model_selection import GroupShuffleSplit
from sklearn.pipeline import Pipeline, FeatureUnion
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import (
    classification_report, confusion_matrix, precision_score, recall_score,
    f1_score, accuracy_score, roc_auc_score, average_precision_score,
)

BASE = Path(__file__).resolve().parent
DATA = BASE / "training_data" / "sentinelllm_seed_dataset.csv"
MODEL_DIR = BASE / "ml_models"
MODEL_PATH = MODEL_DIR / "sentinelllm_tfidf_logreg.joblib"
METRICS_PATH = MODEL_DIR / "training_metrics.json"
SPLIT_PATH = MODEL_DIR / "grouped_test_predictions.csv"
SEED = 20261022


def make_model():
    features = FeatureUnion([
        ("word", TfidfVectorizer(ngram_range=(1, 2), sublinear_tf=True,
                                 strip_accents="unicode", min_df=1, max_features=80000)),
        ("char", TfidfVectorizer(analyzer="char", ngram_range=(3, 5),
                                 sublinear_tf=True, min_df=1, max_features=100000)),
    ])
    return Pipeline([
        ("features", features),
        ("classifier", LogisticRegression(max_iter=2500, class_weight="balanced", C=1.5, random_state=SEED)),
    ])


def split_indices(groups, test_size, seed, indices=None):
    if indices is None:
        indices = np.arange(len(groups))
    local_groups = np.asarray(groups)[indices]
    splitter = GroupShuffleSplit(n_splits=1, test_size=test_size, random_state=seed)
    a, b = next(splitter.split(np.zeros(len(indices)), groups=local_groups))
    return indices[a], indices[b]


def metrics_for(y_true, probs, threshold):
    pred = (probs >= threshold).astype(int)
    tn, fp, fn, tp = confusion_matrix(y_true, pred, labels=[0, 1]).ravel()
    return {
        "threshold": float(threshold), "accuracy": float(accuracy_score(y_true, pred)),
        "precision_attack": float(precision_score(y_true, pred, zero_division=0)),
        "recall_attack": float(recall_score(y_true, pred, zero_division=0)),
        "f1_attack": float(f1_score(y_true, pred, zero_division=0)),
        "benign_false_positive_rate": float(fp / max(1, tn)),
        "false_negative_rate": float(fn / max(1, fn + tp)),
        "tn": int(tn), "fp": int(fp), "fn": int(fn), "tp": int(tp),
    }


def main():
    df = pd.read_csv(DATA).dropna(subset=["text", "label", "family"]).copy()
    df["text"] = df["text"].astype(str).str.strip()
    df = df[df.text.str.len() > 0].drop_duplicates(subset=["text"]).reset_index(drop=True)
    df["label"] = df["label"].astype(int)
    if len(df) != 54000 or df.text.nunique() != 54000:
        raise ValueError(f"Expected 54,000 unique prompts, got {len(df)} rows / {df.text.nunique()} unique")
    if set(df.label.unique()) != {0, 1}:
        raise ValueError("Both labels 0 and 1 are required")
    X = df.text.to_numpy()
    y = df.label.to_numpy()
    groups = df.family.astype(str).to_numpy()

    # 20% final test families; 20% of remaining families for validation (~16% overall).
    trainval_idx, test_idx = split_indices(groups, 0.20, SEED)
    train_idx, val_idx = split_indices(groups, 0.20, SEED + 1, trainval_idx)
    family_sets = {name: set(groups[idx]) for name, idx in [("train", train_idx), ("validation", val_idx), ("test", test_idx)]}
    if (family_sets['train'] & family_sets['validation'] or family_sets['train'] & family_sets['test'] or family_sets['validation'] & family_sets['test']):
        raise RuntimeError("Template family leakage detected")
    for name, idx in [("train", train_idx), ("validation", val_idx), ("test", test_idx)]:
        if len(set(y[idx])) < 2:
            raise RuntimeError(f"Split {name} lacks both classes; adjust grouping")

    model = make_model()
    model.fit(X[train_idx], y[train_idx])
    val_probs = model.predict_proba(X[val_idx])[:, 1]
    val_rows = [metrics_for(y[val_idx], val_probs, round(float(t), 3)) for t in np.arange(0.35, 0.901, 0.025)]
    eligible = [r for r in val_rows if r["recall_attack"] >= 0.97 and r["benign_false_positive_rate"] <= 0.05]
    if eligible:
        chosen = max(eligible, key=lambda r: (r["recall_attack"], -r["benign_false_positive_rate"], r["precision_attack"]))
    else:
        chosen = max(val_rows, key=lambda r: (r["f1_attack"], -r["benign_false_positive_rate"]))
    threshold = round(float(chosen["threshold"]), 3)

    # Final model learns from train+validation; test remains untouched.
    final_model = make_model()
    fit_idx = np.concatenate([train_idx, val_idx])
    final_model.fit(X[fit_idx], y[fit_idx])
    test_probs = final_model.predict_proba(X[test_idx])[:, 1]
    test_metrics = metrics_for(y[test_idx], test_probs, threshold)
    test_metrics["roc_auc"] = float(roc_auc_score(y[test_idx], test_probs))
    test_metrics["average_precision"] = float(average_precision_score(y[test_idx], test_probs))
    test_metrics["classification_report"] = classification_report(y[test_idx], (test_probs >= threshold).astype(int), target_names=["benign", "attack"], output_dict=True, zero_division=0)

    MODEL_DIR.mkdir(exist_ok=True)
    joblib.dump(final_model, MODEL_PATH)
    test_df = df.iloc[test_idx][["text", "label", "category", "family"]].copy()
    test_df["attack_score"] = test_probs
    test_df["predicted_label"] = (test_probs >= threshold).astype(int)
    test_df["correct"] = test_df.label == test_df.predicted_label
    test_df.to_csv(SPLIT_PATH, index=False)
    metrics = {
        "model_name": "TF-IDF word+character n-grams + LogisticRegression",
        "model_version": "4.1.0-54k-media-context",
        "library_versions": {"scikit_learn": sklearn.__version__, "pandas": pd.__version__, "numpy": np.__version__, "joblib": joblib.__version__},
        "dataset_path": str(DATA.relative_to(BASE)), "dataset_rows": int(len(df)),
        "dataset_sha256": hashlib.sha256(DATA.read_bytes()).hexdigest(),
        "class_counts": {str(k): int(v) for k, v in df.label.value_counts().sort_index().items()},
        "topic_counts": df.topic.value_counts().to_dict() if "topic" in df else {},
        "source_type_counts": df.source_type.value_counts().to_dict() if "source_type" in df else {},
        "split_method": "Three-way GroupShuffleSplit by prompt-template family; threshold tuned on validation only",
        "split_rows": {"train": int(len(train_idx)), "validation": int(len(val_idx)), "test": int(len(test_idx))},
        "split_family_counts": {"train": len(family_sets['train']), "validation": len(family_sets['validation']), "test": len(family_sets['test'])},
        "family_overlap": False, "random_state": SEED, "threshold": float(threshold),
        "validation_threshold_selection": {"criteria": "recall >= 0.97 and benign FPR <= 0.05 where possible", "selected_validation_metrics": chosen, "sweep": val_rows},
        "grouped_test": test_metrics,
        "limitations": [
            "The 54,000-row training corpus is synthetic/template-generated; grouped splitting reduces exact template leakage but cannot remove generator/semantic bias.",
            "The grouped test set is drawn from the same synthetic corpus and is not a real-world external benchmark.",
            "A separate curated challenge set is included for stress testing but is also not a substitute for independently collected, human-reviewed production data.",
            "Binary attack labels combine prompt injection/jailbreak with malicious cyber and other harmful requests; those are related but distinct detection tasks.",
            "TF-IDF is lexical and may miss paraphrases, multilingual content, long-context dilution, tool-use chains, or novel encoded attacks.",
            "Probability scores are not calibrated probabilities of real-world risk.",
            "Rule engine and behavioral/session layers require separate integration and threat-model validation.",
        ],
    }
    METRICS_PATH.write_text(json.dumps(metrics, indent=2), encoding="utf-8")
    print(json.dumps({"model_path": str(MODEL_PATH), "metrics_path": str(METRICS_PATH), "rows": len(df), "threshold": threshold, "splits": metrics["split_rows"], "grouped_test": {k:v for k,v in test_metrics.items() if k != 'classification_report'}}, indent=2))

if __name__ == "__main__": main()
