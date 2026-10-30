"""
SentinelLLM - Application Configuration

Centralizes configuration settings and path resolution for models,
thresholds, behavioral session management, and security policies.
All paths are resolved relative to the backend directory.
"""

from pathlib import Path
import os
import json

# Base paths
BACKEND_DIR = Path(__file__).resolve().parent
ML_MODELS_DIR = BACKEND_DIR / "ml_models"

# Supported model artifacts and defaults
SUPPORTED_MODELS = {
    "baseline_logreg": {
        "name": "TF-IDF + LogisticRegression",
        "version": "4.2.0-54k-media-context",
        "filename": "sentinelllm_tfidf_logreg.joblib",
        "default_threshold": 0.50,
        "description": "Trained word+character TF-IDF n-grams with balanced Logistic Regression; see training_metrics.json.",
    },
    "random_forest": {
        "name": "Random Forest",
        "version": "1.0.0-candidate",
        "filename": "sentinelllm_random_forest.joblib",
        "default_threshold": 0.35,
        "description": "Random Forest (150 estimators, max depth 45, balanced weights).",
    },
    "xgboost": {
        "name": "XGBoost",
        "version": "1.0.0-candidate",
        "filename": "sentinelllm_xgboost.joblib",
        "default_threshold": 0.15,
        "description": "XGBoost (200 estimators, max depth 6, lr 0.15, scaled pos weights).",
    },
}

# Determine active model type from environment variable or default
ACTIVE_MODEL_KEY = os.environ.get("MODEL_TYPE", "baseline_logreg").lower().strip()
if ACTIVE_MODEL_KEY not in SUPPORTED_MODELS:
    ACTIVE_MODEL_KEY = "baseline_logreg"

_active_def = SUPPORTED_MODELS[ACTIVE_MODEL_KEY]
ACTIVE_MODEL_FILENAME = _active_def["filename"]
ACTIVE_MODEL_PATH = ML_MODELS_DIR / ACTIVE_MODEL_FILENAME

# Load tuned threshold from candidate_experiment_report.json or metrics.json if available
DEFAULT_THRESHOLD = _active_def["default_threshold"]
EXP_REPORT_PATH = ML_MODELS_DIR / "candidate_experiment_report.json"

# Use threshold from the reproducible training run when available.
TRAIN_METRICS_PATH = ML_MODELS_DIR / "training_metrics.json"
if TRAIN_METRICS_PATH.exists() and ACTIVE_MODEL_KEY == "baseline_logreg":
    try:
        train_metrics = json.loads(TRAIN_METRICS_PATH.read_text(encoding="utf-8"))
        DEFAULT_THRESHOLD = float(train_metrics.get("threshold", DEFAULT_THRESHOLD))
    except Exception:
        pass
elif EXP_REPORT_PATH.exists():
    try:
        exp_data = json.loads(EXP_REPORT_PATH.read_text(encoding="utf-8"))
        for rec in exp_data.get("validation_comparison", []):
            if _active_def["name"] in rec.get("model_name", ""):
                DEFAULT_THRESHOLD = float(rec.get("threshold", DEFAULT_THRESHOLD))
                break
    except Exception:
        pass

# Active Model configuration dictionary
MODEL_CONFIG = {
    "key": ACTIVE_MODEL_KEY,
    "name": _active_def["name"],
    "version": _active_def["version"],
    "filename": ACTIVE_MODEL_FILENAME,
    "path": ACTIVE_MODEL_PATH,
    "threshold": DEFAULT_THRESHOLD,
    "description": _active_def["description"],
}

# -------------------------------------------------------------
# Behavioral Analysis & Session Configuration
# -------------------------------------------------------------
MAX_SESSION_HISTORY = int(os.environ.get("MAX_SESSION_HISTORY", 20))
SESSION_TTL_SECONDS = int(os.environ.get("SESSION_TTL_SECONDS", 1800))  # 30 minutes
BEHAVIORAL_WINDOW_SECONDS = int(os.environ.get("BEHAVIORAL_WINDOW_SECONDS", 300))  # 5 minutes
SIMILARITY_THRESHOLD = float(os.environ.get("SIMILARITY_THRESHOLD", 0.65))
ESCALATION_SCORE_DELTA = float(os.environ.get("ESCALATION_SCORE_DELTA", 0.20))

# -------------------------------------------------------------
# Risk Engine & Policy Configuration
# -------------------------------------------------------------
POLICY_VERSION = "4.2.0"
RISK_THRESHOLD_REVIEW = float(os.environ.get("RISK_THRESHOLD_REVIEW", 35.0))
RISK_THRESHOLD_BLOCK = float(os.environ.get("RISK_THRESHOLD_BLOCK", 70.0))
ML_HIGH_ATTACK_THRESHOLD = float(os.environ.get("ML_HIGH_ATTACK_THRESHOLD", 0.85))
ML_MODERATE_ATTACK_THRESHOLD = float(os.environ.get("ML_MODERATE_ATTACK_THRESHOLD", 0.50))
