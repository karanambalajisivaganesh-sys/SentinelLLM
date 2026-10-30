"""
SentinelLLM - Prompt Injection & Jailbreak ML Classifier

Loads and caches fitted scikit-learn or XGBoost pipelines
and provides thread-safe inference without refitting or blocking the application.
Paths are resolved independently of the current working directory.
"""

from pathlib import Path
from typing import Dict, Any, Optional
import threading
import joblib

from config import MODEL_CONFIG, DEFAULT_THRESHOLD, SUPPORTED_MODELS, ML_MODELS_DIR


class PromptClassifier:
    """
    Singleton / thread-safe classifier wrapper for SentinelLLM models.
    Supports switching between baseline_logreg, random_forest, and xgboost.
    """
    _instance: Optional["PromptClassifier"] = None
    _lock = threading.Lock()

    def __init__(
        self,
        model_path: Optional[Path] = None,
        threshold: Optional[float] = None,
        model_name: Optional[str] = None,
        model_version: Optional[str] = None,
    ):
        self.model_path = Path(model_path or MODEL_CONFIG["path"])
        self.threshold = float(threshold if threshold is not None else MODEL_CONFIG["threshold"])
        self.model_name = model_name or MODEL_CONFIG["name"]
        self.model_version = model_version or MODEL_CONFIG["version"]
        self.model = None
        self.is_loaded = False
        self.load_error: Optional[str] = None
        self._load_model()

    @classmethod
    def get_instance(cls) -> "PromptClassifier":
        """Thread-safe singleton accessor."""
        if cls._instance is None:
            with cls._lock:
                if cls._instance is None:
                    cls._instance = cls()
        return cls._instance

    @classmethod
    def reload_with_model(cls, model_key: str) -> "PromptClassifier":
        """Helper to switch active model in memory."""
        if model_key not in SUPPORTED_MODELS:
            raise ValueError(f"Unsupported model_key: {model_key}. Available: {list(SUPPORTED_MODELS.keys())}")
        info = SUPPORTED_MODELS[model_key]
        path = ML_MODELS_DIR / info["filename"]
        with cls._lock:
            cls._instance = cls(
                model_path=path,
                threshold=info["default_threshold"],
                model_name=info["name"],
                model_version=info["version"],
            )
        return cls._instance

    def _load_model(self):
        """Loads the saved joblib pipeline artifact."""
        if not self.model_path.exists():
            self.load_error = f"Model artifact not found at {self.model_path.resolve()}"
            self.is_loaded = False
            return

        try:
            self.model = joblib.load(self.model_path)
            # Cross-version compatibility for LogisticRegression when unpickled across scikit-learn versions
            if hasattr(self.model, "named_steps"):
                clf_step = self.model.named_steps.get("classifier") or self.model.named_steps.get("clf")
                if clf_step and not hasattr(clf_step, "multi_class"):
                    clf_step.multi_class = "auto"
            elif not hasattr(self.model, "multi_class") and hasattr(self.model, "predict_proba"):
                try:
                    self.model.multi_class = "auto"
                except Exception:
                    pass

            self.is_loaded = True
            self.load_error = None
        except Exception as exc:
            self.load_error = f"Failed to load model artifact: {exc}"
            self.is_loaded = False
            self.model = None

    def predict(self, text: str) -> Dict[str, Any]:
        """
        Runs inference on the provided text.

        Args:
            text: Text string to classify.

        Returns:
            Dict containing predicted class, attack score, threshold, and status.
        """
        if not self.is_loaded:
            return {
                "success": False,
                "error": self.load_error or "Model is not loaded",
                "model_name": self.model_name,
                "model_version": self.model_version,
                "predicted_label": None,
                "predicted_class": "unknown",
                "attack_score": None,
                "threshold_used": self.threshold,
                "is_attack": False,
                "text_evaluated": text,
            }

        input_str = str(text or "").strip()
        if not input_str:
            return {
                "success": False,
                "error": "Empty input text for classification",
                "model_name": self.model_name,
                "model_version": self.model_version,
                "predicted_label": None,
                "predicted_class": "unknown",
                "attack_score": None,
                "threshold_used": self.threshold,
                "is_attack": False,
                "text_evaluated": "",
            }

        try:
            # predict_proba returns [prob_benign (0), prob_attack (1)]
            probs = self.model.predict_proba([input_str])[0]
            attack_prob = float(probs[1])
            is_attack = attack_prob >= self.threshold
            predicted_label = 1 if is_attack else 0
            predicted_class = "attack" if is_attack else "benign"

            return {
                "success": True,
                "error": None,
                "model_name": self.model_name,
                "model_version": self.model_version,
                "predicted_label": predicted_label,
                "predicted_class": predicted_class,
                "attack_score": round(attack_prob, 4),
                "threshold_used": self.threshold,
                "is_attack": is_attack,
                "text_evaluated": input_str,
            }
        except Exception as exc:
            return {
                "success": False,
                "error": f"Inference error: {exc}",
                "model_name": self.model_name,
                "model_version": self.model_version,
                "predicted_label": None,
                "predicted_class": "unknown",
                "attack_score": None,
                "threshold_used": self.threshold,
                "is_attack": False,
                "text_evaluated": input_str,
            }


def classify_prompt(text: str) -> Dict[str, Any]:
    """Convenience helper using singleton classifier."""
    return PromptClassifier.get_instance().predict(text)
