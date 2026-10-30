# SentinelLLM Backend (v4.1.0)

This FastAPI backend runs normalization and encoding/Unicode analysis, the trained classifier, deterministic rules, behavioral session analysis, and the final `ALLOW` / `FLAG_FOR_REVIEW` / `BLOCK` policy. See the root `README.md` for full setup, training, evaluation, limitations, and project structure.

## Setup

```bash
cd backend
python -m venv .venv
# Windows PowerShell: .\.venv\Scripts\Activate.ps1
# macOS/Linux: source .venv/bin/activate
python -m pip install --upgrade pip
pip install -r requirements.txt
uvicorn main:app --reload --host 127.0.0.1 --port 8000
```

- Health: `GET http://127.0.0.1:8000/health`
- Analyze: `POST http://127.0.0.1:8000/analyze` with JSON `{"prompt":"Explain binary search."}`
- API docs: `http://127.0.0.1:8000/docs`

The active model artifact is `ml_models/sentinelllm_tfidf_logreg.joblib`. It was trained with scikit-learn 1.8.0; `requirements.txt` pins that version for artifact compatibility.

## Train and evaluate

```bash
python train_classifier.py
python evaluate_challenge_set.py
python -m pytest -q
```

`training_data/sentinelllm_seed_dataset.csv` is the 54,000-row training corpus. `training_data/independent_challenge_set.csv` is not used for model fitting or threshold selection, but policy rules were reviewed and tuned against its false positives/negatives; therefore the final policy-layer score on that set is a development/regression result, not independent validation.

To evaluate a separately downloaded CSV with a dedicated test split, see `evaluate_external_dataset.py` and the root README. No public benchmark is bundled or claimed as tested.

## Important limitations

The training corpus is synthetic and template-generated. The TF-IDF model may miss novel paraphrases, multilingual/encoded attacks, long-context dilution, and multi-turn/tool-mediated attacks. Binary attack labels combine prompt injection/jailbreak with malicious cyber and other harmful requests. Session state is process-local. Do not expose this research prototype publicly without additional authentication, rate limiting, shared session storage, monitoring, and security review.
