# SentinelLLM v4.1.0 — Prompt Security Research Prototype

SentinelLLM is a React/Vite frontend and FastAPI backend that combines text normalization, encoding/Unicode checks, a TF-IDF word/character classifier, deterministic security rules, and multi-turn risk signals to produce `ALLOW`, `FLAG_FOR_REVIEW`, or `BLOCK` decisions.

**Research prototype only.** Do not treat its score as a production guarantee or use it as the only security control. The 54,000-row training corpus is synthetic/template-generated. The included 120-row challenge set is separately authored and not used for fitting or threshold selection, but it is not a real-world external benchmark.

## What's new in v4.1
- Focused 2,000-prompt help-word balancing set, including benign everyday/defensive requests and explicit harmful requests. The word `help` alone is not a blocking signal.


- 52,000 unique prompts: 26,000 benign and 26,000 attack-labelled.
- Added 20,000 diverse rows with emphasis on everyday safe/unsafe prompts, non-technical harmful intent, the eight user-supplied hard-negative categories, and contrastive examples; added 400 short queries.
- Three-way split by prompt-template family: train, validation, and untouched grouped test. Threshold selection uses validation only.
- Separate internal challenge set and evaluation script; false positives and false negatives are written to CSV/JSON for review.
- Added an evaluator for independently downloaded public CSV benchmarks; it refuses to evaluate a full dataset unless a held-out split is selected.
- Expanded deterministic rules for prompt injection, unauthorized access, spyware, weapon concealment, toxin/poison instructions, property sabotage, and log tampering.
- Added explicit non-actionable analysis/translation handling for quoted prompt-injection text.
- Restricted credentialed CORS to local frontend origins by default; configurable with `CORS_ORIGINS`.
- Pinned scikit-learn to match the active serialized model.

## Project structure

```text
backend/
  main.py                         FastAPI app
  detection/classifier.py         Active model inference
  detection/rules.py              Deterministic security rules
  detection/risk_engine.py        ALLOW/REVIEW/BLOCK policy
  preprocessing/                  Normalization and encoding checks
  behavior/                       Multi-turn/session analysis
  training_data/sentinelllm_seed_dataset.csv  54k training corpus
  training_data/independent_challenge_set.csv  120 held-out challenge prompts
  ml_models/sentinelllm_tfidf_logreg.joblib   Trained active model
  ml_models/training_metrics.json             Train/validation/test metrics
  ml_models/challenge_set_results.json        Challenge evaluation report
  ml_models/challenge_set_predictions.csv     Per-example challenge predictions
  train_classifier.py             Reproducible training
  create_challenge_set.py          Recreate the challenge set
  evaluate_challenge_set.py        Evaluate classifier + policy layer
  evaluate_external_dataset.py     Evaluate a separate public dataset CSV
  tests/                           Backend regression tests
frontend/
  src/                              React UI
  package.json                      Vite scripts
```

## Run the project on Windows

### 1. Start the backend

Open PowerShell in the extracted project folder:

```powershell
cd backend
py -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install --upgrade pip
pip install -r requirements.txt
uvicorn main:app --reload --host 127.0.0.1 --port 8000
```

API health: `http://127.0.0.1:8000/health`  
API docs: `http://127.0.0.1:8000/docs`

### 2. Start the frontend

Open a second PowerShell terminal in the project folder:

```powershell
cd frontend
npm install
npm run dev
```

Open the Vite URL shown in the terminal, normally `http://localhost:5173`.

If the API is hosted elsewhere, set `VITE_API_BASE_URL` before running/building the frontend, for example:

```powershell
$env:VITE_API_BASE_URL="http://127.0.0.1:8000"
npm run dev
```

### 3. Run backend tests

```powershell
cd backend
python -m pytest -q
```

### 4. Retrain the model

From `backend`:

```powershell
python train_classifier.py
```

Training writes the active model and grouped evaluation metrics under `backend/ml_models/`. Training uses only the training partition for fitting, validation for threshold selection, and a grouped test split for final development metrics.

### 5. Evaluate the internal challenge set

```powershell
python evaluate_challenge_set.py
```

This creates `ml_models/challenge_set_results.json` and `ml_models/challenge_set_predictions.csv`. Review the false-positive and false-negative rows; do not interpret this small internal set as production performance.

### 6. Evaluate an external held-out benchmark

A public synthetic dataset with an unseen-attack-type split is available at:

- https://github.com/mirzaakhi/prompt-injection-detection-dataset

After downloading its CSV, run from `backend`:

```powershell
python evaluate_external_dataset.py path\to\prompt_injection_dataset.csv --text-column prompt --label-column label --split-column split --test-value test
```

The evaluator only scores rows marked as the test split and never changes the model or threshold. Check the dataset license and label definitions before use. Prompt-injection-only labels are not identical to SentinelLLM's broader combined attack label, so results require careful interpretation. For stronger external evaluation, use multiple independently sourced benchmarks, including benign hard negatives and indirect-injection examples; public datasets can themselves be synthetic or known to model developers.

## Latest evaluation (v4.1.0)

The exact metrics and dataset SHA-256 are recorded in `backend/ml_models/training_metrics.json`; the full audit is in `SENTINELLLM_52000_TRAINING_REPORT.md`.

- Dataset: 52,000 unique rows, balanced 26,000 / 26,000.
- Grouped test: 10,585 rows, separated by prompt-template family.
- Grouped test accuracy: 97.97%.
- Attack precision: 95.67%; attack recall: 100.00%.
- Benign false-positive rate: 3.82%; attack false-negative rate: 0.00% on this grouped synthetic test split.
- Backend tests: 62 passed, 47 subtests passed.
- The challenge set is a development/regression set; do not interpret results on it as independent validation because policy rules were tuned against known errors.

**Important:** grouped test metrics are calculated on a synthetic corpus and may be optimistic. No independent public benchmark was downloaded or evaluated in this build.

## Known limitations that remain

1. **Synthetic training distribution:** synthetic prompts are not equivalent to independently collected scenarios. Grouped splitting reduces template leakage but cannot eliminate generator/topic bias.
2. **External benchmark not bundled as verified ground truth:** this package includes a script to score an external held-out CSV, but the external dataset must be downloaded, license-checked, and label-mapped separately. The small internal challenge set does not solve the real-world generalization problem.
3. **Mixed task labels:** the binary `attack` class combines prompt injection/jailbreak with malicious cyber and other harmful requests. A future version should separate these into multi-label outputs.
4. **Lexical model:** TF-IDF can miss novel paraphrases, multilingual/encoded content, long-context signal dilution, and multi-turn/tool-mediated attacks.
5. **Rule coverage:** deterministic patterns are incomplete and can over-match or miss novel phrasing. Keep a reviewed regression corpus.
6. **Probability calibration:** the score is a model score, not a calibrated probability of real-world risk.
7. **Session state:** behavioral analysis is process-local; multi-worker deployment needs shared session storage and explicit privacy/retention controls.
8. **Deployment hardening:** configure CORS, rate limiting, authentication, request logging policy, model artifact integrity, and monitoring before exposing the service publicly.

## Public evaluation references

- Mirza Akhi, *Prompt Injection Detection Dataset* (synthetic; CC BY 4.0; unseen attack-type split): https://github.com/mirzaakhi/prompt-injection-detection-dataset
- Lakera PINT benchmark (multilingual attacks, hard negatives, chats and public-document inputs; check current access/license terms): https://github.com/lakeraai/pint-benchmark
- BIPIA indirect prompt injection benchmark repository: https://github.com/microsoft/BIPIA
