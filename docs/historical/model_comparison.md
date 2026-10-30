> **Historical phase document.** Its model metrics and policy details may predate SentinelLLM v2.0.0. Use the root README and SENTINELLLM_20000_TRAINING_REPORT.md for current implementation and evaluation.

# SentinelLLM — Model Comparison Report (Phase 3)

## 1. Executive Summary & Selection Decision

In Phase 3, we conducted a rigorous, reproducible, apples-to-apples comparison of three candidate architectures on the official SentinelLLM dataset:
1. **Baseline**: Word TF-IDF + Balanced Logistic Regression
2. **Candidate 1**: Word TF-IDF + Random Forest Classifier
3. **Candidate 2**: Word TF-IDF + XGBoost Classifier

### Winning Model Selection
**Selected Model:** `TF-IDF + Logistic Regression (Baseline)`  
**Selected Threshold:** `0.50` (selected strictly on validation data to maximize Attack F1 score)

**Selection Rationale:**
- **Superior Attack F1 Score:** Baseline achieved **0.9619** on validation data, exceeding Random Forest (0.9556) and XGBoost (0.9553).
- **Substantially Lower False Positive Rate (FPR):** In a security firewall gateway, false alarms interrupt legitimate user prompts. The baseline produced an FPR of only **5.90%** (24 false alarms out of 407 benign validation prompts), whereas Random Forest produced **10.32%** (42 false alarms) and XGBoost produced **9.34%** (38 false alarms).
- **Superior Generalization (ROC-AUC):** Baseline achieved an ROC-AUC of **0.9918** compared to 0.9833 (RF) and 0.9855 (XGBoost).
- **Operational Efficiency:** Baseline inference latency is **0.092 ms/prompt** (5.5x faster than Random Forest's 0.508 ms) and artifact size is **0.55 MB** (10x smaller than Random Forest's 5.49 MB).
- **Ensemble Decision:** An ensemble is **not justified**. Combining Logistic Regression with Random Forest or XGBoost would increase false alarms, degrade precision, multiply latency, and increase artifact size without improving F1 or ROC-AUC.

---

## 2. Dataset & Split Specifications

All models were evaluated using the strict split separation protocol:
- **`train.parquet` (7,572 rows):** Exclusively used to fit vectorizers and train candidate classifiers.
  - Benign (`0`): 1,741 rows (23.0%)
  - Attack (`1`): 5,831 rows (77.0%) — includes 3,181 archive attack prompts.
- **`validation.parquet` (941 rows):** Exclusively used for hyperparameter evaluation, threshold selection, and model selection.
  - Benign (`0`): 407 rows (43.3%)
  - Attack (`1`): 534 rows (56.7%)
- **`test.parquet` (942 rows):** Held out untouched during model tuning and evaluated only once on the selected winning candidate.
  - Benign (`0`): 390 rows (41.4%)
  - Attack (`1`): 552 rows (58.6%)

---

## 3. Architecture & Hyperparameter Specifications

| Model | Feature Representation | Hyperparameters | Training Time | Latency (ms/prompt) | Artifact Size |
|---|---|---|---|---|---|
| **TF-IDF + Logistic Regression** | Word TF-IDF (1,2-grams, max 200k features, sublinear TF, unicode accents stripped) | `max_iter=2000`, `class_weight='balanced'`, `solver='liblinear'`, `random_state=42` | Pre-trained baseline | 0.092 ms | 0.55 MB |
| **Random Forest** | Word TF-IDF (1,2-grams, min_df=3, max 25k features, sublinear TF) | `n_estimators=150`, `max_depth=45`, `class_weight='balanced'`, `random_state=42`, `n_jobs=-1` | 0.91 sec | 0.508 ms | 5.49 MB |
| **XGBoost** | Word TF-IDF (1,2-grams, min_df=3, max 25k features, sublinear TF) | `n_estimators=200`, `max_depth=6`, `learning_rate=0.15`, `scale_pos_weight=0.2986`, `subsample=0.8`, `colsample_bytree=0.8`, `eval_metric='logloss'`, `random_state=42` | 5.48 sec | 0.138 ms | 0.57 MB |

---

## 4. Validation Comparison Metrics (Strict Evaluation on `validation.parquet`)

All metrics were computed using the threshold selected strictly from validation data:

| Metric | TF-IDF + Logistic Regression (Selected) | Random Forest | XGBoost |
|---|---|---|---|
| **Selected Threshold** | **0.50** | 0.35 | 0.15 |
| **Validation Accuracy** | **95.64%** | 94.79% | 94.79% |
| **Attack Precision** | **95.56%** | 92.62% | 93.23% |
| **Attack Recall** | 96.82% | **98.69%** | 97.94% |
| **Attack F1-Score** | **0.9619** | 0.9556 | 0.9553 |
| **Benign Precision** | **95.75%** | 98.11% | 97.10% |
| **Benign Recall** | **94.10%** | 89.68% | 90.66% |
| **Benign F1-Score** | **0.9492** | 0.9370 | 0.9377 |
| **Macro F1-Score** | **0.9555** | 0.9463 | 0.9465 |
| **False Positive Rate (FPR)** | **5.90%** (24 / 407) | 10.32% (42 / 407) | 9.34% (38 / 407) |
| **False Negative Rate (FNR)** | 3.18% (17 / 534) | **1.31%** (7 / 534) | 2.06% (11 / 534) |
| **ROC-AUC** | **0.9918** | 0.9833 | 0.9855 |
| **Confusion Matrix `[[TN, FP], [FN, TP]]`** | `[[383, 24], [17, 517]]` | `[[365, 42], [7, 527]]` | `[[369, 38], [11, 523]]` |

---

## 5. Final Holdout Test Evaluation (`test.parquet`)

Following the strict protocol, the selected winning model (`TF-IDF + Logistic Regression` at threshold `0.50`) was evaluated on the held-out `test.parquet` (942 rows):

### Test Set Metrics
- **Accuracy:** `94.80%`
- **Attack Precision:** `94.67%`
- **Attack Recall:** `96.56%`
- **Attack F1-Score:** `0.9561`
- **Benign Precision:** `94.99%`
- **Benign Recall:** `92.31%`
- **Benign F1-Score:** `0.9363`
- **Macro F1-Score:** `0.9462`
- **False Positive Rate (FPR):** `7.69%` (30 false alarms out of 390 benign test prompts)
- **False Negative Rate (FNR):** `3.44%` (19 missed attacks out of 552 attack test prompts)
- **ROC-AUC:** `0.9906`
- **Confusion Matrix:**
  - True Benign (TN): `360`
  - False Alarms (FP): `30`
  - Missed Attacks (FN): `19`
  - Correct Attacks (TP): `533`

---

## 6. Limitations & Security Caveats

1. **Class Imbalance & Model Intercept:**  
   The training split is heavily attack-oriented (77% attack vs 23% benign) due to archive dataset additions, while the validation and test splits reflect the official benchmark distribution (~57% attack). Consequently, the linear model carries a positive intercept (+0.865). Prompts with sparse vocabulary matches hover near 0.50–0.54. Therefore, model outputs must be interpreted as **decision scores**, not calibrated Bayesian probabilities.
2. **False Alarm Trade-off:**  
   Tree-based ensembles (Random Forest and XGBoost) achieved higher raw recall on validation by lowering their effective threshold, but did so at the cost of nearly double the false alarm rate on benign inputs (FPR > 9-10%). For LLM applications, excessive false positives alienate legitimate users.
3. **Lexical vs. Semantic Limitations:**  
   TF-IDF models rely on token and n-gram occurrences. While highly effective at detecting recurring jailbreak templates, token smuggling, and instruction override phrases, they are vulnerable to novel zero-day prompt engineering attacks that avoid common attack n-grams. Hence, a multi-layer defense (incorporating preprocessing, behavioral tracking, and risk policy rules) is required.
