> **Historical phase document.** Its model metrics and policy details may predate SentinelLLM v2.0.0. Use the root README and SENTINELLLM_20000_TRAINING_REPORT.md for current implementation and evaluation.

# SentinelLLM — Risk Engine & Decision Policy Documentation (Phase 5)

## 1. Overview & Architecture

The **Risk Engine** (`backend/detection/risk_engine.py`) serves as the central policy synthesis layer in SentinelLLM. Rather than relying on any single detection layer, it consolidates four independent security modules:
1. **Machine Learning Classifier:** Semantic attack probability (TF-IDF + Logistic Regression / Random Forest / XGBoost).
2. **Preprocessing & Obfuscation Signals:** Base64, Hexadecimal, URL encoding, and covert zero-width Unicode injection.
3. **Deterministic Security Rules:** Explicit regex heuristics for instruction overrides, system prompt leaking, and jailbreak role-hijacking.
4. **Behavioral Analysis:** Multi-turn session velocity, prompt mutation/similarity, and risk escalation.

```text
Prompt Input
     │
     ├─► Preprocessing Engine ────► (Encodings, Zero-Width, Anomalies)
     │                                            │
     ├─► ML Classifier (on clean text) ───────────┼─► Risk Engine ──► Policy Decision:
     │                                            │   (Composite       - ALLOW
     ├─► Explicit Security Rules ─────────────────┤    Score 0-100)    - FLAG_FOR_REVIEW
     │                                            │                    - BLOCK
     └─► Behavioral Session Tracker ──────────────┘
```

---

## 2. Risk Scoring Formula & Policy Thresholds

The composite policy risk score (`risk_score`) ranges from **0.0 to 100.0**. It represents a policy-driven threat index rather than a raw statistical probability.

### Signal Contributions
| Component | Maximum Contribution | Description |
|---|---|---|
| **ML Attack Probability** | Up to **45.0 points** | Scaled as `attack_score * 45.0`. |
| **Deterministic Rule Match** | **30.0 points** | Triggered by explicit prompt injection or system prompt leaking patterns. |
| **Multi-Turn Behavioral Risk** | Up to **30.0 points** | Scaled from session history (`min(session_risk_score * 0.30, 30.0)`). |
| **Zero-Width Hidden Characters** | **15.0 points** | Covert invisible character smuggling (`U+200B`, `U+200C`, etc.). |
| **Encoding / Obfuscation** | **10.0 points** | Base64, Hexadecimal, or URL encoding detected. |
| **Clean Session Safeguard** | Clamps score $\le 15.0$ | When ML is confidently benign ($< 0.35$), with zero rules, zero obfuscation, and clean session. |

### Configurable Thresholds (`backend/config.py`)
- `RISK_THRESHOLD_BLOCK = 70.0`
- `RISK_THRESHOLD_REVIEW = 35.0`
- `ML_HIGH_ATTACK_THRESHOLD = 0.85`
- `ML_MODERATE_ATTACK_THRESHOLD = 0.50`

---

## 3. Deterministic Decision Rules

### Outcome 1: `BLOCK`
The prompt is rejected and prevented from reaching downstream language models if:
1. `risk_score >= 70.0` (critical multi-signal threat accumulation); OR
2. `attack_score >= 0.85` (high-confidence semantic attack instruction); OR
3. `(zero_width_detected or obfuscation_detected)` AND `(attack_score >= 0.70 or rules_triggered)` (stealth attack payload hidden in encoding or invisible characters); OR
4. `rules_triggered` AND `is_attack` (explicit injection syntax confirmed by ML); OR
5. `repeated_attack` AND `(attack_score >= 0.65 or rules_triggered)` (persistent hostile session activity).

### Outcome 2: `FLAG_FOR_REVIEW`
The prompt is quarantined or routed to human review / secondary validation if:
1. `35.0 <= risk_score < 70.0`; OR
2. `0.50 <= attack_score < 0.85` without secondary corroborating block signals; OR
3. `obfuscation_detected` or `zero_width_detected` on a benign/borderline payload (preventing false-positive blocking of benign encoded data); OR
4. Conflicting signals exist (e.g. security rule matched in a quotation, but ML score is low); OR
5. Multi-turn session behavioral risk score is elevated ($\ge 30.0$); OR
6. ML classifier fails or is unavailable (Fail-Safe Review Policy).

### Outcome 3: `ALLOW`
The prompt is accepted and permitted to proceed if:
1. `risk_score < 35.0`; AND
2. `attack_score < 0.50`; AND
3. No explicit security rules triggered.

---

## 4. Failure Handling & Fail-Safe Policy

If model inference fails, the joblib artifact is missing, or an unexpected exception occurs:
- **Decision:** `FLAG_FOR_REVIEW`
- **Risk Level:** `medium`
- **Risk Score:** `50.0`
- **Reason Code:** `ML_INFERENCE_UNAVAILABLE`
- **Safety Invariant:** Model failures **never** silently default to `ALLOW`.

---

## 5. Machine-Readable Explanation Codes

| Code | Description |
|---|---|
| `BENIGN_PROMPT` | Evaluated as benign with low risk across all signals. |
| `ML_HIGH_ATTACK_SCORE` | Attack probability $\ge 0.85$ from ML model. |
| `ML_ATTACK_CLASSIFICATION` | Semantic attack instruction identified by ML model ($\ge 0.50$). |
| `EXPLICIT_SECURITY_RULE_MATCH` | Matches deterministic prompt-injection regex rules. |
| `ZERO_WIDTH_DETECTED` | Invisible zero-width codepoints detected in input. |
| `OBFUSCATION_DETECTED` | Payload utilized encoding or representation obfuscation. |
| `REPEATED_ATTACK_ATTEMPTS` | Multiple attack events detected across session history. |
| `ATTACK_ESCALATION_DETECTED` | Sudden escalation in prompt threat intensity. |
| `HIGH_BEHAVIORAL_RISK` | Multi-turn behavioral risk score $\ge 40.0$. |
| `MODERATE_RISK_REVIEW` | Borderline threat score requiring secondary review. |
| `ML_INFERENCE_UNAVAILABLE` | Classifier error; fail-safe quarantine active. |

---

## 6. Trade-Offs & Security Considerations

1. **Defense-in-Depth vs. False Positives:**  
   Single weak signals (such as valid international Unicode or a Base64 string encoding benign text) do not trigger blocking on their own. They trigger review or pass safely based on the decoded payload content.
2. **Mitigating Linear Intercept Bias:**  
   Because the baseline model was trained with `class_weight='balanced'` on an attack-heavy split, very short neutral inputs can register around $0.52$. The risk policy prevents these borderline scores from causing automatic blocks unless accompanied by explicit attack rule triggers or high-confidence attack scores.
