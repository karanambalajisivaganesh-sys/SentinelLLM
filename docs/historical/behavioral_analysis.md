> **Historical phase document.** Its model metrics and policy details may predate SentinelLLM v2.0.0. Use the root README and SENTINELLLM_20000_TRAINING_REPORT.md for current implementation and evaluation.

# SentinelLLM — Behavioral Analysis Architecture & Documentation (Phase 4)

## 1. Overview & Purpose

The **Behavioral Analysis Module** (`backend/behavior/analyzer.py`) provides multi-turn contextual tracking for LLM interactions. While single-prompt classifiers evaluate inputs in isolation, sophisticated prompt-injection and jailbreak attacks often unfold over multiple conversational turns (e.g., initial policy reconnaissance, minor semantic mutations to bypass filters, or repeated retry loops).

The behavioral analyzer tracks:
- **Session History:** Evaluates patterns across sequential prompts in a session.
- **Attack Frequency & Velocity:** Quantifies how many attacks occurred within a rolling time window.
- **Prompt Mutation / Evasion:** Calculates token Jaccard similarity against prior attacks to identify near-duplicate rephrasing attempts.
- **Attack Escalation:** Detects sudden jumps from probing queries to high-confidence attack instructions.
- **Repeated Obfuscation:** Flags recurring encoding attempts (Base64, Hex, URL, zero-width spaces).

---

## 2. Request Flow & Architectural Design

```text
Incoming POST /analyze (prompt, optional session_id)
        ↓
Input Validation & Preprocessing (normalization, encoding decoding, zero-width detection)
        ↓
ML Classifier Inference (evaluates normalized or decoded text representation)
        ↓
Behavioral Analyzer:
  1. Retrieve isolated session history using session_id (generate if missing)
  2. Compute similarity against prior attack events in session
  3. Detect escalation, repetition, and velocity within rolling time window
  4. Compute session_risk_score (0.0 to 100.0) and explanation codes
  5. Record lightweight event metadata into session history
        ↓
Structured API Response (AnalyzeResponse with preprocessing, ml_result, and behavioral_analysis)
```

---

## 3. Session Management & Privacy Protections

### Session Isolation
- Every session is keyed strictly by a unique `session_id`.
- Two distinct session IDs never share history or state.
- If a client does not provide a `session_id`, a secure pseudorandom identifier (`sess_<uuid4().hex[:16]>`) is automatically assigned.

### Bounded In-Memory Storage & Expiration
- **Bounded History:** Configured by `MAX_SESSION_HISTORY = 20`. History is stored in a fixed-size `collections.deque(maxlen=20)` preventing memory exhaustion.
- **Session Expiration (TTL):** Configured by `SESSION_TTL_SECONDS = 1800` (30 minutes). Inactive sessions are pruned automatically upon expiration.
- **Thread Safety:** State mutations and reads are protected by `threading.RLock()`.
- **Replaceable Storage Interface:** Built with an abstract `SessionStore` base class (`InMemorySessionStore` implementation), making future migration to MongoDB or Redis straightforward.
- **Privacy Protections:** The session store **does not retain raw prompt text**. Only a 16-character SHA-256 fingerprint, token sets (word n-grams and character 3-grams), attack scores, and detection flags are stored.

---

## 4. Behavioral Signals & Scoring Formula

The behavioral risk score (`session_risk_score`) is a bounded index ranging from **0.0 to 100.0**, reflecting behavioral threat intensity. It is explicitly separated from the ML model's attack probability.

### Scoring Contributions
1. **Current Attack Flag:**
   - If the current prompt is classified as an attack by the ML model: `+20.0` (`CURRENT_ATTACK_DETECTED`).
2. **Repeated Attack Attempt:**
   - If the current prompt is an attack and prior attacks exist in the session: `+25.0` (`REPEATED_ATTACK_ATTEMPT`).
3. **Near-Duplicate Attack Mutation:**
   - If the current attack has a token Jaccard similarity $\ge 0.65$ against a previous attack in the session: `+20.0` (`NEAR_DUPLICATE_ATTACK_MUTATION`).
4. **Attack Escalation:**
   - If the previous prompt in the session was benign/probing and the current prompt jumped by $\ge 0.20$ into attack territory: `+20.0` (`ESCALATION_DETECTED`).
5. **Attack Velocity (5-Minute Window):**
   - If $\ge 2$ attacks occurred within the last 300 seconds: `+10.0` per recent attack, capped at `+25.0` (`HIGH_ATTACK_VELOCITY`).
6. **Repeated Obfuscation:**
   - If multiple encoding or hidden character injections occur across turns: `+15.0` (`REPEATED_OBFUSCATION`). Single obfuscation: `+5.0` (`OBFUSCATION_SIGNAL`).
7. **Benign Activity Safeguard:**
   - If current and past prompts are non-malicious with no obfuscation: `score = 0.0` (`CLEAN_SESSION`). Repeated benign queries **never** accumulate risk.

---

## 5. Configuration Parameters (`backend/config.py`)

| Parameter | Default Value | Description |
|---|---|---|
| `MAX_SESSION_HISTORY` | `20` | Maximum number of request events retained per session. |
| `SESSION_TTL_SECONDS` | `1800` | Session idle timeout in seconds (30 minutes). |
| `BEHAVIORAL_WINDOW_SECONDS` | `300` | Sliding window for velocity tracking (5 minutes). |
| `SIMILARITY_THRESHOLD` | `0.65` | Jaccard similarity threshold for near-duplicate attack detection. |
| `ESCALATION_SCORE_DELTA` | `0.20` | Attack score jump threshold triggering escalation detection. |

---

## 6. Known Limitations & Potential False Positives

1. **In-Memory Volatility:** In-memory session history resets when the backend restarts. Persistent storage (MongoDB) is planned for later phases.
2. **Session Identifier Spoofing:** In an unauthenticated development environment, a client could theoretically guess or reuse another client's session ID. Production deployments require authenticated session tokens.
3. **Repetitive Benign Prompts with Technical Jargon:** Complex legitimate research queries containing recurring security terminology (e.g. studying binary exploitation) may trigger elevated lexical similarity, though the benign safeguard prevents score accumulation unless the ML classifier misclassifies the prompt as an attack.

---

## 7. Verification Test Results

All 12 focused behavioral analysis tests passed:
- `test_01_new_session_clean_history`: Passed.
- `test_02_same_session_shares_history`: Passed.
- `test_03_different_sessions_isolated`: Passed.
- `test_04_repeated_suspicious_updates_signals`: Passed.
- `test_05_repeated_benign_prompts_do_not_become_attacks`: Passed.
- `test_06_obfuscation_history_tracked_independently`: Passed.
- `test_07_escalation_detection_rules`: Passed.
- `test_08_session_history_bounded`: Passed.
- `test_09_expired_sessions_reset`: Passed.
- `test_10_concurrent_requests_thread_safe`: Passed.
- `test_11_missing_or_invalid_session_id_handling`: Passed.
- `test_12_analyze_endpoint_returns_behavioral_fields`: Passed.
