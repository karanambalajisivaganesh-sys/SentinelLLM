> **Historical phase document.** Its model metrics and policy details may predate SentinelLLM v2.0.0. Use the root README and SENTINELLLM_20000_TRAINING_REPORT.md for current implementation and evaluation.

# SentinelLLM — Frontend Integration (Phase 6)

## 1. Overview

Phase 6 connects the React 18 + Vite frontend with the FastAPI backend security pipeline completed in Phase 5.

The frontend presents a comprehensive, multi-layer security dashboard that displays:
- **Final Policy Decision Banner:** High-visibility policy verdict (`ALLOW`, `FLAG_FOR_REVIEW`, `BLOCK`) with actionable guidance.
- **Composite Risk Score Gauge:** Linear threat gauge (0–100) mapped to four severity tiers (`low`, `medium`, `high`, `critical`) with explicit policy threshold markers (35 for Review, 70 for Block).
- **Explainable Reasons & Signals:** Plain-text decision justifications, machine-readable reason codes, and contributing security signals.
- **Multi-Layer Detection Cards:** Individual findings from the ML Pattern Classifier, Behavioral Session Risk, Input Representation, Encoding Detection, and Zero-Width Unicode detection.
- **Multi-Turn Session Tracking:** Active session identifier display, session resets, and live behavioral risk aggregation across turns.
- **Text Representations:** Visual side-by-side comparison of original, normalized, decoded, and sanitized inputs.
- **Collapsible Technical Inspector:** Verbatim formatted JSON payload returned by the FastAPI backend for debugging and inspection.

---

## 2. Component Architecture

```
App.jsx (State orchestration, API fetch, session management)
 ├── Header.jsx (Project title, subtitle, framework badge)
 ├── PromptInput.jsx (Textarea, presets, char count, session manager)
 ├── PipelineStatus.jsx (7-stage sequential visual pipeline flow)
 ├── AnalysisResult.jsx (Policy banner, risk gauge, reasons, signals, cards, text transformations)
 │    └── DetectionCard.jsx (Reusable status card component)
 └── Collapsible Raw JSON Viewer (Embedded in AnalysisResult)
```

### Component Breakdown

1. **`Header.jsx`**
   - Displays framework title *"SENTINEL LLM"* with badge *"Adaptive Behavioral Security Framework for LLMs"*.
   - Free of extraneous emojis, maintaining a professional and clean presentation.

2. **`PromptInput.jsx`**
   - Controlled textarea with character counter.
   - Interactive session badge displaying current `session_id` and a `"New Session"` button for resetting behavioral tracking.
   - 7 demonstration presets representing all critical security scenarios:
     1. *Normal Prompt (ALLOW)* — Standard algorithmic question.
     2. *Direct Injection (BLOCK)* — Direct prompt override (`Ignore previous instructions...`).
     3. *Base64 Attack (BLOCK)* — Obfuscated jailbreak payload.
     4. *Encoded Benign (REVIEW)* — Base64-encoded harmless text triggering stealth / review policy.
     5. *Zero-Width Unicode (BLOCK/REVIEW)* — Invisible character injection.
     6. *Valid Japanese (ALLOW)* — Multi-script international text test.
     7. *Research Query (ALLOW/REVIEW)* — Security discussion query.

3. **`PipelineStatus.jsx`**
   - Displays the 7 actual backend security stages:
     1. `Input Validation`
     2. `Preprocessing & Encodings`
     3. `ML Pattern Classification`
     4. `Explicit Security Rules`
     5. `Behavioral Session Analysis`
     6. `Composite Risk Scoring`
     7. `Final Policy Decision`
   - Reflects state transitions (`pending`, `processing`, `completed`, `error`) using clear textual markers (`[OK]`, `[..]`, `[X]`, `[--]`).

4. **`AnalysisResult.jsx`**
   - **Data Consistency Verification:** Checks that top-level `result.policy_decision` strictly matches `result.risk_assessment.policy_decision`. If a mismatch is detected, displays an alert banner.
   - **Policy Decision Banner:** Styled with high-contrast colored borders and backgrounds (Red for BLOCK, Amber for FLAG_FOR_REVIEW, Green for ALLOW).
   - **Risk Gauge:** Visual linear bar representing `risk_score` (0–100) with calibrated color classes (`fill-low`, `fill-medium`, `fill-high`, `fill-critical`).
   - **Explainable Policy Evaluation:** Dedicated section displaying `reasons`, `reason_codes` (rendered as mono-font pills), and `signals`.
   - **Multi-Layer Findings:** Grid of `DetectionCard` components summarizing findings from each defense module.
   - **Text Representations:** Side-by-side view of Original vs. Normalized text, plus dedicated highlight containers for decoded payloads or cleaned unicode.
   - **JSON Inspector:** Collapsible code block showing the full structured API response.

---

## 3. Backend API Contract Integration

The frontend communicates with `POST /analyze` at `http://localhost:8000/analyze`:

### Request Payload
```json
{
  "prompt": "Explain binary search algorithm",
  "session_id": "sess_k9x2m4p1"
}
```

### Response Payload Structure
```json
{
  "success": true,
  "original_text": "...",
  "normalized_text": "...",
  "input_type": "plain_text",
  "encoding_detected": [],
  "zero_width_detected": false,
  "decoded_content": null,
  "cleaned_content": "...",
  "policy_decision": "ALLOW",
  "session_id": "sess_k9x2m4p1",
  "session_risk_score": 0.0,
  "ml_result": {
    "model_name": "TF-IDF + Logistic Regression",
    "predicted_class": "benign",
    "attack_score": 0.0412,
    "threshold_used": 0.50
  },
  "behavioral_analysis": {
    "session_id": "sess_k9x2m4p1",
    "session_risk_score": 0.0,
    "recent_suspicious_count": 0,
    "repeated_attack_detected": false,
    "escalation_detected": false,
    "turn_count": 1
  },
  "risk_assessment": {
    "risk_score": 4.12,
    "risk_level": "low",
    "policy_decision": "ALLOW",
    "reason_codes": [],
    "reasons": ["Risk score 4.1 within safe operational boundary (< 35.0)."],
    "signals": ["ml_attack_score=0.0412"],
    "policy_version": "1.0.0"
  }
}
```

---

## 4. Frontend Design Invariants & Safeguards

1. **No Client-Side Risk Calculation:**
   The frontend never calculates, averages, or overrides risk scores. All scores, levels, decisions, and reasons are displayed verbatim as computed by the backend Risk Engine.

2. **No Unsafe HTML Rendering:**
   React JSX interpolation (`{text}`) is used exclusively. `dangerouslySetInnerHTML` is strictly prohibited to prevent cross-site scripting (XSS) from malicious prompt reflections.

3. **Data Consistency Assertion:**
   The frontend monitors both `result.policy_decision` and `result.risk_assessment.policy_decision`. If the backend ever returns conflicting values, an explicit warning is presented to the user.

4. **Composite Score vs. Probability Disclaimer:**
   The risk score card includes an explicit footnote: *"Policy risk score represents a composite threat index (0–100), not a statistical Bayesian probability."*

5. **Student-Level Clean CSS:**
   Styled using standard CSS flexbox and grid layouts without third-party UI component libraries (Tailwind, MUI, Bootstrap) or complex animations. Uses accessible, high-contrast dark-mode colors (`#111827`, `#1f2937`, `#374151`).

---

## 5. Local Setup and Execution Guide

### Starting the FastAPI Backend
```powershell
cd C:\Users\karan\OneDrive\Desktop\Sentinelllm\backend
uvicorn main:app --reload --port 8000
```
- API will be accessible at: `http://localhost:8000`
- Swagger documentation: `http://localhost:8000/docs`

### Starting the React Frontend
```powershell
cd C:\Users\karan\OneDrive\Desktop\Sentinelllm\frontend
npm run dev
```
- Open browser at: `http://localhost:5173`

### Production Build Verification
```powershell
cd C:\Users\karan\OneDrive\Desktop\Sentinelllm\frontend
npm run build
```
Build outputs are bundled to `frontend/dist/`.
