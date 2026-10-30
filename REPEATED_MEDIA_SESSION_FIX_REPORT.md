# SentinelLLM repeated media prompt consistency fix

## Issue
A safe image/video generation prompt could be allowed on its first request but blocked on repetition in the same session. The media-generation safeguard in `backend/detection/risk_engine.py` required behavioral flags (`repeated_attack_detected`, `escalation_detected`, and session risk) to be clear. Because an ML false positive was recorded as an attack event, repetition disabled the safeguard.

## Fix
The media-generation contextual safeguard now runs after deterministic dangerous-intent and high-confidence prompt-injection rules, but does not get disabled merely by behavioral signals derived from the same ML false positive. Explicit abuse, obfuscation, zero-width and encoding checks still apply. This is a policy/pipeline fix; the active trained model is retained because the reported inconsistency came from session-dependent policy gating rather than a need for retraining.

## Regression tests
Added `backend/tests/test_repeated_media_session_consistency.py`:
- Repeated `generate an image` remains ALLOW even when session behavior reports repeated attack/escalation signals.
- Explicit non-consensual deepfake request remains BLOCK even when repeated.

Command run: `python -m unittest discover -s tests -v` from `backend/`.
Result: **56 tests passed**. Warnings were emitted when loading optional legacy Random Forest/XGBoost artifacts due to library-version differences; the active Logistic Regression model loaded and existing classifier tests passed.

## Limitations
- The patch was verified through backend policy/unit tests, not a live browser session in the user's local environment.
- The active model was not retrained; this issue was traced to policy logic gating a contextual exception based on session state. Existing trained model artifacts remain included.
- This safeguard only applies to prompts recognized as ordinary media-generation requests and does not override explicit dangerous-intent or prompt-injection rules.
