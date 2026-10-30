"""
SentinelLLM - Risk Engine & Decision Policy

Synthesizes multiple defense layers:
1. Machine Learning attack probability
2. Preprocessing & obfuscation signals
3. Deterministic security rules
4. Multi-turn behavioral session context

Produces explainable policy decisions (ALLOW, FLAG_FOR_REVIEW, BLOCK) with
human-readable reasons and machine-readable explanation codes.
"""

from typing import Dict, List, Any, Optional

from config import (
    POLICY_VERSION,
    RISK_THRESHOLD_REVIEW,
    RISK_THRESHOLD_BLOCK,
    ML_HIGH_ATTACK_THRESHOLD,
    ML_MODERATE_ATTACK_THRESHOLD,
)
from detection.rules import evaluate_security_rules, is_defensive_cybersecurity_context, is_benign_media_generation_context


def evaluate_risk_policy(
    text: str,
    preprocessing_result: Dict[str, Any],
    ml_result: Dict[str, Any],
    behavioral_result: Dict[str, Any],
) -> Dict[str, Any]:
    """
    Combines security signals into a unified policy risk score and decision.

    Args:
        text: Evaluated prompt text representation.
        preprocessing_result: Dict from preprocessor.py.
        ml_result: Dict from classifier.py.
        behavioral_result: Dict from analyzer.py.

    Returns:
        Structured risk assessment dictionary matching RiskAssessment schema.
    """
    signals: List[str] = []
    reason_codes: List[str] = []
    reasons: List[str] = []

    # -------------------------------------------------------------
    # 1. Rule Engine Evaluation
    # -------------------------------------------------------------
    rule_eval = evaluate_security_rules(text)
    rules_triggered = rule_eval["triggered"]
    if rules_triggered:
        rule_list = ", ".join(rule_eval["rule_names"])
        signals.append(f"Security rules triggered: {rule_list}")
        reason_codes.append("EXPLICIT_SECURITY_RULE_MATCH")
        reasons.append(f"Prompt matches known injection pattern: {rule_list}")

    # Explicitly bounded analysis/translation of quoted malicious text is data,
    # not an instruction to execute. The rule layer only emits this exemption when
    # both an analysis task and a non-execution boundary are present.
    if rule_eval.get("context_exemption") == "explicit_non_actionable_safety_analysis":
        return {
            "risk_score": 5.0,
            "risk_level": "low",
            "policy_decision": "ALLOW",
            "reason_codes": ["NON_ACTIONABLE_SAFETY_ANALYSIS"],
            "reasons": ["Prompt explicitly asks to analyze or transform untrusted text without executing its instructions."],
            "signals": ["Narrow non-actionable analysis exemption applied."],
            "policy_version": POLICY_VERSION,
        }

    # Deterministic high-confidence safety rule: actionable explosive/weapon
    # construction requests are blocked even when the ML model is wrong.
    if rule_eval.get("dangerous_intent", False):
        dangerous_names = ", ".join(rule_eval.get("dangerous_rule_names", []))
        return {
            "risk_score": 100.0,
            "risk_level": "critical",
            "policy_decision": "BLOCK",
            "reason_codes": ["DANGEROUS_CONSTRUCTION_REQUEST"],
            "reasons": ["Prompt matches a high-confidence rule for actionable harmful or unauthorized activity."],
            "signals": [f"High-confidence dangerous-intent rule matched: {dangerous_names}"],
            "policy_version": POLICY_VERSION,
        }

    # High-confidence prompt-injection rules are deterministic blocks even when the
    # lexical classifier misses a paraphrase. The narrow safe-analysis exemption is
    # applied inside evaluate_security_rules before these names are returned.
    high_confidence_injection_rules = {
        "INSTRUCTION_OVERRIDE", "SYSTEM_PROMPT_LEAK", "ROLE_HIJACK_JAILBREAK", "DELIMITER_INJECTION"
    }
    matched_injection_rules = high_confidence_injection_rules.intersection(rule_eval.get("rule_names", []))
    # Reported speech and explicit educational discussion of the phrase are not
    # automatically treated as an active override instruction.
    reported_speech_context = bool(__import__("re").search(
        r"\b(teacher said|the phrase|the sentence|the word|in my documentation|writing a new test)\b",
        (text or "").casefold(),
    ))
    if reported_speech_context:
        matched_injection_rules.discard("INSTRUCTION_OVERRIDE")
    if matched_injection_rules:
        return {
            "risk_score": 95.0,
            "risk_level": "critical",
            "policy_decision": "BLOCK",
            "reason_codes": ["HIGH_CONFIDENCE_PROMPT_INJECTION_RULE"],
            "reasons": ["Prompt contains a high-confidence instruction-hijacking or confidential-instruction extraction pattern."],
            "signals": ["High-confidence injection rules matched: " + ", ".join(sorted(matched_injection_rules))],
            "policy_version": POLICY_VERSION,
        }

    # Safe image/video generation requests should not be blocked solely by an ML lexical false positive.
    # This is evaluated only after explicit dangerous-intent and prompt-injection rules.
    if (
        is_benign_media_generation_context(text)
        and not preprocessing_result.get("obfuscation_detected", False)
        and not preprocessing_result.get("zero_width_detected", False)
        and not preprocessing_result.get("encoding_detected", [])
    ):
        return {
            "risk_score": 5.0,
            "risk_level": "low",
            "policy_decision": "ALLOW",
            "reason_codes": ["BENIGN_MEDIA_GENERATION_CONTEXT"],
            "reasons": ["Ordinary image/video creation request; no explicit harmful-intent or injection rule matched."],
            "signals": ["Media-generation context safeguard prevented an ML-only false positive."],
            "policy_version": POLICY_VERSION,
        }

    # Clearly defensive/authorized cybersecurity questions should not be flagged
    # solely because the text contains security vocabulary. This runs only after
    # high-confidence harmful rules, which always take precedence.
    if (
        is_defensive_cybersecurity_context(text)
        and not rule_eval.get("dangerous_intent", False)
        and not any(name in rule_eval.get("rule_names", []) for name in ["INSTRUCTION_OVERRIDE", "SYSTEM_PROMPT_LEAK", "ROLE_HIJACK_JAILBREAK", "DELIMITER_INJECTION"])
        and not preprocessing_result.get("obfuscation_detected", False)
        and not preprocessing_result.get("zero_width_detected", False)
        and not preprocessing_result.get("encoding_detected", [])
    ):
        return {
            "risk_score": float(round(min(max(float(ml_result.get("attack_score", 0.0)) * 15.0, 0.0), 25.0), 1)),
            "risk_level": "low",
            "policy_decision": "ALLOW",
            "reason_codes": ["DEFENSIVE_CYBERSECURITY_CONTEXT"],
            "reasons": ["Prompt appears to request defensive, authorized, or educational cybersecurity guidance without explicit abuse indicators."],
            "signals": ["Defensive cybersecurity context reduced ML-only false-positive escalation."],
            "policy_version": POLICY_VERSION,
        }

    # -------------------------------------------------------------
    # 2. Check for Machine Learning Inference Failures
    # -------------------------------------------------------------
    ml_success = ml_result.get("success", False)
    if not ml_success:
        reason_codes.append("ML_INFERENCE_UNAVAILABLE")
        reasons.append("ML classifier is unavailable or encountered an error; failing safe to review.")
        signals.append(f"ML failure: {ml_result.get('error', 'Unknown inference error')}")
        return {
            "risk_score": 50.0,
            "risk_level": "medium",
            "policy_decision": "FLAG_FOR_REVIEW",
            "reason_codes": reason_codes,
            "reasons": reasons,
            "signals": signals,
            "policy_version": POLICY_VERSION,
        }

    # Extract ML metrics
    attack_score = float(ml_result.get("attack_score") or 0.0)
    is_attack = bool(ml_result.get("is_attack", False))

    if is_attack:
        signals.append(f"ML model classified prompt as attack (score: {attack_score:.4f})")
        if attack_score >= ML_HIGH_ATTACK_THRESHOLD:
            reason_codes.append("ML_HIGH_ATTACK_SCORE")
            reasons.append(f"High-confidence attack probability from ML model ({attack_score:.2f})")
        else:
            reason_codes.append("ML_ATTACK_CLASSIFICATION")
            reasons.append(f"Prompt classified as attack instruction by ML model ({attack_score:.2f})")
    else:
        signals.append(f"ML model classified prompt as benign (score: {attack_score:.4f})")

    # -------------------------------------------------------------
    # 3. Preprocessing & Obfuscation Signals
    # -------------------------------------------------------------
    obf_detected = bool(preprocessing_result.get("obfuscation_detected", False))
    zw_detected = bool(preprocessing_result.get("zero_width_detected", False))
    encodings = preprocessing_result.get("encoding_detected", [])

    if zw_detected:
        signals.append("Zero-width hidden Unicode characters detected")
        reason_codes.append("ZERO_WIDTH_DETECTED")
        reasons.append("Prompt contains invisible zero-width space characters often used for stealth injection")

    if obf_detected or encodings:
        enc_str = ", ".join(encodings) if encodings else "Obfuscation"
        signals.append(f"Encoding/obfuscation detected: {enc_str}")
        reason_codes.append("OBFUSCATION_DETECTED")
        reasons.append(f"Input payload utilized encoding or representation obfuscation ({enc_str})")

    # -------------------------------------------------------------
    # 4. Behavioral Session Signals
    # -------------------------------------------------------------
    beh_score = float(behavioral_result.get("session_risk_score", 0.0))
    repeated_attack = bool(behavioral_result.get("repeated_attack_detected", False))
    escalation = bool(behavioral_result.get("escalation_detected", False))
    recent_suspicious = int(behavioral_result.get("recent_suspicious_count", 0))

    if repeated_attack:
        signals.append("Repeated attack attempts in current session")
        reason_codes.append("REPEATED_ATTACK_ATTEMPTS")
        reasons.append("Multiple attack attempts detected across session turns")

    if escalation:
        signals.append("Attack intensity escalation detected in session")
        reason_codes.append("ATTACK_ESCALATION_DETECTED")
        reasons.append("Rapid escalation from benign queries to attack instructions")

    if beh_score >= 40.0:
        signals.append(f"Elevated behavioral risk score: {beh_score:.1f}/100")
        reason_codes.append("HIGH_BEHAVIORAL_RISK")
        reasons.append(f"Multi-turn session behavioral threat score elevated to {beh_score:.1f}")

    # -------------------------------------------------------------
    # 5. Composite Risk Score Calculation (0.0 to 100.0)
    # -------------------------------------------------------------
    # Weighted calculation:
    # - ML attack probability contributes up to 45 points
    # - Explicit rule matches contribute 30 points
    # - Multi-turn behavioral analysis contributes up to 30 points
    # - Zero-width covert injection contributes 15 points
    # - Encodings contribute 10 points
    score = 0.0
    score += attack_score * 45.0

    if rules_triggered:
        score += 30.0

    if zw_detected:
        score += 15.0

    if obf_detected or encodings:
        score += 10.0

    # Behavioral contribution (scaled to 30 max points)
    score += min(beh_score * 0.30, 30.0)

    # Clean session safeguard: If ML is confidently benign and no rules/anomalies triggered
    if not is_attack and attack_score < 0.35 and not rules_triggered and not zw_detected and not obf_detected and beh_score == 0:
        score = min(score, 15.0)

    computed_risk_score = float(round(min(max(score, 0.0), 100.0), 1))

    # -------------------------------------------------------------
    # 6. Policy Decision Logic
    # -------------------------------------------------------------
    # Rule A: BLOCK Decisions
    # Triggered by high-confidence attacks or strong composite multi-signal evidence
    is_high_ml = attack_score >= ML_HIGH_ATTACK_THRESHOLD
    is_stealth_attack = (zw_detected or obf_detected) and (attack_score >= 0.70 or rules_triggered)
    is_rule_and_ml_attack = rules_triggered and is_attack
    is_repeated_high_risk = repeated_attack and (attack_score >= 0.65 or rules_triggered)

    if (
        computed_risk_score >= RISK_THRESHOLD_BLOCK and (rules_triggered or obf_detected or zw_detected or repeated_attack or escalation or beh_score >= 40.0)
        or is_high_ml
        or is_stealth_attack
        or is_rule_and_ml_attack
        or is_repeated_high_risk
    ):
        policy_decision = "BLOCK"
        if not reasons:
            reasons.append("High-confidence attack indicators or critical composite risk exceeded threshold.")

    # Rule B: FLAG_FOR_REVIEW Decisions
    # Triggered by moderate uncertainty, conflicting signals, or borderline thresholds
    elif (
        computed_risk_score >= RISK_THRESHOLD_REVIEW and (rules_triggered or obf_detected or zw_detected or repeated_attack or escalation or beh_score >= 30.0)
        or (is_high_ml and (rules_triggered or obf_detected or zw_detected or repeated_attack or escalation or beh_score >= 30.0))
        or rules_triggered  # Conflicting signal: rule matched but ML did not reach block threshold
        or (is_attack and not is_high_ml)
        or (obf_detected and not is_attack)  # Obfuscated but payload classified as benign -> review, not block
        or beh_score >= 30.0
    ):
        policy_decision = "FLAG_FOR_REVIEW"
        if not reason_codes:
            reason_codes.append("MODERATE_RISK_REVIEW")
            reasons.append("Moderate composite risk or conflicting detection signals require review.")

    # Rule C: ALLOW Decisions
    # Low-risk benign queries with no strong threat signals
    else:
        policy_decision = "ALLOW"
        if not reason_codes:
            reason_codes.append("BENIGN_PROMPT")
            reasons.append("Prompt evaluated as benign with no critical security signals.")

    # -------------------------------------------------------------
    # 7. Risk Level Assignment
    # -------------------------------------------------------------
    if policy_decision == "BLOCK":
        risk_level = "critical" if computed_risk_score >= 85.0 else "high"
    elif policy_decision == "FLAG_FOR_REVIEW":
        risk_level = "medium"
    else:
        risk_level = "low"

    return {
        "risk_score": computed_risk_score,
        "risk_level": risk_level,
        "policy_decision": policy_decision,
        "reason_codes": reason_codes,
        "reasons": reasons,
        "signals": signals,
        "policy_version": POLICY_VERSION,
    }
