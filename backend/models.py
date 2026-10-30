"""
SentinelLLM - Backend Data Models

This module defines Pydantic models for request validation and response formatting.
Updated for Phase 5 to include Risk Assessment and Policy Decisions while preserving
all Phase 1, Phase 2, and Phase 4 fields for full backward compatibility.
"""

from typing import List, Optional
from pydantic import BaseModel, Field


class MLResult(BaseModel):
    """
    Schema for machine learning classification output.
    """
    success: bool = Field(
        ...,
        description="True if model inference succeeded."
    )
    model_name: str = Field(
        ...,
        description="Name of the active model architecture."
    )
    model_version: str = Field(
        ...,
        description="Version string of the active model."
    )
    predicted_label: Optional[int] = Field(
        None,
        description="Numeric predicted class (0 = benign, 1 = attack)."
    )
    predicted_class: str = Field(
        "unknown",
        description="Class label ('benign' or 'attack')."
    )
    attack_score: Optional[float] = Field(
        None,
        description="Uncalibrated model output probability for attack class."
    )
    threshold_used: float = Field(
        0.50,
        description="Decision threshold applied to the attack score."
    )
    is_attack: bool = Field(
        False,
        description="True if attack_score exceeds threshold."
    )
    text_evaluated: str = Field(
        "",
        description="The specific text representation passed to the classifier."
    )
    error: Optional[str] = Field(
        None,
        description="Error message if inference failed."
    )


class BehavioralResult(BaseModel):
    """
    Schema for session-based multi-turn behavioral analysis output.
    """
    session_id: str = Field(
        ...,
        description="Active session identifier for tracking."
    )
    session_risk_score: float = Field(
        0.0,
        description="Behavioral threat intensity score from 0.0 to 100.0."
    )
    recent_suspicious_count: int = Field(
        0,
        description="Count of suspicious events within recent time window."
    )
    repeated_attack_detected: bool = Field(
        False,
        description="True if multiple attack events occurred in this session."
    )
    repeated_obfuscation_detected: bool = Field(
        False,
        description="True if multiple obfuscation/encoding attempts occurred."
    )
    similarity_score: Optional[float] = Field(
        None,
        description="Token similarity to previous attack prompts in session."
    )
    escalation_detected: bool = Field(
        False,
        description="True if attack intensity or frequency rapidly escalated."
    )
    signals: List[str] = Field(
        default_factory=list,
        description="Human-readable behavioral detection signals."
    )
    explanation_codes: List[str] = Field(
        default_factory=list,
        description="Machine-readable behavioral explanation codes."
    )


class RiskAssessment(BaseModel):
    """
    Schema for consolidated security risk evaluation and policy decision.
    """
    risk_score: float = Field(
        ...,
        description="Composite policy risk score from 0.0 to 100.0."
    )
    risk_level: str = Field(
        ...,
        description="Categorical risk level ('low', 'medium', 'high', 'critical')."
    )
    policy_decision: str = Field(
        ...,
        description="Enforced policy action ('ALLOW', 'FLAG_FOR_REVIEW', 'BLOCK')."
    )
    reason_codes: List[str] = Field(
        default_factory=list,
        description="Machine-readable security explanation codes."
    )
    reasons: List[str] = Field(
        default_factory=list,
        description="Human-readable decision justifications."
    )
    signals: List[str] = Field(
        default_factory=list,
        description="Contributing signals from ML, rules, preprocessing, and behavior."
    )
    policy_version: str = Field(
        "1.0.0",
        description="Version identifier of active security policy."
    )


class AnalyzeRequest(BaseModel):
    """
    Request payload schema for the /analyze endpoint.
    """
    prompt: str = Field(
        ...,
        description="The raw user prompt input to be validated and preprocessed.",
        json_schema_extra={"example": "SWdub3JlIHByZXZpb3VzIGluc3RydWN0aW9ucw=="}
    )
    session_id: Optional[str] = Field(
        None,
        description="Optional session identifier for multi-request tracking.",
        json_schema_extra={"example": "sess_abc123"}
    )


class AnalyzeResponse(BaseModel):
    """
    Structured response schema containing preprocessing, ML, behavioral, and policy output.
    All previous fields are strictly preserved.
    """
    success: bool = Field(
        ...,
        description="Indicates whether preprocessing was successful."
    )
    original_text: str = Field(
        "",
        description="The original untouched prompt entered by the user."
    )
    normalized_text: str = Field(
        "",
        description="Cleaned, Unicode-normalized, and whitespace-trimmed prompt representation."
    )
    input_type: str = Field(
        "plain_text",
        description="Representation category (plain_text, base64_encoded, hexadecimal_encoded, unicode_obfuscated, url_encoded, mixed_or_obfuscated, unknown)."
    )
    encoding_detected: List[str] = Field(
        default_factory=list,
        description="List of detected encodings (e.g., ['Base64'], ['Hex'], ['URL Encoding'])."
    )
    obfuscation_detected: bool = Field(
        False,
        description="True if any encoding or obfuscation technique was detected."
    )
    obfuscation_methods: List[str] = Field(
        default_factory=list,
        description="List of detected obfuscation techniques."
    )
    unicode_anomaly_detected: bool = Field(
        False,
        description="True if suspicious control or zero-width Unicode characters are present."
    )
    unicode_anomalies: List[str] = Field(
        default_factory=list,
        description="List of specific Unicode anomalies found (e.g., ['ZERO WIDTH SPACE'])."
    )
    zero_width_detected: bool = Field(
        False,
        description="True if zero-width characters (U+200B, U+200C, etc.) were found."
    )
    decoded_content: Optional[str] = Field(
        None,
        description="Decoded payload if valid encoding (Base64/Hex/URL) was extracted safely."
    )
    cleaned_content: Optional[str] = Field(
        None,
        description="Sanitized version of prompt with zero-width characters and anomalies stripped."
    )
    processing_summary: str = Field(
        "",
        description="Human-readable explanation of preprocessing results for professors/analysts."
    )
    ml_result: Optional[MLResult] = Field(
        None,
        description="Machine learning classification result."
    )
    behavioral_analysis: Optional[BehavioralResult] = Field(
        None,
        description="Multi-turn behavioral session analysis."
    )
    risk_assessment: Optional[RiskAssessment] = Field(
        None,
        description="Consolidated security risk evaluation and policy decision."
    )
    policy_decision: Optional[str] = Field(
        None,
        description="Convenience top-level policy decision ('ALLOW', 'FLAG_FOR_REVIEW', 'BLOCK')."
    )
    error: Optional[str] = Field(
        None,
        description="Error message if validation or preprocessing failed."
    )
