"""
SentinelLLM - Main Preprocessing Pipeline Orchestrator

Assembles input validation, text normalization, encoding detection, and Unicode analysis
into a unified structured output schema for the FastAPI endpoint and downstream framework layers.
"""

import re
from typing import Dict, Any, List

from .normalizer import normalize_text
from .encoding_detector import (
    detect_and_decode_base64,
    detect_and_decode_hex,
    detect_and_decode_url_encoding,
    detect_and_decode_html_entities
)
from .unicode_detector import analyze_unicode

MAX_PROMPT_LENGTH = 50000


def preprocess_prompt(prompt: str) -> Dict[str, Any]:
    """
    Executes the SentinelLLM Review 1 preprocessing pipeline on a prompt.

    Args:
        prompt (str): Raw user prompt input

    Returns:
        dict: Preprocessing output dictionary matching AnalyzeResponse structure
    """
    # ------------------------------------------------------------------
    # Step 1: Input Validation
    # ------------------------------------------------------------------
    if prompt is None:
        return {
            "success": False,
            "error": "Prompt cannot be null.",
            "processing_summary": "Validation failed: Null prompt received."
        }

    original_text = str(prompt)

    if not original_text.strip():
        return {
            "success": False,
            "error": "Prompt cannot be empty.",
            "processing_summary": "Validation failed: Empty prompt received."
        }

    if len(original_text) > MAX_PROMPT_LENGTH:
        return {
            "success": False,
            "error": f"Prompt exceeds maximum allowed size ({MAX_PROMPT_LENGTH} characters).",
            "processing_summary": "Validation failed: Exceeded maximum input length limit."
        }

    # ------------------------------------------------------------------
    # Step 2: Normalization
    # ------------------------------------------------------------------
    normalized_text = normalize_text(original_text)

    # Initialize tracking variables
    encoding_detected: List[str] = []
    obfuscation_methods: List[str] = []
    decoded_content: str = None
    input_type = "plain_text"

    # ------------------------------------------------------------------
    # Step 3: Encoding & Obfuscation Detection
    # ------------------------------------------------------------------
    # 3a. Base64 Check
    is_b64, b64_decoded = detect_and_decode_base64(normalized_text)
    if is_b64:
        encoding_detected.append("Base64")
        obfuscation_methods.append("Base64 Encoding")
        decoded_content = b64_decoded
        input_type = "base64_encoded"

    # 3b. Hexadecimal Check
    is_hex, hex_decoded = detect_and_decode_hex(normalized_text)
    if is_hex:
        encoding_detected.append("Hex")
        obfuscation_methods.append("Hexadecimal Encoding")
        if not decoded_content:
            decoded_content = hex_decoded
        input_type = "hexadecimal_encoded" if input_type == "plain_text" else "mixed_or_obfuscated"

    # 3c. URL Encoding Check
    is_url_enc, url_decoded = detect_and_decode_url_encoding(original_text)
    if is_url_enc:
        encoding_detected.append("URL Encoding")
        obfuscation_methods.append("URL Encoding")
        if not decoded_content:
            decoded_content = url_decoded
        if input_type == "plain_text":
            input_type = "url_encoded"
        elif input_type != "url_encoded":
            input_type = "mixed_or_obfuscated"

    # 3d. HTML Entity Check
    is_html_ent, html_decoded = detect_and_decode_html_entities(original_text)
    if is_html_ent:
        encoding_detected.append("HTML Entities")
        obfuscation_methods.append("HTML Entity Encoding")
        if not decoded_content:
            decoded_content = html_decoded
        if input_type == "plain_text":
            input_type = "mixed_or_obfuscated"

    # 3e. Additional Obfuscation Checks (Character Repetition)
    if re.search(r'(.)\1{15,}', original_text):
        obfuscation_methods.append("Excessive Character Repetition")

    # ------------------------------------------------------------------
    # Step 4: Unicode & Zero-Width Analysis
    # ------------------------------------------------------------------
    # Analyze the target text (if encoded and decoded, check decoded too; otherwise check normalized)
    text_to_analyze_unicode = decoded_content if decoded_content else original_text
    zero_width_detected, unicode_anomaly_detected, unicode_anomalies, cleaned_content = analyze_unicode(text_to_analyze_unicode)

    if zero_width_detected:
        obfuscation_methods.append("Zero-Width Character Injection")
        if input_type == "plain_text":
            input_type = "unicode_obfuscated"
        else:
            input_type = "mixed_or_obfuscated"
    elif unicode_anomaly_detected:
        obfuscation_methods.append("Suspicious Unicode Control Characters")
        if input_type == "plain_text":
            input_type = "unicode_obfuscated"

    obfuscation_detected = len(obfuscation_methods) > 0

    # If decoded content was found, clean it up as well
    if decoded_content:
        _, _, _, cleaned_decoded = analyze_unicode(decoded_content)
        cleaned_content = normalize_text(cleaned_decoded)

    # ------------------------------------------------------------------
    # Step 5: Summary Generation
    # ------------------------------------------------------------------
    summary_parts = []
    if encoding_detected:
        summary_parts.append(f"{', '.join(encoding_detected)} encoded input detected and decoded.")
    if zero_width_detected:
        summary_parts.append("Zero-width hidden characters detected.")
    elif unicode_anomaly_detected:
        summary_parts.append("Suspicious Unicode control characters detected.")
    
    if not summary_parts:
        summary = "Normal plain text input detected."
    else:
        summary = " ".join(summary_parts)

    return {
        "success": True,
        "original_text": original_text,
        "normalized_text": normalized_text,
        "input_type": input_type,
        "encoding_detected": encoding_detected,
        "obfuscation_detected": obfuscation_detected,
        "obfuscation_methods": obfuscation_methods,
        "unicode_anomaly_detected": unicode_anomaly_detected,
        "unicode_anomalies": unicode_anomalies,
        "zero_width_detected": zero_width_detected,
        "decoded_content": decoded_content,
        "cleaned_content": cleaned_content,
        "processing_summary": summary,
        "error": None
    }
