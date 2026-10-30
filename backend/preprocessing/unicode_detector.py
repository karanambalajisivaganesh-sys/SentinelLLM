"""
SentinelLLM - Unicode & Zero-Width Detector

Identifies invisible zero-width characters and suspicious Unicode control character anomalies.
Crucial distinction: Standard international languages (e.g. Japanese, Arabic, Spanish) are preserved
and NOT flagged as anomalies.
"""

import unicodedata
from typing import Tuple, List, Dict

# Specific dictionary mapping targeted zero-width codepoints to human-readable names
ZERO_WIDTH_MAP: Dict[str, str] = {
    '\u200b': 'ZERO WIDTH SPACE (U+200B)',
    '\u200c': 'ZERO WIDTH NON-JOINER (U+200C)',
    '\u200d': 'ZERO WIDTH JOINER (U+200D)',
    '\u2060': 'WORD JOINER (U+2060)',
    '\ufeff': 'ZERO WIDTH NO-BREAK SPACE / BOM (U+FEFF)'
}

# Suspicious bidirectional control characters used in spoofing/jailbreak obfuscation
BIDI_CONTROLS: Dict[str, str] = {
    '\u202a': 'LEFT-TO-RIGHT EMBEDDING (U+202A)',
    '\u202b': 'RIGHT-TO-LEFT EMBEDDING (U+202B)',
    '\u202c': 'POP DIRECTIONAL FORMATTING (U+202C)',
    '\u202d': 'LEFT-TO-RIGHT OVERRIDE (U+202D)',
    '\u202e': 'RIGHT-TO-LEFT OVERRIDE (U+202E)',
    '\u2066': 'LEFT-TO-RIGHT ISOLATE (U+2066)',
    '\u2067': 'RIGHT-TO-LEFT ISOLATE (U+2067)',
    '\u2068': 'FIRST STRONG ISOLATE (U+2068)',
    '\u2069': 'POP DIRECTIONAL ISOLATE (U+2069)'
}


def analyze_unicode(text: str) -> Tuple[bool, bool, List[str], str]:
    """
    Performs comprehensive Unicode analysis on the input text.

    Args:
        text (str): Input prompt string

    Returns:
        Tuple containing:
        - zero_width_detected (bool)
        - unicode_anomaly_detected (bool)
        - unicode_anomalies (List[str])
        - cleaned_text (str): Input text stripped of zero-width and invisible control chars
    """
    if not text:
        return False, False, [], ""

    zero_width_detected = False
    unicode_anomaly_detected = False
    anomalies_set = set()
    cleaned_chars = []

    for char in text:
        # Check 1: Zero-width characters
        if char in ZERO_WIDTH_MAP:
            zero_width_detected = True
            unicode_anomaly_detected = True
            anomalies_set.add(ZERO_WIDTH_MAP[char])
            continue  # Omit from cleaned text

        # Check 2: Suspicious BiDi overrides
        if char in BIDI_CONTROLS:
            unicode_anomaly_detected = True
            anomalies_set.add(BIDI_CONTROLS[char])
            continue  # Omit from cleaned text

        # Check 3: Other unexpected control characters (Category 'Cc' or 'Cf')
        # Exclude standard whitespace control chars (\n, \r, \t)
        category = unicodedata.category(char)
        if category in ('Cc', 'Cf') and char not in ('\n', '\r', '\t'):
            unicode_anomaly_detected = True
            char_name = unicodedata.name(char, f'U+{ord(char):04X}')
            anomalies_set.add(f'CONTROL CHARACTER: {char_name}')
            continue  # Omit from cleaned text

        # Valid character (including normal non-ASCII characters like Japanese, Chinese, Accents)
        cleaned_chars.append(char)

    cleaned_text = "".join(cleaned_chars)
    anomalies_list = sorted(list(anomalies_set))

    return zero_width_detected, unicode_anomaly_detected, anomalies_list, cleaned_text
