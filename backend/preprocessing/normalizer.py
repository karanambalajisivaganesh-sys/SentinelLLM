"""
SentinelLLM - Text Normalizer

Responsible for standardizing text formatting without losing original input context.
- Strips leading/trailing whitespace
- Collapses repeated internal whitespace
- Performs Unicode normalization (NFKC)
"""

import re
import unicodedata


def normalize_text(text: str) -> str:
    """
    Normalizes a given prompt text while leaving original text intact.

    Args:
        text (str): Raw input text

    Returns:
        str: Normalized text string
    """
    if not text:
        return ""

    # Step 1: Unicode normalization (NFKC compatibility decomposition followed by canonical composition)
    normalized = unicodedata.normalize('NFKC', text)

    # Step 2: Strip leading and trailing whitespace
    normalized = normalized.strip()

    # Step 3: Replace multiple spaces/newlines/tabs with a single space
    normalized = re.sub(r'\s+', ' ', normalized)

    return normalized
