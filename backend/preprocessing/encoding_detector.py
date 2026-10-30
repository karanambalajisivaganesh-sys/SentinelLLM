"""
SentinelLLM - Encoding & Obfuscation Detector

Detects and safely decodes encoded text payloads including:
- Base64 Encoding
- Hexadecimal Encoding
- URL Encoding
- HTML Entity Encoding

Safety: Content is ONLY decoded into text representation. It is NEVER executed.
"""

import base64
import binascii
import html
import re
import unicodedata
import urllib.parse
from typing import Tuple, Optional


def is_meaningful_text(text: str) -> bool:
    """
    Helper function to check if decoded output represents meaningful, printable text
    rather than random binary noise or strange codepoint sequences.

    Args:
        text (str): Decoded candidate string

    Returns:
        bool: True if the string is printable text with reasonable character composition.
    """
    if not text or len(text.strip()) == 0:
        return False

    valid_count = 0
    total_len = len(text)

    for c in text:
        # Printable ASCII (32-126) plus standard whitespace
        if 32 <= ord(c) <= 126 or c in ('\n', '\r', '\t'):
            valid_count += 1
        else:
            cat = unicodedata.category(c)
            # Common international letters/numbers/punctuation
            if cat in ('Lu', 'Ll', 'Lt', 'Lm', 'Lo', 'Nd', 'Po', 'Ps', 'Pe', 'Pi', 'Pf', 'Pd'):
                valid_count += 1

    ratio = valid_count / total_len
    return ratio >= 0.85


def detect_and_decode_hex(text: str) -> Tuple[bool, Optional[str]]:
    """
    Detects if the input string is Hexadecimal encoded and decodes it if valid.

    Args:
        text (str): Input text candidate

    Returns:
        Tuple[bool, Optional[str]]: (is_hex, decoded_text)
    """
    clean_text = text.strip().replace(" ", "")

    # Hex must have an even length and at least 8 hex characters (e.g. 4 bytes of text)
    if len(clean_text) < 8 or len(clean_text) % 2 != 0:
        return False, None

    # Must consist strictly of hexadecimal digits (0-9, a-f, A-F)
    if not re.match(r'^[0-9a-fA-F]+$', clean_text):
        return False, None

    try:
        decoded_bytes = binascii.unhexlify(clean_text)
        decoded_str = decoded_bytes.decode('utf-8', errors='ignore')

        if decoded_str.strip() != clean_text and is_meaningful_text(decoded_str):
            return True, decoded_str.strip()

    except Exception:
        pass

    return False, None


def detect_and_decode_base64(text: str) -> Tuple[bool, Optional[str]]:
    """
    Detects if the input string is Base64 encoded and decodes it if valid.

    Args:
        text (str): Cleaned input candidate

    Returns:
        Tuple[bool, Optional[str]]: (is_base64, decoded_text)
    """
    clean_text = text.strip()

    # Minimum reasonable length for a Base64 prompt payload
    if len(clean_text) < 8:
        return False, None

    # Base64 pattern check (alphanumeric, +, /, =, and url-safe - and _)
    if not re.match(r'^[A-Za-z0-9+/=\-_\s]+$', clean_text):
        return False, None

    # If the text consists STRICTLY of hex digits, prefer hex detection over base64
    # unless hex decoding fails.
    compact_text = re.sub(r'\s+', '', clean_text)
    if re.match(r'^[0-9a-fA-F]+$', compact_text) and len(compact_text) % 2 == 0:
        is_hex, hex_decoded = detect_and_decode_hex(compact_text)
        if is_hex:
            # It's Hexadecimal, not Base64!
            return False, None

    # If it looks like standard space-separated words, it's plain text, not Base64
    words = clean_text.split()
    if len(words) > 1 and all(w.isalpha() and not w.endswith('=') for w in words):
        return False, None

    # Must be valid length or padded for base64 (multiple of 4 after adding padding)
    padding_needed = (4 - len(compact_text) % 4) % 4
    padded_text = compact_text + ('=' * padding_needed)

    try:
        # Standard or URL-safe base64 decoding
        standardized = padded_text.replace('-', '+').replace('_', '/')
        decoded_bytes = base64.b64decode(standardized, validate=True)
        decoded_str = decoded_bytes.decode('utf-8', errors='ignore')

        # Check if the decoded string is meaningful text and not identical to original
        if decoded_str.strip() != clean_text and is_meaningful_text(decoded_str):
            return True, decoded_str.strip()

    except Exception:
        pass

    return False, None


def detect_and_decode_url_encoding(text: str) -> Tuple[bool, Optional[str]]:
    """
    Detects if the input string contains URL-encoded characters (e.g., %49%67%6e%6f%72%65).

    Args:
        text (str): Input text

    Returns:
        Tuple[bool, Optional[str]]: (is_url_encoded, decoded_text)
    """
    if '%' not in text:
        return False, None

    # Check for % followed by 2 hex digits
    if not re.search(r'%[0-9a-fA-F]{2}', text):
        return False, None

    try:
        unquoted = urllib.parse.unquote(text)
        if unquoted != text and is_meaningful_text(unquoted):
            return True, unquoted.strip()
    except Exception:
        pass

    return False, None


def detect_and_decode_html_entities(text: str) -> Tuple[bool, Optional[str]]:
    """
    Detects if the input string contains HTML entity encoding (e.g. &#73;&#103;...).

    Args:
        text (str): Input text

    Returns:
        Tuple[bool, Optional[str]]: (is_html_entity, decoded_text)
    """
    if '&#' not in text:
        return False, None

    if not re.search(r'&#[0-9]+;|&#x[0-9a-fA-F]+;', text):
        return False, None

    try:
        unescaped = html.unescape(text)
        if unescaped != text and is_meaningful_text(unescaped):
            return True, unescaped.strip()
    except Exception:
        pass

    return False, None
