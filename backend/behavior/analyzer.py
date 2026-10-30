"""
SentinelLLM - Behavioral Analysis & Multi-Turn Session Tracker

Tracks session history, detects repeated attacks, prompt mutation/evasion,
obfuscation velocity, and risk escalation across requests in the same session.
Thread-safe, bounded in memory, with configurable TTL expiration.
"""

from abc import ABC, abstractmethod
from collections import deque
from dataclasses import dataclass
from typing import Dict, List, Optional, Set, Tuple, Any
import hashlib
import re
import threading
import time
import uuid

from config import (
    MAX_SESSION_HISTORY,
    SESSION_TTL_SECONDS,
    BEHAVIORAL_WINDOW_SECONDS,
    SIMILARITY_THRESHOLD,
    ESCALATION_SCORE_DELTA,
)


def extract_token_features(text: str) -> Set[str]:
    """
    Extracts word tokens and character 3-grams for bounded similarity comparison.
    Avoids retaining raw sensitive prompts in session history.
    """
    if not text:
        return set()
    cleaned = re.sub(r"\s+", " ", text.lower().strip())
    words = set(re.findall(r"\b\w{2,}\b", cleaned))
    # Extract char 3-grams for detecting near-duplicate obfuscation/edits
    char_grams = {cleaned[i:i + 3] for i in range(len(cleaned) - 2)} if len(cleaned) >= 3 else set()
    return words | char_grams


def jaccard_similarity(tokens_a: Set[str], tokens_b: Set[str]) -> float:
    """Calculates Jaccard similarity between two token sets."""
    if not tokens_a or not tokens_b:
        return 0.0
    intersection = len(tokens_a & tokens_b)
    union = len(tokens_a | tokens_b)
    return float(round(intersection / union, 4)) if union > 0 else 0.0


@dataclass
class PromptEvent:
    """Lightweight metadata representation of a single request event."""
    timestamp: float
    prompt_fingerprint: str
    tokens: Set[str]
    attack_score: float
    is_attack: bool
    obfuscation_detected: bool
    zero_width_detected: bool


class SessionStore(ABC):
    """Abstract interface for session storage to allow future MongoDB integration."""

    @abstractmethod
    def get_history(self, session_id: str) -> List[PromptEvent]:
        pass

    @abstractmethod
    def record_event(self, session_id: str, event: PromptEvent) -> None:
        pass

    @abstractmethod
    def cleanup_expired(self) -> None:
        pass

    @abstractmethod
    def reset_session(self, session_id: str) -> None:
        pass


class InMemorySessionStore(SessionStore):
    """
    Thread-safe, in-memory session manager with bounded history and TTL expiration.
    """

    def __init__(self, max_history: int = MAX_SESSION_HISTORY, ttl_seconds: int = SESSION_TTL_SECONDS):
        self.max_history = max_history
        self.ttl_seconds = ttl_seconds
        self._store: Dict[str, Dict[str, Any]] = {}
        self._lock = threading.RLock()

    def _is_expired(self, last_active: float, now: float) -> bool:
        return (now - last_active) > self.ttl_seconds

    def get_history(self, session_id: str) -> List[PromptEvent]:
        now = time.time()
        with self._lock:
            data = self._store.get(session_id)
            if not data:
                return []
            if self._is_expired(data["last_active"], now):
                del self._store[session_id]
                return []
            return list(data["events"])

    def record_event(self, session_id: str, event: PromptEvent) -> None:
        now = time.time()
        with self._lock:
            # Periodic cleanup on updates
            if len(self._store) > 100:
                self.cleanup_expired()

            data = self._store.get(session_id)
            if not data or self._is_expired(data["last_active"], now):
                data = {
                    "created_at": now,
                    "last_active": now,
                    "events": deque(maxlen=self.max_history),
                }
                self._store[session_id] = data

            data["last_active"] = now
            data["events"].append(event)

    def cleanup_expired(self) -> None:
        now = time.time()
        with self._lock:
            expired_keys = [
                sid for sid, d in self._store.items()
                if self._is_expired(d["last_active"], now)
            ]
            for sid in expired_keys:
                del self._store[sid]

    def reset_session(self, session_id: str) -> None:
        with self._lock:
            self._store.pop(session_id, None)

    def clear_all(self) -> None:
        with self._lock:
            self._store.clear()


class BehavioralAnalyzer:
    """
    Analyzes incoming prompts in context of the session history to generate
    behavioral indicators, escalation signals, and session risk scores.
    """

    def __init__(self, store: Optional[SessionStore] = None):
        self.store = store or InMemorySessionStore()

    def analyze_session(
        self,
        session_id: Optional[str],
        text_for_analysis: str,
        ml_result: Dict[str, Any],
        preprocessing_result: Dict[str, Any],
    ) -> Dict[str, Any]:
        """
        Evaluates behavioral context for the incoming request, computes risk score,
        and safely appends the event to session history.
        """
        # Step 1: Validate or generate session ID
        clean_sid = (session_id or "").strip()
        if not clean_sid:
            clean_sid = f"sess_{uuid.uuid4().hex[:16]}"

        now = time.time()
        current_tokens = extract_token_features(text_for_analysis)
        current_fp = hashlib.sha256(text_for_analysis.encode("utf-8")).hexdigest()[:16]
        current_score = float(ml_result.get("attack_score") or 0.0)
        current_is_attack = bool(ml_result.get("is_attack", False))
        current_obf = bool(
            preprocessing_result.get("obfuscation_detected", False)
            or preprocessing_result.get("encoding_detected")
        )
        current_zw = bool(preprocessing_result.get("zero_width_detected", False))

        # Step 2: Retrieve existing session history (prior to this event)
        history = self.store.get_history(clean_sid)

        # Step 3: Compute Behavioral Signals against history
        window_start = now - BEHAVIORAL_WINDOW_SECONDS
        recent_events = [e for e in history if e.timestamp >= window_start]
        recent_attack_events = [e for e in recent_events if e.is_attack]
        recent_suspicious_count = len(recent_attack_events)

        # Prior attack existence
        prior_attacks = [e for e in history if e.is_attack]
        prior_obfuscations = [e for e in history if e.obfuscation_detected or e.zero_width_detected]

        # Repeated attack detection
        repeated_attack_detected = current_is_attack and len(prior_attacks) > 0

        # Repeated obfuscation detection
        repeated_obfuscation_detected = (current_obf or current_zw) and len(prior_obfuscations) > 0

        # Similarity to previous attack attempts
        max_attack_similarity = 0.0
        for prior_att in prior_attacks:
            sim = jaccard_similarity(current_tokens, prior_att.tokens)
            if sim > max_attack_similarity:
                max_attack_similarity = sim

        near_duplicate_attack = (
            current_is_attack
            and max_attack_similarity >= SIMILARITY_THRESHOLD
            and len(prior_attacks) > 0
        )

        # Escalation detection
        # Triggered if previous prompt in history was non-attack (< threshold)
        # and current prompt jumped significantly into high-attack territory
        escalation_detected = False
        if history:
            prev_event = history[-1]
            score_delta = current_score - prev_event.attack_score
            if not prev_event.is_attack and current_is_attack and score_delta >= ESCALATION_SCORE_DELTA:
                escalation_detected = True
            elif len(recent_attack_events) >= 2 and score_delta >= 0.10:
                escalation_detected = True

        # Step 4: Behavioral Risk Score Calculation (0.0 to 100.0)
        # Bounded score reflecting behavioral threat intensity, distinct from ML probability
        score = 0.0
        signals: List[str] = []
        explanation_codes: List[str] = []

        if current_is_attack:
            score += 20.0
            signals.append("Current prompt flagged as attack by ML classifier.")
            explanation_codes.append("CURRENT_ATTACK_DETECTED")

        if repeated_attack_detected:
            score += 25.0
            signals.append(f"Repeated attack attempt detected in session ({len(prior_attacks)} prior attack events).")
            explanation_codes.append("REPEATED_ATTACK_ATTEMPT")

        if near_duplicate_attack:
            score += 20.0
            signals.append(f"High similarity to prior attack ({max_attack_similarity:.2f} token match) indicates evasion/mutation attempt.")
            explanation_codes.append("NEAR_DUPLICATE_ATTACK_MUTATION")

        if escalation_detected:
            score += 20.0
            signals.append("Rapid escalation in prompt attack intensity detected.")
            explanation_codes.append("ESCALATION_DETECTED")

        if recent_suspicious_count >= 2:
            velocity_boost = min(recent_suspicious_count * 10.0, 25.0)
            score += velocity_boost
            signals.append(f"High attack frequency ({recent_suspicious_count} attacks in past 5 minutes).")
            explanation_codes.append("HIGH_ATTACK_VELOCITY")

        if repeated_obfuscation_detected:
            score += 15.0
            signals.append("Repeated encoding or obfuscation detected across session events.")
            explanation_codes.append("REPEATED_OBFUSCATION")
        elif current_obf or current_zw:
            score += 5.0
            signals.append("Obfuscation or hidden Unicode character detected.")
            explanation_codes.append("OBFUSCATION_SIGNAL")

        # Safeguard: Purely benign repeated activity must NOT accumulate attack risk
        if not current_is_attack and not prior_attacks and not (current_obf or current_zw):
            score = 0.0
            signals.append("Clean session activity: benign prompt pattern.")
            explanation_codes.append("CLEAN_SESSION")

        session_risk_score = float(round(min(max(score, 0.0), 100.0), 1))

        # Step 5: Append the current event to session history
        current_event = PromptEvent(
            timestamp=now,
            prompt_fingerprint=current_fp,
            tokens=current_tokens,
            attack_score=current_score,
            is_attack=current_is_attack,
            obfuscation_detected=current_obf,
            zero_width_detected=current_zw,
        )
        self.store.record_event(clean_sid, current_event)

        return {
            "session_id": clean_sid,
            "session_risk_score": session_risk_score,
            "recent_suspicious_count": recent_suspicious_count + (1 if current_is_attack else 0),
            "repeated_attack_detected": repeated_attack_detected,
            "repeated_obfuscation_detected": repeated_obfuscation_detected,
            "similarity_score": round(max_attack_similarity, 4) if max_attack_similarity > 0 else None,
            "escalation_detected": escalation_detected,
            "signals": signals,
            "explanation_codes": explanation_codes,
        }


# Global singleton instance
_default_analyzer: Optional[BehavioralAnalyzer] = None
_analyzer_lock = threading.Lock()


def get_behavioral_analyzer() -> BehavioralAnalyzer:
    """Accessor for global BehavioralAnalyzer singleton."""
    global _default_analyzer
    if _default_analyzer is None:
        with _analyzer_lock:
            if _default_analyzer is None:
                _default_analyzer = BehavioralAnalyzer()
    return _default_analyzer


def analyze_session_behavior(
    session_id: Optional[str],
    text_for_analysis: str,
    ml_result: Dict[str, Any],
    preprocessing_result: Dict[str, Any],
) -> Dict[str, Any]:
    """Convenience helper for behavioral analysis."""
    return get_behavioral_analyzer().analyze_session(
        session_id=session_id,
        text_for_analysis=text_for_analysis,
        ml_result=ml_result,
        preprocessing_result=preprocessing_result,
    )
