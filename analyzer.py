"""
analyzer.py - Advanced password strength analysis engine.

Evaluates passwords across multiple security dimensions including
entropy, pattern detection, character diversity, and common password
vulnerability checks.
"""

from __future__ import annotations

import math
import re
import string
from dataclasses import dataclass, field
from enum import Enum
from typing import List, Tuple


# ---------------------------------------------------------------------------
# Public constants
# ---------------------------------------------------------------------------

COMMON_PATTERNS: List[str] = [
    r"(.)\1{2,}",          # Three or more repeated chars  (aaa, 111)
    r"(?:012|123|234|345|456|567|678|789|890|abc|bcd|cde|def|efg|fgh|ghi|"
    r"hij|ijk|jkl|klm|lmn|mno|nop|opq|pqr|qrs|rst|stu|tuv|uvw|vwx|wxy|xyz)",
    r"(?:qwerty|asdf|zxcv|qazwsx|password|passw0rd|letmein|iloveyou|"
    r"admin|login|welcome|monkey|dragon|master|sunshine)",
]

KEYBOARD_WALKS: List[str] = [
    "qwerty", "qwertyuiop", "asdfghjkl", "zxcvbnm",
    "1234567890", "0987654321",
]


# ---------------------------------------------------------------------------
# Data structures
# ---------------------------------------------------------------------------

class Strength(str, Enum):
    VERY_WEAK  = "Very Weak"
    WEAK       = "Weak"
    FAIR       = "Fair"
    STRONG     = "Strong"
    VERY_STRONG = "Very Strong"


@dataclass
class AnalysisResult:
    """Immutable container for a single password analysis."""

    score: int                          # 0–100
    strength: Strength
    entropy_bits: float
    suggestions: List[str] = field(default_factory=list)
    warnings: List[str]    = field(default_factory=list)
    breakdown: dict        = field(default_factory=dict)

    # Convenience ----------------------------------------------------------
    @property
    def passed(self) -> bool:
        return self.score >= 70

    def __str__(self) -> str:  # pragma: no cover
        lines = [
            f"Score     : {self.score}/100",
            f"Strength  : {self.strength.value}",
            f"Entropy   : {self.entropy_bits:.1f} bits",
        ]
        if self.warnings:
            lines += ["", "⚠  Warnings:"] + [f"   • {w}" for w in self.warnings]
        if self.suggestions:
            lines += ["", "💡 Suggestions:"] + [f"   • {s}" for s in self.suggestions]
        return "\n".join(lines)


# ---------------------------------------------------------------------------
# Core analysis helpers
# ---------------------------------------------------------------------------

def _character_pool_size(password: str) -> int:
    """Return the effective alphabet size used in *password*."""
    pool = 0
    if re.search(r"[a-z]", password):
        pool += 26
    if re.search(r"[A-Z]", password):
        pool += 26
    if re.search(r"\d", password):
        pool += 10
    special = set(password) & set(string.punctuation)
    pool += len(special)
    return max(pool, 1)


def _calculate_entropy(password: str) -> float:
    """Shannon-inspired entropy: log2(pool ** length)."""
    pool = _character_pool_size(password)
    return len(password) * math.log2(pool)


def _detect_patterns(password: str) -> List[str]:
    """Return a list of human-readable pattern warnings found."""
    found: List[str] = []
    pw_lower = password.lower()

    for pattern in COMMON_PATTERNS:
        if re.search(pattern, pw_lower, re.IGNORECASE):
            found.append(pattern)

    for walk in KEYBOARD_WALKS:
        if walk in pw_lower:
            found.append(f"keyboard walk '{walk}'")

    return found


def _check_character_classes(password: str) -> dict:
    """Return a dict of booleans for each character class."""
    return {
        "lowercase" : bool(re.search(r"[a-z]", password)),
        "uppercase" : bool(re.search(r"[A-Z]", password)),
        "digit"     : bool(re.search(r"\d", password)),
        "special"   : bool(re.search(r"[!@#$%^&*()\-_=+\[\]{}|;:',.<>?/`~\"\\]", password)),
    }


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def analyze_password(password: str) -> AnalysisResult:
    """
    Analyse *password* and return a detailed :class:`AnalysisResult`.

    Scoring breakdown (100 points total)
    ─────────────────────────────────────
      Length           : up to 30 pts
      Character classes: up to 30 pts  (lowercase / uppercase / digit / special)
      Entropy bonus    : up to 25 pts
      Pattern penalty  : up to −25 pts
      Uniqueness ratio : up to 15 pts
    """
    if not isinstance(password, str):
        raise TypeError(f"password must be str, got {type(password).__name__!r}")

    suggestions: List[str] = []
    warnings:    List[str] = []
    breakdown:   dict      = {}

    # ── 1. Length score (0–30) ──────────────────────────────────────────
    length = len(password)
    if length == 0:
        return AnalysisResult(
            score=0,
            strength=Strength.VERY_WEAK,
            entropy_bits=0.0,
            suggestions=["Password cannot be empty."],
            warnings=["Empty password"],
        )

    length_score = min(30, int(length / 16 * 30)) if length <= 16 else 30
    if length < 8:
        suggestions.append("Use at least 8 characters (12+ is recommended).")
    elif length < 12:
        suggestions.append("Consider extending to 12+ characters for better security.")
    breakdown["length"] = length_score

    # ── 2. Character-class score (0–30) ────────────────────────────────
    classes      = _check_character_classes(password)
    class_score  = sum(classes.values()) * 7   # max = 4 × 7 = 28 → cap at 30
    class_score  = min(30, class_score)

    if not classes["uppercase"]:
        suggestions.append("Add uppercase letters (A–Z).")
    if not classes["lowercase"]:
        suggestions.append("Add lowercase letters (a–z).")
    if not classes["digit"]:
        suggestions.append("Include at least one digit (0–9).")
    if not classes["special"]:
        suggestions.append("Include special characters (e.g. !@#$%^&*).")
    breakdown["character_classes"] = class_score

    # ── 3. Entropy bonus (0–25) ────────────────────────────────────────
    entropy      = _calculate_entropy(password)
    # 128 bits → full score; linear below that
    entropy_score = min(25, int(entropy / 128 * 25))
    breakdown["entropy"] = entropy_score

    # ── 4. Pattern penalty (0 – −25) ───────────────────────────────────
    patterns      = _detect_patterns(password)
    pattern_penalty = min(25, len(patterns) * 10)
    if patterns:
        warnings.append(
            "Predictable patterns detected — these are easy to guess or crack."
        )
        suggestions.append(
            "Avoid keyboard walks, repeated characters, and common words."
        )
    breakdown["pattern_penalty"] = -pattern_penalty

    # ── 5. Uniqueness ratio (0–15) ─────────────────────────────────────
    unique_ratio   = len(set(password)) / length
    unique_score   = int(unique_ratio * 15)
    if unique_ratio < 0.6:
        suggestions.append("Use more varied characters — avoid repeating the same ones.")
    breakdown["uniqueness"] = unique_score

    # ── Final score ────────────────────────────────────────────────────
    raw_score = (
        length_score
        + class_score
        + entropy_score
        - pattern_penalty
        + unique_score
    )
    score = max(0, min(100, raw_score))

    # ── Strength label ─────────────────────────────────────────────────
    if score < 20:
        strength = Strength.VERY_WEAK
    elif score < 40:
        strength = Strength.WEAK
    elif score < 60:
        strength = Strength.FAIR
    elif score < 80:
        strength = Strength.STRONG
    else:
        strength = Strength.VERY_STRONG

    return AnalysisResult(
        score=score,
        strength=strength,
        entropy_bits=entropy,
        suggestions=suggestions,
        warnings=warnings,
        breakdown=breakdown,
    )