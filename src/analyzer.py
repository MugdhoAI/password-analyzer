"""
analyzer.py

Scores password strength using entropy math instead of naive rule
counting ("has a number? +1 point"). No CLI or generation logic here —
this module only analyzes a given password string and returns
structured results, same decide/act separation as the earlier
projects' classifier.py and wifi_string.py.
"""

import math
import re
from dataclasses import dataclass, field


# Character pool sizes used to estimate entropy. These represent how
# many distinct characters an attacker must guess from, per position,
# once they know which character classes are present.
POOL_LOWERCASE = 26
POOL_UPPERCASE = 26
POOL_DIGITS = 10
POOL_SYMBOLS = 32  # common punctuation/symbol set on a standard keyboard

COMMON_PASSWORDS = {
    "password", "123456", "12345678", "qwerty", "abc123", "letmein",
    "monkey", "111111", "iloveyou", "admin", "welcome", "password1",
}


@dataclass
class AnalysisResult:
    """Structured result of analyzing a password's strength."""
    entropy_bits: float
    pool_size: int
    strength_label: str
    reasons: list[str] = field(default_factory=list)
    is_common_password: bool = False


def _detect_pool_size(password: str) -> int:
    """
    Determine the total character pool size based on which character
    classes actually appear in the password. This is the core idea
    behind entropy-based scoring: strength depends on how large a
    space an attacker must search, not on arbitrary rule-checking.
    """
    pool = 0
    if re.search(r"[a-z]", password):
        pool += POOL_LOWERCASE
    if re.search(r"[A-Z]", password):
        pool += POOL_UPPERCASE
    if re.search(r"[0-9]", password):
        pool += POOL_DIGITS
    if re.search(r"[^a-zA-Z0-9]", password):
        pool += POOL_SYMBOLS
    return pool


def _calculate_entropy(password: str, pool_size: int) -> float:
    """
    Estimate password entropy in bits: log2(pool_size ^ length).

    This answers "how many guesses would a brute-force attacker need,
    in the worst case, assuming they know the character pool but not
    the password itself?" Higher entropy means exponentially more
    guesses required. This is a standard, widely-used approximation —
    not a perfect model of real-world cracking (which also accounts
    for dictionary attacks, patterns, and known leaked passwords),
    which is why it's combined with the common-password check below.
    """
    if pool_size == 0 or len(password) == 0:
        return 0.0
    return len(password) * math.log2(pool_size)


def _label_strength(entropy_bits: float, is_common: bool) -> str:
    """
    Convert a raw entropy number into a human-readable label.
    Thresholds are based on commonly cited entropy guidelines:
    under 28 bits is crackable in seconds/minutes, 60+ bits is
    considered strong against offline brute-force attacks.
    """
    if is_common:
        return "Very Weak"
    if entropy_bits < 28:
        return "Very Weak"
    if entropy_bits < 36:
        return "Weak"
    if entropy_bits < 60:
        return "Moderate"
    if entropy_bits < 80:
        return "Strong"
    return "Very Strong"


def analyze_password(password: str) -> AnalysisResult:
    """
    Analyze a password and return a structured strength assessment.

    Args:
        password: The password string to analyze.

    Returns:
        An AnalysisResult with entropy, pool size, a strength label,
        and a list of human-readable reasons explaining the result.
    """
    reasons: list[str] = []
    is_common = password.lower() in COMMON_PASSWORDS

    if is_common:
        reasons.append("This is one of the most commonly used passwords and would be guessed instantly.")

    pool_size = _detect_pool_size(password)
    entropy_bits = _calculate_entropy(password, pool_size)

    if len(password) < 8:
        reasons.append(f"Only {len(password)} characters long — under 8 characters is considered too short.")
    if not re.search(r"[A-Z]", password):
        reasons.append("No uppercase letters — reduces the character pool an attacker must search.")
    if not re.search(r"[a-z]", password):
        reasons.append("No lowercase letters — reduces the character pool an attacker must search.")
    if not re.search(r"[0-9]", password):
        reasons.append("No digits — reduces the character pool an attacker must search.")
    if not re.search(r"[^a-zA-Z0-9]", password):
        reasons.append("No symbols — adding symbols significantly increases the character pool.")

    if not reasons:
        reasons.append("Good length and character variety across multiple character classes.")

    label = _label_strength(entropy_bits, is_common)

    return AnalysisResult(
        entropy_bits=round(entropy_bits, 1),
        pool_size=pool_size,
        strength_label=label,
        reasons=reasons,
        is_common_password=is_common,
    )
