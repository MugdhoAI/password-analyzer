"""
generator.py

Generates strong random passwords. This is the only module that
imports Python's `secrets` module — kept separate from analyzer.py
so the analysis logic has zero dependency on how passwords are
created, and can analyze any password regardless of its origin.
"""

import string
import secrets


# Characters that are easy to confuse when a password is read aloud
# or typed from a printed note: lowercase L, capital I, digit 1,
# capital O, digit 0.
AMBIGUOUS_CHARACTERS = "Il1O0"


def _pool(characters: str, exclude_ambiguous: bool) -> str:
    """Return a character pool, optionally without ambiguous characters."""
    if exclude_ambiguous:
        return "".join(c for c in characters if c not in AMBIGUOUS_CHARACTERS)
    return characters


def generate_password(length: int = 16, use_symbols: bool = True,
                      exclude_ambiguous: bool = False) -> str:
    """
    Generate a cryptographically secure random password.

    Args:
        length: Desired password length. Minimum enforced at 8.
        use_symbols: Whether to include punctuation symbols in the
            character pool, in addition to letters and digits.
        exclude_ambiguous: Whether to leave out characters that are
            easy to confuse (I, l, 1, O, 0), useful when a password
            must be typed from a printed note or read aloud.

    Returns:
        A randomly generated password string guaranteed to contain
        at least one lowercase letter, one uppercase letter, one
        digit, and (if use_symbols) one symbol.

    Raises:
        ValueError: If length is below 8.
    """
    if length < 8:
        raise ValueError("Password length must be at least 8 characters for reasonable security.")

    alphabet = _pool(string.ascii_lowercase, exclude_ambiguous)
    alphabet += _pool(string.ascii_uppercase, exclude_ambiguous)
    alphabet += _pool(string.digits, exclude_ambiguous)
    if use_symbols:
        alphabet += string.punctuation

    # Guarantee at least one character from each required class, so a
    # long random draw can't unluckily skip a whole category (e.g. an
    # all-lowercase result from pure chance, however unlikely).
    required = [
        secrets.choice(_pool(string.ascii_lowercase, exclude_ambiguous)),
        secrets.choice(_pool(string.ascii_uppercase, exclude_ambiguous)),
        secrets.choice(_pool(string.digits, exclude_ambiguous)),
    ]
    if use_symbols:
        required.append(secrets.choice(string.punctuation))

    remaining_length = length - len(required)
    remaining = [secrets.choice(alphabet) for _ in range(remaining_length)]

    password_chars = required + remaining
    # Shuffle so the guaranteed characters aren't predictably at the
    # start of the password — secrets.SystemRandom gives a
    # cryptographically secure shuffle, unlike random.shuffle().
    secrets.SystemRandom().shuffle(password_chars)

    return "".join(password_chars)
