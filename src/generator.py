"""
generator.py

Generates strong random passwords. This is the only module that
imports Python's `secrets` module — kept separate from analyzer.py
so the analysis logic has zero dependency on how passwords are
created, and can analyze any password regardless of its origin.
"""

import string
import secrets


def generate_password(length: int = 16, use_symbols: bool = True) -> str:
    """
    Generate a cryptographically secure random password.

    Args:
        length: Desired password length. Minimum enforced at 8.
        use_symbols: Whether to include punctuation symbols in the
            character pool, in addition to letters and digits.

    Returns:
        A randomly generated password string guaranteed to contain
        at least one lowercase letter, one uppercase letter, one
        digit, and (if use_symbols) one symbol.

    Raises:
        ValueError: If length is below 8.
    """
    if length < 8:
        raise ValueError("Password length must be at least 8 characters for reasonable security.")

    alphabet = string.ascii_lowercase + string.ascii_uppercase + string.digits
    if use_symbols:
        alphabet += string.punctuation

    # Guarantee at least one character from each required class, so a
    # long random draw can't unluckily skip a whole category (e.g. an
    # all-lowercase result from pure chance, however unlikely).
    required = [
        secrets.choice(string.ascii_lowercase),
        secrets.choice(string.ascii_uppercase),
        secrets.choice(string.digits),
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
