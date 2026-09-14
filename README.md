# Password Strength Analyzer & Generator

A command-line tool that scores password strength using entropy math ,not naive rule counting and explains exactly why a password is weak or strong. Can also generate cryptographically secure random passwords.

## Demo

```
$ python main.py check --password "correcthorsebatterystaple"

Strength: Very Strong
Estimated entropy: 117.5 bits
Character pool size: 26

Details:
  - Good length and character variety across multiple character classes.

$ python main.py generate --length 20

Generated password: cFHq1k(4t?@[I#c"RDyR
Strength: Very Strong (131.1 bits of entropy)
```

## Why entropy instead of naive rules?

Most password checkers score strength with simple rule counting: "+1 point for a number, +1 for a symbol." This produces misleading results ,a short password like `Xy9!` can look "complex" while a long passphrase like `correcthorsebatterystaple` gets flagged as weak for having no symbols, even though the passphrase would actually take far longer to brute-force.

This tool instead estimates entropy: `length × log2(character_pool_size)`, which measures how large a search space an attacker must brute force through. Length matters more than most people expect this tool will correctly tell you so.

## Features

- **Entropy-based scoring** (Very Weak → Very Strong), not arbitrary point counting
- **Common password detection** — instantly flags passwords from a known commonly used list
- **Human readable explanations** — every result includes specific reasons, not just a score
- **Secure password generation** using Python's `secrets` module (cryptographically secure, unlike the standard `random` module)
- **Guaranteed character variety** in generated passwords always includes at least one lowercase, uppercase, and digit (and symbol, unless disabled)
- **Hidden input option**  analyze a password without it ever appearing on screen or in shell history
- **Installable as a real CLI tool** via `pyproject.toml` run `password-analyzer` directly after installing, no need to `cd` into the project folder

## Tech Stack

- Python 3.9+
- `re` (regex) — character class detection
- `math` — entropy calculation
- `secrets` — cryptographically secure random generation
- `dataclasses` — structured result objects
- `argparse` (with subcommands) — CLI interface
- `pyproject.toml` / `setuptools` — package installation

## Getting Started

### Prerequisites
- Python 3.9 or higher (standard library only , no external dependencies)

### Installation

**Option 1 — run directly:**
```bash
git clone https://github.com/MugdhoAI/password-analyzer
cd password-analyzer
python main.py check --password "test123"
```

**Option 2 — install as a CLI tool:**
```bash
cd password-analyzer
pip install -e .
password-analyzer check --password "test123"
```

### Usage
```bash
# Analyze a password
python main.py check --password "mypassword123"

# Analyze without exposing the password as a CLI argument (prompts securely)
python main.py check

# Generate a strong 20-character password
python main.py generate --length 20

# Generate without symbols
python main.py generate --length 16 --no-symbols
```

## Project Structure
```
password-analyzer/
├── main.py                # CLI entry point with check/generate subcommands
├── src/
│   ├── analyzer.py         # Entropy calculation and strength scoring
│   └── generator.py         # Secure random password generation
├── tests/
│   └── test_main.py          # Unit tests for both modules
├── pyproject.toml
└── .gitignore
```

## Running Tests
```bash
python -m unittest discover tests
```

## What I Learned

The main insight this project is built around: password strength is fundamentally about search space size (entropy), not surface level "complexity." I also learned the real difference between Python's `random` module and `secrets` module `random` is deterministic enough to be predictable by an attacker who studies its output, while `secrets` draws from the operating system's cryptographic randomness source, which matters for anything security-related. Packaging with `pyproject.toml` also taught me that a config file looking correct isn't the same as it actually working my first attempt at `[project.scripts]` failed silently until I tested the installed command from a separate directory and caught a missing `py-modules` declaration.

## Future Improvements
- [ ] Check against a larger, real leaked-password dataset (e.g. Have I Been Pwned's API)
- [ ] Estimate realistic crack time (in seconds/days/years) instead of just raw entropy bits
- [ ] Optional GUI or web interface

## Author
**Mugdho (All Asmaul Husnain)**
[GitHub](https://github.com/MugdhoAI) | [LinkedIn](https://linkedin.com/in/mugdhoai)
