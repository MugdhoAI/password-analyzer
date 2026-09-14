#!/usr/bin/env python3
"""
Password Strength Analyzer & Generator
----------------------------------------
Scores password strength using entropy math (not naive rule-counting),
explains why a password is weak or strong, and can generate strong
random passwords on request.

Usage:
    python main.py check --password "mypassword123"
    python main.py generate --length 20
    python main.py generate --length 12 --no-symbols
"""

import argparse
import getpass
import sys

from src.analyzer import analyze_password
from src.generator import generate_password


def run_check(args: argparse.Namespace) -> None:
    """Handle the 'check' subcommand: analyze a password's strength."""
    password = args.password
    if password is None:
        # Prompt securely (input is hidden) rather than requiring the
        # password to be typed as a plain command-line argument, which
        # would otherwise be visible in shell history and process lists.
        password = getpass.getpass("Enter password to analyze (input hidden): ")

    result = analyze_password(password)

    print(f"\nStrength: {result.strength_label}")
    print(f"Estimated entropy: {result.entropy_bits} bits")
    print(f"Character pool size: {result.pool_size}")
    print("\nDetails:")
    for reason in result.reasons:
        print(f"  - {reason}")


def run_generate(args: argparse.Namespace) -> None:
    """Handle the 'generate' subcommand: create a strong password."""
    try:
        password = generate_password(length=args.length, use_symbols=not args.no_symbols)
    except ValueError as e:
        print(f"Error: {e}")
        sys.exit(1)

    result = analyze_password(password)
    print(f"\nGenerated password: {password}")
    print(f"Strength: {result.strength_label} ({result.entropy_bits} bits of entropy)")


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Analyze password strength or generate a strong random password."
    )
    subparsers = parser.add_subparsers(dest="command", required=True)

    check_parser = subparsers.add_parser("check", help="Analyze the strength of a password.")
    check_parser.add_argument(
        "--password", default=None,
        help="Password to analyze. If omitted, you'll be prompted securely (input hidden)."
    )
    check_parser.set_defaults(func=run_check)

    generate_parser = subparsers.add_parser("generate", help="Generate a strong random password.")
    generate_parser.add_argument(
        "--length", type=int, default=16,
        help="Length of the generated password. Default: 16."
    )
    generate_parser.add_argument(
        "--no-symbols", action="store_true",
        help="Exclude symbols from the generated password."
    )
    generate_parser.set_defaults(func=run_generate)

    args = parser.parse_args()
    args.func(args)


if __name__ == "__main__":
    main()
