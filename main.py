"""
main.py - SecurePassAnalyzer CLI entry-point.

Provides an interactive command-line interface for:
  • Analysing password strength with detailed feedback
  • Generating cryptographically secure passwords / passphrases
  • Reviewing analysis history stored in a local SQLite database

Run
───
  python main.py              # interactive menu
  python main.py --analyze    # analyse a single password and exit
  python main.py --generate   # generate and print a password and exit
  python main.py --history    # show recent history and exit
"""

from __future__ import annotations

import argparse
import getpass
import os
import sys
from typing import Optional

# ── Project imports ─────────────────────────────────────────────────────────
from analyzer import analyze_password, AnalysisResult, Strength
from generator import (
    generate_password,
    generate_batch,
    generate_passphrase,
    POLICY_BASIC,
    POLICY_STANDARD,
    POLICY_HIGH_SECURITY,
    PasswordPolicy,
)
from database import PasswordDatabase


# ---------------------------------------------------------------------------
# Terminal colour helpers (no third-party deps)
# ---------------------------------------------------------------------------

_USE_COLOR = sys.stdout.isatty() and os.environ.get("NO_COLOR") is None

def _c(text: str, code: str) -> str:
    return f"\033[{code}m{text}\033[0m" if _USE_COLOR else text

def red(t: str)     -> str: return _c(t, "31")
def yellow(t: str)  -> str: return _c(t, "33")
def green(t: str)   -> str: return _c(t, "32")
def cyan(t: str)    -> str: return _c(t, "36")
def bold(t: str)    -> str: return _c(t, "1")
def dim(t: str)     -> str: return _c(t, "2")


# ---------------------------------------------------------------------------
# Display helpers
# ---------------------------------------------------------------------------

_BAR_WIDTH = 30

def _strength_color(strength: Strength) -> str:
    mapping = {
        Strength.VERY_WEAK:   red,
        Strength.WEAK:        red,
        Strength.FAIR:        yellow,
        Strength.STRONG:      green,
        Strength.VERY_STRONG: green,
    }
    return mapping.get(strength, str)(strength.value)


def _score_bar(score: int) -> str:
    filled = int(_BAR_WIDTH * score / 100)
    empty  = _BAR_WIDTH - filled
    bar    = "█" * filled + "░" * empty
    if score < 40:
        bar = red(bar)
    elif score < 70:
        bar = yellow(bar)
    else:
        bar = green(bar)
    return f"[{bar}] {score}/100"


def _print_separator(char: str = "─", width: int = 52) -> None:
    print(dim(char * width))


def _print_result(result: AnalysisResult, label: str = "Password Report") -> None:
    print()
    _print_separator("═")
    print(bold(f"  {label}"))
    _print_separator("═")

    print(f"  Score    : {_score_bar(result.score)}")
    print(f"  Strength : {_strength_color(result.strength)}")
    print(f"  Entropy  : {result.entropy_bits:.1f} bits")

    # Breakdown
    print()
    print(dim("  Breakdown"))
    _print_separator()
    for key, val in result.breakdown.items():
        sign = "+" if val >= 0 else ""
        col  = green if val > 0 else (red if val < 0 else dim)
        label_str = key.replace("_", " ").title()
        print(f"  {label_str:<22} {col(sign + str(val)):>8} pts")

    # Warnings
    if result.warnings:
        print()
        print(yellow("  ⚠  Warnings"))
        _print_separator()
        for w in result.warnings:
            print(f"  {yellow('•')} {w}")

    # Suggestions
    if result.suggestions:
        print()
        print(cyan("  💡 Suggestions"))
        _print_separator()
        for s in result.suggestions:
            print(f"  {cyan('→')} {s}")

    _print_separator("═")
    print()


def _print_passwords(passwords: list[str], title: str = "Generated Passwords") -> None:
    print()
    _print_separator("═")
    print(bold(f"  {title}"))
    _print_separator()
    for i, pw in enumerate(passwords, 1):
        print(f"  {dim(str(i) + '.')} {green(pw)}")
    _print_separator("═")
    print()


# ---------------------------------------------------------------------------
# Feature flows
# ---------------------------------------------------------------------------

def flow_analyze(save_to_db: bool = True) -> None:
    """Interactive password-strength analysis flow."""
    print()
    print(bold("  Analyse Password Strength"))
    _print_separator()

    try:
        password = getpass.getpass(
            "  Enter password (input hidden): "
        )
    except (KeyboardInterrupt, EOFError):
        print("\n  Cancelled.")
        return

    if not password:
        print(red("  No password entered."))
        return

    result = analyze_password(password)
    _print_result(result)

    if save_to_db:
        try:
            with PasswordDatabase() as db:
                db.save(result, password)
            print(dim("  ✓ Result saved to local history."))
        except Exception as exc:
            print(dim(f"  (History unavailable: {exc})"))
    print()


def flow_generate() -> None:
    """Interactive password-generation flow."""
    print()
    print(bold("  Generate Secure Password"))
    _print_separator()
    print("  Choose a policy:")
    print(f"  {cyan('1')} Basic         (12 chars)")
    print(f"  {cyan('2')} Standard      (16 chars)  [default]")
    print(f"  {cyan('3')} High Security  (24 chars, no ambiguous)")
    print(f"  {cyan('4')} Passphrase     (4 memorable words)")
    print(f"  {cyan('5')} Custom")
    print()

    choice = input("  Select [1-5]: ").strip() or "2"

    if choice == "1":
        policy = POLICY_BASIC
        passwords = generate_batch(5, policy)
        _print_passwords(passwords, "Basic Passwords")

    elif choice == "2":
        passwords = generate_batch(5, POLICY_STANDARD)
        _print_passwords(passwords, "Standard Passwords")

    elif choice == "3":
        passwords = generate_batch(5, POLICY_HIGH_SECURITY)
        _print_passwords(passwords, "High-Security Passwords (no ambiguous chars)")

    elif choice == "4":
        try:
            n = int(input("  Number of words [4]: ").strip() or "4")
            n = max(3, min(8, n))
        except ValueError:
            n = 4
        phrases = [generate_passphrase(word_count=n) for _ in range(5)]
        _print_passwords(phrases, "Passphrases")

    elif choice == "5":
        try:
            length    = int(input("  Length [16]:           ").strip() or "16")
            min_upper = int(input("  Min uppercase [2]:     ").strip() or "2")
            min_lower = int(input("  Min lowercase [2]:     ").strip() or "2")
            min_digit = int(input("  Min digits [2]:        ").strip() or "2")
            min_spec  = int(input("  Min specials [2]:      ").strip() or "2")
            policy    = PasswordPolicy(
                length=length,
                min_uppercase=min_upper,
                min_lowercase=min_lower,
                min_digits=min_digit,
                min_special=min_spec,
            )
            passwords = generate_batch(5, policy)
            _print_passwords(passwords, "Custom Passwords")
        except (ValueError, Exception) as exc:
            print(red(f"\n  Error: {exc}"))
            return
    else:
        print(yellow("  Invalid choice."))


def flow_history() -> None:
    """Display recent analysis history."""
    print()
    print(bold("  Analysis History"))
    _print_separator()

    try:
        with PasswordDatabase() as db:
            records = db.recent(15)
            stats   = db.stats()
    except Exception as exc:
        print(red(f"  Could not open history database: {exc}"))
        return

    if not records:
        print(dim("  No records found."))
        print()
        return

    # Stats summary
    print(f"  Total analyses : {stats.get('total', 0)}")
    print(f"  Average score  : {stats.get('avg_score', 'N/A')}/100")
    print(f"  Best score     : {stats.get('max_score', 'N/A')}/100")
    print(f"  Lowest score   : {stats.get('min_score', 'N/A')}/100")
    _print_separator()

    for record in records:
        score_col = green if record.score >= 70 else (yellow if record.score >= 40 else red)
        print(
            f"  {dim('#' + str(record.id)):<8} "
            f"{dim(record.checked_at)}  "
            f"score={score_col(str(record.score) + '/100'):<18} "
            f"strength={record.strength}"
        )

    _print_separator("═")
    print()


# ---------------------------------------------------------------------------
# CLI argument parsing
# ---------------------------------------------------------------------------

def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="securepass",
        description="SecurePassAnalyzer — password strength analysis & generation tool",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=(
            "Examples:\n"
            "  python main.py                 # interactive menu\n"
            "  python main.py --analyze       # analyse one password\n"
            "  python main.py --generate      # generate passwords\n"
            "  python main.py --history       # show recent history\n"
        ),
    )
    group = parser.add_mutually_exclusive_group()
    group.add_argument("--analyze",  "-a", action="store_true", help="Analyse a password and exit")
    group.add_argument("--generate", "-g", action="store_true", help="Generate passwords and exit")
    group.add_argument("--history",  "-H", action="store_true", help="Show analysis history and exit")
    parser.add_argument("--no-save", action="store_true", help="Do not persist analysis to history")
    return parser


# ---------------------------------------------------------------------------
# Interactive menu
# ---------------------------------------------------------------------------

_BANNER = r"""
  ┌──────────────────────────────────────────┐
  │   🔐  SecurePassAnalyzer  v2.0           │
  │   Professional Password Security Tool    │
  └──────────────────────────────────────────┘
"""

def _interactive_menu() -> None:
    print(bold(cyan(_BANNER)))

    while True:
        print(bold("  Main Menu"))
        _print_separator()
        print(f"  {cyan('1')}  Analyse a password")
        print(f"  {cyan('2')}  Generate secure passwords")
        print(f"  {cyan('3')}  View analysis history")
        print(f"  {cyan('q')}  Quit")
        print()

        choice = input("  Select option: ").strip().lower()
        print()

        if choice == "1":
            flow_analyze()
        elif choice == "2":
            flow_generate()
        elif choice == "3":
            flow_history()
        elif choice in ("q", "quit", "exit"):
            print(dim("  Goodbye.\n"))
            break
        else:
            print(yellow("  Unknown option.  Please choose 1, 2, 3, or q.\n"))


# ---------------------------------------------------------------------------
# Entry-point
# ---------------------------------------------------------------------------

def main(argv: Optional[list[str]] = None) -> int:
    parser = _build_parser()
    args   = parser.parse_args(argv)

    save = not args.no_save

    if args.analyze:
        flow_analyze(save_to_db=save)
    elif args.generate:
        flow_generate()
    elif args.history:
        flow_history()
    else:
        _interactive_menu()

    return 0


if __name__ == "__main__":
    sys.exit(main())