#!/usr/bin/env python3
"""Main CLI entrypoint for Secure Password Generator.

Supports command-line arguments via argparse as well as an interactive
step-by-step wizard when invoked without arguments, styled with Rich.
"""

import sys
import argparse
import csv
import threading
import time
from pathlib import Path
from typing import List, Optional

import pyperclip

from password_generator import (
    generate_password,
    generate_passphrase,
    get_pool_size,
)
from entropy import (
    calculate_entropy,
    estimate_crack_time,
    classify_strength,
)
from breach_check import check_password_breach
from profiles import save_profile, load_profile, list_profiles
from ui import (
    console,
    display_error,
    display_password_result,
    display_passphrase_result,
    display_multiple_results,
    display_breach_result,
    display_export_confirmation,
    display_clipboard_message,
    display_profiles_list,
    display_profile_saved,
    display_wizard_header,
    display_section,
)


def build_parser() -> argparse.ArgumentParser:
    """Create and configure the argparse argument parser."""
    parser = argparse.ArgumentParser(
        description="Secure Password Generator - generate cryptographically secure passwords and passphrases."
    )
    parser.add_argument(
        "--length",
        type=int,
        default=16,
        help="Password length (default: 16)",
    )
    parser.add_argument(
        "--count",
        type=int,
        default=1,
        help="Number of passwords or passphrases to generate (default: 1)",
    )
    parser.add_argument(
        "--no-uppercase",
        dest="no_uppercase",
        action="store_true",
        help="Exclude uppercase letters (A-Z)",
    )
    parser.add_argument(
        "--uppercase",
        dest="no_uppercase",
        action="store_false",
        help="Include uppercase letters (A-Z)",
    )
    parser.add_argument(
        "--no-lowercase",
        dest="no_lowercase",
        action="store_true",
        help="Exclude lowercase letters (a-z)",
    )
    parser.add_argument(
        "--lowercase",
        dest="no_lowercase",
        action="store_false",
        help="Include lowercase letters (a-z)",
    )
    parser.add_argument(
        "--no-digits",
        dest="no_digits",
        action="store_true",
        help="Exclude digits (0-9)",
    )
    parser.add_argument(
        "--digits",
        dest="no_digits",
        action="store_false",
        help="Include digits (0-9)",
    )
    parser.add_argument(
        "--no-symbols",
        dest="no_symbols",
        action="store_true",
        help="Exclude symbols / special characters",
    )
    parser.add_argument(
        "--symbols",
        dest="no_symbols",
        action="store_false",
        help="Include symbols / special characters",
    )
    parser.add_argument(
        "--exclude-ambiguous",
        action="store_true",
        help="Exclude visually confusable characters (0, O, o, 1, l, I, |)",
    )
    parser.add_argument(
        "--avoid-sequential",
        action="store_true",
        help="Avoid 3+ sequential (e.g. 'abc', '123') or repeated ('aaa') characters",
    )
    parser.add_argument(
        "--check-breach",
        action="store_true",
        help="Check generated password(s) against HaveIBeenPwned breach database using k-anonymity",
    )
    parser.add_argument(
        "--passphrase",
        action="store_true",
        help="Switch to passphrase mode instead of random characters",
    )
    parser.add_argument(
        "--words",
        type=int,
        default=6,
        help="Number of words when in passphrase mode (default: 6)",
    )
    parser.add_argument(
        "--separator",
        type=str,
        default="-",
        help="Separator character between passphrase words (default: '-')",
    )
    # Phase 5: Export, Clipboard auto-clear, and Config profiles
    parser.add_argument(
        "--export",
        type=str,
        default=None,
        metavar="FILEPATH",
        help="Export generated passwords/passphrases to a .csv or .txt file",
    )
    parser.add_argument(
        "--copy",
        action="store_true",
        help="Copy the first generated password/passphrase to the system clipboard",
    )
    parser.add_argument(
        "--clear-after",
        type=int,
        default=30,
        metavar="SECONDS",
        help="Seconds before auto-clearing clipboard if unchanged (default: 30)",
    )
    parser.add_argument(
        "--save-profile",
        type=str,
        default=None,
        metavar="NAME",
        help="Save current configuration settings as a named profile",
    )
    parser.add_argument(
        "--load-profile",
        type=str,
        default=None,
        metavar="NAME",
        help="Load settings from a named configuration profile",
    )
    parser.add_argument(
        "--list-profiles",
        action="store_true",
        help="List all saved configuration profiles and exit",
    )
    return parser


def copy_to_clipboard_with_autoclear(target_text: str, delay_seconds: int = 30) -> None:
    """Copy text to clipboard and launch a background thread to clear it after delay."""
    try:
        pyperclip.copy(target_text)
    except Exception as exc:
        display_error(f"Failed to copy to clipboard: {exc}")
        return

    def _clear_worker():
        time.sleep(delay_seconds)
        try:
            current = pyperclip.paste()
            if current == target_text:
                pyperclip.copy("")
        except Exception:
            pass

    thread = threading.Thread(target=_clear_worker, name="ClipboardAutoClear", daemon=False)
    thread.start()
    display_clipboard_message(delay_seconds)


def export_items_to_file(
    filepath: str,
    items: List[str],
    entropy_bits: Optional[float] = None,
    strength: Optional[str] = None,
    is_passphrase: bool = False,
) -> None:
    """Export generated passwords or passphrases to a .csv or .txt file."""
    path = Path(filepath)
    path.parent.mkdir(parents=True, exist_ok=True)
    ext = path.suffix.lower()

    if ext == ".csv":
        with open(path, "w", newline="", encoding="utf-8") as f:
            writer = csv.writer(f)
            if not is_passphrase and entropy_bits is not None and strength is not None:
                writer.writerow(["password", "entropy_bits", "strength"])
                for item in items:
                    writer.writerow([item, f"{entropy_bits:.1f}", strength])
            else:
                header = "passphrase" if is_passphrase else "password"
                writer.writerow([header])
                for item in items:
                    writer.writerow([item])
        display_export_confirmation(len(items), str(path), is_passphrase=is_passphrase)
    elif ext == ".txt":
        with open(path, "w", encoding="utf-8") as f:
            for item in items:
                f.write(f"{item}\n")
        display_export_confirmation(len(items), str(path), is_passphrase=is_passphrase)
    else:
        raise ValueError(f"Unsupported export format '{ext}'. Only .csv and .txt are supported.")


def prompt_int(prompt_text: str, default: int, min_val: int = 1) -> int:
    """Prompt the user for an integer with a default value and minimum bound."""
    while True:
        try:
            val_str = input(f"{prompt_text} (default: {default}): ").strip()
            if not val_str:
                return default
            val = int(val_str)
            if val < min_val:
                console.print(f"  [yellow]Please enter a number >= {min_val}.[/yellow]")
                continue
            return val
        except ValueError:
            console.print("  [yellow]Invalid number. Please enter a valid integer.[/yellow]")


def prompt_bool(prompt_text: str, default: bool = True) -> bool:
    """Prompt the user for a yes/no boolean answer."""
    hint = "[Y/n]" if default else "[y/N]"
    while True:
        response = input(f"{prompt_text} {hint}: ").strip().lower()
        if not response:
            return default
        if response in ("y", "yes"):
            return True
        if response in ("n", "no"):
            return False
        console.print("  [yellow]Please enter 'y' for yes or 'n' for no.[/yellow]")


def run_interactive() -> None:
    """Run an interactive wizard to guide the user step by step."""
    display_wizard_header()

    console.print("[bold]Choose generation mode:[/bold]")
    console.print("  [cyan][1][/cyan] Character-based password (default)")
    console.print("  [cyan][2][/cyan] Passphrase (word-based)")
    mode_choice = input("Select mode [1/2] (default: 1): ").strip()

    is_passphrase = mode_choice == "2"

    if is_passphrase:
        display_section("Passphrase Settings")
        words = prompt_int("Enter number of words", default=6, min_val=1)
        sep = input("Enter word separator (default: '-'): ")
        if not sep:
            sep = "-"
        count = prompt_int("Number of passphrases to generate", default=1, min_val=1)

        display_section("Options & Clipboard")
        copy_clip = prompt_bool("Copy first result to clipboard (with auto-clear)?", default=False)
        clear_delay = 30
        if copy_clip:
            clear_delay = prompt_int("Seconds before clipboard auto-clears", default=30, min_val=1)

        export_file = input("Export results to file? (e.g. passphrases.txt, or press Enter to skip): ").strip()

        passphrases = [generate_passphrase(words=words, separator=sep) for _ in range(count)]

        if count == 1:
            display_passphrase_result(passphrases[0])
        else:
            display_multiple_results(passphrases, is_passphrase=True)

        if export_file:
            try:
                export_items_to_file(export_file, passphrases, is_passphrase=True)
            except Exception as exc:
                display_error(f"Export failed: {exc}")

        if copy_clip and passphrases:
            copy_to_clipboard_with_autoclear(passphrases[0], delay_seconds=clear_delay)

    else:
        display_section("Character Password Settings")
        length = prompt_int("Enter password length", default=16, min_val=1)

        while True:
            console.print("\n[bold]Select character types to include:[/bold]")
            inc_upper = prompt_bool("Include uppercase letters (A-Z)?", default=True)
            inc_lower = prompt_bool("Include lowercase letters (a-z)?", default=True)
            inc_digits = prompt_bool("Include digits (0-9)?", default=True)
            inc_symbols = prompt_bool("Include symbols (!@#$...)?", default=True)

            if inc_upper or inc_lower or inc_digits or inc_symbols:
                break
            display_error("You must select at least one character type. Please try again.")

        display_section("Smart Character Rules")
        exc_ambig = prompt_bool("Exclude ambiguous characters (0/O, 1/l/I, etc.)?", default=False)
        avoid_seq = prompt_bool("Avoid sequential or repeated characters (e.g., 'abc', '111')?", default=False)

        display_section("Breach Database Check")
        check_breach = prompt_bool("Check this password against known data breaches?", default=False)

        display_section("Options & Clipboard")
        count = prompt_int("Number of passwords to generate", default=1, min_val=1)
        copy_clip = prompt_bool("Copy first result to clipboard (with auto-clear)?", default=False)
        clear_delay = 30
        if copy_clip:
            clear_delay = prompt_int("Seconds before clipboard auto-clears", default=30, min_val=1)

        export_file = input("Export results to file? (e.g. passwords.csv, or press Enter to skip): ").strip()

        pool_size = get_pool_size(
            include_uppercase=inc_upper,
            include_lowercase=inc_lower,
            include_digits=inc_digits,
            include_symbols=inc_symbols,
            exclude_ambiguous=exc_ambig,
        )

        passwords: List[str] = [
            generate_password(
                length=length,
                include_uppercase=inc_upper,
                include_lowercase=inc_lower,
                include_digits=inc_digits,
                include_symbols=inc_symbols,
                exclude_ambiguous=exc_ambig,
                avoid_sequential=avoid_seq,
            )
            for _ in range(count)
        ]

        entropy_bits = calculate_entropy(passwords[0], pool_size)
        strength = classify_strength(entropy_bits)
        crack_time = estimate_crack_time(entropy_bits)

        if count == 1:
            display_password_result(passwords[0], entropy_bits, strength, crack_time)
            if check_breach:
                breach_count = check_password_breach(passwords[0])
                display_breach_result(breach_count)
        else:
            display_multiple_results(
                passwords,
                entropy_bits=entropy_bits,
                strength=strength,
                crack_time=crack_time,
                is_passphrase=False,
            )
            if check_breach:
                for i, pwd in enumerate(passwords, start=1):
                    console.print(f"[bold cyan]Breach status for Password #{i}:[/bold cyan]")
                    breach_count = check_password_breach(pwd)
                    display_breach_result(breach_count)

        if export_file:
            try:
                export_items_to_file(
                    export_file,
                    passwords,
                    entropy_bits=entropy_bits,
                    strength=strength,
                    is_passphrase=False,
                )
            except Exception as exc:
                display_error(f"Export failed: {exc}")

        if copy_clip and passwords:
            copy_to_clipboard_with_autoclear(passwords[0], delay_seconds=clear_delay)


def run_cli(args: argparse.Namespace) -> int:
    """Execute password generation based on parsed command line arguments."""
    if args.count < 1:
        display_error("--count must be at least 1.")
        return 1

    try:
        if args.passphrase:
            if args.words < 1:
                display_error("--words must be at least 1.")
                return 1

            passphrases = [
                generate_passphrase(words=args.words, separator=args.separator)
                for _ in range(args.count)
            ]

            if args.count == 1:
                display_passphrase_result(passphrases[0])
            else:
                display_multiple_results(passphrases, is_passphrase=True)

            if args.export:
                export_items_to_file(args.export, passphrases, is_passphrase=True)

            if args.copy and passphrases:
                copy_to_clipboard_with_autoclear(passphrases[0], delay_seconds=args.clear_after)

        else:
            if args.length < 1:
                display_error("--length must be at least 1.")
                return 1

            include_upper = not args.no_uppercase
            include_lower = not args.no_lowercase
            include_digits = not args.no_digits
            include_symbols = not args.no_symbols

            if not (include_upper or include_lower or include_digits or include_symbols):
                display_error(
                    "At least one character type must be included (all types were excluded)."
                )
                return 1

            pool_size = get_pool_size(
                include_uppercase=include_upper,
                include_lowercase=include_lower,
                include_digits=include_digits,
                include_symbols=include_symbols,
                exclude_ambiguous=args.exclude_ambiguous,
            )

            passwords: List[str] = [
                generate_password(
                    length=args.length,
                    include_uppercase=include_upper,
                    include_lowercase=include_lower,
                    include_digits=include_digits,
                    include_symbols=include_symbols,
                    exclude_ambiguous=args.exclude_ambiguous,
                    avoid_sequential=args.avoid_sequential,
                )
                for _ in range(args.count)
            ]

            entropy_bits = calculate_entropy(passwords[0], pool_size)
            strength = classify_strength(entropy_bits)
            crack_time = estimate_crack_time(entropy_bits)

            if args.count == 1:
                display_password_result(passwords[0], entropy_bits, strength, crack_time)
                if args.check_breach:
                    breach_count = check_password_breach(passwords[0])
                    display_breach_result(breach_count)
            else:
                display_multiple_results(
                    passwords,
                    entropy_bits=entropy_bits,
                    strength=strength,
                    crack_time=crack_time,
                    is_passphrase=False,
                )
                if args.check_breach:
                    for i, pwd in enumerate(passwords, start=1):
                        console.print(f"[bold cyan]Breach status for Password #{i}:[/bold cyan]")
                        breach_count = check_password_breach(pwd)
                        display_breach_result(breach_count)

            if args.export:
                export_items_to_file(
                    args.export,
                    passwords,
                    entropy_bits=entropy_bits,
                    strength=strength,
                    is_passphrase=False,
                )

            if args.copy and passwords:
                copy_to_clipboard_with_autoclear(passwords[0], delay_seconds=args.clear_after)

        # Save profile if requested
        if args.save_profile:
            profile_settings = {
                "length": args.length,
                "count": args.count,
                "no_uppercase": args.no_uppercase,
                "no_lowercase": args.no_lowercase,
                "no_digits": args.no_digits,
                "no_symbols": args.no_symbols,
                "exclude_ambiguous": args.exclude_ambiguous,
                "avoid_sequential": args.avoid_sequential,
                "check_breach": args.check_breach,
                "passphrase": args.passphrase,
                "words": args.words,
                "separator": args.separator,
                "copy": args.copy,
                "clear_after": args.clear_after,
            }
            saved_path = save_profile(args.save_profile, profile_settings)
            display_profile_saved(args.save_profile, str(saved_path))

        return 0
    except Exception as exc:
        display_error(str(exc))
        return 1


def main() -> int:
    """Main entrypoint."""
    if "--list-profiles" in sys.argv:
        display_profiles_list(list_profiles())
        return 0

    if len(sys.argv) == 1:
        try:
            run_interactive()
            return 0
        except (KeyboardInterrupt, EOFError):
            console.print("\n[yellow]Operation cancelled.[/yellow]")
            return 130

    parser = build_parser()

    # Pre-parse --load-profile to configure defaults before final parse
    pre_parser = argparse.ArgumentParser(add_help=False)
    pre_parser.add_argument("--load-profile", type=str, default=None)
    pre_args, _ = pre_parser.parse_known_args()

    if pre_args.load_profile:
        try:
            profile_data = load_profile(pre_args.load_profile)
            parser.set_defaults(**profile_data)
        except Exception as exc:
            display_error(str(exc))
            return 1

    args = parser.parse_args()
    return run_cli(args)


if __name__ == "__main__":
    sys.exit(main())
