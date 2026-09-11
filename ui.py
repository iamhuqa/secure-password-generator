"""Rich terminal UI module for Secure Password Generator.

Provides formatted panels, tables, strength bars, and color-coded status
using the Rich library.
"""

import sys
from typing import List, Optional
from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.text import Text
from rich import box

# Ensure UTF-8 output encoding on Windows consoles
if sys.platform == "win32":
    try:
        if sys.stdout and hasattr(sys.stdout, "reconfigure"):
            sys.stdout.reconfigure(encoding="utf-8")
        if sys.stderr and hasattr(sys.stderr, "reconfigure"):
            sys.stderr.reconfigure(encoding="utf-8")
    except Exception:
        pass

console = Console()
error_console = Console(stderr=True)


def get_strength_style(strength: str) -> str:
    """Return Rich style string based on strength classification."""
    s = strength.strip().lower()
    if "very strong" in s:
        return "bold bright_green"
    elif "strong" in s:
        return "green"
    elif "fair" in s:
        return "yellow"
    else:
        return "red"


def render_strength_bar(entropy_bits: float, strength: str, max_blocks: int = 12) -> str:
    """Render a text-based visual strength meter using block characters.

    Args:
        entropy_bits: Entropy in bits.
        strength: Strength classification ('Weak', 'Fair', 'Strong', 'Very Strong').
        max_blocks: Total number of blocks in the meter.

    Returns:
        A Rich markup formatted string (e.g. '[green]████████░░░░[/]').
    """
    fraction = min(max(entropy_bits / 100.0, 0.0), 1.0)
    filled = int(round(fraction * max_blocks))
    if entropy_bits > 0 and filled == 0:
        filled = 1
    empty = max_blocks - filled

    style = get_strength_style(strength)
    filled_str = "█" * filled
    empty_str = "░" * empty

    return f"[{style}]{filled_str}[/][dim]{empty_str}[/dim]"


def display_password_result(
    password: str,
    entropy_bits: float,
    strength: str,
    crack_time: str,
) -> None:
    """Display a generated password in a styled panel and an analysis table.

    Args:
        password: The generated password string.
        entropy_bits: Password entropy in bits.
        strength: Strength classification string.
        crack_time: Human-readable crack time estimate.
    """
    style = get_strength_style(strength)
    bar = render_strength_bar(entropy_bits, strength)

    # Main password panel
    pwd_text = Text(password, style="bold bright_white")
    panel = Panel(
        pwd_text,
        title="[bold cyan]Generated Password[/bold cyan]",
        subtitle=f"[dim]Length: {len(password)} characters[/dim]",
        border_style="cyan",
        box=box.ROUNDED,
        expand=False,
        padding=(1, 3),
    )
    console.print()
    console.print(panel)

    # Security analysis table
    table = Table(
        title="Security & Strength Analysis",
        box=box.ROUNDED,
        show_header=True,
        header_style="bold cyan",
    )
    table.add_column("Metric", style="bold white", width=22)
    table.add_column("Value")

    table.add_row("Entropy", f"[white]{entropy_bits:.1f} bits[/white]")
    table.add_row("Strength Rating", f"[{style}]{strength}[/{style}]  {bar}")
    table.add_row("Est. Crack Time", f"[bold white]{crack_time}[/bold white]")

    console.print(table)
    console.print()


def display_passphrase_result(passphrase: str) -> None:
    """Display a generated passphrase in a styled panel.

    Args:
        passphrase: The generated passphrase string.
    """
    panel = Panel(
        Text(passphrase, style="bold bright_yellow"),
        title="[bold green]Generated Passphrase[/bold green]",
        subtitle="[dim]EFF Diceware Cryptographic Wordlist[/dim]",
        border_style="green",
        box=box.ROUNDED,
        expand=False,
        padding=(1, 3),
    )
    console.print()
    console.print(panel)
    console.print()


def display_multiple_results(
    results: List[str],
    entropy_bits: Optional[float] = None,
    strength: Optional[str] = None,
    crack_time: Optional[str] = None,
    is_passphrase: bool = False,
) -> None:
    """Display multiple generated passwords or passphrases in a numbered table.

    Args:
        results: List of generated password or passphrase strings.
        entropy_bits: Optional entropy in bits (for passwords).
        strength: Optional strength rating (for passwords).
        crack_time: Optional crack time (for passwords).
        is_passphrase: True if displaying passphrases.
    """
    title = "Generated Passphrases" if is_passphrase else "Generated Passwords"
    header_col = "Passphrase" if is_passphrase else "Password"
    val_style = "bold bright_yellow" if is_passphrase else "bold bright_white"

    table = Table(
        title=f"[bold cyan]{title} ({len(results)} total)[/bold cyan]",
        box=box.ROUNDED,
        show_header=True,
        header_style="bold cyan",
    )
    table.add_column("#", justify="right", style="bold cyan", width=4)
    table.add_column(header_col, style=val_style)

    for idx, item in enumerate(results, start=1):
        table.add_row(str(idx), item)

    console.print()
    console.print(table)

    # If entropy information is provided, display summary table below
    if entropy_bits is not None and strength is not None and crack_time is not None:
        style = get_strength_style(strength)
        bar = render_strength_bar(entropy_bits, strength)

        analysis_table = Table(
            title="Security Profile (Applies to all generated items)",
            box=box.ROUNDED,
            show_header=True,
            header_style="bold cyan",
        )
        analysis_table.add_column("Metric", style="bold white", width=22)
        analysis_table.add_column("Value")

        analysis_table.add_row("Entropy", f"[white]{entropy_bits:.1f} bits[/white]")
        analysis_table.add_row("Strength Rating", f"[{style}]{strength}[/{style}]  {bar}")
        analysis_table.add_row("Est. Crack Time", f"[bold white]{crack_time}[/bold white]")

        console.print(analysis_table)

    console.print()


def display_error(message: str) -> None:
    """Display an error message using Rich red styling."""
    error_console.print(f"[bold red][!] Error:[/] {message}")


def display_wizard_header() -> None:
    """Display styled header for interactive mode."""
    panel = Panel(
        Text(
            "Secure Password Generator\nCryptographically Secure Generator & Strength Analyzer",
            justify="center",
            style="bold cyan",
        ),
        box=box.DOUBLE,
        border_style="cyan",
        expand=False,
        padding=(1, 4),
    )
    console.print()
    console.print(panel)
    console.print("[dim]No CLI arguments detected. Running interactive wizard.[/dim]\n")


def display_section(title: str) -> None:
    """Display a section divider in the wizard."""
    console.print(f"\n[bold cyan]─── {title} ───[/bold cyan]")
