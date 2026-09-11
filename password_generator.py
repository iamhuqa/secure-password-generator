"""Core password generation module.

Provides cryptographically secure generation of character-based passwords
and EFF wordlist-based passphrases using Python's secrets module.
"""

import string
import secrets
from pathlib import Path
from typing import List, Optional, Sequence

DEFAULT_WORDLIST_PATH = Path(__file__).resolve().parent / "wordlist.txt"
_CACHED_WORDLIST: Optional[List[str]] = None


def load_wordlist(wordlist_path: Optional[Path | str] = None) -> List[str]:
    """Load the wordlist from disk. Uses module cache when possible.

    Args:
        wordlist_path: Path to the wordlist file. Defaults to DEFAULT_WORDLIST_PATH.

    Returns:
        A list of words from the file.

    Raises:
        FileNotFoundError: If the wordlist file does not exist.
        ValueError: If the wordlist file contains no valid words.
    """
    global _CACHED_WORDLIST

    path = Path(wordlist_path) if wordlist_path else DEFAULT_WORDLIST_PATH

    # Return cached words if loading default wordlist
    if wordlist_path is None and _CACHED_WORDLIST is not None:
        return _CACHED_WORDLIST

    if not path.is_file():
        raise FileNotFoundError(f"Wordlist file not found at: {path}")

    with open(path, "r", encoding="utf-8") as f:
        words = [line.strip() for line in f if line.strip()]

    if not words:
        raise ValueError(f"Wordlist at {path} is empty.")

    if wordlist_path is None:
        _CACHED_WORDLIST = words

    return words


def generate_password(
    length: int = 16,
    include_uppercase: bool = True,
    include_lowercase: bool = True,
    include_digits: bool = True,
    include_symbols: bool = True,
    symbols: Optional[str] = None,
) -> str:
    """Generate a cryptographically secure random password.

    Args:
        length: Desired password length. Must be >= 1.
        include_uppercase: Include uppercase ASCII letters (A-Z).
        include_lowercase: Include lowercase ASCII letters (a-z).
        include_digits: Include digits (0-9).
        include_symbols: Include punctuation / symbol characters.
        symbols: Custom symbols string. Defaults to string.punctuation if None.

    Returns:
        A cryptographically secure random password string.

    Raises:
        ValueError: If length < 1 or no character types are selected.
    """
    if length < 1:
        raise ValueError("Password length must be at least 1.")

    pools: List[str] = []
    if include_lowercase:
        pools.append(string.ascii_lowercase)
    if include_uppercase:
        pools.append(string.ascii_uppercase)
    if include_digits:
        pools.append(string.digits)
    if include_symbols:
        pools.append(symbols if symbols is not None else string.punctuation)

    if not pools:
        raise ValueError("At least one character type must be selected.")

    chars: List[str] = []
    combined_pool = "".join(pools)

    # Ensure at least one character from each selected category if length allows
    if length >= len(pools):
        for pool in pools:
            chars.append(secrets.choice(pool))
        remaining = length - len(chars)
        for _ in range(remaining):
            chars.append(secrets.choice(combined_pool))
        # Cryptographically secure in-place shuffle
        secrets.SystemRandom().shuffle(chars)
    else:
        for _ in range(length):
            chars.append(secrets.choice(combined_pool))

    return "".join(chars)


def generate_passphrase(
    words: int = 6,
    separator: str = "-",
    wordlist: Optional[Sequence[str]] = None,
    wordlist_path: Optional[Path | str] = None,
) -> str:
    """Generate a cryptographically secure passphrase using EFF wordlist.

    Args:
        words: Number of words in the passphrase. Must be >= 1.
        separator: String delimiter placed between words.
        wordlist: Optional pre-loaded wordlist. If None, loaded from disk.
        wordlist_path: Optional custom path to wordlist.

    Returns:
        A passphrase string composed of randomly chosen words.

    Raises:
        ValueError: If words < 1 or wordlist is empty.
    """
    if words < 1:
        raise ValueError("Passphrase word count must be at least 1.")

    pool = list(wordlist) if wordlist is not None else load_wordlist(wordlist_path)
    if not pool:
        raise ValueError("Wordlist cannot be empty.")

    selected_words = [secrets.choice(pool) for _ in range(words)]
    return separator.join(selected_words)
