"""Core password generation module.

Provides cryptographically secure generation of character-based passwords
and EFF wordlist-based passphrases using Python's secrets module.
"""

import string
import secrets
from pathlib import Path
from typing import List, Optional, Sequence, Set

DEFAULT_WORDLIST_PATH = Path(__file__).resolve().parent / "wordlist.txt"
_CACHED_WORDLIST: Optional[List[str]] = None

# Visually ambiguous characters across alphanumeric and symbols
AMBIGUOUS_CHARACTERS: Set[str] = set("0Oo1Il|")


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


def has_sequential_or_repeated(password: str) -> bool:
    """Check if password contains 3+ sequential or 3+ repeated characters in a row.

    Sequential examples: 'abc', 'cba', '123', '987'.
    Repeated examples: 'aaa', '111', '$$$'.

    Args:
        password: The string to test.

    Returns:
        True if 3+ sequential or repeated characters are found, False otherwise.
    """
    if len(password) < 3:
        return False

    for i in range(len(password) - 2):
        c1, c2, c3 = password[i], password[i + 1], password[i + 2]

        # 3+ repeated characters in a row (case-insensitive)
        if c1.lower() == c2.lower() == c3.lower():
            return True

        # 3+ sequential digits (ascending or descending)
        if c1.isdigit() and c2.isdigit() and c3.isdigit():
            d1, d2, d3 = int(c1), int(c2), int(c3)
            if (d2 == d1 + 1 and d3 == d2 + 1) or (d2 == d1 - 1 and d3 == d2 - 1):
                return True

        # 3+ sequential letters (ascending or descending, case-insensitive)
        if c1.isalpha() and c2.isalpha() and c3.isalpha():
            o1, o2, o3 = ord(c1.lower()), ord(c2.lower()), ord(c3.lower())
            if (o2 == o1 + 1 and o3 == o2 + 1) or (o2 == o1 - 1 and o3 == o2 - 1):
                return True

    return False


def get_character_pools(
    include_uppercase: bool = True,
    include_lowercase: bool = True,
    include_digits: bool = True,
    include_symbols: bool = True,
    exclude_ambiguous: bool = False,
    symbols: Optional[str] = None,
) -> List[str]:
    """Return active character pools based on selections and ambiguous character filter.

    Args:
        include_uppercase: Include uppercase ASCII letters (A-Z).
        include_lowercase: Include lowercase ASCII letters (a-z).
        include_digits: Include digits (0-9).
        include_symbols: Include punctuation / symbol characters.
        exclude_ambiguous: Exclude visually confusable characters (0/O, 1/l/I, |).
        symbols: Custom symbols string. Defaults to string.punctuation if None.

    Returns:
        A list of non-empty string pools.
    """
    pools: List[str] = []

    def filter_pool(characters: str) -> str:
        if exclude_ambiguous:
            return "".join(c for c in characters if c not in AMBIGUOUS_CHARACTERS)
        return characters

    if include_lowercase:
        p = filter_pool(string.ascii_lowercase)
        if p:
            pools.append(p)
    if include_uppercase:
        p = filter_pool(string.ascii_uppercase)
        if p:
            pools.append(p)
    if include_digits:
        p = filter_pool(string.digits)
        if p:
            pools.append(p)
    if include_symbols:
        sym = symbols if symbols is not None else string.punctuation
        p = filter_pool(sym)
        if p:
            pools.append(p)

    return pools


def get_pool_size(
    include_uppercase: bool = True,
    include_lowercase: bool = True,
    include_digits: bool = True,
    include_symbols: bool = True,
    exclude_ambiguous: bool = False,
    symbols: Optional[str] = None,
) -> int:
    """Return total number of unique characters in the allowed character pool."""
    pools = get_character_pools(
        include_uppercase=include_uppercase,
        include_lowercase=include_lowercase,
        include_digits=include_digits,
        include_symbols=include_symbols,
        exclude_ambiguous=exclude_ambiguous,
        symbols=symbols,
    )
    return len("".join(pools))


def _generate_single_password(
    pools: List[str],
    length: int,
) -> str:
    """Helper to generate a single password given pools and length."""
    chars: List[str] = []
    combined_pool = "".join(pools)

    # Ensure at least one character from each selected pool if length permits
    if length >= len(pools):
        for pool in pools:
            chars.append(secrets.choice(pool))
        remaining = length - len(chars)
        for _ in range(remaining):
            chars.append(secrets.choice(combined_pool))
        secrets.SystemRandom().shuffle(chars)
    else:
        for _ in range(length):
            chars.append(secrets.choice(combined_pool))

    return "".join(chars)


def generate_password(
    length: int = 16,
    include_uppercase: bool = True,
    include_lowercase: bool = True,
    include_digits: bool = True,
    include_symbols: bool = True,
    exclude_ambiguous: bool = False,
    avoid_sequential: bool = False,
    symbols: Optional[str] = None,
) -> str:
    """Generate a cryptographically secure random password.

    Args:
        length: Desired password length. Must be >= 1.
        include_uppercase: Include uppercase ASCII letters (A-Z).
        include_lowercase: Include lowercase ASCII letters (a-z).
        include_digits: Include digits (0-9).
        include_symbols: Include punctuation / symbol characters.
        exclude_ambiguous: Exclude visually confusable characters (0, O, o, 1, l, I, |).
        avoid_sequential: Avoid 3+ sequential (e.g. 'abc', '123') or repeated ('aaa') characters.
        symbols: Custom symbols string. Defaults to string.punctuation if None.

    Returns:
        A cryptographically secure random password string.

    Raises:
        ValueError: If length < 1, no character types are selected, or constraints cannot be satisfied.
    """
    if length < 1:
        raise ValueError("Password length must be at least 1.")

    pools = get_character_pools(
        include_uppercase=include_uppercase,
        include_lowercase=include_lowercase,
        include_digits=include_digits,
        include_symbols=include_symbols,
        exclude_ambiguous=exclude_ambiguous,
        symbols=symbols,
    )

    if not pools:
        raise ValueError("At least one character type must be selected.")

    # Max attempts when regenerating to avoid sequential or repeated patterns
    max_attempts = 1000 if avoid_sequential else 1

    for _ in range(max_attempts):
        candidate = _generate_single_password(pools, length)
        if not avoid_sequential or not has_sequential_or_repeated(candidate):
            return candidate

    raise ValueError("Could not generate a password satisfying avoid_sequential constraints.")


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
