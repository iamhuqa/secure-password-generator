"""Entropy calculation, crack-time estimation, and strength classification.

Provides tools to assess the cryptographic strength of generated passwords
against brute-force attacks.
"""

import math


def calculate_entropy(password: str, pool_size: int) -> float:
    """Compute password entropy in bits using the standard formula: length * log2(pool_size).

    Args:
        password: The password string to evaluate.
        pool_size: The number of unique possible characters in the selection pool.

    Returns:
        Entropy in bits as a float. Returns 0.0 if password is empty or pool_size <= 1.
    """
    if not password or pool_size <= 1:
        return 0.0
    return len(password) * math.log2(pool_size)


def estimate_crack_time(entropy_bits: float, guesses_per_second: float = 1e9) -> str:
    """Estimate time to brute-force a password at a given guess rate.

    On average, a brute-force attack succeeds after searching 50% of the keyspace,
    so average guesses = 2^(entropy_bits - 1).

    Args:
        entropy_bits: Information entropy of the password in bits.
        guesses_per_second: Attack rate (default: 1e9, ~1 billion guesses/sec for a modern GPU).

    Returns:
        Human-readable estimate string (e.g., 'instantly', '3 seconds', '142 years').
    """
    if entropy_bits <= 0 or guesses_per_second <= 0:
        return "instantly"

    # For large entropy values, avoid float overflow
    if entropy_bits <= 100:
        avg_guesses = 2.0 ** (entropy_bits - 1.0)
        seconds = avg_guesses / guesses_per_second
    else:
        # Use log10 math or int conversion for very large numbers
        log10_guesses = (entropy_bits - 1.0) * math.log10(2)
        log10_seconds = log10_guesses - math.log10(guesses_per_second)
        if log10_seconds > 300:
            return "> 1e100 years"
        seconds = 10.0 ** log10_seconds

    if seconds < 1.0:
        return "instantly"

    if seconds < 60.0:
        s = round(seconds)
        return f"{s} second" if s == 1 else f"{s} seconds"

    minutes = seconds / 60.0
    if minutes < 60.0:
        m = round(minutes)
        return f"{m} minute" if m == 1 else f"{m} minutes"

    hours = minutes / 60.0
    if hours < 24.0:
        h = round(hours)
        return f"{h} hour" if h == 1 else f"{h} hours"

    days = hours / 24.0
    if days < 365.25:
        d = round(days)
        return f"{d} day" if d == 1 else f"{d} days"

    years = days / 365.25
    if years < 1000.0:
        y = round(years)
        return f"{y} year" if y == 1 else f"{y} years"
    elif years < 1e6:
        return f"{years / 1e3:.1f} thousand years"
    elif years < 1e9:
        return f"{years / 1e6:.1f} million years"
    elif years < 1e12:
        return f"{years / 1e9:.1f} billion years"
    elif years < 1e15:
        return f"{years / 1e12:.1f} trillion years"
    else:
        return f"{years:.1e} years"


def classify_strength(entropy_bits: float) -> str:
    """Classify password strength based on entropy in bits.

    Thresholds based on modern computational benchmarks (e.g. 10^9 guesses/sec GPU):
      - < 36 bits: Weak (brute-forced in seconds or minutes)
      - 36 to < 60 bits: Fair (resistant to fast online attacks, vulnerable offline)
      - 60 to < 80 bits: Strong (resistant to offline attacks for years)
      - >= 80 bits: Very Strong (cryptographically secure against massive GPU clusters)

    Args:
        entropy_bits: Password entropy in bits.

    Returns:
        One of 'Weak', 'Fair', 'Strong', or 'Very Strong'.
    """
    if entropy_bits < 36.0:
        return "Weak"
    elif entropy_bits < 60.0:
        return "Fair"
    elif entropy_bits < 80.0:
        return "Strong"
    else:
        return "Very Strong"
