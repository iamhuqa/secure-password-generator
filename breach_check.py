"""Breach-checking module using HaveIBeenPwned Pwned Passwords API.

Implements the k-anonymity model to verify whether a password has appeared in
known data breaches without compromising user privacy.
"""

import hashlib
from typing import Optional
import requests


def check_password_breach(password: str, timeout: float = 5.0) -> Optional[int]:
    """Check if a password has appeared in known data breaches via HaveIBeenPwned API.

    K-Anonymity Privacy Guarantee:
    ------------------------------
    Neither the plaintext password nor its full cryptographic hash is ever
    transmitted across the network.

    1. The client computes the 40-character SHA-1 hash of the password.
    2. Only the first 5 hexadecimal characters (prefix) are sent to the
       HaveIBeenPwned API (e.g. https://api.pwnedpasswords.com/range/21BD1).
    3. The API responds with a list of all hash suffixes in its database that
       share that 5-character prefix (usually hundreds to thousands of hashes).
    4. The client locally searches that list for the remaining 35-character suffix.

    Because millions of distinct passwords share the same 5-character SHA-1 prefix,
    neither HaveIBeenPwned nor any intermediary network eavesdropper can determine
    which specific password or hash was queried.

    Args:
        password: The password string to check.
        timeout: Network request timeout in seconds (default: 5.0).

    Returns:
        int: Number of times the password was observed in breaches (0 if clean).
        None: If the check could not be completed due to network error, timeout,
              or API unavailability (graceful failure).
    """
    if not password:
        return 0

    try:
        # Step a: Compute SHA-1 hash in uppercase hexadecimal
        sha1_hash = hashlib.sha1(password.encode("utf-8")).hexdigest().upper()

        # Step b: Split into 5-character prefix and 35-character suffix
        prefix = sha1_hash[:5]
        suffix = sha1_hash[5:]

        # Step c: GET request to HIBP range endpoint
        url = f"https://api.pwnedpasswords.com/range/{prefix}"
        headers = {"User-Agent": "SecurePasswordGenerator/1.0"}

        response = requests.get(url, headers=headers, timeout=timeout)
        if response.status_code != 200:
            return None

        # Step d: Parse response lines formatted as SUFFIX:COUNT
        for line in response.text.splitlines():
            line = line.strip()
            if not line:
                continue
            parts = line.split(":")
            if len(parts) == 2:
                resp_suffix, count_str = parts[0].strip().upper(), parts[1].strip()
                if resp_suffix == suffix:
                    return int(count_str)

        # Suffix was not in the returned list -> 0 breach occurrences
        return 0

    except Exception:
        # Step e: Catch all network/parsing errors gracefully
        return None
