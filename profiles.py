"""Configuration profile manager for Secure Password Generator.

Allows saving, loading, and listing reusable generation profiles stored as JSON
in the config_profiles/ directory.
"""

import json
import re
from pathlib import Path
from typing import Any, Dict, List

PROFILES_DIR = Path(__file__).resolve().parent / "config_profiles"


def _sanitize_name(name: str) -> str:
    """Sanitize profile name to ensure safe filename."""
    clean = re.sub(r"[^\w\-]", "_", name.strip())
    if not clean:
        raise ValueError("Profile name cannot be empty or invalid.")
    return clean


def save_profile(name: str, settings: Dict[str, Any]) -> Path:
    """Save a named configuration profile as JSON.

    Args:
        name: Name of the profile.
        settings: Dictionary of configuration parameters.

    Returns:
        The Path to the saved profile file.
    """
    clean_name = _sanitize_name(name)
    PROFILES_DIR.mkdir(parents=True, exist_ok=True)
    file_path = PROFILES_DIR / f"{clean_name}.json"
    with open(file_path, "w", encoding="utf-8") as f:
        json.dump(settings, f, indent=2)
    return file_path


def load_profile(name: str) -> Dict[str, Any]:
    """Load a saved configuration profile by name.

    Args:
        name: Name of the profile to load.

    Returns:
        Dictionary of configuration parameters.

    Raises:
        FileNotFoundError: If profile does not exist.
    """
    clean_name = _sanitize_name(name)
    file_path = PROFILES_DIR / f"{clean_name}.json"
    if not file_path.is_file():
        available = list_profiles()
        avail_str = ", ".join(f"'{p}'" for p in available) if available else "None"
        raise FileNotFoundError(
            f"Profile '{name}' not found at {file_path}. Available profiles: {avail_str}"
        )
    with open(file_path, "r", encoding="utf-8") as f:
        return json.load(f)


def list_profiles() -> List[str]:
    """List names of all available configuration profiles.

    Returns:
        Alphabetically sorted list of profile names.
    """
    if not PROFILES_DIR.is_dir():
        return []
    return sorted(p.stem for p in PROFILES_DIR.glob("*.json"))
