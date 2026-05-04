"""GuardDog (DataDog) integration — Phase 1 capture mode.

Runs the GuardDog CLI against an already-extracted package directory and
returns a dict of findings. All failure modes (timeout, crash, malformed
JSON, missing binary) collapse to an empty dict so the caller's extraction
flow never breaks.

Output is consumed by extract_dag.py and build_dataset.py and stored only
inside the existing raw_features JSONB column. No DB schema changes.
The model FEATURES list is unchanged — these signals are captured for
analysis and are not yet used at inference time.
"""
import json
import subprocess
from typing import Any

GUARDDOG_TIMEOUT = 60  # seconds, hard kill — keeps DAG batches predictable
SUPPORTED_REGISTRIES = ("pypi", "npm")

# Map GuardDog rule-name substrings to high-level boolean flags. Keeps the
# stored output compact and stable even if GuardDog renames individual rules.
_CATEGORY_KEYWORDS: dict[str, tuple[str, ...]] = {
    "has_crypto_mining":    ("crypto", "mining"),
    "has_clipboard_access": ("clipboard",),
    "has_silent_exec":      ("silent",),
    "has_bundled_binary":   ("bundled", "binary"),
    "has_token_theft":      ("token", "npmrc", "auth"),
    "has_cmd_overwrite":    ("cmd_overwrite", "overwrite"),
    "has_exfiltration":     ("exfiltrat",),
}


def _categorize(rule_names: list[str]) -> dict[str, bool]:
    """Map raw rule names to high-level boolean signals."""
    return {
        flag: any(any(kw in r.lower() for kw in keywords) for r in rule_names)
        for flag, keywords in _CATEGORY_KEYWORDS.items()
    }


def extract_guarddog_features(package_dir: str, registry: str) -> dict[str, Any]:
    """Run GuardDog on a local package directory.

    Returns a dict with findings count, triggered rule names, and a
    categorized boolean flags dict. Returns {} on any failure so the
    caller's extraction can continue.
    """
    if registry not in SUPPORTED_REGISTRIES:
        return {}

    try:
        proc = subprocess.run(
            ["guarddog", registry, "scan", package_dir, "--output-format", "json"],
            capture_output=True,
            text=True,
            timeout=GUARDDOG_TIMEOUT,
            check=False,
        )
        # GuardDog returns 0 (clean) or 1 (findings present); other codes are errors.
        if proc.returncode not in (0, 1):
            return {}
        if not proc.stdout.strip():
            return {}

        result = json.loads(proc.stdout)
    except (subprocess.TimeoutExpired, json.JSONDecodeError, OSError, FileNotFoundError):
        return {}

    # GuardDog JSON shape: {"issues": <int>, "results": {<rule>: <list|dict>, ...}}
    # Every rule that ran appears in `results`; an empty value means it found nothing.
    # Treat a rule as triggered only when its value is a non-empty list/dict.
    raw_results = result.get("results", {})
    triggered = sorted(
        name for name, payload in raw_results.items()
        if (isinstance(payload, list) and payload)
        or (isinstance(payload, dict) and payload)
    )
    return {
        "guarddog_findings_count":   int(result.get("issues", 0) or 0),
        "guarddog_rules_triggered":  triggered,
        "guarddog_categories":       _categorize(triggered),
    }
