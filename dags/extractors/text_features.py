import os
import re
from typing import Any

_README_NAMES = [
    "README.md", "README.rst", "README.txt", "README",
    "readme.md", "readme.rst", "readme.txt",
]

_SUSPICIOUS_PHRASES = [
    re.compile(r"unofficial.{0,20}(fork|version|port|mirror)", re.I),
    re.compile(r"drop.in replacement for", re.I),
    re.compile(r"compatible with (requests|numpy|flask|django|express|lodash)", re.I),
    re.compile(r"faster.{0,20}(requests|numpy|pandas)", re.I),
    re.compile(r"(pip|npm) install .{0,30}\|\|", re.I),  # chained install commands
]

_PLACEHOLDER_DESCRIPTIONS = {
    "", "todo", "fixme", "placeholder", "test", "my package",
    "a python package", "an npm package", "package description",
}


def _read_readme(package_dir: str) -> str:
    for name in _README_NAMES:
        path = os.path.join(package_dir, name)
        if os.path.isfile(path):
            try:
                with open(path, "r", encoding="utf-8", errors="ignore") as fh:
                    return fh.read()
            except OSError:
                pass
    return ""


def extract_text_features(package_dir: str, pkg_meta: dict) -> dict[str, Any]:
    description = pkg_meta.get("description") or ""
    readme = _read_readme(package_dir)
    combined = description + " " + readme

    return {
        "description_length":          len(description),
        "readme_length":               len(readme),
        "suspicious_phrase_count":     sum(1 for p in _SUSPICIOUS_PHRASES if p.search(combined)),
        "has_placeholder_description": description.strip().lower() in _PLACEHOLDER_DESCRIPTIONS,
    }
