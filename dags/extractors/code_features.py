import math
import os
import re
from collections import Counter
from typing import Any

DANGEROUS_IMPORTS = {
    "subprocess", "socket", "urllib", "urllib2", "urllib3",
    "requests", "http.client", "ftplib", "ctypes", "cffi",
    "pickle", "marshal", "importlib",
}

_CREDENTIAL_PATTERNS = [
    re.compile(r"\.ssh[/\\]"),
    re.compile(r"\.aws[/\\]credentials"),
    re.compile(r"\.npmrc"),
    re.compile(r"\.netrc"),
    re.compile(r'os\.environ\[.[A-Z_]*(TOKEN|SECRET|KEY|PASS)[A-Z_]*.\]', re.I),
    re.compile(r'os\.getenv\(.[A-Z_]*(TOKEN|SECRET|KEY|PASS)[A-Z_]*.\)', re.I),
]

_NETWORK_PATTERNS = [
    re.compile(r'\b(requests|urllib|http\.client|socket)\b'),
    re.compile(r'\b(fetch|axios|https?\.get|https?\.request)\b'),
    re.compile(r'https?://'),
]

_EXEC_EVAL_PATTERNS = [
    re.compile(r'\beval\s*\('),
    re.compile(r'\bexec\s*\('),
    re.compile(r'\b__import__\s*\('),
    re.compile(r'\bcompile\s*\('),
]

_OBFUSCATION_PATTERNS = [
    re.compile(r'base64\.b64decode'),
    re.compile(r'codecs\.decode'),
    re.compile(r'[A-Za-z0-9+/]{80,}={0,2}'),  # long base64-like string
    re.compile(r'(\\x[0-9a-fA-F]{2}){10,}'),   # hex escape sequence run
]

_OS_TARGETING_PATTERNS = [
    re.compile(r'\bsys\.platform\b'),
    re.compile(r'\bplatform\.system\s*\('),
    re.compile(r'\bos\.name\b'),
    re.compile(r"['\"]win32['\"]|['\"]linux['\"]|['\"]darwin['\"]"),
]

# Downloading content at runtime then executing it (external payload pattern from paper)
_EXTERNAL_PAYLOAD_PATTERNS = [
    re.compile(r'(urlretrieve|urlopen|requests\.get).{0,300}(exec|eval|compile|__import__)', re.S),
    re.compile(r'(exec|eval)\s*\(.{0,100}(urlopen|requests\.get|urllib)', re.S),
]

# Five API categories from the paper — count how many distinct categories appear
_API_CATEGORIES: dict[str, list[re.Pattern]] = {
    "network":    [re.compile(r'\b(requests|urllib|socket|http\.client|ftplib|aiohttp|httpx)\b')],
    "file":       [re.compile(r'\bopen\s*\('), re.compile(r'\b(shutil|pathlib)\b')],
    "process":    [re.compile(r'\b(subprocess|os\.system|os\.popen|os\.execv|os\.execl)\b')],
    "encryption": [re.compile(r'\b(base64|codecs|hashlib|cryptography|Fernet)\b')],
    "execution":  [re.compile(r'\b(eval|exec|compile|__import__)\s*\(')],
}

_INSTALL_FILENAMES = {"setup.py", "setup.cfg", "package.json"}
_SOURCE_EXTENSIONS = (".py", ".js", ".ts")
_SKIP_DIRS = {"node_modules", ".git", "__pycache__", ".tox", "dist", "build"}


def _shannon_entropy(data: str) -> float:
    if not data:
        return 0.0
    freq = Counter(data)
    n = len(data)
    return -sum((c / n) * math.log2(c / n) for c in freq.values())


def _read_sources(package_dir: str) -> list[tuple[str, str]]:
    results = []
    for root, dirs, files in os.walk(package_dir):
        dirs[:] = [d for d in dirs if d not in _SKIP_DIRS]
        for fname in files:
            if fname.endswith(_SOURCE_EXTENSIONS):
                path = os.path.join(root, fname)
                try:
                    with open(path, "r", encoding="utf-8", errors="ignore") as fh:
                        results.append((path, fh.read()))
                except OSError:
                    pass
    return results


def _read_install_scripts(package_dir: str) -> str:
    content = ""
    for fname in _INSTALL_FILENAMES:
        path = os.path.join(package_dir, fname)
        if os.path.isfile(path):
            try:
                with open(path, "r", encoding="utf-8", errors="ignore") as fh:
                    content += fh.read()
            except OSError:
                pass
    return content


def extract_code_features(package_dir: str) -> dict[str, Any]:
    sources = _read_sources(package_dir)
    install_src = _read_install_scripts(package_dir)
    all_src = "\n".join(src for _, src in sources)

    # Highest entropy over any 200-char window
    max_entropy = 0.0
    for _, src in sources:
        for i in range(0, len(src), 200):
            e = _shannon_entropy(src[i : i + 200])
            if e > max_entropy:
                max_entropy = e

    dangerous_import_count = sum(
        1 for imp in DANGEROUS_IMPORTS
        if re.search(rf"\b{re.escape(imp)}\b", all_src)
    )

    api_category_count = sum(
        1 for patterns in _API_CATEGORIES.values()
        if any(p.search(all_src) for p in patterns)
    )

    return {
        "entropy_max":              round(max_entropy, 4),
        "has_network_in_install":   any(p.search(install_src) for p in _NETWORK_PATTERNS),
        "has_credential_access":    any(p.search(all_src) for p in _CREDENTIAL_PATTERNS),
        "has_obfuscated_code":      any(p.search(all_src) for p in _OBFUSCATION_PATTERNS),
        "has_exec_eval":            any(p.search(all_src) for p in _EXEC_EVAL_PATTERNS),
        "install_script_lines":     install_src.count("\n"),
        "dangerous_import_count":   dangerous_import_count,
        "has_os_targeting":         any(p.search(all_src) for p in _OS_TARGETING_PATTERNS),
        "has_external_payload":     any(p.search(all_src) for p in _EXTERNAL_PAYLOAD_PATTERNS),
        "api_category_count":       api_category_count,
    }
