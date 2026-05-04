import json
import subprocess
from unittest.mock import patch

import pytest

from extractors.guarddog_features import (
    GUARDDOG_TIMEOUT,
    extract_guarddog_features,
)


def _mk_proc(stdout: str, returncode: int = 0):
    return subprocess.CompletedProcess(
        args=["guarddog"], returncode=returncode, stdout=stdout, stderr=""
    )


def test_unsupported_registry_returns_empty():
    assert extract_guarddog_features("/tmp/x", "rubygems") == {}
    assert extract_guarddog_features("/tmp/x", "") == {}


def test_clean_package_returns_zero_findings():
    payload = json.dumps({"issues": 0, "results": {}})
    with patch("subprocess.run", return_value=_mk_proc(payload, 0)):
        result = extract_guarddog_features("/tmp/clean-pkg", "pypi")
    assert result["guarddog_findings_count"] == 0
    assert result["guarddog_rules_triggered"] == []
    assert all(v is False for v in result["guarddog_categories"].values())


def test_findings_parsed_and_categorized():
    payload = json.dumps({
        "issues": 3,
        "results": {
            "code_execution": {"matches": ["..."]},
            "obfuscation": {"matches": ["..."]},
            "exfiltrate_sensitive_data": {"matches": ["..."]},
        },
    })
    # Returncode 1 means findings present — must be treated as success
    with patch("subprocess.run", return_value=_mk_proc(payload, 1)):
        result = extract_guarddog_features("/tmp/dirty-pkg", "pypi")
    assert result["guarddog_findings_count"] == 3
    assert "code_execution" in result["guarddog_rules_triggered"]
    assert "obfuscation" in result["guarddog_rules_triggered"]
    assert result["guarddog_categories"]["has_exfiltration"] is True


def test_crypto_mining_category():
    payload = json.dumps({"issues": 1, "results": {"npm_crypto_miner": [{"loc": "x"}]}})
    with patch("subprocess.run", return_value=_mk_proc(payload, 1)):
        result = extract_guarddog_features("/tmp/x", "npm")
    assert result["guarddog_categories"]["has_crypto_mining"] is True


def test_token_theft_category():
    payload = json.dumps({"issues": 1, "results": {"npm_steals_auth_token": [{"loc": "x"}]}})
    with patch("subprocess.run", return_value=_mk_proc(payload, 1)):
        result = extract_guarddog_features("/tmp/x", "npm")
    assert result["guarddog_categories"]["has_token_theft"] is True


def test_subprocess_timeout_returns_empty():
    with patch("subprocess.run", side_effect=subprocess.TimeoutExpired(cmd="guarddog", timeout=GUARDDOG_TIMEOUT)):
        assert extract_guarddog_features("/tmp/x", "pypi") == {}


def test_missing_binary_returns_empty():
    with patch("subprocess.run", side_effect=FileNotFoundError("no such file")):
        assert extract_guarddog_features("/tmp/x", "pypi") == {}


def test_malformed_json_returns_empty():
    with patch("subprocess.run", return_value=_mk_proc("not json at all", 0)):
        assert extract_guarddog_features("/tmp/x", "pypi") == {}


def test_empty_stdout_returns_empty():
    with patch("subprocess.run", return_value=_mk_proc("", 0)):
        assert extract_guarddog_features("/tmp/x", "pypi") == {}


def test_unexpected_returncode_returns_empty():
    with patch("subprocess.run", return_value=_mk_proc('{"issues":0}', 2)):
        assert extract_guarddog_features("/tmp/x", "pypi") == {}


def test_missing_issues_field_defaults_to_zero():
    payload = json.dumps({"results": {"obfuscation": [{"loc": "main.py:1"}]}})
    with patch("subprocess.run", return_value=_mk_proc(payload, 1)):
        result = extract_guarddog_features("/tmp/x", "pypi")
    assert result["guarddog_findings_count"] == 0
    assert "obfuscation" in result["guarddog_rules_triggered"]


def test_empty_rule_results_not_triggered():
    """Rules that ran but found nothing return empty dicts — must not be flagged as triggered."""
    payload = json.dumps({
        "issues": 1,
        "results": {
            "exec-base64": [{"loc": "main.py:1"}],
            "clipboard-access": {},
            "crypto-mining": {},
        },
    })
    with patch("subprocess.run", return_value=_mk_proc(payload, 1)):
        result = extract_guarddog_features("/tmp/x", "pypi")
    assert result["guarddog_rules_triggered"] == ["exec-base64"]
    assert result["guarddog_categories"]["has_clipboard_access"] is False
    assert result["guarddog_categories"]["has_crypto_mining"] is False
