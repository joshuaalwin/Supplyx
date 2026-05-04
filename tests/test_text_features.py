import os
import shutil
import tempfile

import pytest

from extractors.text_features import extract_text_features


@pytest.fixture
def pkg_dir():
    tmp = tempfile.mkdtemp()
    yield tmp
    shutil.rmtree(tmp, ignore_errors=True)


def _write_readme(pkg_dir: str, content: str, filename: str = "README.md") -> None:
    with open(os.path.join(pkg_dir, filename), "w") as f:
        f.write(content)


def test_empty_description_is_placeholder(pkg_dir):
    result = extract_text_features(pkg_dir, {"description": ""})
    assert result["description_length"] == 0
    assert result["has_placeholder_description"] is True


def test_known_placeholder_description(pkg_dir):
    result = extract_text_features(pkg_dir, {"description": "todo"})
    assert result["has_placeholder_description"] is True


def test_real_description_not_placeholder(pkg_dir):
    result = extract_text_features(pkg_dir, {"description": "A library for HTTP requests"})
    assert result["has_placeholder_description"] is False
    assert result["description_length"] > 0


def test_readme_md_detected(pkg_dir):
    _write_readme(pkg_dir, "This is a real readme with content.")
    result = extract_text_features(pkg_dir, {"description": "test"})
    assert result["readme_length"] > 0


def test_readme_rst_detected(pkg_dir):
    _write_readme(pkg_dir, "Real content", filename="README.rst")
    result = extract_text_features(pkg_dir, {"description": "test"})
    assert result["readme_length"] > 0


def test_no_readme(pkg_dir):
    result = extract_text_features(pkg_dir, {"description": "test"})
    assert result["readme_length"] == 0


def test_suspicious_phrase_unofficial_fork(pkg_dir):
    _write_readme(pkg_dir, "Unofficial fork of requests with extra features.")
    result = extract_text_features(pkg_dir, {"description": ""})
    assert result["suspicious_phrase_count"] >= 1


def test_suspicious_phrase_drop_in_replacement(pkg_dir):
    _write_readme(pkg_dir, "")
    result = extract_text_features(pkg_dir, {
        "description": "Drop-in replacement for requests",
    })
    assert result["suspicious_phrase_count"] >= 1


def test_no_suspicious_phrase_in_normal_text(pkg_dir):
    _write_readme(pkg_dir, "A useful utility for parsing JSON data.")
    result = extract_text_features(pkg_dir, {
        "description": "JSON parsing utility",
    })
    assert result["suspicious_phrase_count"] == 0
