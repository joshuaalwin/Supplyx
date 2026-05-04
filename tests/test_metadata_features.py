from extractors.metadata_features import extract_metadata_features


def test_typosquat_detected_pypi():
    result = extract_metadata_features({
        "name": "reqests",
        "registry": "pypi",
        "version": "1.0.0",
    })
    assert result["typosquat_target"] == "requests"
    assert result["typosquat_distance"] is not None
    assert result["typosquat_distance"] >= 1


def test_typosquat_detected_npm():
    result = extract_metadata_features({
        "name": "expres",
        "registry": "npm",
        "version": "1.0.0",
    })
    assert result["typosquat_target"] == "express"


def test_no_typosquat_for_unique_name():
    result = extract_metadata_features({
        "name": "completely-unique-package-xyz",
        "registry": "pypi",
        "version": "1.0.0",
    })
    assert result["typosquat_target"] is None
    assert result["typosquat_distance"] is None


def test_exact_name_match_excluded():
    result = extract_metadata_features({
        "name": "requests",
        "registry": "pypi",
        "version": "1.0.0",
    })
    assert result["typosquat_target"] is None


def test_version_jump_suspicious_high_major_few_releases():
    result = extract_metadata_features({
        "name": "totally-new-pkg",
        "registry": "pypi",
        "version": "9.0.0",
        "version_count": 1,
    })
    assert result["version_jump_suspicious"] is True


def test_version_jump_not_suspicious_for_low_major():
    result = extract_metadata_features({
        "name": "totally-new-pkg",
        "registry": "pypi",
        "version": "1.0.0",
        "version_count": 1,
    })
    assert result["version_jump_suspicious"] is False


def test_version_jump_not_suspicious_with_many_releases():
    result = extract_metadata_features({
        "name": "totally-new-pkg",
        "registry": "pypi",
        "version": "9.0.0",
        "version_count": 50,
    })
    assert result["version_jump_suspicious"] is False


def test_repo_link_detected():
    result = extract_metadata_features({
        "name": "test-pkg",
        "registry": "pypi",
        "version": "1.0.0",
        "repository": "https://github.com/user/test-pkg",
    })
    assert result["has_repo_link"] is True


def test_repo_link_absent():
    result = extract_metadata_features({
        "name": "test-pkg",
        "registry": "pypi",
        "version": "1.0.0",
    })
    assert result["has_repo_link"] is False


def test_account_age_days_always_none():
    result = extract_metadata_features({
        "name": "test-pkg",
        "registry": "pypi",
        "version": "1.0.0",
    })
    assert result["account_age_days"] is None
