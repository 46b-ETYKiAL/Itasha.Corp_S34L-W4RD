"""Tests for the pre-publish secret-scrub gate.

The gate is the HARD precondition before the repo is made public. These tests
prove the load-bearing invariant: the gate BLOCKS (exits non-zero, names the
finding) on planted synthetic key-shaped fixtures, and PASSES on a clean tree.

No test writes a real secret. Every planted fixture is obviously synthetic
(fake PEM body, fake password, fake ARN-shaped token) and lives only under
``tmp_path`` — never in the repository tree (test-pollution rule).
"""

from __future__ import annotations

import importlib.util
import sys
from pathlib import Path

import pytest

# Load the gate module directly from scripts/ (it is not an installed package).
_SCRIPT = Path(__file__).resolve().parent.parent / "scripts" / "pre_publish_secret_scrub.py"
_spec = importlib.util.spec_from_file_location("pre_publish_secret_scrub", _SCRIPT)
assert _spec is not None and _spec.loader is not None
scrub = importlib.util.module_from_spec(_spec)
sys.modules["pre_publish_secret_scrub"] = scrub
_spec.loader.exec_module(scrub)


# --- synthetic (clearly-fake) key-shaped fixtures ----------------------------

# A SYNTHETIC PEM block. The body is the literal word "FAKE" repeated — not real
# key material. The gate keys on the BEGIN/END header shape, so this exercises
# the detector without any real secret.
_FAKE_PEM = (
    "-----BEGIN PRIVATE KEY-----\n"
    "RkFLRUZBS0VGQUtFRkFLRUZBS0VGQUtFRkFLRUZBS0VGQUtF\n"
    "-----END PRIVATE KEY-----\n"
)
_FAKE_MATCH = 'MATCH_PASSWORD="totally-fake-not-a-real-password"\n'
_FAKE_KEYSTORE = "KEYSTORE_PASSWORD=fake-keystore-pw-xyz\n"
_FAKE_AWS = "AKIAFAKEFAKEFAKEFAKE\n"  # AKIA + 16 chars, synthetic
_FAKE_PIN = "PKCS11_PIN=000000fake\n"


def _scan(root: Path):
    return scrub.scan_tree(root)


# --- clean tree passes -------------------------------------------------------


def test_clean_tree_has_no_findings(tmp_path) -> None:
    """A tree with only benign files yields zero findings and exit 0."""
    (tmp_path / "README.md").write_text("# hello\nno secrets here\n", encoding="utf-8")
    (tmp_path / "code.py").write_text(
        "import os\npw = os.environ.get('KEYSTORE_PASSWORD')\n", encoding="utf-8"
    )
    result = _scan(tmp_path)
    assert result.findings == []
    assert scrub.main(["--root", str(tmp_path)]) == 0


def test_handle_reference_is_not_flagged(tmp_path) -> None:
    """A custody HANDLE (ARN / Key Vault URI) in code is not key material."""
    (tmp_path / "config.py").write_text(
        'KEY = "arn:aws:kms:us-east-1:111122223333:key/abc-def"\n'
        'VAULT = "https://example.vault.azure.net/keys/release-key"\n',
        encoding="utf-8",
    )
    assert _scan(tmp_path).findings == []


def test_env_var_read_by_name_is_not_flagged(tmp_path) -> None:
    """Code that READS a password by env-var name holds no value → no finding."""
    (tmp_path / "signer.py").write_text(
        "import os\n"
        "keystore_password = os.environ.get('SEALWARD_KEYSTORE_PASSWORD')\n"
        "key_password = os.environ.get('SEALWARD_KEY_PASSWORD')\n",
        encoding="utf-8",
    )
    assert _scan(tmp_path).findings == []


# --- planted key material BLOCKS ---------------------------------------------


def test_blocks_planted_pem_block(tmp_path) -> None:
    """A planted synthetic PEM block is detected and BLOCKS (exit 1)."""
    planted = tmp_path / "leaked.txt"
    planted.write_text(_FAKE_PEM, encoding="utf-8")
    result = _scan(tmp_path)
    rules = {f.rule for f in result.findings}
    assert "pem-private-key-block" in rules
    assert any(f.path == "leaked.txt" for f in result.findings)
    assert scrub.main(["--root", str(tmp_path)]) == 1


def test_blocks_planted_p12_file(tmp_path) -> None:
    """A planted ``.p12`` file is BLOCKED by the extension denylist."""
    (tmp_path / "release.p12").write_bytes(b"\x30\x82FAKE-not-a-real-pkcs12")
    result = _scan(tmp_path)
    rules = {f.rule for f in result.findings}
    assert "key-material-file" in rules
    assert any(f.path == "release.p12" for f in result.findings)
    assert scrub.main(["--root", str(tmp_path)]) == 1


@pytest.mark.parametrize(
    ("ext", "name"),
    [
        (".pfx", "cert.pfx"),
        (".pem", "key.pem"),
        (".key", "id.key"),
        (".jks", "release.jks"),
        (".keystore", "app.keystore"),
        (".p8", "appstore.p8"),
        (".mobileprovision", "app.mobileprovision"),
        (".cer", "ca.cer"),
        (".crt", "leaf.crt"),
    ],
)
def test_blocks_every_key_material_extension(tmp_path, ext, name) -> None:
    """Each key-material extension on the no-key list is BLOCKED."""
    (tmp_path / name).write_bytes(b"synthetic-not-real-key-material")
    result = _scan(tmp_path)
    assert any(f.path == name for f in result.findings), f"{ext} not blocked"


def test_blocks_id_rsa_private_key_filename(tmp_path) -> None:
    """A conventional ``id_rsa`` private-key filename (no extension) is BLOCKED."""
    (tmp_path / "id_rsa").write_bytes(b"synthetic-not-real")
    result = _scan(tmp_path)
    assert any(f.path == "id_rsa" for f in result.findings)


def test_blocks_planted_match_password(tmp_path) -> None:
    """A planted Fastlane MATCH_PASSWORD value assignment is BLOCKED."""
    (tmp_path / "Fastfile").write_text(_FAKE_MATCH, encoding="utf-8")
    result = _scan(tmp_path)
    assert "fastlane-match-password" in {f.rule for f in result.findings}


def test_blocks_planted_keystore_password(tmp_path) -> None:
    """A planted keystore password VALUE assignment is BLOCKED."""
    (tmp_path / "gradle.properties").write_text(_FAKE_KEYSTORE, encoding="utf-8")
    assert "keystore-password" in {f.rule for f in _scan(tmp_path).findings}


def test_blocks_planted_pkcs11_pin(tmp_path) -> None:
    """A planted PKCS#11 token PIN VALUE assignment is BLOCKED."""
    (tmp_path / "hsm.env").write_text(_FAKE_PIN, encoding="utf-8")
    assert "pkcs11-token-pin" in {f.rule for f in _scan(tmp_path).findings}


def test_blocks_planted_aws_access_key(tmp_path) -> None:
    """A planted AWS access-key-id shape is BLOCKED."""
    (tmp_path / "creds.txt").write_text(_FAKE_AWS, encoding="utf-8")
    assert "aws-access-key-id" in {f.rule for f in _scan(tmp_path).findings}


def test_block_names_every_planted_fixture(tmp_path) -> None:
    """When several fixtures are planted the gate names ALL of them."""
    (tmp_path / "a.pem").write_bytes(b"synthetic")
    (tmp_path / "Fastfile").write_text(_FAKE_MATCH, encoding="utf-8")
    (tmp_path / "leaked.txt").write_text(_FAKE_PEM, encoding="utf-8")
    result = _scan(tmp_path)
    named = {f.path for f in result.findings}
    assert {"a.pem", "Fastfile", "leaked.txt"} <= named
    assert scrub.main(["--root", str(tmp_path)]) == 1


# --- synthetic-fixture + docs allowlist --------------------------------------


def test_synthetic_example_fixture_is_allowlisted(tmp_path) -> None:
    """A clearly-synthetic ``tests/fixtures/*.example`` fixture is NOT a finding."""
    fix = tmp_path / "tests" / "fixtures" / "fake-key.pem.example"
    fix.parent.mkdir(parents=True)
    fix.write_text(_FAKE_PEM, encoding="utf-8")
    assert _scan(tmp_path).findings == []


def test_docs_naming_secret_env_vars_not_flagged(tmp_path) -> None:
    """A doc that NAMES secret env-vars (without values) is not flagged."""
    doc = tmp_path / "ships-publicly-vs-never.md"
    doc.write_text(
        "Never commit MATCH_PASSWORD or KEYSTORE_PASSWORD values.\n"
        "Reference keys by handle (KMS ARN / Key Vault URI) only.\n",
        encoding="utf-8",
    )
    assert _scan(tmp_path).findings == []


# --- CLI surface -------------------------------------------------------------


def test_main_returns_2_on_missing_root() -> None:
    """A non-existent scan root is an invocation error (exit 2)."""
    assert scrub.main(["--root", "/no/such/dir/xyz-does-not-exist"]) == 2


def test_main_json_report_is_machine_readable(tmp_path, capsys) -> None:
    """``--json`` emits a parseable report carrying the blocked verdict."""
    import json

    (tmp_path / "leaked.txt").write_text(_FAKE_PEM, encoding="utf-8")
    rc = scrub.main(["--root", str(tmp_path), "--json"])
    assert rc == 1
    payload = json.loads(capsys.readouterr().out)
    assert payload["blocked"] is True
    assert payload["findings"]
    # The report names paths + rules, never a secret VALUE.
    assert "PRIVATE KEY" not in json.dumps(payload)
