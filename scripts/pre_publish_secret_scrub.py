"""Pre-publish secret-scrub gate (Layer 3 of the four-layer defense).

This is the HARD precondition run before the SealWard repository is ever made
public or a release is cut. It walks the whole repository tree and BLOCKS (exits
non-zero, emits a SECURITY-class message) on ANY committed key material:

* **Key-material file extensions** — ``.p12 .pfx .pem .key .jks .keystore .p8
  .mobileprovision .cer .crt .der .csr .bks .sec .gpg .pgp .asc`` and the
  conventional private-key filenames ``id_rsa* id_ed25519* id_ecdsa* id_dsa*
  secring.* minisign.key``.
* **PEM private-key / cert / PGP blocks** inside any text file.
* **Secret-VALUE assignment shapes** — ``MATCH_PASSWORD`` (Fastlane), Android /
  PKCS#12 keystore passwords, PKCS#11 / HSM / token PINs, and cloud credentials
  (AWS access key + secret, Azure SP client secret, GCP service-account JSON
  private_key, HashiCorp Vault token).

The scanner is **stdlib-only** by design: it is the canonical gate and must run
with zero install steps (it complements, never depends on, gitleaks). It mirrors
the ``.gitleaks.toml`` ruleset and the ``ships-publicly-vs-never.md`` boundary.

What is intentionally NOT a finding (the allowlist):

* Files that NAME secret env-vars without a value (docs / CI / ``.gitignore`` /
  ``.gitleaks.toml`` / this scanner itself / the IP-safety doc).
* Example custody HANDLES (KMS ARN, Key Vault URI, PKCS#11 slot, Vault path) —
  a handle names *where* a key lives, never its value (Kerckhoffs).
* Clearly-synthetic test fixtures under ``tests/`` whose names mark them as fake
  (``*.example``) — tests plant obviously-fake values to prove this gate BLOCKS
  real-shaped content.

Exit codes:
    0  clean tree — safe to publish.
    1  one or more key-material findings — HARD BLOCK; nothing publishes.
    2  invocation error (root does not exist).

Usage:
    python scripts/pre_publish_secret_scrub.py [--root <dir>] [--json]
"""

from __future__ import annotations

import argparse
import json
import re
import sys
from dataclasses import dataclass, field
from pathlib import Path

__all__ = ["Finding", "main", "scan_tree"]

# --- Key-material file extensions (never publishable) ------------------------

_KEY_MATERIAL_EXTENSIONS: frozenset[str] = frozenset(
    {
        ".p12",
        ".pfx",
        ".pem",
        ".key",
        ".jks",
        ".keystore",
        ".p8",
        ".mobileprovision",
        ".provisionprofile",
        ".cer",
        ".crt",
        ".der",
        ".csr",
        ".bks",
        ".sec",
        ".gpg",
        ".pgp",
        ".asc",
    }
)

# Conventional private-key *filenames* that carry no telltale extension.
_KEY_MATERIAL_FILENAME_PATTERNS: tuple[re.Pattern[str], ...] = (
    re.compile(r"^id_rsa(\.|$)"),
    re.compile(r"^id_ed25519(\.|$)"),
    re.compile(r"^id_ecdsa(\.|$)"),
    re.compile(r"^id_dsa(\.|$)"),
    re.compile(r"^secring\."),
    re.compile(r"^minisign\.key$"),
)

# --- In-file content shapes (PEM blocks + secret-VALUE assignments) ----------

# A secret VALUE is a quoted string literal, OR a bare run of non-space
# secret-shaped characters that is NOT a Python/code expression. We exclude RHS
# that contains ``(`` ``.`` ``$`` ``{`` (function calls, attribute access,
# os.environ.get(...), ${VAR} interpolation) — those NAME a secret, never hold
# its value. ``_VALUE`` matches either:
#   * a quoted literal: '...' or "..." with >= 4 inner chars, no interpolation
#   * a bare literal: >= 6 chars of [A-Za-z0-9/+=_-] only (no ( . $ { space)
_VALUE = (
    r"(?:"
    r"'[^'\n${}().]{4,}'"  # single-quoted literal
    r'|"[^"\n${}().]{4,}"'  # double-quoted literal
    r"|[A-Za-z0-9/+=_-]{6,}(?:\s|$)"  # bare secret-shaped token
    r")"
)

_CONTENT_RULES: tuple[tuple[str, re.Pattern[str]], ...] = (
    (
        "pem-private-key-block",
        re.compile(
            r"-----BEGIN (?:RSA |EC |DSA |OPENSSH |ENCRYPTED |PGP )?PRIVATE KEY"
            r"(?: BLOCK)?-----"
        ),
    ),
    # Fastlane MATCH_PASSWORD = <literal value>. The keyword is the canonical
    # UPPERCASE env-var name (case-sensitive) so a lowercase code variable
    # ``match_password = os.environ.get(...)`` is NOT a finding.
    (
        "fastlane-match-password",
        re.compile(r"\bMATCH_PASSWORD\b\s*[:=]\s*" + _VALUE),
    ),
    # Android / PKCS#12 keystore + key passwords — UPPERCASE env-var name only.
    (
        "keystore-password",
        re.compile(
            r"\b(?:KEYSTORE_PASSWORD|KEY_PASSWORD|STOREPASS|KEYPASS|"
            r"SIGNING_STORE_PASSWORD|SIGNING_KEY_PASSWORD|P12_PASSWORD|PFX_PASSWORD|"
            r"CERT_PASSWORD|CERTIFICATE_PASSWORD|PKCS12_PASSWORD)\b"
            r"\s*[:=]\s*" + _VALUE
        ),
    ),
    # PKCS#11 / HSM / token PINs — UPPERCASE env-var name only.
    (
        "pkcs11-token-pin",
        re.compile(r"\b(?:PKCS11_PIN|TOKEN_PIN|HSM_PIN|SLOT_PIN)\b\s*[:=]\s*" + _VALUE),
    ),
    # AWS access-key id (the literal shape is itself the secret).
    (
        "aws-access-key-id",
        re.compile(r"\b(?:AKIA|ASIA)[0-9A-Z]{16}\b"),
    ),
    (
        "aws-secret-access-key",
        re.compile(r"\bAWS_SECRET_ACCESS_KEY\b\s*[:=]\s*['\"]?[A-Za-z0-9/+=]{40}\b"),
    ),
    # Azure service-principal client secret assignment.
    (
        "azure-client-secret",
        re.compile(r"\b(?:AZURE_CLIENT_SECRET|ARM_CLIENT_SECRET)\b\s*[:=]\s*" + _VALUE),
    ),
    # GCP service-account JSON private_key field.
    (
        "gcp-service-account-private-key",
        re.compile(r'"private_key"\s*:\s*"-----BEGIN [A-Z ]*PRIVATE KEY-----'),
    ),
    # HashiCorp Vault token (hvs. / s. legacy prefix) assignment.
    (
        "hashicorp-vault-token",
        re.compile(r"\bVAULT_TOKEN\b\s*[:=]\s*['\"]?(?:hvs\.|s\.)[A-Za-z0-9._-]{12,}"),
    ),
)

# --- Allowlist (NAMES-not-values / handles / synthetic fixtures) -------------

# Paths whose CONTENT may name secret env-var NAMES without holding values, and
# the scanner itself (it literally contains the patterns it scans for).
_ALLOWLIST_CONTENT_PATH_PATTERNS: tuple[re.Pattern[str], ...] = (
    re.compile(r"(?:^|/)ships-publicly-vs-never\.md$"),
    re.compile(r"(?:^|/)README\.md$"),
    re.compile(r"(?:^|/)\.gitleaks\.toml$"),
    re.compile(r"(?:^|/)\.gitignore$"),
    re.compile(r"(?:^|/)scripts/pre_publish_secret_scrub\.py$"),
    # Test modules legitimately embed clearly-synthetic key-shaped strings to
    # exercise the detectors. The extension denylist still blocks any real
    # ``.pem`` / ``.p12`` etc. file regardless of where it lives — only the
    # in-file content shapes inside test SOURCE are exempt here.
    re.compile(r"(?:^|/)tests/test_[^/]+\.py$"),
    re.compile(r"(?:^|/)\.github/workflows/[^/]+\.ya?ml$"),
)

# Clearly-synthetic fixture files: extension/content findings under these paths
# are expected (tests plant fake values to prove the gate BLOCKS them).
_ALLOWLIST_FIXTURE_PATTERNS: tuple[re.Pattern[str], ...] = (
    re.compile(r"(?:^|/)tests/fixtures/.*\.example$"),
)

# Directories never worth walking (VCS internals, caches, build output, venvs).
_SKIP_DIRS: frozenset[str] = frozenset(
    {
        ".git",
        ".ruff_cache",
        ".pytest_cache",
        "__pycache__",
        ".mypy_cache",
        ".venv",
        "venv",
        "node_modules",
        "dist",
        "build",
        ".tox",
        ".idea",
        ".vscode",
    }
)

# Cap per-file read so a giant binary cannot stall the gate; key material is
# small and always lands well within this window.
_MAX_READ_BYTES = 5_000_000


@dataclass(frozen=True)
class Finding:
    """A single key-material hit. Carries the rule + location, NEVER the value."""

    path: str
    rule: str
    detail: str

    def render(self) -> str:
        """One-line human-readable rendering (no secret value)."""
        return f"  [{self.rule}] {self.path} — {self.detail}"


@dataclass
class _ScanResult:
    findings: list[Finding] = field(default_factory=list)
    files_scanned: int = 0


def _is_allowlisted_content(rel_posix: str) -> bool:
    """True when the path may legitimately NAME secrets without holding values."""
    return any(p.search(rel_posix) for p in _ALLOWLIST_CONTENT_PATH_PATTERNS)


def _is_allowlisted_fixture(rel_posix: str) -> bool:
    """True when the path is a clearly-synthetic test fixture."""
    return any(p.search(rel_posix) for p in _ALLOWLIST_FIXTURE_PATTERNS)


def _filename_is_key_material(name: str) -> bool:
    """True when a bare filename matches a conventional private-key name."""
    return any(p.search(name) for p in _KEY_MATERIAL_FILENAME_PATTERNS)


def _scan_content(rel_posix: str, path: Path, result: _ScanResult) -> None:
    """Scan a single file's text content for PEM blocks / secret assignments."""
    try:
        raw = path.read_bytes()[:_MAX_READ_BYTES]
    except OSError:
        return
    # Decode leniently — secret shapes are ASCII; binary noise is ignored.
    text = raw.decode("utf-8", errors="replace")
    for rule_id, pattern in _CONTENT_RULES:
        if pattern.search(text):
            result.findings.append(
                Finding(
                    path=rel_posix,
                    rule=rule_id,
                    detail="key-material content shape detected in file body",
                )
            )


def scan_tree(root: Path) -> _ScanResult:
    """Walk ``root`` and collect every key-material finding.

    Args:
        root: Repository root to scan.

    Returns:
        A :class:`_ScanResult` carrying findings (rule + path only — never a
        secret value) and the count of files scanned.
    """
    result = _ScanResult()
    root = root.resolve()
    for path in sorted(root.rglob("*")):
        if path.is_dir():
            continue
        # Skip anything under an ignored directory.
        rel = path.relative_to(root)
        if any(part in _SKIP_DIRS for part in rel.parts):
            continue
        rel_posix = rel.as_posix()
        result.files_scanned += 1

        # Synthetic fixtures are expected to carry fake key-shaped content.
        if _is_allowlisted_fixture(rel_posix):
            continue

        # 1. Extension / filename denylist (the file IS key material).
        if path.suffix.lower() in _KEY_MATERIAL_EXTENSIONS or _filename_is_key_material(path.name):
            result.findings.append(
                Finding(
                    path=rel_posix,
                    rule="key-material-file",
                    detail=f"key-material file extension/name '{path.name}'",
                )
            )
            continue

        # 2. In-file content shapes — unless the path may NAME secrets.
        if _is_allowlisted_content(rel_posix):
            continue
        _scan_content(rel_posix, path, result)

    return result


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="pre_publish_secret_scrub",
        description=(
            "Pre-publish secret-scrub gate — HARD BLOCK on any committed key "
            "material. Run before the repo is made public or a release is cut."
        ),
    )
    parser.add_argument(
        "--root",
        default=None,
        help="Repository root to scan (default: the repo containing this script).",
    )
    parser.add_argument(
        "--json",
        action="store_true",
        help="Emit a JSON report instead of human-readable text.",
    )
    return parser


def _default_root() -> Path:
    """Repo root = the parent of this script's ``scripts/`` directory."""
    return Path(__file__).resolve().parent.parent


def main(argv: list[str] | None = None) -> int:
    """Gate entry point. Returns a process exit code (0 clean / 1 block / 2 error)."""
    args = _build_parser().parse_args(argv if argv is not None else sys.argv[1:])
    root = Path(args.root).expanduser() if args.root else _default_root()
    if not root.is_dir():
        print(f"error: scan root does not exist: {root}", file=sys.stderr)
        return 2

    result = scan_tree(root)

    if args.json:
        print(
            json.dumps(
                {
                    "root": str(root),
                    "files_scanned": result.files_scanned,
                    "blocked": bool(result.findings),
                    "findings": [
                        {"path": f.path, "rule": f.rule, "detail": f.detail}
                        for f in result.findings
                    ],
                },
                indent=2,
            )
        )
    elif result.findings:
        print(
            "SECURITY: pre-publish secret-scrub gate BLOCKED — "
            f"{len(result.findings)} key-material finding(s); nothing publishes.",
            file=sys.stderr,
        )
        for finding in result.findings:
            print(finding.render(), file=sys.stderr)
        print(
            "\nRemediation: remove the material, ROTATE the exposed secret, then "
            "re-run the gate. Secrets belong in HSM/KMS/keychain/CI store — never "
            "the repo.",
            file=sys.stderr,
        )
    else:
        print(
            f"pre-publish secret-scrub: CLEAN ({result.files_scanned} files scanned) "
            "— safe to publish."
        )

    return 1 if result.findings else 0


if __name__ == "__main__":
    raise SystemExit(main())
