"""Unit tests for the own-release provenance modules (SBOM / SLSA / Sigstore).

These tests use fakes/mocks for the optional ``sigstore`` library — they never
contact the real Fulcio/Rekor services and never require a credential. The
load-bearing assertions are the HONESTY properties:

* the Sigstore signer degrades to a structured ``SKIPPED_*`` outcome when the
  library is absent or below the CVE-2026-24137 floor (never a fabricated
  ``SIGNED``);
* the verify path REJECTS a bundle not bound to the artifact digest
  (GHSA-whqx-f9j3-ch6m);
* the SBOM is a valid CycloneDX 1.6 document listing every declared dep and
  carries no secret;
* the SLSA statement computes real subject digests and never fabricates one.
"""

from __future__ import annotations

import json
from datetime import UTC, datetime
from pathlib import Path

import pytest

from sealward.provenance import sbom, sigstore_release, slsa
from sealward.provenance.sigstore_release import SigstoreReleaseSigner
from sealward.result import SigningStatus, VerifyVerdict

# --------------------------------------------------------------------------- #
# SBOM (T7.2)                                                                  #
# --------------------------------------------------------------------------- #


def test_sbom_is_valid_cyclonedx_1_6() -> None:
    doc = sbom.build_sbom()
    assert doc["bomFormat"] == "CycloneDX"
    assert doc["specVersion"] == "1.6"
    assert str(doc["serialNumber"]).startswith("urn:uuid:")
    assert doc["version"] == 1
    metadata = doc["metadata"]
    assert isinstance(metadata, dict)
    assert "timestamp" in metadata
    root = metadata["component"]
    assert isinstance(root, dict)
    assert root["name"] == "sealward"
    assert isinstance(doc["components"], list)


def test_sbom_lists_pydantic_core_dependency() -> None:
    # pydantic is the single declared core dependency — it MUST appear.
    doc = sbom.build_sbom()
    names = {c["name"].lower() for c in doc["components"]}  # type: ignore[index]
    assert "pydantic" in names


def test_sbom_falls_back_to_pyproject_when_distribution_absent() -> None:
    """When the dist is NOT installed, deps come from pyproject.toml (no omission).

    Reconciliation #1: an SBOM must list declared deps regardless of install
    state. Querying a distribution name that is not installed forces the
    pyproject fallback; pydantic (the declared core dep) MUST still appear.
    """
    components = sbom._collect_components("sealward-definitely-not-installed-xyz")
    names = {c.name.lower() for c in components}
    assert "pydantic" in names
    # The fallback marks versions as declared-not-installed honestly (no fabricated
    # concrete version) UNLESS the package happens to be importable in the env.
    assert all(c.version for c in components)


def test_sbom_component_declared_not_installed_carries_honesty_flag() -> None:
    comp = sbom.SbomComponent("nope-not-real-pkg", "1.2.3", installed=False)
    rendered = comp.to_dict()
    props = rendered["properties"]
    assert props[0]["value"] == "declared-not-installed"
    assert rendered["purl"] == "pkg:pypi/nope-not-real-pkg@1.2.3"


def test_sbom_root_component_falls_back_to_zero_version_when_absent() -> None:
    root = sbom._root_component("sealward-not-installed-xyz")
    assert root["name"] == "sealward-not-installed-xyz"
    assert root["version"] == "0.0.0"  # honest fallback, never fabricated


def test_sbom_components_have_purl_and_version() -> None:
    doc = sbom.build_sbom()
    for component in doc["components"]:  # type: ignore[union-attr]
        assert component["name"]
        assert component["version"]
        assert str(component["purl"]).startswith("pkg:pypi/")


def test_sbom_deterministic_serial_and_timestamp() -> None:
    when = datetime(2026, 1, 1, tzinfo=UTC)
    serial = "urn:uuid:00000000-0000-0000-0000-000000000000"
    a = sbom.build_sbom(serial_number=serial, timestamp=when)
    b = sbom.build_sbom(serial_number=serial, timestamp=when)
    assert json.dumps(a) == json.dumps(b)
    assert a["serialNumber"] == serial
    assert a["metadata"]["timestamp"] == "2026-01-01T00:00:00Z"  # type: ignore[index]


def test_sbom_no_secret_shaped_content() -> None:
    rendered = sbom.render_sbom_json().lower()
    for forbidden in ("private key", "begin rsa", "password", "secret_access_key"):
        assert forbidden not in rendered


def test_sbom_render_json_roundtrips() -> None:
    parsed = json.loads(sbom.render_sbom_json())
    assert parsed["bomFormat"] == "CycloneDX"


# --------------------------------------------------------------------------- #
# SLSA (T7.3)                                                                  #
# --------------------------------------------------------------------------- #


def _artifact(tmp_path: Path, name: str = "sealward-0.1.0.tar.gz") -> Path:
    path = tmp_path / name
    path.write_bytes(b"release-artifact-bytes")
    return path


def test_slsa_statement_shape(tmp_path: Path) -> None:
    artifact = _artifact(tmp_path)
    statement = slsa.build_slsa_provenance(
        [artifact],
        builder_id="https://github.com/46b-ETYKiAL/Itasha.Corp_S34L-W4RD/.github/workflows/release.yml",
        build_type="https://slsa.dev/github-actions/v1",
    )
    assert statement["_type"] == slsa.IN_TOTO_STATEMENT_TYPE
    assert statement["predicateType"] == slsa.SLSA_PREDICATE_TYPE
    subjects = statement["subject"]
    assert len(subjects) == 1  # type: ignore[arg-type]
    subject = subjects[0]  # type: ignore[index]
    assert subject["name"] == artifact.name
    assert "sha256" in subject["digest"]  # type: ignore[index]


def test_slsa_digest_is_real_not_fabricated(tmp_path: Path) -> None:
    import hashlib

    artifact = _artifact(tmp_path)
    expected = hashlib.sha256(artifact.read_bytes()).hexdigest()
    statement = slsa.build_slsa_provenance(
        [artifact], builder_id="urn:builder", build_type="urn:buildtype"
    )
    assert statement["subject"][0]["digest"]["sha256"] == expected  # type: ignore[index]


def test_slsa_missing_artifact_refuses_to_fabricate(tmp_path: Path) -> None:
    with pytest.raises(FileNotFoundError):
        slsa.build_slsa_provenance(
            [tmp_path / "does-not-exist.tar.gz"],
            builder_id="urn:builder",
            build_type="urn:buildtype",
        )


def test_slsa_requires_at_least_one_subject() -> None:
    with pytest.raises(ValueError, match="at least one subject"):
        slsa.build_slsa_provenance([], builder_id="urn:b", build_type="urn:t")


def test_slsa_includes_materials(tmp_path: Path) -> None:
    artifact = _artifact(tmp_path)
    material = slsa.BuildMaterial(
        "git+https://github.com/46b-ETYKiAL/Itasha.Corp_S34L-W4RD@v0.1.0",
        {"sha1": "deadbeef" * 5},
    )
    statement = slsa.build_slsa_provenance(
        [artifact],
        builder_id="urn:builder",
        build_type="urn:buildtype",
        materials=[material],
        external_parameters={"ref": "refs/tags/v0.1.0"},
    )
    deps = statement["predicate"]["buildDefinition"]["resolvedDependencies"]  # type: ignore[index]
    assert deps[0]["uri"].startswith("git+https://")
    assert deps[0]["digest"]["sha1"]
    ext = statement["predicate"]["buildDefinition"]["externalParameters"]  # type: ignore[index]
    assert ext["ref"] == "refs/tags/v0.1.0"


def test_slsa_no_secret_in_attestation(tmp_path: Path) -> None:
    artifact = _artifact(tmp_path)
    rendered = slsa.render_slsa_json(
        [artifact], builder_id="urn:builder", build_type="urn:buildtype"
    ).lower()
    for forbidden in ("private key", "password", "secret_access_key", "begin rsa"):
        assert forbidden not in rendered


# --------------------------------------------------------------------------- #
# Sigstore (T7.1)                                                              #
# --------------------------------------------------------------------------- #


class _FakeSignResult:
    """Stand-in for a real sigstore sign result (bundle + Rekor log index)."""

    def __init__(self, bundle: str, log_index: int) -> None:
        self.bundle = bundle
        self.log_index = log_index


class _FakeVerdict:
    def __init__(self, *, verified: bool, artifact_digest: str | None) -> None:
        self.verified = verified
        self.artifact_digest = artifact_digest


class _FakeClient:
    """Fake Sigstore client: deterministic, offline, digest-aware.

    ``sign_artifact`` returns a fake bundle + log index; ``verify_artifact``
    returns a verdict that BINDS the artifact's real SHA-256 by default, so the
    happy path exercises the digest-binding check truthfully.
    """

    def __init__(self, *, bind_digest: bool = True, verified: bool = True) -> None:
        self._bind = bind_digest
        self._verified = verified

    def sign_artifact(self, artifact: Path) -> _FakeSignResult:
        return _FakeSignResult(bundle=f'{{"artifact":"{artifact.name}"}}', log_index=4242)

    def verify_artifact(self, artifact: Path, bundle_bytes: bytes) -> _FakeVerdict:
        import hashlib

        digest = hashlib.sha256(artifact.read_bytes()).hexdigest()
        return _FakeVerdict(
            verified=self._verified,
            artifact_digest=digest if self._bind else None,
        )


def test_sigstore_unavailable_degrades_to_skipped(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    # Simulate the library being absent and no injected client.
    monkeypatch.setattr(sigstore_release, "_SIGSTORE_AVAILABLE", False)
    artifact = _artifact(tmp_path)
    signer = SigstoreReleaseSigner()  # no client injected
    outcome = signer.sign(artifact)
    assert outcome.status == SigningStatus.SKIPPED_TOOL_ABSENT
    assert outcome.status.is_success is False
    assert outcome.skipped_reason is not None
    assert "sigstore-unavailable" in outcome.skipped_reason


def test_sigstore_below_version_floor_refuses_to_sign(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    # Library present but below the CVE-2026-24137 floor → SKIPPED, never SIGNED.
    monkeypatch.setattr(sigstore_release, "_SIGSTORE_AVAILABLE", True)
    monkeypatch.setattr(sigstore_release, "sigstore_version", lambda: "3.9.0")
    artifact = _artifact(tmp_path)
    signer = SigstoreReleaseSigner(client=_FakeClient())
    outcome = signer.sign(artifact)
    assert outcome.status == SigningStatus.SKIPPED_TOOL_ABSENT
    assert "CVE-2026-24137" in (outcome.skipped_reason or "")


def test_sigstore_happy_path_signs_and_verifies_with_fake(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(sigstore_release, "_SIGSTORE_AVAILABLE", True)
    monkeypatch.setattr(sigstore_release, "sigstore_version", lambda: "4.0.1")
    artifact = _artifact(tmp_path)
    signer = SigstoreReleaseSigner(client=_FakeClient(bind_digest=True, verified=True))
    outcome = signer.sign(artifact)
    assert outcome.status == SigningStatus.SIGNED
    assert outcome.verify_verdict == VerifyVerdict.PASSED
    assert outcome.evidence["rekor_log_index"] == 4242
    assert outcome.evidence["sigstore_version"] == "4.0.1"
    # The bundle was written next to the artifact.
    assert (tmp_path / (artifact.name + ".sigstore.json")).is_file()


def test_sigstore_rejects_bundle_not_bound_to_digest(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    # GHSA-whqx-f9j3-ch6m: a green verify that does not bind the digest is rejected.
    monkeypatch.setattr(sigstore_release, "_SIGSTORE_AVAILABLE", True)
    monkeypatch.setattr(sigstore_release, "sigstore_version", lambda: "4.0.1")
    artifact = _artifact(tmp_path)
    signer = SigstoreReleaseSigner(client=_FakeClient(bind_digest=False, verified=True))
    outcome = signer.sign(artifact)
    assert outcome.status == SigningStatus.FAILED
    assert outcome.verify_verdict == VerifyVerdict.FAILED
    assert "digest" in (outcome.error or "").lower()


def test_sigstore_version_floor_constant() -> None:
    assert sigstore_release.SIGSTORE_MIN_VERSION == (4, 0, 1)


def test_sigstore_missing_artifact_fails_honestly(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(sigstore_release, "_SIGSTORE_AVAILABLE", True)
    monkeypatch.setattr(sigstore_release, "sigstore_version", lambda: "4.0.1")
    signer = SigstoreReleaseSigner(client=_FakeClient())
    outcome = signer.sign(tmp_path / "missing.tar.gz")
    assert outcome.status == SigningStatus.FAILED
    assert "not found" in (outcome.error or "").lower()


def test_sigstore_sign_error_degrades_to_failed_not_raise(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    class _BoomClient:
        def sign_artifact(self, artifact: Path) -> object:
            raise RuntimeError("fulcio unreachable")

    monkeypatch.setattr(sigstore_release, "_SIGSTORE_AVAILABLE", True)
    monkeypatch.setattr(sigstore_release, "sigstore_version", lambda: "4.0.1")
    artifact = _artifact(tmp_path)
    signer = SigstoreReleaseSigner(client=_BoomClient())
    outcome = signer.sign(artifact)
    assert outcome.status == SigningStatus.FAILED
    assert "fulcio unreachable" in (outcome.error or "")


def test_sigstore_no_key_material_logged_on_error(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    class _LeakyClient:
        def sign_artifact(self, artifact: Path) -> object:
            raise RuntimeError("-----BEGIN PRIVATE KEY-----\nAAAA\n-----END PRIVATE KEY-----")

    monkeypatch.setattr(sigstore_release, "_SIGSTORE_AVAILABLE", True)
    monkeypatch.setattr(sigstore_release, "sigstore_version", lambda: "4.0.1")
    artifact = _artifact(tmp_path)
    signer = SigstoreReleaseSigner(client=_LeakyClient())
    outcome = signer.sign(artifact)
    assert outcome.status == SigningStatus.FAILED
    assert "PRIVATE KEY" not in (outcome.error or "")
    assert "[redacted key material]" in (outcome.error or "")


# --------------------------------------------------------------------------- #
# Module CLIs — the runnable entry points the release workflow invokes         #
# --------------------------------------------------------------------------- #


def test_sbom_cli_writes_valid_document_to_output(tmp_path: Path) -> None:
    out = tmp_path / "nested" / "sealward.cdx.json"
    rc = sbom.main(["--output", str(out)])
    assert rc == 0
    doc = json.loads(out.read_text(encoding="utf-8"))
    assert doc["bomFormat"] == "CycloneDX"
    assert doc["specVersion"] == "1.6"
    names = {c["name"].lower() for c in doc["components"]}
    assert "pydantic" in names


def test_sbom_cli_stdout_default(capsys) -> None:
    rc = sbom.main([])
    assert rc == 0
    doc = json.loads(capsys.readouterr().out)
    assert doc["bomFormat"] == "CycloneDX"


def test_sbom_cli_deterministic_serial(capsys) -> None:
    serial = "urn:uuid:00000000-0000-0000-0000-000000000000"
    rc = sbom.main(["--serial-number", serial])
    assert rc == 0
    assert json.loads(capsys.readouterr().out)["serialNumber"] == serial


def test_slsa_cli_emits_statement_with_real_digest(tmp_path: Path, capsys) -> None:
    artifact = _artifact(tmp_path)
    rc = slsa.main(
        [
            "--artifact",
            str(artifact),
            "--builder-id",
            "https://example.test/ci",
            "--build-type",
            "https://example.test/build",
        ]
    )
    assert rc == 0
    statement = json.loads(capsys.readouterr().out)
    assert statement["_type"] == slsa.IN_TOTO_STATEMENT_TYPE
    assert statement["subject"][0]["name"] == artifact.name
    assert len(statement["subject"][0]["digest"]["sha256"]) == 64


def test_slsa_cli_requires_an_artifact(capsys) -> None:
    rc = slsa.main(["--builder-id", "https://example.test/ci"])
    assert rc == 2
    assert "at least one --artifact" in capsys.readouterr().err


def test_slsa_cli_missing_subject_file_is_clean_error(tmp_path: Path, capsys) -> None:
    rc = slsa.main(
        [
            "--artifact",
            str(tmp_path / "does-not-exist.whl"),
            "--builder-id",
            "https://example.test/ci",
        ]
    )
    assert rc == 2  # FileNotFoundError handled, never raised into the process


def test_slsa_cli_uses_github_env_defaults(tmp_path: Path, capsys, monkeypatch) -> None:
    artifact = _artifact(tmp_path)
    monkeypatch.setenv(
        "GITHUB_WORKFLOW_REF", "owner/repo/.github/workflows/release.yml@refs/tags/v1"
    )
    monkeypatch.setenv("GITHUB_SERVER_URL", "https://github.com")
    monkeypatch.setenv("GITHUB_REPOSITORY", "owner/repo")
    monkeypatch.setenv("GITHUB_SHA", "a" * 40)
    monkeypatch.setenv("GITHUB_RUN_ID", "12345")
    monkeypatch.setenv("GITHUB_REF", "refs/tags/v1")
    rc = slsa.main(["--artifact", str(artifact)])  # no --builder-id; from env
    assert rc == 0
    statement = json.loads(capsys.readouterr().out)
    builder = statement["predicate"]["runDetails"]["builder"]["id"]
    assert builder.endswith("release.yml@refs/tags/v1")
    deps = statement["predicate"]["buildDefinition"]["resolvedDependencies"]
    assert any(d["uri"].endswith("owner/repo") for d in deps)


def test_sigstore_release_cli_skips_cleanly_when_unavailable(
    tmp_path: Path, monkeypatch, capsys
) -> None:
    """When sigstore is absent, the CLI exits 3 (honest 'could not sign')."""
    monkeypatch.setattr(sigstore_release, "_SIGSTORE_AVAILABLE", False)
    dist = tmp_path / "dist"
    dist.mkdir()
    (dist / "sealward-0.1.0-py3-none-any.whl").write_bytes(b"wheel")
    rc = sigstore_release.main(["--dist", str(dist)])
    assert rc == 3
    assert "skipped" in capsys.readouterr().err.lower()


def test_sigstore_release_cli_missing_dist_is_error(tmp_path: Path, capsys) -> None:
    rc = sigstore_release.main(["--dist", str(tmp_path / "nope")])
    assert rc == 2
    assert "not found" in capsys.readouterr().err


def test_sigstore_release_cli_no_artifacts_is_error(tmp_path: Path, capsys) -> None:
    dist = tmp_path / "dist"
    dist.mkdir()
    rc = sigstore_release.main(["--dist", str(dist)])
    assert rc == 2
    assert "no *.whl" in capsys.readouterr().err


def test_sigstore_release_cli_rejects_wrong_bundle_suffix(tmp_path: Path, capsys) -> None:
    dist = tmp_path / "dist"
    dist.mkdir()
    rc = sigstore_release.main(["--dist", str(dist), "--bundle-suffix", ".sig"])
    assert rc == 2
    assert "bundle-suffix" in capsys.readouterr().err


def test_sigstore_release_cli_signs_when_client_available(
    tmp_path: Path, monkeypatch, capsys
) -> None:
    """With a fake signing client + version floor met, the CLI signs + exits 0."""

    class _FakeBundle:
        def to_json(self) -> str:
            return "{}"

    class _FakeResult:
        bundle = _FakeBundle()
        log_index = 7

    class _FakeClient:
        def sign_artifact(self, artifact: Path) -> object:
            return _FakeResult()

        def verify_artifact(self, artifact: Path, bundle_bytes: bytes) -> object:
            import hashlib

            digest = hashlib.sha256(artifact.read_bytes()).hexdigest()

            class _V:
                verified = True
                artifact_digest = digest

            return _V()

    monkeypatch.setattr(sigstore_release, "_SIGSTORE_AVAILABLE", True)
    monkeypatch.setattr(sigstore_release, "sigstore_version", lambda: "4.0.1")
    monkeypatch.setattr(
        sigstore_release.SigstoreReleaseSigner,
        "_build_client",
        lambda self: _FakeClient(),
    )
    dist = tmp_path / "dist"
    dist.mkdir()
    (dist / "sealward-0.1.0-py3-none-any.whl").write_bytes(b"wheel-bytes")
    rc = sigstore_release.main(["--dist", str(dist)])
    assert rc == 0
    assert (dist / "sealward-0.1.0-py3-none-any.whl.sigstore.json").is_file()
