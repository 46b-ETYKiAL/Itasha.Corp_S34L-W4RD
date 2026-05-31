# ADR-0001: Cross-Platform Code-Signer Architecture

- Status: Accepted
- Date: 2026-05-30
- Deciders: Itasha.Corp engineering
- Supersedes: none

## Context

Itasha.Corp ships software for five target platforms — Windows, macOS,
Linux, Android, and iOS — and needs to **sign** the produced artifacts so
end users and OS gatekeepers (SmartScreen, Gatekeeper, Play Protect)
trust them. Before SealWard, signing logic lived as a handful of
platform-specific scripts co-located inside the installer repo
(`sign-windows.ps1`, `sign-artifacts.sh`, `gen-minisign-key.sh`). That
arrangement had three problems:

1. **No reuse.** Any repo other than the installer that needed to sign a
   release artifact had to copy the scripts.
2. **No uniform contract.** Each script took different arguments, emitted
   different output, and handled the "tool absent" / "credential absent"
   cases differently — some faked success.
3. **Key-custody coupling.** The scripts assumed a particular local cert
   store. Moving a key into an HSM/KMS (now mandatory under the
   CA/Browser Forum hardware-key requirement, effective 2023-06-01)
   meant rewriting the script.

We also operate under hard constraints from the org:

- **Engine/CLI/model-agnostic** — no vendor LLM SDK; the tool is plain
  Python + shell-out to OS/OSS signing tools.
- **No paid services as a forced dependency** — the default path must
  work with free local tooling; any cloud HSM/KMS is BYO-key, opt-in.
- **Keys never live in the repo** — the repository source is published
  publicly; security must come from key secrecy + HSM/KMS custody, not
  from hiding source (Kerckhoffs's principle).

## Decision

Build **SealWard**, a standalone, reusable, cross-platform code-signing
orchestrator, with the following architecture:

### 1. Single orchestrator over a per-platform backend boundary

One orchestrator (`sealward.cli` → dispatch) reads a declarative signing
config, resolves each target's platform, and dispatches to exactly one
**backend** per platform. Every backend implements a single
`SignBackend` protocol (`sealward.backends.base`) exposing
`capabilities()`, `sign()`, and `verify()`. The backends shell out to
the canonical, battle-tested OS/OSS tool for each platform:

| Platform | Backend tool(s) |
|----------|-----------------|
| Windows | SignTool / osslsigncode / jsign + RFC-3161 timestamp |
| macOS | codesign + notarytool + stapler |
| Linux | GPG + minisign + Sigstore cosign |
| Android | apksigner (v2/v3/v4) + jarsigner fallback |
| iOS | codesign + Fastlane Match (BYO private profile repo) |

This is the industry SOTA pattern (cosign, jsign): a thin orchestrator
over per-target signers. One backend per file keeps each platform
implementation small (<500 LOC) and uniform; extension is
**add-a-backend**, never fork.

### 2. Pluggable key-custody abstraction (handles, never key bytes)

A single key-custody resolver (`sealward.keycustody.resolver`) is the
**only** point that turns a configured key reference into a signing
capability. It resolves a **handle** — a PKCS#11 slot label, a Windows
CNG/KSP key name, an Azure Key Vault URI, an AWS KMS ARN, a Google Cloud
KMS resource name, or a HashiCorp Vault path — and lets the **external**
custody store perform the cryptographic operation. SealWard never reads,
stores, copies, or logs key material. The default path uses the keys the
local platform already custodies (SignTool cert store, GPG keyring,
minisign key); cloud KMS / Azure Artifact Signing backends activate only
when the operator configures a cloud handle and are off by default.

### 3. The signer signs its OWN releases with public provenance

SealWard's own published CLI binary carries:

- **Sigstore keyless** signatures (Fulcio short-lived cert bound to an
  ambient OIDC CI identity + Rekor transparency log) — no long-lived
  signing key exists anywhere;
- a **CycloneDX SBOM** (`sealward.provenance.sbom`);
- a **SLSA build-provenance** attestation.

So a consumer that pins a SealWard semver tag can verify the binary they
run was built and published by SealWard's CI identity through an
auditable transparency log. Own-release provenance is deliberately
**separate** from the artifact-signing path (different module,
`sealward.provenance.*`) — they solve different problems and must not be
conflated.

### 4. Public-safety: keys-never-here, enforced in four layers

The repo is public on purpose. Four layers keep key material out:

1. a hardened `.gitignore`,
2. a `.gitleaks.toml` ruleset run at pre-commit + pre-push + CI,
3. a `scripts/pre_publish_secret_scrub.py` gate that is a **hard
   precondition** of the release workflow (a missing or red scrub
   blocks the entire release; it is never a silent pass), and
4. the architectural invariant that no code path ever holds key bytes —
   only handles.

### 5. Distribution boundary is the binary + config schema

SealWard publishes a versioned, Sigstore-signed CLI binary plus a stable
declarative signing-config schema. Consumers (the installer repo and any
org repo) pin a semver tag and invoke the binary. The contract is the
CLI arguments + the config schema — **not** a Python import. This keeps
the signer's evolution decoupled from its consumers and avoids the
cross-repo import-coupling that would otherwise grow a sync burden.

## Data flow

```
  signing.toml
       │
       ▼
  orchestrator ──► key-custody resolver  (handle ⇒ capability;
       │                                   custody stays in the
       │                                   external HSM/KMS/keychain)
       ▼
  per-platform backend  ──► shell-out to OS/OSS signing tool
       │
       ▼
  verify-after-sign  (every artifact re-verified before SigningOutcome)
       │
       ▼
  SigningOutcome (structured JSON per artifact)

  own releases:  build ─► sigstore keyless sign ─► SBOM ─► SLSA ─► GH release
                          (scrub gate is the hard precondition)
```

## Consequences

### Positive

- **Reuse across the org** — any repo signs releases by pinning the
  binary; no copied scripts.
- **Uniform contract** — one `SignBackend` protocol; one structured
  `SigningOutcome`; one honest absent-tool/absent-credential policy
  (warn + structured skip, never fake success).
- **Custody-agnostic** — moving a key from a local store to an HSM/KMS is
  a config change (a different handle), not a code change.
- **Public-safe** — the source can be public because security rests on
  key secrecy + external custody, not on source obscurity, and four
  layers keep key material out of the tree.
- **Auditable own-provenance** — Sigstore keyless + SBOM + SLSA let
  consumers verify the signer binary itself.

### Negative / trade-offs

- **Shell-out coupling** — backends depend on the OS/OSS tool being
  installed and on PATH; tool-version drift must be absorbed per backend.
  Mitigated by enforcing version floors at probe time (cosign ≥ 2.6.0 /
  v3 per GHSA-whqx-f9j3-ch6m, osslsigncode ≥ 2.13 per the 2.12 verify-time
  RCE, apksigner v4) and by a structured capability report.
- **Network for the cloud/provenance paths** — Sigstore, notarization,
  and cloud KMS require network; offline runs emit a structured
  skipped/blocked reason rather than failing silently or faking success.
- **A separate repo to maintain** — the standalone signer adds a
  cross-repo dependency vs. keeping signing co-located in the installer.
  Accepted because the reuse + isolated-audit-surface benefits outweigh
  the sync cost, and the binary+schema boundary keeps the coupling thin.

## Alternatives considered

- **Keep signing co-located in the installer repo.** Rejected: blocks
  reuse by any other repo and couples signer evolution to installer
  releases. The genuine gap was a *reusable* signer, not more installer
  scripts.
- **Mandatory cloud KMS / Azure Artifact Signing.** Rejected: violates
  the no-forced-paid-services constraint and excludes the free local
  path. Cloud KMS is retained only as an opt-in BYO-key backend.
- **A Python-import library boundary instead of a binary+schema.**
  Rejected: would couple every consumer's dependency tree to the
  signer's and grow a cross-repo sync burden. The CLI-binary + config
  schema is the thinner, more stable contract.
- **One mega-signer module for all platforms.** Rejected: a single file
  for five platforms violates file-size governance and makes the
  per-platform tool-version logic unmaintainable. One backend per file
  behind a shared protocol is the chosen decomposition.

## References

- CA/Browser Forum — code-signing private-key hardware requirement
  (effective 2023-06-01).
- Kerckhoffs's principle — security from key secrecy, not source secrecy.
- Sigstore (Fulcio + Rekor) keyless signing; SLSA build provenance;
  CycloneDX SBOM.
- cosign / jsign — orchestrator-over-per-target-signer prior art.
- Security advisories tracked at probe-time version floors:
  GHSA-whqx-f9j3-ch6m (cosign), CVE-2026-24137 (sigstore-python ≥ 4.0.0),
  osslsigncode 2.12 verify-time RCE (fixed in 2.13).
- Research dossier: the originating plan's `*-research/dossier.md` (see the
  plan archive for the full cited synthesis).
