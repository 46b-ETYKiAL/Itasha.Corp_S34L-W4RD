# Ships Publicly vs. Never — SealWard IP-Safety Boundary

This repository is **public on purpose**. A code-signing tool's security comes
from **private-key secrecy and key custody**, not from hiding the source. This
is [Kerckhoffs's principle](https://en.wikipedia.org/wiki/Kerckhoffs's_principle)
applied directly: a cryptosystem must remain secure even when everything about
it *except the key* is public knowledge. The entire industry signs production
software with public tools — cosign, jsign, osslsigncode, minisign, GnuPG,
apksigner, Apple `codesign`/`notarytool`, Microsoft `SignTool`. Publishing a
signing tool's source reveals nothing that protects the apps it signs.

What actually protects the apps is enforced **outside** this repo by the
[CA/Browser Forum hardware-key mandate](https://www.entrust.com/blog/2022/09/ca-browser-forum-updates-requirements-for-code-signing-certificate-private-keys)
(Ballot CSC-17, effective 2023-06-01): every newly issued code-signing
certificate private key — Standard and EV alike — must be generated and stored
in a hardware crypto module meeting **FIPS 140-2 Level 2 or Common Criteria
EAL 4+**, with a **non-exportable** private key. SealWard is built to honour
that boundary: it references keys by handle and never holds the material.

## EXACT conditions under which public is safe

Public is safe **if and only if ALL** of the following hold (dossier §1):

1. **No private keys, certificates with private keys, `.p12`/`.pfx`, `.pem`
   keys, keystores, Apple provisioning profiles (`.mobileprovision`/`.p8`
   App Store Connect keys), or CI credentials are ever committed.** Secrets
   live ONLY in HSM/KMS/OS keychain/CI secret store.
2. Secret material is referenced by **handle/URI** (e.g., Key Vault URL, KMS
   key ARN, PKCS#11 slot label), never by inline value.
3. A **secret-scanning gate** (gitleaks, plus push protection) runs
   pre-commit + pre-push + CI and blocks any key-shaped content.
4. A hardened **`.gitignore`** excludes `*.p12 *.pfx *.pem *.key *.keystore
   *.jks *.mobileprovision *.p8 *.cer` and any `secrets/` dir.

## MUST NEVER be in a public repo

The following must **never** be committed (verbatim from dossier §1):

> signing private keys; keystore/JKS files + their passwords; `.p12`/`.pfx`
> bundles; PEM private keys; Apple `.p8` App Store Connect keys; provisioning
> profiles; the Fastlane `MATCH_PASSWORD`; any cloud credential (Azure SP
> secret, AWS access key, GCP SA JSON); HSM/token PINs.

Expanded to the concrete file/secret shapes the four-layer defense blocks:

| Category | Never commit |
|---|---|
| Private keys / cert bundles | `*.p12`, `*.pfx`, `*.pem` (private), `*.key`, `*.der`, `*.cer`, `*.crt`, `*.csr` |
| Java keystores | `*.jks`, `*.keystore`, `*.bks` + their store/key passwords |
| Apple signing material | `*.p8` (App Store Connect API key), `*.mobileprovision`, `*.provisionprofile` |
| SSH / GPG private keys | `id_rsa*`, `id_ed25519*`, `id_ecdsa*`, `id_dsa*`, `*.gpg`, `*.pgp`, `*.asc`, `secring.*` |
| minisign / signify | `*.sec`, `minisign.key` |
| Fastlane | `MATCH_PASSWORD` |
| Cloud credentials | Azure SP client secret, AWS access key + secret, GCP service-account JSON, HashiCorp Vault token |
| HSM / token | PKCS#11 PIN, token PIN, HSM PIN, slot PIN |

## What MAY be public

| May be public | Why it is safe |
|---|---|
| All source code (`src/sealward/**`) | Kerckhoffs — implementation reveals no key |
| Config files referencing secret **handles** | A handle (slot label / ARN / Key Vault URI / Vault path) names *where* a key lives, never its value |
| `.gitleaks.toml`, `.gitignore`, CI workflows | They name secret env-var NAMES, never values |
| SBOM, SLSA provenance, Sigstore bundles for SealWard's OWN releases | Transparency artifacts — public by design |
| Example/fixture secrets that are **clearly synthetic** | Tests plant obviously-fake values to prove the scrub gate BLOCKS them |

## Residual risk of public + mitigations (dossier §1)

- **Metadata leakage** — public CI config can reveal which secret/env-var NAMES
  exist (e.g., `AZURE_KEY_VAULT_URL`, `MATCH_PASSWORD`), aiding targeted
  phishing. *Mitigation:* names only, never values; least-privilege CI
  identities (OIDC/workload identity, not long-lived PATs); branch protection
  + required reviews so a malicious PR cannot exfiltrate via a modified
  workflow.
- **Supply-chain targeting of the tool itself** — attackers know the build
  path. *Mitigation:* pin dependencies, sign the signer's own releases, enable
  SLSA provenance, restrict who can trigger signing workflows.

These are the standard public-OSS posture; none require source secrecy.

## The four-layer defense (enforcement)

| Layer | Mechanism |
|---|---|
| 1. Hardened `.gitignore` | Excludes every key-shaped extension + secret directory |
| 2. `.gitleaks.toml` | Default rule pack + 9 signing-specific custom rules (pre-commit + pre-push + CI) |
| 3. Pre-publish secret-scrub gate | Hard precondition on any release; BLOCKS on any planted key-shaped content |
| 4. Human approval | The release workflow never force-publishes; a human approves every release |

If any layer detects key-shaped content, the operation is HARD-BLOCKED, a
SECURITY-class event is emitted, and nothing is published. Remediation: remove
the material, **rotate the exposed secret**, then resume.
