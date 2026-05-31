"""Per-platform signing backends.

Each backend shells out to the canonical OS / OSS signing tool for its platform
(Windows: SignTool/osslsigncode/jsign; macOS/iOS: codesign/notarytool/stapler;
Linux: gpg/minisign/cosign; Android: apksigner/jarsigner) and emits a structured
SigningOutcome. A backend NEVER fakes a signature: when its tool or the required
credential is absent it emits a structured skipped/blocked reason.
"""

from __future__ import annotations

__all__: list[str] = []
