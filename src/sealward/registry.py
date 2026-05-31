"""Canonical, invocation-independent backend registry.

This module is the SINGLE source of truth for the ``platform → backend factory``
dispatch table. It lives in its OWN module (never ``sealward.cli``) so the
registry dict is the same object regardless of how the CLI is entered:

* the ``sealward`` console-script entry point (``sealward.cli:main``), and
* ``python -m sealward.cli`` (which loads ``cli.py`` a SECOND time under the
  module name ``__main__``).

Under ``python -m sealward.cli`` the runpy machinery executes ``cli.py`` as the
``__main__`` module — a *distinct* module object from ``sealward.cli``. If the
registry dict lived in ``cli.py``, the ``__main__`` copy and the ``sealward.cli``
copy would each hold their OWN empty dict, while the backend modules (which do
``from sealward.cli import register_backend``) would populate only the
``sealward.cli`` copy. The ``probe`` command running inside ``__main__`` would
then read its own empty dict and report every platform as unregistered — the
"registry double-import trap".

By anchoring the dict here, both ``cli.py`` instances and every backend module
share ONE dict (``sealward.registry`` is imported exactly once, normally), so
registration is canonical and idempotent under every entry point.

The registry holds only zero-arg backend factories (a class or callable). It
never holds key material and never imports a concrete backend (the backends
import *this* module, not the reverse — keeping the dependency edge acyclic).
"""

from __future__ import annotations

from typing import TYPE_CHECKING

from sealward.config_schema import Platform

if TYPE_CHECKING:  # pragma: no cover - typing only
    from sealward.backends.base import SignerBackend

__all__ = [
    "get_backend",
    "register_backend",
    "registered_platforms",
]

#: The single canonical dispatch table. Backends self-register a zero-arg
#: factory here at import time; ``get_backend`` resolves a live instance.
_BACKEND_FACTORIES: dict[Platform, type[SignerBackend] | object] = {}


def register_backend(platform: Platform, factory: object) -> None:
    """Register a backend factory (zero-arg callable) for ``platform``.

    Idempotent: re-registering the same platform replaces the prior factory,
    so a backend module imported more than once (e.g. once as a package member
    and again via a re-export) never duplicates or corrupts the table.
    """
    _BACKEND_FACTORIES[platform] = factory


def get_backend(platform: Platform) -> SignerBackend | None:
    """Return a backend instance for ``platform``, or ``None`` if unregistered."""
    factory = _BACKEND_FACTORIES.get(platform)
    if factory is None:
        return None
    return factory()  # type: ignore[operator]


def registered_platforms() -> list[Platform]:
    """Return the platforms with a registered backend (sorted by value)."""
    return sorted(_BACKEND_FACTORIES.keys(), key=lambda p: p.value)
