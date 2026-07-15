"""Shared fixtures for the signer test suite."""

from __future__ import annotations

import os
import shutil
import tempfile
from collections.abc import Iterator

import pytest


@pytest.fixture
def short_sock() -> Iterator[str]:
    """Yield a short AF_UNIX socket path and clean up its directory.

    pytest's ``tmp_path`` on macOS resolves under ``/private/var/folders/...``,
    producing paths >104 bytes. macOS/BSD cap ``sun_path`` at 104 (Linux 108),
    so ``bind()`` on a ``tmp_path``-based socket raises ``OSError`` before the
    server can ``listen()``. Bind under the platform temp root instead, which is
    short enough on every supported OS.
    """
    d = tempfile.mkdtemp(prefix="pgs_")
    try:
        yield os.path.join(d, "s.sock")
    finally:
        shutil.rmtree(d, ignore_errors=True)
