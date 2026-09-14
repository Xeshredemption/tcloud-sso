# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Xeshredemption
import os

import pytest

import tcloud


@pytest.fixture
def tccli_dir(tmp_path, monkeypatch):
    """Point tcloud at an empty ~/.tccli of its own."""
    monkeypatch.setattr(tcloud, "TCCLI_DIR", str(tmp_path))
    monkeypatch.setattr(tcloud, "REGISTRY", str(tmp_path / "accounts.conf"))
    return tmp_path


@pytest.fixture
def restore_umask():
    old = os.umask(0o022)
    os.umask(old)
    yield
    os.umask(old)
