# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Xeshredemption
"""The tccli-private surface tcloud depends on.

tcloud drives tccli's sso internals directly. They are not a public api and can change
in any release, so this pins down exactly what is used: a tccli bump that breaks it
fails here, in CI, instead of in the middle of someone's login.

Verified in tccli-intl-en 3.1.164.1.
"""

import inspect
import json
import os
import stat

import pytest

sso = pytest.importorskip("tccli.sso")

from tccli.plugins.sso import configs  # noqa: E402
from tccli.plugins.sso.login import _get_token  # noqa: E402

import tcloud  # noqa: E402

SIGNATURES = {
    "verify_login_skey": ["token", "site"],
    "list_accounts_for_access_assignment": ["token", "site"],
    "list_role_configurations_for_account": ["uin", "token", "site"],
    "gen_saml_response": ["token", "login_type", "uin", "user_id", "conf_id", "site"],
    "assume_role_with_saml": ["saml_assertion", "principal_arn", "role_arn",
                              "role_ses_name", "dur", "site"],
    "save_credential": ["cred", "sso_info", "profile"],
    "cred_path_of_profile": ["profile"],
}


@pytest.mark.parametrize("name", sorted(SIGNATURES))
def test_sso_function_signature(name):
    assert list(inspect.signature(getattr(sso, name)).parameters) == SIGNATURES[name]


def test_get_token_signature():
    assert list(inspect.signature(_get_token).parameters) == ["auth_url", "state", "language"]


def test_default_lang():
    assert isinstance(configs.DEFAULT_LANG, str) and configs.DEFAULT_LANG


def test_tcloud_finds_the_internals():
    assert tcloud.import_tccli_internals() == (sso, configs, _get_token)


def test_save_credential_is_private_under_tclouds_umask(tmp_path, monkeypatch, restore_umask):
    """tccli writes with the process umask; tcloud's 077 must make the file 0600."""
    monkeypatch.setattr(sso, "cred_path_of_profile",
                        lambda profile: str(tmp_path / (profile + ".credential")))
    os.umask(0o077)
    sso.save_credential(
        {"Credentials": {"TmpSecretId": "id", "TmpSecretKey": "key", "Token": "tok"},
         "ExpiredTime": 0},
        {"token": "tok", "uin": 200000000001, "roleConfigurationId": "rc",
         "roleConfigurationName": "ReadOnly", "zoneId": "zone", "site": "site",
         "authUrl": "https://tencentcloudssointl.com/myorg/login", "expiresAt": 0},
        "p")
    path = tmp_path / "p.credential"
    assert stat.S_IMODE(path.stat().st_mode) == 0o600
    assert json.loads(path.read_text())["sso"]["uin"] == 200000000001
