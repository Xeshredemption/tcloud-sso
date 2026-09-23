# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Xeshredemption
"""Offline tests: no tccli process and no Tencent api is ever reached.

Every payload here is synthetic. Never paste a real api response in as a fixture —
it carries account uins, resource ids and addresses.
"""

import argparse
import json
import os
import signal
import subprocess
import time

import pytest

import tcloud

URL = "https://tencentcloudssointl.com/myorg/login"
OTHER = "https://tencentcloudssointl.com/otherorg/login"
PROFILES = {"a": {"auth_url": URL}, "b": {"auth_url": URL}, "c": {"auth_url": OTHER}}


def ns(**overrides):
    base = {"profile": None, "sso": None, "all": False}
    base.update(overrides)
    return argparse.Namespace(**base)


def write_cred(directory, name, payload, mode=0o600):
    path = directory / (name + ".credential")
    path.write_text(json.dumps(payload))
    path.chmod(mode)
    return path


def cred(creds_in, session_in, token="tok"):
    now = time.time()
    return {"expiresAt": int(now + creds_in),
            "sso": {"authUrl": URL, "uin": 200000000001, "token": token,
                    "expiresAt": int(now + session_in)}}


# ------------------------------------------------------------------ registry


def test_load_registry_merges_defaults(tccli_dir):
    (tccli_dir / "accounts.conf").write_text(
        "[defaults]\nrole = ReadOnly\nregion = ap-singapore\n\n"
        "[profile app-dev]\nuin = 200000000001\nauth_url = %s\n" % URL)
    assert tcloud.load_registry() == {"app-dev": {
        "role": "ReadOnly", "region": "ap-singapore", "uin": "200000000001", "auth_url": URL}}


@pytest.mark.parametrize("name", ["../escape", "a b", "-dash", "x/y", ".hidden"])
def test_load_registry_rejects_unsafe_profile_names(tccli_dir, name):
    (tccli_dir / "accounts.conf").write_text("[profile %s]\nauth_url = %s\n" % (name, URL))
    with pytest.raises(SystemExit):
        tcloud.load_registry()


@pytest.mark.parametrize("url", ["http://tencentcloudssointl.com/myorg/login",
                                 "tencentcloudssointl.com/myorg/login", "ftp://host/org/login"])
def test_load_registry_rejects_non_https_auth_url(tccli_dir, url):
    (tccli_dir / "accounts.conf").write_text("[profile p]\nauth_url = %s\n" % url)
    with pytest.raises(SystemExit):
        tcloud.load_registry()


def test_unknown_sso_host_warns_but_proceeds(capsys):
    tcloud.check_auth_url("https://sso.example.com/org/login", "t", warn_unknown=True)
    assert "not a known Tencent sso host" in capsys.readouterr().err


def test_known_sso_host_is_silent(capsys):
    tcloud.check_auth_url(URL, "t", warn_unknown=True)
    assert capsys.readouterr().err == ""


# ------------------------------------------------------------------ scope


def test_realm_of():
    assert tcloud.realm_of(URL) == "myorg"
    assert tcloud.realm_of("https://weird.example/") == "https://weird.example/"
    assert tcloud.realm_of(None) == "-"


def test_select_realms_by_slug_or_url():
    assert sorted(tcloud.select_realms(PROFILES, ["myorg"])) == ["a", "b"]
    assert sorted(tcloud.select_realms(PROFILES, [OTHER])) == ["c"]
    with pytest.raises(SystemExit):
        tcloud.select_realms(PROFILES, ["nope"])


def test_scope_of():
    assert tcloud.scope_of(ns(), PROFILES) is None
    assert sorted(tcloud.scope_of(ns(all=True), PROFILES)) == ["a", "b", "c"]
    for bad in (ns(all=True, sso=["myorg"]), ns(profile="a", all=True),
                ns(profile="a", sso=["myorg"])):
        with pytest.raises(SystemExit):
            tcloud.scope_of(bad, PROFILES)


def test_targets_of():
    assert tcloud.targets_of(ns(profile="c"), PROFILES) == ["c"]
    assert tcloud.targets_of(ns(sso=["myorg"]), PROFILES) == ["a", "b"]
    with pytest.raises(SystemExit):
        tcloud.targets_of(ns(), PROFILES)
    with pytest.raises(SystemExit):
        tcloud.targets_of(ns(profile="zzz"), PROFILES)


# ------------------------------------------------------------------ auth state


@pytest.mark.parametrize("payload,state", [
    (None, "none"),
    ({"sso": {}}, "unconfigured"),
    ({"sso": {"authUrl": URL}}, "none"),
    (cred(3600, -1), "active"),
    (cred(-1, -1), "expired"),
    (cred(-1, 3600), "refreshable"),
    (cred(-1, 3600, token=""), "expired"),
    (cred(3600, 7200), "active"),
])
def test_auth_status(tccli_dir, payload, state):
    if payload is not None:
        write_cred(tccli_dir, "p", payload)
    assert tcloud.auth_status("p")[0] == state


def test_ls_flags_credential_readable_by_others(tccli_dir, capsys):
    tcloud.Colour.strip()
    write_cred(tccli_dir, "open", cred(3600, 7200), mode=0o644)
    write_cred(tccli_dir, "closed", cred(3600, 7200), mode=0o600)
    tcloud.cmd_ls(argparse.Namespace(sso=None),
                  {"open": {"auth_url": URL}, "closed": {"auth_url": URL}})
    lines = {line.split()[0]: line for line in capsys.readouterr().out.splitlines()[1:]}
    assert "chmod 600" in lines["open"]
    assert "chmod 600" not in lines["closed"]


def test_main_sets_private_umask(monkeypatch, restore_umask):
    os.umask(0o022)
    monkeypatch.setattr("sys.argv", ["tcloud", "--version"])
    with pytest.raises(SystemExit):
        tcloud.main()
    assert os.umask(0o022) == 0o077


def test_tccli_bin_prefers_the_one_beside_the_interpreter(tmp_path, monkeypatch):
    fake = tmp_path / "tccli"
    fake.write_text("#!/bin/sh\n")
    fake.chmod(0o755)
    monkeypatch.setattr("sys.executable", str(tmp_path / "python"))
    assert tcloud.tccli_bin() == str(fake)
    fake.unlink()
    assert tcloud.tccli_bin() == "tccli"


# ------------------------------------------------------------------ login


class Configs:
    DEFAULT_LANG = "en-US"


class ApproveSSO:
    @staticmethod
    def verify_login_skey(token, site):
        return {"ZoneId": "zone"}


def test_approve_uses_a_fresh_unguessable_state():
    seen = []

    def get_token(url, state, lang):
        seen.append(state)
        return {"State": state, "Token": "tok", "Site": "site"}

    assert tcloud.approve(ApproveSSO, Configs, get_token, URL, 0) == ("tok", "site", "zone")
    tcloud.approve(ApproveSSO, Configs, get_token, URL, 0)
    assert len(seen[0]) == 32 and seen[0].isalnum() and seen[0] != seen[1]


def test_approve_rejects_a_mismatched_state():
    def get_token(url, state, lang):
        return {"State": "forged", "Token": "tok", "Site": "site"}

    with pytest.raises(ValueError, match="mismatched state"):
        tcloud.approve(ApproveSSO, Configs, get_token, URL, 0)


def test_deadline_aborts_a_hung_wait(capsys):
    started = time.monotonic()
    with pytest.raises(SystemExit):
        with tcloud.deadline(1, "test login"):
            time.sleep(10)
    assert time.monotonic() - started < 5
    assert "not approved within 1s" in capsys.readouterr().err


def test_deadline_zero_never_fires_and_restores_the_handler():
    before = signal.getsignal(signal.SIGALRM)
    with tcloud.deadline(0, "x"):
        pass
    assert signal.getsignal(signal.SIGALRM) is before


def test_deadline_counts_wall_clock_time_across_sleep(monkeypatch):
    """macOS pauses alarms during sleep; the deadline must still see the hour pass."""
    monkeypatch.setattr(tcloud, "DEADLINE_STEP", 1)
    real, slept = time.time, {"for": 0}
    monkeypatch.setattr(time, "time", lambda: real() + slept["for"])
    started = time.monotonic()
    with pytest.raises(SystemExit):
        with tcloud.deadline(900, "test login"):
            slept["for"] = 3600  # the lid was closed for an hour
            time.sleep(10)
    assert time.monotonic() - started < 5


def test_approve_turns_a_dropped_connection_into_a_legible_error():
    def get_token(url, state, lang):
        raise ConnectionError("Connection aborted.")

    with pytest.raises(ValueError, match="lost contact with Tencent"):
        tcloud.approve(ApproveSSO, Configs, get_token, URL, 0)


OVERTIME = b'{"Error": "InvalidParameter.OverTimeError: time set too long"}'
DENIED = b'{"Error": "AuthFailure.UnauthorizedOperation"}'


class LadderSSO:
    def __init__(self, cap=None, error=None):
        self.cap, self.error, self.calls = cap, error, []

    def assume_role_with_saml(self, saml, principal, role, session, duration, site):
        self.calls.append(duration)
        if self.error:
            raise ValueError(self.error)
        if duration > self.cap:
            raise ValueError(OVERTIME)
        return {"duration": duration}


def test_ladder_steps_down_only_on_a_duration_rejection():
    sso = LadderSSO(cap=7200)
    assert tcloud.assume_with_ladder(sso, "saml", "p", "r", 43200, "site") == {"duration": 7200}
    assert sso.calls == [43200, 28800, 7200]


def test_ladder_surfaces_other_errors_on_the_first_attempt():
    sso = LadderSSO(error=DENIED)
    with pytest.raises(ValueError):
        tcloud.assume_with_ladder(sso, "saml", "p", "r", 43200, "site")
    assert sso.calls == [43200]


# ------------------------------------------------------------------ scanners


def test_tccli_json_treats_an_error_body_as_failure(monkeypatch):
    body = '{"Error": {"Code": "AuthFailure", "Message": "denied"}}'
    monkeypatch.setattr(tcloud, "run", lambda cmd, **kw: subprocess.CompletedProcess(
        cmd, 0, stdout=body, stderr=""))
    with pytest.raises(ValueError, match="denied"):
        tcloud.tccli_json(["vpc", "DescribeVpcs"], "p")


def test_fetch_all_pages_until_total(monkeypatch):
    items, offsets = list(range(250)), []

    def fake(argv, profile, region=None):
        offset = int(argv[argv.index("--Offset") + 1])
        limit = int(argv[argv.index("--Limit") + 1])
        offsets.append(offset)
        return {"Set": items[offset:offset + limit], "TotalCount": len(items)}

    monkeypatch.setattr(tcloud, "tccli_json", fake)
    assert tcloud.fetch_all(["vpc", "DescribeVpcs"], "Set", "p") == items
    assert offsets == [0, 100, 200]


def test_fetch_all_stops_on_a_total_that_never_converges(monkeypatch):
    monkeypatch.setattr(tcloud, "tccli_json",
                        lambda argv, profile, region=None: {"Set": [1] * 100, "TotalCount": 10**9})
    with pytest.raises(ValueError, match="did not terminate"):
        tcloud.fetch_all(["vpc", "DescribeVpcs"], "Set", "p")


def test_fetch_all_unpaginated_sends_no_limit(monkeypatch):
    seen = []

    def fake(argv, profile, region=None):
        seen.append(argv)
        return {"Set": [1, 2]}

    monkeypatch.setattr(tcloud, "tccli_json", fake)
    assert tcloud.fetch_all(["tke", "DescribeAddon"], "Set", "p", paginated=False) == [1, 2]
    assert "--Limit" not in seen[0]


def row_specs():
    for res, spec in tcloud.RESOURCES.items():
        yield "%s-ls" % res, spec, set()
        for action, child in spec.get("children", {}).items():
            yield "%s-%s" % (res, action), child, {child.get("parent_column", res)}


@pytest.mark.parametrize("spec,injected", [s[1:] for s in row_specs()],
                         ids=[s[0] for s in row_specs()])
def test_row_mapper_fills_every_column_from_an_empty_item(spec, injected):
    row = spec["row"]({})
    assert {key for key, _ in spec["columns"]} - injected <= set(row)


def test_nat_row_surfaces_a_restricted_gateway():
    row = tcloud.RESOURCES["nat"]["row"]({
        "State": "AVAILABLE", "RestrictState": "RESTRICTED",
        "PublicIpAddressSet": [{"PublicIpAddress": "203.0.113.7"}]})
    assert row["state"] == "AVAILABLE/RESTRICTED"
    assert row["eips"] == "203.0.113.7"


def test_privatedns_row_tags_cross_account_vpcs_with_their_uin():
    row = tcloud.RESOURCES["privatedns"]["row"]({
        "VpcSet": [{"UniqVpcId": "vpc-own"}],
        "AccountVpcSet": [{"Uin": "200000000001", "UniqVpcId": "vpc-other"}]})
    assert row["vpcs"] == "vpc-own,200000000001:vpc-other"


# ------------------------------------------------------------------ code-review fixes


def test_registry_is_optional_for_discover(tccli_dir):
    assert tcloud.load_registry(optional=True) == {}
    (tccli_dir / "accounts.conf").write_text("[defaults]\nregion = ap-singapore\n")
    assert tcloud.load_registry(optional=True) == {}
    with pytest.raises(SystemExit):
        tcloud.load_registry()


def test_discover_without_a_url_or_registry_explains_itself(capsys):
    with pytest.raises(SystemExit):
        tcloud.cmd_discover(argparse.Namespace(auth_url=[], json=False, timeout=0), {})
    assert "give an sso url" in capsys.readouterr().err


SCAN_PROFILES = {"p1": {"region": "r1"}, "p2": {"region": "r1"}}


def scan_args(**overrides):
    base = dict(cmd="tke", action="nodes", state=None, all=False, profile=["p1", "p2"],
                region=["r1"], home_region=False, workers=2, json=True, tke_id=None)
    base.update(overrides)
    return argparse.Namespace(**base)


def run_tke_scan(monkeypatch, capsys, args, clusters):
    """`clusters` maps profile -> cluster ids; every cluster has one node."""
    def fetch_all(argv, key, profile, region=None, page=100, paginated=True):
        if argv[1] == "DescribeClusters":
            return [{"ClusterId": cid, "ClusterName": ""} for cid in clusters.get(profile, [])]
        return [{"InstanceId": "ins-%s" % argv[argv.index("--ClusterId") + 1]}]

    monkeypatch.setattr(tcloud, "fetch_all", fetch_all)
    with pytest.raises(SystemExit) as exit_info:
        tcloud.cmd_resource(args, SCAN_PROFILES)
    return exit_info.value.code, json.loads(capsys.readouterr().out)


def test_explicit_parent_id_only_has_to_exist_somewhere(monkeypatch, capsys):
    code, out = run_tke_scan(monkeypatch, capsys, scan_args(tke_id=["cls-a"]),
                             {"p1": ["cls-a"], "p2": ["cls-b"]})
    assert code == 0 and out["errors"] == []
    assert [row["id"] for row in out["cluster_nodes"]] == ["ins-cls-a"]


def test_explicit_parent_id_found_nowhere_is_one_error(monkeypatch, capsys):
    code, out = run_tke_scan(monkeypatch, capsys, scan_args(tke_id=["cls-zzz"]),
                             {"p1": ["cls-a"], "p2": ["cls-b"]})
    assert code == 1
    assert [e["error"] for e in out["errors"]] == [
        "cluster cls-zzz not found in any scanned profile or region"]


def test_ambiguous_profile_does_not_discard_other_results(monkeypatch, capsys):
    code, out = run_tke_scan(monkeypatch, capsys, scan_args(),
                             {"p1": ["cls-a"], "p2": ["cls-b", "cls-c"]})
    assert code == 1
    assert [row["id"] for row in out["cluster_nodes"]] == ["ins-cls-a"]
    assert out["errors"][0]["profile"] == "p2" and "pick one" in out["errors"][0]["error"]


def test_profile_without_region_is_counted_not_skipped(monkeypatch, capsys):
    monkeypatch.setattr(tcloud, "fetch_all",
                        lambda argv, key, profile, region=None, **kw: [{"VpcId": "vpc-1"}])
    args = scan_args(cmd="vpc", action="ls", region=None, home_region=True)
    with pytest.raises(SystemExit) as exit_info:
        tcloud.cmd_resource(args, {"p1": {"region": "r1"}, "p2": {}})
    out = json.loads(capsys.readouterr().out)
    assert exit_info.value.code == 1
    assert out["probes"] == 1 and len(out["vpcs"]) == 1
    assert out["errors"][0]["profile"] == "p2"


LOGIN_PROFILES = {"p": {"uin": "200000000001", "role": "ReadOnly", "auth_url": URL}}


def login_args():
    return argparse.Namespace(profile="p", all=False, sso=None, duration=None, timeout=0)


def test_single_login_that_writes_nothing_is_a_failure(tccli_dir, monkeypatch):
    monkeypatch.setattr(tcloud, "run", lambda cmd, **kw: subprocess.CompletedProcess(cmd, 0))
    with pytest.raises(SystemExit) as exit_info:
        tcloud.cmd_login(login_args(), LOGIN_PROFILES)
    assert exit_info.value.code == 1


def test_single_login_that_writes_credentials_succeeds(tccli_dir, monkeypatch):
    def fake_run(cmd, **kw):
        if "login" in cmd:
            write_cred(tccli_dir, "p", cred(43200, 43200))
        return subprocess.CompletedProcess(cmd, 0)

    monkeypatch.setattr(tcloud, "run", fake_run)
    with pytest.raises(SystemExit) as exit_info:
        tcloud.cmd_login(login_args(), LOGIN_PROFILES)
    assert exit_info.value.code == 0


class MintSSO:
    """Just enough of tccli.sso to mint a credential without a network."""

    def __init__(self):
        self.saved = {}

    def verify_login_skey(self, token, site):
        return {"ZoneId": "zone"}

    def list_accounts_for_access_assignment(self, token, site):
        return [{"Uin": 200000000002, "Name": "b"}]

    def list_role_configurations_for_account(self, uin, token, site):
        return [{"RoleConfigurationName": "ReadOnly", "RoleConfigurationId": "rc"}]

    def gen_saml_response(self, token, login_type, uin, user_id, conf_id, site):
        return {"SAMLResponse": "saml"}

    def assume_role_with_saml(self, saml, principal, role, session, duration, site):
        return {"ExpiredTime": int(time.time()) + duration}

    def save_credential(self, cred, sso_info, profile):
        self.saved[profile] = sso_info


def test_login_all_carries_on_after_a_realm_fails(tccli_dir, monkeypatch, capsys):
    sso = MintSSO()

    def get_token(url, state, lang):
        if "/myorg/" in url:
            raise ConnectionError("Connection aborted.")
        return {"State": state, "Token": "tok", "Site": "intl"}

    monkeypatch.setattr(tcloud, "import_tccli_internals", lambda: (sso, Configs, get_token))
    monkeypatch.setattr(tcloud, "run", lambda cmd, **kw: subprocess.CompletedProcess(cmd, 0))
    profiles = {"a": {"uin": "200000000001", "role": "ReadOnly", "auth_url": URL},
                "b": {"uin": "200000000002", "role": "ReadOnly", "auth_url": OTHER}}
    with pytest.raises(SystemExit) as exit_info:
        tcloud.cmd_login_all(argparse.Namespace(duration=None, timeout=0), profiles)
    assert exit_info.value.code == 1
    assert list(sso.saved) == ["b"]
    assert "lost contact" in capsys.readouterr().out


@pytest.mark.parametrize("body,expected", [
    (b'{"Error": "InvalidParameter.OverTimeError"}', "InvalidParameter.OverTimeError"),
    (b'{"Error": {"Code": "AuthFailure", "Message": "denied"}}', "AuthFailure / denied"),
    (b'[1, 2]', "[1, 2]"),
    (b'not json', "not json"),
])
def test_brief_error_always_returns_text(body, expected):
    assert tcloud.brief_error(ValueError(body)) == expected


def test_refresh_keeps_the_session_estimate_but_login_restarts_it():
    sso = MintSSO()
    entry, account = {"role": "ReadOnly", "auth_url": URL}, {"Uin": 200000000002}
    tcloud.mint_credential(sso, "kept", account, entry, "tok", "intl", "zone", 7200,
                           session_expires=12345)
    tcloud.mint_credential(sso, "fresh", account, entry, "tok", "intl", "zone", 7200)
    assert sso.saved["kept"]["expiresAt"] == 12345
    assert sso.saved["fresh"]["expiresAt"] > time.time() + 11 * 3600


def test_changed_auth_url_is_written_through_before_login(tccli_dir, monkeypatch):
    calls = []
    monkeypatch.setattr(tcloud, "run",
                        lambda cmd, **kw: calls.append(cmd) or subprocess.CompletedProcess(cmd, 0))
    write_cred(tccli_dir, "p", {"sso": {"authUrl": URL}})
    tcloud.ensure_configured("p", URL)
    assert calls == []
    tcloud.ensure_configured("p", OTHER)
    assert len(calls) == 1 and "configure" in calls[0] and OTHER in calls[0]
