#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Xeshredemption
"""tcloud — profile registry and multi-account SSO login for the Tencent Cloud CLI (tccli).

tccli has no native profile registry: UIN/role/region only exist inside a
<profile>.credential file *after* a successful login. This reads a declarative
registry (~/.tccli/accounts.conf) and drives tccli from it.

  tcloud ls                  list profiles with live auth status
  tcloud login <profile>     configure (if needed) + SSO login
  tcloud login --all         one browser approval per realm, every profile
  tcloud login --sso <org>   same, but only that realm (the slug in its url)
  tcloud discover <url>      list accounts + roles behind an sso url (pre-registry)
  tcloud who [profile]       GetCallerIdentity for a profile
  tcloud cvm ls              list cvm instances (first profile unless --profile/--all)
  tcloud vpc ls              list vpcs, same flags
  tcloud subnet ls           list subnets (free/total ips, zone, route table)
  tcloud route ls            list route tables (route + association counts)
  tcloud nat ls              list nat gateways
  tcloud clb ls              list load balancers
  tcloud stock ls            instance-type availability; --charge/--zone narrow it
  tcloud tke ls|addons|nodes tke clusters, their addons, their nodes
  tcloud ccn ls              list cloud connect networks (global, one probe/profile)
  tcloud ccn routes          ccn routes; --ccn-id when a profile has more than one
  tcloud ccn attachments     ccn attachments, including PENDING ones
  tcloud privatedns ls       private dns zones (global); --vpc finds a vpc's zones
  tcloud privatedns records  records in a zone; --zone-id when a profile has several
  tcloud refresh [--sso ORG] re-mint from the stored token, no browser
  tcloud logout [--sso ORG]  delete local credential files (no server-side revoke)
"""

import argparse
import configparser
import contextlib
import io
import json
import os
import re
import secrets
import signal
import string
import subprocess
import sys
import time
import urllib.parse
import uuid
from concurrent.futures import ThreadPoolExecutor

__version__ = "0.1.0"

TCCLI_DIR = os.path.expanduser("~/.tccli")
REGISTRY = os.path.join(TCCLI_DIR, "accounts.conf")

# Profile names become file names (~/.tccli/<name>.credential), so anything that could
# walk out of that directory or split into several shell words is refused up front.
PROFILE_NAME = re.compile(r"[A-Za-z0-9][A-Za-z0-9._-]*\Z")

# SSO login hosts seen in the wild. Anything else still works but is warned about
# before the browser opens — the approval page is where a phishing url would bite.
KNOWN_SSO_HOSTS = ("tencentcloudssointl.com",)


def tccli_bin():
    """The tccli beside this interpreter, else whichever one is on PATH.

    tcloud both imports tccli's internals and runs its command. Under pipx the
    library sits in tcloud's own venv while `tccli` on PATH can be another install —
    another version — so prefer the one matching the import.
    """
    local = os.path.join(os.path.dirname(sys.executable), "tccli")
    return local if os.access(local, os.X_OK) else "tccli"


TCCLI = tccli_bin()

# Only these keys are forwarded to tccli; anything else in the registry is metadata.
INHERITED = ("auth_url", "role", "region")

# Credential lifetimes to try, longest first. tccli hardcodes 7200 (2h), but that
# is its own default, not a server limit: AssumeRoleWithSAML against an SSO
# role returns a full 12h when asked for it. The shorter rungs exist only in case
# a role configuration later caps SessionDuration below the ceiling — a capped
# role rejects the request outright rather than silently clamping it, so without a
# fallback the whole login would fail.
DURATION_LADDER = (43200, 28800, 7200)

# How a too-long lifetime comes back. Asking for 24h returns
# `InvalidParameter.OverTimeError / time set too long` — note it never says
# "duration", so matching on that word alone silently disables the fallback.
DURATION_REJECTED = ("overtimeerror", "time set too long", "durationseconds")

# `tccli sso login` handles one profile per browser approval, but the LoginToken it
# gets back is org-wide, not account-scoped: account selection happens client-side
# afterwards. `login --all` reuses these internals to fan one approval out to every
# profile. They are tccli-private, hence the lazy import with a legible failure.
TCCLI_INTERNALS_HINT = (
    "could not import tccli internals (tccli.sso / tccli.plugins.sso).\n"
    "  `login --all` depends on them; tccli may have moved or renamed them.\n"
    "  Fall back to one profile at a time: tcloud login <profile>"
)


def import_tccli_internals():
    try:
        from tccli import sso
        from tccli.plugins.sso import configs
        from tccli.plugins.sso.login import _get_token
    except ImportError as exc:
        die("%s\n  (%s)" % (TCCLI_INTERNALS_HINT, exc))
    return sso, configs, _get_token


class Colour:
    ok = "\033[32m"
    warn = "\033[33m"
    bad = "\033[31m"
    dim = "\033[2m"
    bold = "\033[1m"
    off = "\033[0m"

    @classmethod
    def strip(cls):
        for name in ("ok", "warn", "bad", "dim", "bold", "off"):
            setattr(cls, name, "")


def die(msg):
    print("tcloud: %s" % msg, file=sys.stderr)
    sys.exit(1)


def warn(msg):
    print("tcloud: warning: %s" % msg, file=sys.stderr)


def check_auth_url(url, where, warn_unknown=False):
    """Refuse a non-https sso url; with warn_unknown, flag a host that is not Tencent's.

    The login token never travels to this host — tccli polls cli.cloud.tencent.com
    for it — but the url is opened in a browser for the approval, so a mistyped or
    pasted-in host is a phishing page rather than a harmless typo.
    """
    parsed = urllib.parse.urlparse(url)
    if parsed.scheme != "https" or not parsed.hostname:
        die("%s: sso url must be https:// (got %r)" % (where, url))
    if warn_unknown and parsed.hostname not in KNOWN_SSO_HOSTS:
        warn("%s is not a known Tencent sso host (%s) — check the url before approving" % (
            parsed.hostname, ", ".join(KNOWN_SSO_HOSTS)))


# How often a deadline re-checks the wall clock, in seconds.
DEADLINE_STEP = 30


@contextlib.contextmanager
def deadline(seconds, what):
    """Abort a blocking wait after `seconds` of wall-clock time; 0 waits forever.

    tccli's login poll has no timeout of its own, so an approval nobody acts on
    would otherwise hang the shell indefinitely. POSIX only (SIGALRM).

    One long alarm is not enough: on macOS the alarm timer stops while the machine
    sleeps, and a 900s alarm set just before idle sleep was still pending 39 minutes
    later. So the alarm is re-armed in short steps, each checked against time.time().
    """
    if not seconds:
        yield
        return
    ends = time.time() + seconds

    def tick(_signum, _frame):
        left = ends - time.time()
        if left <= 0:
            # human() rounds to whole minutes, which would print "0m" for a 30s wait.
            die("%s was not approved within %s — no credentials were minted" % (
                what, human(seconds) if seconds % 60 == 0 else "%ds" % seconds))
        signal.alarm(min(int(left) + 1, DEADLINE_STEP))

    previous = signal.signal(signal.SIGALRM, tick)
    signal.alarm(min(seconds, DEADLINE_STEP))
    try:
        yield
    finally:
        signal.alarm(0)
        signal.signal(signal.SIGALRM, previous)


def load_registry(optional=False):
    """Parse the registry. With optional, a missing or empty one is just {}.

    `discover` is how a first registry gets written, so it has to run without one.
    """
    if not os.path.exists(REGISTRY):
        if optional:
            return {}
        die("no registry at %s" % REGISTRY)

    cp = configparser.ConfigParser()
    cp.read(REGISTRY)

    defaults = dict(cp["defaults"]) if cp.has_section("defaults") else {}

    profiles = {}
    for section in cp.sections():
        if section == "defaults":
            continue
        if not section.startswith("profile "):
            continue
        name = section.split(" ", 1)[1].strip()
        if not PROFILE_NAME.match(name):
            die("invalid profile name %r in %s — use letters, digits, '.', '_' and '-'" % (
                name, REGISTRY))
        entry = dict(defaults)
        entry.update(dict(cp[section]))
        if entry.get("auth_url"):
            check_auth_url(entry["auth_url"], "profile %r" % name)
        profiles[name] = entry

    if not profiles and not optional:
        die("registry has no [profile <name>] sections")
    return profiles


def credential_path(profile):
    return os.path.join(TCCLI_DIR, profile + ".credential")


def loose_mode(profile):
    """Group/other permission bits on a credential file; 0 if private or absent.

    tccli writes these files with the process umask — commonly 022, i.e. readable
    by every local user — and each holds a secret key plus a realm-wide login token.
    """
    try:
        return os.stat(credential_path(profile)).st_mode & 0o077
    except OSError:
        return 0


def read_credential(profile):
    try:
        with open(credential_path(profile)) as fh:
            return json.load(fh)
    except (IOError, ValueError):
        return None


def auth_status(profile):
    """-> (state, detail). state in: none, unconfigured, expired, stale, active."""
    cred = read_credential(profile)
    if cred is None:
        return "none", "not configured"

    sso = cred.get("sso") or {}
    if not sso.get("authUrl"):
        return "unconfigured", "no sso url"
    if not sso.get("uin"):
        return "none", "never logged in"

    now = time.time()
    session_left = sso.get("expiresAt", 0) - now
    creds_left = cred.get("expiresAt", 0) - now

    if creds_left > 0:
        # Live role credentials work whatever the session clock says, so they win.
        session = human(session_left) if session_left > 0 else "estimate lapsed"
        return "active", "%s left (session %s)" % (human(creds_left), session)
    if not sso.get("token"):
        return "expired", "creds expired, no login token to refresh from"
    if session_left <= 0:
        # This clock is a client-side guess: tccli and tcloud both stamp the
        # session as now+12h at login rather than recording a server value, so a
        # lapsed estimate is not proof the login token is dead. `tcloud refresh`
        # probes it for real.
        return "expired", "session estimate lapsed — `tcloud refresh` may still work"
    # tccli's own auto-refresh never fires: maybe_refresh_credential
    # (tccli/sso.py) refuses unless the session has more than 12h-5m of a 12h
    # session left, a window only open for ~5min after login. `tcloud refresh`
    # sidesteps it by re-minting from the login token kept in the credential
    # file, which routinely outlives the role credentials — so reaching this
    # state costs a command, not a browser approval.
    return "refreshable", "creds expired — run `tcloud refresh` (session %s left)" % human(session_left)


def human(seconds):
    seconds = int(max(seconds, 0))
    hours, rem = divmod(seconds, 3600)
    minutes = rem // 60
    if hours:
        return "%dh%02dm" % (hours, minutes)
    return "%dm" % minutes


def run(cmd, **kwargs):
    return subprocess.run(cmd, **kwargs)


def require(entry, key, profile):
    value = entry.get(key)
    if not value:
        die("profile %r is missing required key %r in %s" % (profile, key, REGISTRY))
    return value


def realm_of(auth_url):
    """`https://tencentcloudssointl.com/<org>/login` -> "<org>".

    The org slug is the only part of an sso url a person can be expected to type,
    so it is what --sso matches on. A url of an unexpected shape falls back to
    itself, which still works as a --sso value — just a verbose one.
    """
    parts = [p for p in (auth_url or "").split("/") if p]
    if len(parts) >= 2 and parts[-1] == "login":
        return parts[-2]
    return auth_url or "-"


def group_by_realm(profiles):
    by_realm = {}
    for name, entry in profiles.items():
        by_realm.setdefault(realm_of(require(entry, "auth_url", name)), {})[name] = entry
    return by_realm


def select_realms(profiles, wanted):
    """Narrow the registry to the named realms. Accepts a slug or a full url."""
    by_realm = group_by_realm(profiles)
    chosen = {}
    for want in wanted:
        key = realm_of(want) if "/" in want else want
        if key not in by_realm:
            die("unknown sso realm %r\n  known: %s" % (want, ", ".join(sorted(by_realm))))
        chosen.update(by_realm[key])
    return chosen


def scope_of(args, profiles):
    """--sso/--all/<profile> -> the profiles to act on, or None for none of those.

    Shared by login and refresh so the three ways of naming a scope mean the same
    thing in both, and so a new one only has to be added here.
    """
    named = getattr(args, "profile", None)
    realms = getattr(args, "sso", None)

    if args.all and realms:
        die("--all and --sso are mutually exclusive")
    if named and (args.all or realms):
        die("%s takes no profile name (got %r)" % ("--all" if args.all else "--sso", named))

    if realms:
        return select_realms(profiles, realms)
    if args.all:
        return dict(profiles)
    return None


def resolve(profiles, name):
    if name not in profiles:
        die("unknown profile %r\n  known: %s" % (name, ", ".join(sorted(profiles))))
    return profiles[name]


def targets_of(args, profiles):
    """<profile> | --sso | --all -> sorted profile names; dies when none was given."""
    scope = scope_of(args, profiles)
    if scope is not None:
        return sorted(scope)
    if args.profile:
        resolve(profiles, args.profile)
        return [args.profile]
    die("give a profile name, --sso <org>, or --all")


# ---------------------------------------------------------------- subcommands


def cmd_ls(args, profiles):
    marks = {
        "active": (Colour.ok, "ACTIVE"),
        "refreshable": (Colour.warn, "REFRESH"),
        "expired": (Colour.bad, "EXPIRED"),
        "unconfigured": (Colour.dim, "UNCONFIG"),
        "none": (Colour.dim, "-"),
    }

    if args.sso:
        profiles = select_realms(profiles, args.sso)

    rows = []
    for name in sorted(profiles, key=lambda n: (profiles[n].get("env", ""), n)):
        entry = profiles[name]
        state, detail = auth_status(name)
        if loose_mode(name):
            detail = "READABLE BY OTHERS, chmod 600 · %s" % detail
        rows.append((name, realm_of(entry.get("auth_url")), entry.get("uin", "?"),
                     entry.get("env", "-"), entry.get("region", "-"), state, detail))

    if not rows:
        print("no profiles selected")
        return

    width = max(len(r[0]) for r in rows)
    realm_width = max(max(len(r[1]) for r in rows), len("SSO"))
    print("%s%-*s  %-*s  %-13s %-11s %-14s %-9s %s%s" % (
        Colour.bold, width, "PROFILE", realm_width, "SSO", "UIN", "ENV", "REGION",
        "STATUS", "DETAIL", Colour.off))

    for name, realm, uin, env, region, state, detail in rows:
        colour, label = marks[state]
        env_out = "%s%s%s" % (Colour.bad, env, Colour.off) if env == "prod" else env
        pad = len(env_out) - len(env)
        print("%-*s  %-*s  %-13s %-*s %-14s %s%-9s%s %s%s%s" % (
            width, name, realm_width, realm, uin, 11 + pad, env_out, region,
            colour, label, Colour.off, Colour.dim, detail, Colour.off))


def ensure_configured(name, auth_url):
    """Register the SSO url unless the credential file already holds this exact one.

    tccli's single-profile login opens the url stored in the credential file, not the
    registry's, so a changed auth_url has to be written through or the browser keeps
    opening the old one. `tccli sso configure` rewrites only that field.
    """
    cred = read_credential(name)
    if (cred or {}).get("sso", {}).get("authUrl") == auth_url:
        return
    print("%s· registering sso url for %s%s" % (Colour.dim, name, Colour.off), flush=True)
    result = run([TCCLI,"sso", "configure", "--profile", name, "--url", auth_url])
    if result.returncode != 0:
        die("`tccli sso configure` failed for %s" % name)


def apply_region(name, region):
    if not region:
        return
    run([TCCLI,"configure", "set", "region", region, "--profile", name],
        stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)


def cmd_login(args, profiles):
    scope = scope_of(args, profiles)
    if scope is not None:
        return cmd_login_all(args, scope)
    if not args.profile:
        die("give a profile name, --sso <org>, or --all")

    name = args.profile
    entry = resolve(profiles, name)

    uin = require(entry, "uin", name)
    role = require(entry, "role", name)
    auth_url = require(entry, "auth_url", name)

    check_auth_url(auth_url, name, warn_unknown=True)
    ensure_configured(name, auth_url)
    apply_region(name, entry.get("region"))

    # tccli defaults to 7200s. That is its own default, not a role limit, so ask
    # for the top rung explicitly. This path cannot walk DURATION_LADDER the way
    # mint_credential does — tccli owns the assume call — so a role capped below
    # the request fails here and needs an explicit --duration.
    cmd = [TCCLI,"sso", "login", "--profile", name,
           "--rolename", role, "--uin", str(uin),
           "--duration", str(args.duration or DURATION_LADDER[0])]

    print("%s· %s%s" % (Colour.dim, " ".join(cmd), Colour.off), flush=True)
    # Not subprocess's own timeout: it pauses during sleep just like a bare alarm.
    # If the deadline fires mid-wait, run() kills the tccli child on the way out.
    before = (read_credential(name) or {}).get("expiresAt")
    with deadline(args.timeout, name):
        code = run(cmd).returncode
    # tccli exits 0 even when it only printed a refusal (uin not granted, no such
    # role), so success means fresh credentials actually landed.
    if code == 0 and (read_credential(name) or {}).get("expiresAt") == before:
        die("tccli wrote no new credentials for %s — see its message above" % name)
    sys.exit(code)


def brief_error(exc):
    """tccli raises ValueError(response.content), i.e. a bytes blob. Pull the message."""
    text = str(exc)
    if text.startswith(("b'", 'b"')):
        text = text[2:-1]
    try:
        err = json.loads(text).get("Error")
    except (ValueError, AttributeError):  # not json, or json that is not an object
        return text
    if isinstance(err, dict):
        err = " / ".join(str(err[k]) for k in ("Code", "Message") if err.get(k)) or json.dumps(err)
    return str(err) if err else text


def assume_with_ladder(sso, saml_response, principal_arn, role_arn, duration, site):
    """assume_role_with_saml, stepping down DURATION_LADDER if the role caps it.

    A role whose SessionDuration sits below the request rejects the call outright
    instead of clamping it, so one hardcoded lifetime turns a capped role into a
    total login failure. Only a duration complaint falls through to the next rung:
    a permission or token error has to surface on the first attempt rather than be
    retried three times behind a misleading message.
    """
    rungs = [duration] + [d for d in DURATION_LADDER if d < duration]
    failure = None
    for position, want in enumerate(rungs):
        try:
            # tccli prints the raw error body straight to stdout before raising.
            # On a rung we are going to retry that is just noise, so hold it back
            # and let only a final, genuine failure through.
            noise = io.StringIO()
            with contextlib.redirect_stdout(noise):
                return sso.assume_role_with_saml(
                    saml_response, principal_arn, role_arn, "ses-%s" % uuid.uuid4(), want, site)
        except Exception as exc:
            detail = brief_error(exc).lower()
            last_rung = position == len(rungs) - 1
            if last_rung or not any(m in detail for m in DURATION_REJECTED):
                sys.stdout.write(noise.getvalue())
                raise
            failure = exc
    raise failure


def approve(sso, configs, get_token, auth_url, timeout):
    """One browser approval against an sso url -> (login_token, site, zone_id).

    The token that comes back is org-wide rather than account-scoped — account
    selection happens client-side afterwards — so a single approval covers every
    account the sso user can reach behind that url.
    """
    check_auth_url(auth_url, "sso", warn_unknown=True)
    # The state nonce is what ties the polled result to this login, so it has to be
    # unguessable: secrets, not random. Same 32-char alphanumeric shape as tccli's.
    state = "".join(secrets.choice(string.ascii_letters + string.digits) for _ in range(32))
    with deadline(timeout, auth_url):
        try:
            token = get_token(auth_url, state, configs.DEFAULT_LANG)
        except Exception as exc:
            # Typically a laptop that slept mid-poll: its socket is gone on wake.
            # tccli's loop cannot be resumed from outside, so this realm is lost.
            # Raised rather than die(): callers decide whether other realms go on.
            raise ValueError("lost contact with Tencent while waiting for approval (%s)"
                             % brief_error(exc)) from None
    if token["State"] != state:
        raise ValueError("sso returned a mismatched state — refusing its token")

    login_token, site = token["Token"], token["Site"]
    return login_token, site, sso.verify_login_skey(login_token, site)["ZoneId"]


def slugify(text):
    """Account display name -> a plausible registry profile name."""
    flat = "".join(c.lower() if c.isalnum() else "-" for c in text)
    return "-".join(part for part in flat.split("-") if part) or "unnamed"


def mint_credential(sso, name, account, entry, login_token, site, zone_id, duration,
                    session_expires=None):
    """Write <name>.credential from an already-approved login token.

    Mirrors tccli.plugins.sso.login.login() after the browser step: the token is
    org-wide, so the only per-profile inputs are the target uin and role.

    `account` comes from list_accounts_for_access_assignment so that uin stays the
    int the API returned — TargetUin is an int64 server-side and a stringified uin
    is rejected outright. The refresh path (tccli/sso.py) re-sends the uin we save
    here, so it has to keep that type on disk too.

    `session_expires` carries an existing session estimate through a refresh:
    re-minting role credentials does not extend the login token, so only a fresh
    approval may restart that clock.
    """
    uin = account["Uin"]
    role_name = require(entry, "role", name)

    roles = sso.list_role_configurations_for_account(uin, login_token, site)
    role = next((r for r in roles if r["RoleConfigurationName"] == role_name), None)
    if role is None:
        raise ValueError("role %r not available (have: %s)" % (
            role_name, ", ".join(r["RoleConfigurationName"] for r in roles) or "none"))

    saml = sso.gen_saml_response(
        login_token, "RoleSAML", uin, "", role["RoleConfigurationId"], site)

    role_arn = "qcs::cam::uin/%s:roleName/TencentCloudSSO-%s" % (uin, role_name)
    principal_arn = "qcs::cam::uin/%s:saml-provider/TencentReservedSSO-%s" % (uin, zone_id)
    cred = assume_with_ladder(
        sso, saml["SAMLResponse"], principal_arn, role_arn, duration, site)

    sso_info = {
        "token": login_token,
        "uin": uin,
        "roleConfigurationId": role["RoleConfigurationId"],
        "roleConfigurationName": role_name,
        "zoneId": zone_id,
        "site": site,
        "authUrl": entry["auth_url"],
        "expiresAt": session_expires or int(time.time()) + 3600 * 12,
    }
    sso.save_credential(cred, sso_info, name)
    return cred


def cmd_login_all(args, profiles):
    sso, configs, get_token = import_tccli_internals()

    targets = sorted(profiles)
    if not targets:
        die("no profiles selected")

    # One browser approval per distinct auth url, so profiles from different realms
    # never share a token.
    groups = {}
    for name in targets:
        groups.setdefault(require(profiles[name], "auth_url", name), []).append(name)

    failed = []
    for auth_url, names in groups.items():
        print("\n%s· %d profile(s) via %s%s" % (Colour.dim, len(names), auth_url, Colour.off))
        for name in names:
            ensure_configured(name, auth_url)

        try:
            login_token, site, zone_id = approve(
                sso, configs, get_token, auth_url, args.timeout)
            accounts = {str(a["Uin"]): a
                        for a in sso.list_accounts_for_access_assignment(login_token, site)}
        except Exception as exc:
            # A realm that fails before any profile is minted fails as a unit, and
            # the remaining realms still get their turn.
            failed += names
            print("  %s✗%s %d profile(s) in %s: %s" % (
                Colour.bad, Colour.off, len(names), realm_of(auth_url), brief_error(exc)))
            continue

        # Approval succeeded; from here a failure is per-profile, never fatal —
        # aborting would cost another browser round trip for the survivors.

        print()
        for name in names:
            entry = profiles[name]
            uin = str(entry.get("uin", ""))
            try:
                if uin not in accounts:
                    raise ValueError("uin %s not granted to this sso user" % uin)
                mint_credential(sso, name, accounts[uin], entry, login_token, site,
                                zone_id, args.duration or DURATION_LADDER[0])
                apply_region(name, entry.get("region"))
                tag = " %s[prod]%s" % (Colour.bad, Colour.off) if entry.get("env") == "prod" else ""
                print("  %s✓%s %-22s %s%s" % (Colour.ok, Colour.off, name, uin, tag))
            except Exception as exc:
                failed.append(name)
                print("  %s✗%s %-22s %s" % (Colour.bad, Colour.off, name, brief_error(exc)))

    if failed:
        print("\n%s%d failed: %s%s" % (Colour.bad, len(failed), ", ".join(failed), Colour.off))
    sys.exit(1 if failed else 0)


def cmd_discover(args, profiles):
    """List the accounts and roles behind an sso url, before any profile exists.

    accounts.conf needs a uin per profile, but a uin is only knowable *after* an
    approval: list_accounts_for_access_assignment is what produced every uin
    already in the registry. This makes that step repeatable, so registering
    a new org is a paste rather than a hand-edited credential file.

    Roles are listed per account because the registry's `role` key has to name one
    that actually exists there. A wrong name is not caught until login, i.e. after
    a browser round trip has already been spent on it.
    """
    # uin -> profile, per url, so already-registered accounts are marked rather
    # than re-suggested.
    known = {}
    for name, entry in profiles.items():
        known.setdefault(entry.get("auth_url"), {})[str(entry.get("uin", ""))] = name

    urls = args.auth_url or sorted({require(profiles[n], "auth_url", n) for n in profiles})
    if not urls:
        die("give an sso url to discover, e.g. "
            "tcloud discover https://tencentcloudssointl.com/<org>/login")
    sso, configs, get_token = import_tccli_internals()
    found, failed = [], []

    for auth_url in urls:
        print("\n%s· %s%s" % (Colour.dim, auth_url, Colour.off), flush=True)
        try:
            login_token, site, _zone = approve(sso, configs, get_token, auth_url, args.timeout)
            accounts = sso.list_accounts_for_access_assignment(login_token, site)
        except Exception as exc:
            # One unreachable realm must not cost the approvals still to come.
            failed.append(auth_url)
            print("  %s✗%s %s" % (Colour.bad, Colour.off, brief_error(exc)), file=sys.stderr)
            continue
        registered = known.get(auth_url, {})

        rows = []
        for account in sorted(accounts, key=lambda a: a.get("Name") or ""):
            try:
                roles = [r["RoleConfigurationName"] for r in
                         sso.list_role_configurations_for_account(account["Uin"], login_token, site)]
            except Exception as exc:
                # One unreadable account must not cost the whole approval.
                roles = ["!%s" % brief_error(exc)]
            rows.append({"auth_url": auth_url, "uin": account["Uin"],
                         "name": account.get("Name") or "", "roles": roles,
                         "profile": registered.get(str(account["Uin"]), "")})
        found.extend(rows)

        if args.json:
            continue
        if not rows:
            print("  no accounts granted to this sso user")
            continue

        width = max(max(len(r["name"]) for r in rows), len("ACCOUNT"))
        print("\n%s%-*s  %-13s  %-22s %s%s" % (
            Colour.bold, width, "ACCOUNT", "UIN", "PROFILE", "ROLES", Colour.off))
        for r in rows:
            print("%-*s  %-13s  %-22s %s" % (
                width, r["name"], r["uin"], r["profile"] or "-", ", ".join(r["roles"])))

        fresh = [r for r in rows if not r["profile"]]
        if fresh:
            print("\n%s· not in %s — paste and rename to taste%s" % (
                Colour.dim, REGISTRY, Colour.off))
            for r in fresh:
                print("\n[profile %s]" % slugify(r["name"]))
                print("uin      = %s" % r["uin"])
                print("auth_url = %s" % auth_url)
                if r["roles"] and not r["roles"][0].startswith("!"):
                    print("role     = %s" % r["roles"][0])

    if args.json:
        print(json.dumps(found, indent=2))
    sys.exit(1 if failed else 0)


def cmd_refresh(args, profiles):
    """Re-mint credentials from the login token already on disk — no browser.

    The token minted at login is org-wide and outlives the role credentials
    derived from it; only the derived credentials expire on the short clock. tccli
    will not act on that (see auth_status), so extending a session is purely a
    client-side matter of replaying the assume-role call with the stored token.

    Healthy profiles are refreshed too rather than skipped: this is an explicit
    command, and topping every selected profile back up to a full lifetime is less
    surprising than silently passing over the ones that still have time left.
    """
    names = targets_of(args, profiles)
    sso = import_tccli_internals()[0]
    duration = args.duration or DURATION_LADDER[0]

    # Group by token. One approval mints one org-wide token shared by every
    # profile logged in together, so a single verify covers the whole group — and
    # a dead token is reported once instead of as N identical per-profile errors.
    groups, failed = {}, []
    for name in names:
        info = (read_credential(name) or {}).get("sso") or {}
        if not info.get("token"):
            failed.append(name)
            print("  %s✗%s %-22s no login token on disk — run `tcloud login`" % (
                Colour.bad, Colour.off, name))
            continue
        groups.setdefault(info["token"], []).append((name, info))

    for token, members in groups.items():
        site = members[0][1]["site"]
        try:
            sso.verify_login_skey(token, site)
        except Exception as exc:
            failed += [n for n, _ in members]
            print("\n%s· login token rejected for %d profile(s): %s%s" % (
                Colour.bad, len(members), brief_error(exc), Colour.off))
            print("  a refresh cannot recover this — run: tcloud login --all")
            continue

        print("\n%s· %d profile(s) from one login token%s" % (
            Colour.dim, len(members), Colour.off))
        for name, info in members:
            entry = profiles[name]
            try:
                # Uin has to stay the int the api handed back: TargetUin is int64
                # server-side and a stringified uin is rejected outright. The value
                # on disk already has the right type.
                cred = mint_credential(sso, name, {"Uin": info["uin"]}, entry, token,
                                       site, info["zoneId"], duration,
                                       session_expires=info.get("expiresAt"))
                apply_region(name, entry.get("region"))
                tag = " %s[prod]%s" % (Colour.bad, Colour.off) if entry.get("env") == "prod" else ""
                print("  %s✓%s %-22s %s%s" % (Colour.ok, Colour.off, name,
                                              human(cred["ExpiredTime"] - time.time()), tag))
            except Exception as exc:
                failed.append(name)
                print("  %s✗%s %-22s %s" % (Colour.bad, Colour.off, name, brief_error(exc)))

    if failed:
        print("\n%s%d failed: %s%s" % (Colour.bad, len(failed), ", ".join(failed), Colour.off))
    sys.exit(1 if failed else 0)


def cmd_who(args, profiles):
    names = [args.profile] if args.profile else sorted(profiles)
    failed = False

    for name in names:
        resolve(profiles, name)
        result = run([TCCLI,"sts", "GetCallerIdentity", "--profile", name],
                     capture_output=True, text=True)
        if result.returncode == 0:
            try:
                data = json.loads(result.stdout)
                print("%-22s %s%s%s  %s" % (
                    name, Colour.ok, data.get("AccountId", "?"), Colour.off,
                    data.get("Arn", "")))
                continue
            except ValueError:
                pass
        failed = True
        detail = (result.stderr or result.stdout or "").strip().splitlines()
        print("%-22s %s%s%s" % (
            name, Colour.bad, detail[-1] if detail else "failed", Colour.off))

    sys.exit(1 if failed else 0)


def tccli_json(argv, profile, region=None):
    """Run a tccli call and return parsed json, raising ValueError on any failure.

    tccli reports api errors as a 200 with an {"Error": ...} body, so a zero exit
    code is not enough to trust the payload.
    """
    cmd = [TCCLI] + argv + ["--profile", profile]
    if region:
        cmd += ["--region", region]
    result = run(cmd, capture_output=True, text=True)
    out = (result.stdout or "").strip()
    try:
        data = json.loads(out)
    except ValueError:
        detail = (result.stderr or out).strip().splitlines()
        raise ValueError(detail[-1][:120] if detail else "no output from tccli")
    if "Error" in data:
        err = data["Error"]
        raise ValueError(err.get("Message", str(err)) if isinstance(err, dict) else str(err))
    return data


def fetch_all(argv, key, profile, region=None, page=100, paginated=True):
    """Page through a Describe* call until TotalCount is satisfied.

    A bare --Limit truncates silently: a single ccn can hold well over 100 routes, so
    a 100-row call drops the rest and still looks like a clean result.

    A few apis take no --Limit/--Offset at all — tke DescribeAddon rejects them
    outright — so `paginated=False` issues the bare call instead. Those return the
    whole set in one response; there is nothing to page through.
    """
    if not paginated:
        return tccli_json(argv, profile, region).get(key) or []

    items = []
    offset = 0
    while True:
        data = tccli_json(argv + ["--Limit", str(page), "--Offset", str(offset)],
                          profile, region)
        batch = data.get(key) or []
        items += batch
        total = data.get("TotalCount")
        if not batch or total is None or len(items) >= total:
            return items
        offset += page
        if offset > 100000:  # guard against a TotalCount that never converges
            raise ValueError("pagination did not terminate for %s" % " ".join(argv))


def discover_regions(names):
    for name in names:
        try:
            data = tccli_json(["cvm", "DescribeRegions"], name)
        except ValueError:
            continue
        return [r["Region"] for r in data.get("RegionSet", [])
                if r.get("RegionState") == "AVAILABLE"]
    die("could not list regions — is anything logged in?  try: tcloud login --all")


def ips(value):
    return ",".join(value or []) or "-"


# Each resource is one Describe* call plus a row mapper. `regional` says whether the
# result actually varies by region: CCN is account-global — DescribeCcns returns the
# same set from every endpoint — so fanning it across 19 regions would report each
# ccn 19 times. Global resources get exactly one probe per profile.
RESOURCES = {
    "cvm": {
        "argv": ["cvm", "DescribeInstances"],
        "key": "InstanceSet",
        "regional": True,
        "noun": "instance",
        "columns": (("id", "INSTANCE"), ("name", "NAME"), ("type", "TYPE"),
                    ("state", "STATE"), ("private", "PRIVATE"), ("public", "PUBLIC")),
        "row": lambda i: {
            "id": i.get("InstanceId", "?"),
            "name": i.get("InstanceName") or "",
            "type": i.get("InstanceType", ""),
            "state": i.get("InstanceState", ""),
            "private": ips(i.get("PrivateIpAddresses")),
            "public": ips(i.get("PublicIpAddresses")),
        },
    },
    "vpc": {
        "argv": ["vpc", "DescribeVpcs"],
        "key": "VpcSet",
        "regional": True,
        "noun": "vpc",
        "columns": (("id", "VPC"), ("name", "NAME"), ("cidr", "CIDR"),
                    ("ipv6", "IPV6"), ("default", "DEFAULT"), ("created", "CREATED")),
        "row": lambda v: {
            "id": v.get("VpcId", "?"),
            "name": v.get("VpcName") or "",
            "cidr": v.get("CidrBlock", ""),
            "ipv6": v.get("Ipv6CidrBlock") or "-",
            "default": "yes" if v.get("IsDefault") else "-",
            "created": (v.get("CreatedTime") or "")[:10],
        },
    },
    "subnet": {
        "argv": ["vpc", "DescribeSubnets"],
        "key": "SubnetSet",
        "regional": True,
        "noun": "subnet",
        "columns": (("id", "SUBNET"), ("name", "NAME"), ("vpc", "VPC"), ("cidr", "CIDR"),
                    ("zone", "ZONE"), ("ips", "FREE/TOTAL"), ("rtb", "ROUTE-TABLE")),
        "row": lambda s: {
            "id": s.get("SubnetId", "?"),
            "name": s.get("SubnetName") or "",
            "vpc": s.get("VpcId", ""),
            "cidr": s.get("CidrBlock", ""),
            "zone": s.get("Zone", ""),
            "ips": "%s/%s" % (s.get("AvailableIpAddressCount", "?"),
                              s.get("TotalIpAddressCount", "?")),
            "rtb": s.get("RouteTableId") or "-",
        },
    },
    "route": {
        "argv": ["vpc", "DescribeRouteTables"],
        "key": "RouteTableSet",
        "regional": True,
        "noun": "route table",
        "columns": (("id", "ROUTE-TABLE"), ("name", "NAME"), ("vpc", "VPC"),
                    ("main", "MAIN"), ("routes", "ROUTES"), ("subnets", "SUBNETS"),
                    ("created", "CREATED")),
        # Main comes back as the string "True", not a bool — compare loosely.
        "row": lambda t: {
            "id": t.get("RouteTableId", "?"),
            "name": t.get("RouteTableName") or "",
            "vpc": t.get("VpcId", ""),
            "main": "yes" if str(t.get("Main", "")).lower() == "true" else "-",
            "routes": len(t.get("RouteSet") or []),
            "subnets": len(t.get("AssociationSet") or []),
            "created": (t.get("CreatedTime") or "")[:10],
        },
    },
    "nat": {
        "argv": ["vpc", "DescribeNatGateways"],
        "key": "NatGatewaySet",
        # Regional, and verified rather than assumed: one account returned three
        # gateways from ap-singapore and an empty set from ap-hongkong.
        "regional": True,
        "noun": "nat gateway",
        "columns": (("id", "NAT"), ("name", "NAME"), ("vpc", "VPC"), ("zone", "ZONE"),
                    ("bw", "BW-MBPS"), ("eips", "EIPS"), ("state", "STATE"),
                    ("created", "CREATED")),
        # PublicIpAddressSet is a list of dicts, not the list of strings ips() takes
        # elsewhere, so the addresses are pulled out first. They are worth a column:
        # this is the address the whole vpc egresses as.
        #
        # RestrictState is folded into state rather than given a column of its own.
        # It reads NORMAL almost always, but a gateway restricted for arrears stops
        # passing traffic while State still says AVAILABLE -- so on the one occasion
        # it matters, it needs to be impossible to miss.
        "row": lambda g: {
            "id": g.get("NatGatewayId", "?"),
            "name": g.get("NatGatewayName") or "",
            "vpc": g.get("VpcId") or "-",
            "zone": g.get("Zone") or "-",
            "bw": g.get("InternetMaxBandwidthOut", 0),
            "eips": ips([a.get("PublicIpAddress")
                         for a in (g.get("PublicIpAddressSet") or [])]),
            "state": (g.get("State", "")
                      if str(g.get("RestrictState", "NORMAL")) == "NORMAL"
                      else "%s/%s" % (g.get("State", ""), g.get("RestrictState"))),
            "created": (g.get("CreatedTime") or "")[:10],
        },
    },
    "clb": {
        "argv": ["clb", "DescribeLoadBalancers"],
        "key": "LoadBalancerSet",
        "regional": True,
        "noun": "clb",
        "columns": (("id", "CLB"), ("name", "NAME"), ("type", "TYPE"), ("vip", "VIP"),
                    ("vpc", "VPC"), ("snatpro", "SNATPRO"), ("state", "STATE"),
                    ("created", "CREATED")),
        # An OPEN clb often reports no vip and only a public Domain, so fall back to
        # it rather than printing a bare "-" for a load balancer that clearly has an
        # address. SnatPro is surfaced because it gates cross-region binding 2.0.
        "row": lambda lb: {
            "id": lb.get("LoadBalancerId", "?"),
            "name": lb.get("LoadBalancerName") or "",
            "type": lb.get("LoadBalancerType", ""),
            "vip": ips(lb.get("LoadBalancerVips")) if lb.get("LoadBalancerVips")
                   else (lb.get("Domain") or "-"),
            "vpc": lb.get("VpcId") or "-",
            "snatpro": "yes" if lb.get("SnatPro") else "-",
            "state": {0: "CREATING", 1: "NORMAL"}.get(lb.get("Status"),
                                                      str(lb.get("Status", ""))),
            "created": (lb.get("CreateTime") or "")[:10],
        },
    },
    # Availability is not documented per-AZ anywhere — Tencent's own docs say to check
    # the purchase page — so this api IS the documentation. Two fields, not one:
    # Status is catalogue availability (SELL/SOLD_OUT), StatusCategory is live inventory
    # (EnoughStock > NormalStock > UnderStock > WithoutStock). A type reads SELL while
    # being UnderStock, so reading Status alone will mislead you.
    "stock": {
        "argv": ["cvm", "DescribeZoneInstanceConfigInfos"],
        "key": "InstanceTypeQuotaSet",
        "regional": True,
        "noun": "instance type",
        # Rejects --Limit/--Offset; returns every type for the region in one response.
        "paginated": False,
        "charge_flag": True,
        "argv_extra": lambda args: ["--Filters", json.dumps(
            [{"Name": "instance-charge-type", "Values": [args.charge]}]
            + ([{"Name": "zone", "Values": args.zone}] if getattr(args, "zone", None) else []))],
        "columns": (("zone", "ZONE"), ("id", "TYPE"), ("cpu", "CPU"), ("mem", "MEM"),
                    ("state", "STATUS"), ("stock", "STOCK"), ("price", "PRICE"),
                    ("per_gb", "$/GB")),
        "row": lambda i: {
            "id": i.get("InstanceType", "?"),
            "zone": i.get("Zone", ""),
            "cpu": i.get("Cpu") or 0,
            "mem": i.get("Memory") or 0,
            "state": i.get("Status", ""),
            "stock": i.get("StatusCategory") or "-",
            "price": ((i.get("Price") or {}).get("UnitPriceDiscount")
                      or (i.get("Price") or {}).get("UnitPrice") or "-"),
            "per_gb": (round(float((i.get("Price") or {}).get("UnitPriceDiscount")
                                   or (i.get("Price") or {}).get("UnitPrice") or 0)
                             / (i.get("Memory") or 1), 4) or "-"),
        },
    },
    "tke": {
        "argv": ["tke", "DescribeClusters"],
        "key": "Clusters",
        # Genuinely regional, unlike ccn: verified by querying one account from
        # three regions — its cluster came back from one and an empty set from
        # the other two.
        "regional": True,
        "noun": "cluster",
        "id_alias": "--cluster-id",
        "columns": (("id", "CLUSTER"), ("name", "NAME"), ("version", "VERSION"),
                    ("type", "TYPE"), ("level", "LEVEL"), ("nodes", "NODES"),
                    ("state", "STATE"), ("created", "CREATED")),
        "row": lambda c: {
            "id": c.get("ClusterId", "?"),
            "name": c.get("ClusterName") or "",
            "version": c.get("ClusterVersion", ""),
            "type": c.get("ClusterType", ""),
            "level": c.get("ClusterLevel") or "-",
            "nodes": c.get("ClusterNodeNum", 0),
            "state": c.get("ClusterStatus", ""),
            "created": (c.get("CreatedTime") or "")[:10],
        },
        "children": {
            "addons": {
                "argv": ["tke", "DescribeAddon"],
                "parent_arg": "--ClusterId",
                "key": "Addons",
                "noun": "addon",
                # DescribeAddon rejects --Limit/--Offset outright ("Invalid choice"),
                # and returns every addon in one response, so there is nothing to page.
                "paginated": False,
                "parent_column": "cluster",
                "columns": (("cluster", "CLUSTER"), ("id", "ADDON"),
                            ("version", "VERSION"), ("state", "PHASE"),
                            ("reason", "REASON")),
                "row": lambda a: {
                    "id": a.get("AddonName", "?"),
                    "version": a.get("AddonVersion", ""),
                    "state": a.get("Phase", ""),
                    "reason": (a.get("Reason") or "-")[:60],
                },
            },
            "nodes": {
                "argv": ["tke", "DescribeClusterInstances"],
                "parent_arg": "--ClusterId",
                "key": "InstanceSet",
                "noun": "cluster node",
                "parent_column": "cluster",
                "columns": (("cluster", "CLUSTER"), ("id", "INSTANCE"),
                            ("lan", "LAN-IP"), ("type", "TYPE"), ("role", "ROLE"),
                            ("state", "STATE"), ("pool", "POOL"), ("created", "CREATED")),
                "row": lambda i: {
                    "id": i.get("InstanceId", "?"),
                    "lan": i.get("LanIP") or "-",
                    # null on karpenter/native nodes — render a dash, not "None".
                    "type": i.get("InstanceType") or "-",
                    "role": i.get("InstanceRole", ""),
                    "state": i.get("InstanceState", ""),
                    "pool": i.get("NodePoolId") or "-",
                    "created": (i.get("CreatedTime") or "")[:10],
                },
            },
        },
    },
    "ccn": {
        "argv": ["vpc", "DescribeCcns"],
        "key": "CcnSet",
        "regional": False,
        "noun": "ccn",
        "columns": (("id", "CCN"), ("name", "NAME"), ("state", "STATE"),
                    ("attached", "ATTACHED"), ("qos", "QOS"), ("bandwidth", "BW-LIMIT"),
                    ("created", "CREATED")),
        "row": lambda c: {
            "id": c.get("CcnId", "?"),
            "name": c.get("CcnName") or "",
            "state": c.get("State", ""),
            "attached": c.get("InstanceCount", 0),
            "qos": c.get("QosLevel", ""),
            "bandwidth": c.get("BandwidthLimitType", ""),
            "created": (c.get("CreateTime") or "")[:10],
        },
        # Sub-resources hang off a specific ccn, so they need a two-step scan:
        # list the ccns in the profile, then query each one by id.
        "children": {
            "routes": {
                "argv": ["vpc", "DescribeCcnRoutes"],
                "parent_arg": "--CcnId",
                "key": "RouteSet",
                "noun": "ccn route",
                "columns": (("ccn", "CCN"), ("dest", "DEST-CIDR"), ("via", "VIA"),
                            ("type", "TYPE"), ("uin", "UIN"), ("enabled", "ENABLED"),
                            ("route_id", "ROUTE-ID")),
                "row": lambda r: {
                    "dest": r.get("DestinationCidrBlock", ""),
                    "via": r.get("InstanceName") or r.get("InstanceId", ""),
                    "type": r.get("InstanceType", ""),
                    "uin": r.get("InstanceUin", ""),
                    "enabled": "yes" if r.get("Enabled") else "-",
                    "route_id": r.get("RouteId", ""),
                },
            },
            "attachments": {
                "argv": ["vpc", "DescribeCcnAttachedInstances"],
                "parent_arg": "--CcnId",
                "key": "InstanceSet",
                "noun": "ccn attachment",
                "columns": (("ccn", "CCN"), ("id", "INSTANCE"), ("name", "NAME"),
                            ("type", "TYPE"), ("uin", "UIN"), ("state", "STATE"),
                            ("cidr", "CIDR")),
                "row": lambda a: {
                    "id": a.get("InstanceId", "?"),
                    "name": a.get("InstanceName") or "",
                    "type": a.get("InstanceType", ""),
                    "uin": a.get("InstanceUin", ""),
                    "state": a.get("State", ""),
                    "cidr": ",".join(a.get("CidrBlock") or []) or "-",
                },
            },
        },
    },
    "privatedns": {
        "argv": ["privatedns", "DescribePrivateZoneList"],
        "key": "PrivateZoneSet",
        # Global, like ccn: verified by querying one account from ap-singapore,
        # ap-hongkong and eu-frankfurt — every endpoint returned the same zone.
        "regional": False,
        "noun": "private zone",
        "id_alias": "--zone-id",
        # Zones are shared across accounts, so which account owns one matters as much
        # as which profile found it.
        "uin_column": True,
        "columns": (("name", "ZONE"), ("id", "ZONE-ID"), ("state", "STATUS"),
                    ("vpcs", "VPCS"), ("account_vpcs", "ACCOUNT-VPCS"),
                    ("records", "RECORDS"), ("forward", "FORWARD"), ("created", "CREATED")),
        # A zone only resolves inside the vpcs bound to it, so the bindings are the
        # useful part. Cross-account bindings (AccountVpcSet) are prefixed with the
        # owning uin, since a bare vpc id says nothing about which account holds it.
        "row": lambda z: {
            "id": z.get("ZoneId", "?"),
            "name": z.get("Domain") or "",
            "records": z.get("RecordCount", 0),
            "state": z.get("Status", ""),
            "forward": z.get("DnsForwardStatus") or "-",
            "vpcs": ",".join(v.get("UniqVpcId", "?") for v in z.get("VpcSet") or []) or "-",
            "account_vpcs": ",".join(
                "%s:%s" % (v.get("Uin", "?"), v.get("UniqVpcId", "?"))
                for v in z.get("AccountVpcSet") or []) or "-",
            "created": (z.get("CreatedOn") or "")[:10],
        },
        # The api has no reverse lookup from a vpc to the zones bound to it, so
        # --vpc matches client-side against both binding sets.
        "vpcs_of": lambda z: {v.get("UniqVpcId") for v in (z.get("VpcSet") or [])
                              + (z.get("AccountVpcSet") or [])},
        # --records recounts through this child instead of trusting RecordCount.
        "recount": "records",
        "children": {
            "records": {
                "argv": ["privatedns", "DescribePrivateZoneRecordList"],
                "parent_arg": "--ZoneId",
                "key": "RecordSet",
                "noun": "dns record",
                "parent_column": "zone",
                "columns": (("zone", "ZONE"), ("id", "RECORD"), ("name", "NAME"),
                            ("type", "TYPE"), ("value", "VALUE"), ("ttl", "TTL"),
                            ("state", "STATE"), ("updated", "UPDATED")),
                "row": lambda r: {
                    "id": r.get("RecordId", "?"),
                    "name": r.get("SubDomain", ""),
                    "type": r.get("RecordType", ""),
                    "value": r.get("RecordValue", ""),
                    "ttl": r.get("TTL", ""),
                    "state": r.get("Status", ""),
                    "updated": (r.get("UpdatedOn") or "")[:10],
                },
            },
        },
    },
}


def resolve_parents(parent_spec, args, profile, region):
    """Ids of the parent resources to query in one profile.

    An explicit id is always honoured, and an id is *required* only when the profile
    holds more than one candidate.
    """
    found = fetch_all(parent_spec["argv"], parent_spec["key"], profile, region)
    available = [(parent_spec["row"](item)["id"], parent_spec["row"](item)["name"])
                 for item in found]

    wanted = getattr(args, "%s_id" % args.cmd, None)
    if wanted:
        # Only the ids this profile and region actually hold. An id lives in one
        # place, so its absence here is not an error; cmd_resource reports an id
        # that turned up nowhere.
        known = {pid for pid, _ in available}
        return [w for w in wanted if w in known]

    if len(available) > 1:
        # Raised, not die(): this runs in a worker thread, and one ambiguous profile
        # must not throw away every other probe's results.
        raise ValueError("%d %ss — pick one with --%s-id: %s" % (
            len(available), parent_spec["noun"], args.cmd,
            ", ".join("%s (%s)" % (pid, nm) if nm else pid for pid, nm in available)))
    return [pid for pid, _ in available]


def cmd_resource(args, profiles):
    parent_spec = RESOURCES[args.cmd]
    action = getattr(args, "action", "ls")
    spec = parent_spec if action == "ls" else parent_spec["children"][action]

    # Validate before scanning: checking inside the row loop would pass silently
    # whenever the scan happened to return nothing, and abort half-rendered when it
    # did not.
    if args.state and "state" not in [key for key, _ in spec["columns"]]:
        die("%s %s has no state field — drop --state" % (args.cmd, action))
    if action != "ls" and (getattr(args, "vpc", None) or getattr(args, "records", False)):
        die("--vpc and --records apply to `%s ls` only" % args.cmd)
    if args.sso and (args.all or args.profile):
        die("--sso cannot be combined with --all or --profile")

    # Default to a single profile: a full fan-out is the expensive, deliberate case.
    # "first" means first declared in accounts.conf, not alphabetical — the registry
    # order is the one the user controls.
    if args.all:
        names = list(profiles)
    elif args.sso:
        # Registry order, not select_realms' dict order, so --sso and --all agree.
        chosen = select_realms(profiles, args.sso)
        names = [name for name in profiles if name in chosen]
    elif args.profile:
        names = args.profile
    else:
        names = [next(iter(profiles))]
        print("%s· %s (first in accounts.conf) — --profile NAME or --all for more%s" % (
            Colour.dim, names[0], Colour.off))

    for name in names:
        resolve(profiles, name)

    # Children inherit their parent's regionality: a ccn is global, so its routes
    # and attachments are too.
    regional = parent_spec["regional"]
    if not regional:
        # One endpoint is enough; --region just picks which one to ask.
        regions = [args.region[0]] if args.region else None
    elif args.region:
        regions = args.region
    elif args.home_region:
        regions = None  # each profile uses its own configured region
    else:
        regions = discover_regions(names)

    jobs, unscoped = [], []
    for name in names:
        if regions is None and not profiles[name].get("region"):
            # Nothing to ask. Count it as an error rather than let the profile vanish
            # from the denominator and leave an empty table looking clean.
            unscoped.append((name, "-", "no region in the registry — set one or pass --region"))
            continue
        for region in (regions if regions is not None else [profiles[name]["region"]]):
            jobs.append((name, region))

    # Parent ids some probe actually found, so an explicit --<res>-id that exists
    # nowhere is reported once instead of passing as an empty result.
    matched = set()

    def probe(job):
        name, region = job
        try:
            paginated = spec.get("paginated", True)
            # Some Describe* calls need a filter that is not pagination — stock has to
            # say which billing mode it means, since spot and pay-as-you-go carry
            # completely different inventory.
            argv = spec["argv"] + (spec["argv_extra"](args) if spec.get("argv_extra") else [])
            if action == "ls":
                items = fetch_all(argv, spec["key"], name, region, paginated=paginated)
                if getattr(args, "records", False):
                    # A failed recount fails the whole profile: a zone showing a stale
                    # or zero count would look like a real answer.
                    child = spec["children"][spec["recount"]]
                    for item in items:
                        item["RecordCount"] = len(fetch_all(
                            child["argv"] + [child["parent_arg"], spec["row"](item)["id"]],
                            child["key"], name, region))
                return name, region, items, None
            items = []
            parents = resolve_parents(parent_spec, args, name, region)
            matched.update(parents)
            for parent_id in parents:
                for item in fetch_all(spec["argv"] + [spec["parent_arg"], parent_id],
                                      spec["key"], name, region, paginated=paginated):
                    item["_parent"] = parent_id
                    items.append(item)
            return name, region, items, None
        except ValueError as exc:
            return name, region, None, str(exc)

    with ThreadPoolExecutor(max_workers=args.workers) as pool:
        results = sorted(pool.map(probe, jobs), key=lambda r: (r[0], r[1]))

    errors = unscoped + [(n, r, e) for n, r, items, e in results if items is None]
    if action != "ls":
        for missing in sorted(set(getattr(args, "%s_id" % args.cmd, None) or ()) - matched):
            errors.append(("-", "-", "%s %s not found in any scanned profile or region" % (
                parent_spec["noun"], missing)))
    wanted_vpcs = set(getattr(args, "vpc", None) or ())
    rows = []
    for name, region, items, _ in results:
        for item in items or []:
            if wanted_vpcs and not wanted_vpcs & spec["vpcs_of"](item):
                continue
            row = spec["row"](item)
            if "_parent" in item:
                row[spec.get("parent_column", args.cmd)] = item["_parent"]
            if args.state and str(row["state"]).upper() != args.state.upper():
                continue
            row.update(profile=name, env=profiles[name].get("env", "-"), region=region,
                       uin=profiles[name].get("uin", "-"))
            rows.append(row)

    if args.json:
        print(json.dumps({spec["noun"].replace(" ", "_") + "s": rows,
                          "probes": len(jobs),
                          "errors": [{"profile": n, "region": r, "error": e}
                                     for n, r, e in errors]}, indent=2))
        sys.exit(1 if errors else 0)

    columns = ((("profile", "PROFILE"),)
               + ((("uin", "UIN"),) if parent_spec.get("uin_column") else ())
               + ((("region", "REGION"),) if regional else ())
               + spec["columns"])

    if rows:
        widths = [max([len(head)] + [len(str(r[key])) for r in rows]) for key, head in columns]
        fmt = "  ".join("%-*s" for _ in columns)
        print("%s%s%s" % (
            Colour.bold, fmt % sum(zip(widths, [h for _, h in columns]), ()), Colour.off))
        for r in rows:
            tag = " %s[prod]%s" % (Colour.bad, Colour.off) if r["env"] == "prod" else ""
            print("%s%s" % (fmt % sum(zip(widths, [r[k] for k, _ in columns]), ()), tag))
    else:
        print("%sno %ss%s%s" % (Colour.dim, spec["noun"],
                                " bound to " + ",".join(sorted(wanted_vpcs)) if wanted_vpcs
                                else "", Colour.off))

    # Always state the denominator: an empty table is only meaningful next to the
    # number of probes that actually succeeded.
    unit = "profile×region" if regional else "profile"
    print("\n%s%d %s(s) from %d %s probe(s), %d error(s)%s" % (
        Colour.dim, len(rows), spec["noun"], len(jobs), unit, len(errors), Colour.off))
    for name, region, err in errors[:10]:
        print("  %s✗ %-22s %-16s %s%s" % (Colour.bad, name, region, err, Colour.off))
    if len(errors) > 10:
        print("  %s... and %d more%s" % (Colour.dim, len(errors) - 10, Colour.off))

    sys.exit(1 if errors else 0)


def cmd_logout(args, profiles):
    """Delete local credential files.

    This is local only: tccli's logout removes the file and tells Tencent nothing,
    so a login token copied before logout stays usable until it expires.
    """
    failed = False
    for name in targets_of(args, profiles):
        failed |= run([TCCLI,"sso", "logout", "--profile", name]).returncode != 0
    sys.exit(1 if failed else 0)


def main():
    # Before anything is written or any tccli child starts (they inherit it): the
    # credential files hold secret keys and a realm-wide login token, and tccli
    # creates them with whatever umask it is given.
    os.umask(0o077)

    if not sys.stdout.isatty() or os.environ.get("NO_COLOR"):
        Colour.strip()

    parser = argparse.ArgumentParser(
        prog="tcloud", description="Tencent Cloud profile manager (registry: %s)" % REGISTRY)
    parser.add_argument("--version", action="version", version="tcloud %s" % __version__)
    subs = parser.add_subparsers(dest="cmd", required=True)

    p_ls = subs.add_parser("ls", help="list profiles and auth status")
    p_ls.add_argument("--sso", action="append", metavar="ORG",
                      help="show only this sso realm, repeatable (the url slug)")
    p_ls.set_defaults(fn=cmd_ls)

    p_login = subs.add_parser("login", help="configure + SSO login")
    p_login.add_argument("profile", nargs="?")
    p_login.add_argument("--all", action="store_true",
                         help="every profile, prod included: one approval per realm")
    p_login.add_argument("--sso", action="append", metavar="ORG",
                         help="every profile in this sso realm, repeatable — one "
                              "approval each (e.g. --sso myorg)")
    p_login.add_argument("--duration", type=int, help="credential lifetime in seconds")
    p_login.add_argument("--timeout", type=int, default=600, metavar="SEC",
                         help="give up on an unapproved login after SEC seconds "
                              "(default 600, 0 = wait forever)")
    p_login.set_defaults(fn=cmd_login)

    p_disc = subs.add_parser(
        "discover", help="list accounts + roles behind an sso url (one approval per url)")
    p_disc.add_argument("auth_url", nargs="*",
                        help="sso login url(s); default: every url already in the registry")
    p_disc.add_argument("--json", action="store_true", help="machine-readable output")
    p_disc.add_argument("--timeout", type=int, default=600, metavar="SEC",
                        help="give up on an unapproved login after SEC seconds "
                             "(default 600, 0 = wait forever)")
    p_disc.set_defaults(fn=cmd_discover)

    p_refresh = subs.add_parser(
        "refresh", help="re-mint credentials from the stored login token (no browser)")
    p_refresh.add_argument("profile", nargs="?")
    p_refresh.add_argument("--all", action="store_true", help="refresh every profile")
    p_refresh.add_argument("--sso", action="append", metavar="ORG",
                           help="refresh every profile in this sso realm, repeatable")
    p_refresh.add_argument("--duration", type=int, help="credential lifetime in seconds")
    p_refresh.set_defaults(fn=cmd_refresh)

    p_who = subs.add_parser("who", help="GetCallerIdentity (all profiles if omitted)")
    p_who.add_argument("profile", nargs="?")
    p_who.set_defaults(fn=cmd_who)

    for res, spec in RESOURCES.items():
        actions = ["ls"] + sorted(spec.get("children", {}))
        p_res = subs.add_parser(res, help="%ss (%s)" % (spec["noun"], ", ".join(actions)))
        p_res.add_argument("action", nargs="?", default="ls", choices=actions,
                           help="what to do (default: ls)")
        if spec.get("children"):
            # --<res>-id is the canonical flag, but it reads badly when the resource
            # key and its noun differ (tke/cluster), so a spec may name an alias.
            flags = ["--%s-id" % res] + ([spec["id_alias"]] if spec.get("id_alias") else [])
            p_res.add_argument(*flags, action="append", dest="%s_id" % res,
                               help="%s to query, repeatable; required only when a "
                                    "profile holds more than one" % spec["noun"])
        p_res.add_argument("--profile", action="append",
                           help="profile to scan, repeatable (default: first in accounts.conf)")
        p_res.add_argument("--all", action="store_true", help="scan every profile")
        p_res.add_argument("--sso", action="append", metavar="ORG",
                           help="scan every profile in this sso realm, repeatable")
        if spec.get("vpcs_of"):
            p_res.add_argument("--vpc", action="append", metavar="VPC_ID",
                               help="only %ss bound to this vpc, own-account or "
                                    "cross-account, repeatable" % spec["noun"])
        if spec.get("recount"):
            p_res.add_argument("--records", action="store_true",
                               help="count records with one extra call per %s instead of "
                                    "trusting its RecordCount" % spec["noun"])
        p_res.add_argument("--region", action="append",
                           help="region to scan, repeatable%s" % (
                               " (default: every available region)" if spec["regional"]
                               else " (%ss are global; one probe per profile)" % spec["noun"]))
        p_res.add_argument("--home-region", action="store_true",
                           help="scan only each profile's configured region (fast)")
        if spec.get("charge_flag"):
            p_res.add_argument("--charge", default="POSTPAID_BY_HOUR",
                               choices=["POSTPAID_BY_HOUR", "SPOTPAID", "PREPAID"],
                               help="billing mode (default POSTPAID_BY_HOUR); spot and "
                                    "pay-as-you-go have different stock")
            p_res.add_argument("--zone", action="append",
                               help="availability zone to ask about, repeatable")
        p_res.add_argument("--state", help="filter by state, e.g. RUNNING")
        p_res.add_argument("--json", action="store_true", help="machine-readable output")
        p_res.add_argument("--workers", type=int, default=12,
                           help="parallel probes (default 12)")
        p_res.set_defaults(fn=cmd_resource)

    p_logout = subs.add_parser(
        "logout", help="delete local credential files (does not revoke the token)")
    p_logout.add_argument("profile", nargs="?")
    p_logout.add_argument("--all", action="store_true", help="every profile")
    p_logout.add_argument("--sso", action="append", metavar="ORG",
                          help="every profile in this sso realm, repeatable")
    p_logout.set_defaults(fn=cmd_logout)

    args = parser.parse_args()
    args.fn(args, load_registry(optional=args.cmd == "discover"))


if __name__ == "__main__":
    main()
