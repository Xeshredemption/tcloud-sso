# Contributing

## Development setup

```bash
git clone https://github.com/Xeshredemption/tcloud-sso.git
cd tcloud-sso
python3 -m venv .venv && . .venv/bin/activate
pip install -e ".[dev]"
ruff check src tests
pytest
```

The test suite is offline: it never runs `tccli` or reaches Tencent.
`tests/test_tccli_contract.py` pins the tccli-private functions tcloud calls, and CI
runs it against `tccli-intl-en`.

**Fixtures are synthetic, always.** Never paste a real API response into a test: it
carries account UINs, resource ids and addresses. Use placeholder values such as
UIN `200000000001` and IPs from `203.0.113.0/24`.

Pull requests need green CI (ruff and pytest). Note user-visible changes in
`CHANGELOG.md`.

## Adding a resource scanner

Resource scanners are declarative. Adding a service is one entry in the `RESOURCES`
table: the Describe call, the result key, a `regional` flag, the columns, and a row
mapper. The scanner, parallelism, region fan-out, filtering, JSON output and the
probe/error denominator all come for free. Sub-resources that hang off a parent
(`tke nodes`, `ccn routes`) go under the parent's `children`. A child whose data is
not a Tencent API (`tke ingress` reads Kubernetes) supplies a
`fetch(profile, region, parent_id)` callable instead of `argv`.

Before adding one, **check whether the resource is regional or account-global**.
Query the same profile from two different regions and compare. Getting this wrong
produces silent duplicates, not an error.

## tccli quirks

Each of these was confirmed against the live API. They are the reasons the code looks
the way it does.

- **CCN is account-global, not regional.** `DescribeCcns` returns an identical set
  from every regional endpoint, so an all-region fan-out reports each CCN once per
  region.
- **`tccli` returns API errors as HTTP 200** with an `{"Error": ...}` body. A zero
  exit code does not mean success; always inspect the payload.
- **API parameters are case-sensitive** (`--Limit`, `--Filters`, `--Offset`), while
  global flags (`--profile`, `--region`) are lowercase.
- **`TargetUin` is an int64 server-side.** Passing the UIN as a string, which is
  exactly what `configparser` hands you from the registry, fails every SAML call
  with `cannot unmarshal string into Go struct field .TargetUin of type int64`.
  Take the UIN from the accounts API response and keep it an int on disk.
- **The 2h credential lifetime is tccli's default, not a server limit.**
  `AssumeRoleWithSAML` accepts up to 12h. A role's configured session duration can
  cap it lower, but `list_role_configurations_for_account` reports
  `SessionDuration: 0` either way, so the real limit can only be found by asking.
- **A too-long duration is rejected, never clamped**, and the error reads
  `InvalidParameter.OverTimeError / time set too long`. It never contains the word
  "duration", so matching on that word silently disables any fallback. `tcloud`
  steps 43200 → 28800 → 7200 on that marker only; a permission error must surface on
  the first attempt rather than be retried behind a misleading message.
- **`tccli`'s auto-refresh is dead by construction.** `maybe_refresh_credential`
  returns early unless the session has more than `12h − 5min` of a 12h session
  left, a window only open for about 5 minutes after login.
- **`sso.expiresAt` is fabricated client-side** as `now + 12h`. It is not a server
  value, so a lapsed estimate is not proof the token is dead. `tcloud refresh`
  probes it for real.
- **The login flow polls rather than using a loopback callback.** It prints an
  `https://` URL and polls Tencent for the result, so approving from a phone works.
- **tccli's poll loop has no timeout.** tcloud wraps it in `--timeout`, counted in
  wall-clock time, because macOS pauses alarm timers while the machine sleeps.
- **tccli writes credential files with the process umask**, commonly leaving them
  world-readable. tcloud sets umask `077` before anything is written.
- **tcloud imports tccli internals** (`tccli.sso`, `tccli.plugins.sso`), which are not
  a public API. Supported versions are capped below the next minor release, and the
  contract test fails CI if a signature changes.
