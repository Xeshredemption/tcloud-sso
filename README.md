# tcloud

Profile registry and one-approval multi-account SSO login for the Tencent Cloud CLI
(`tccli`).

> Independent project, not affiliated with or endorsed by Tencent. "Tencent Cloud" is
> a trademark of Tencent.
>
> **Use at your own risk.** tcloud handles cloud credentials and is provided "as is",
> without warranty of any kind. See [LICENSE](LICENSE), sections 7 and 8. Read the
> code, and try it against non-production accounts first.

`tccli` has no native profile registry. A profile's UIN, role and region only exist
inside `~/.tccli/<profile>.credential`, and only *after* a successful login — so
there is nowhere to write down "these are my accounts" before you have already
logged into them.

`tcloud` adds the missing layer: a declarative registry at `~/.tccli/accounts.conf`
that lists every account you can reach, and a driver that turns those declarations
into the right `tccli` calls.

```
$ tcloud ls
PROFILE               SSO        UIN           ENV         REGION         STATUS    DETAIL
app-dev               myorg      2000xxxxxxxx  dev         ap-singapore   ACTIVE    11h51m left (session 11h51m)
egress-prod           myorg      2000xxxxxxxx  prod        ap-singapore   REFRESH   creds expired — run `tcloud refresh`
audit                 otherorg   2000xxxxxxxx  shared      ap-singapore   EXPIRED   session estimate lapsed
```

---

## Why it exists

Three problems, each of which costs a browser round trip to hit:

1. **One login per account.** `tccli sso login` handles a single profile per
   invocation and makes you pick the account from an interactive menu. N accounts
   meant N browser approvals.
2. **No record of what exists.** Nothing on disk says which accounts you can reach
   until you have logged into each one, so onboarding a new org is archaeology.
3. **Credentials that expire quietly.** `tccli`'s auto-refresh never fires (see
   [tccli quirks](CONTRIBUTING.md#tccli-quirks)), so sessions lapse and every command
   starts failing at once.

`tcloud` fixes all three by relying on one fact `tccli` hides: **the SSO LoginToken
is realm-wide, not account-scoped.** Account selection happens client-side, after
the token is issued. So one approval can mint credentials for every account in that
realm. It only ever uses roles your SSO administrator has already granted you.

---

## Install

Requires Python 3.10+ on macOS or Linux. Supports the international Tencent Cloud
site (`tencentcloudssointl.com`) only; the China site is not supported. Installing
brings a supported `tccli`, and tcloud uses that copy rather than whatever is on
`PATH`:

```bash
pipx install tcloud-sso
```

From source:

```bash
git clone https://github.com/Xeshredemption/tcloud-sso.git
pipx install ./tcloud-sso
```

Then create your registry:

```bash
cp accounts.conf.example ~/.tccli/accounts.conf
```

Real UINs are discovered, not guessed — see [Registering a new org](#registering-a-new-org).

## Tested on

- The Tencent Cloud **international site** (`tencentcloudssointl.com`) only. The China
  site is not supported.
- **Live, against real accounts:** macOS (arm64, Python 3.12) and Linux (Debian arm64,
  Python 3.10). Covered: multi-realm SSO login, refresh, discover, identity, logout,
  and every scanner including sub-commands.
- **CI:** offline tests on Ubuntu and macOS, Python 3.10 and 3.14.
- Windows is not supported.

---

## The registry

`~/.tccli/accounts.conf` is INI, read by `tcloud` only — `tccli` never sees it.

```ini
[defaults]
role   = ReadOnly
region = ap-singapore

[profile app-dev]
uin      = 200000000001
env      = dev
auth_url = https://tencentcloudssointl.com/myorg/login
```

| Key | Required | Meaning |
|---|---|---|
| `uin` | yes | Tencent account UIN. Discovered, never invented. |
| `auth_url` | yes | The org's SSO login URL (`https://` only). Also defines the profile's *realm*. |
| `role` | yes | Role configuration name to assume, e.g. `ReadOnly`. |
| `region` | no | Default region for this profile. |
| `env` | no | Informational: colours `tcloud ls` and tags `prod` in output. |

Profile names may use letters, digits, `.`, `_` and `-`.

`[defaults]` applies to every profile unless overridden. **`auth_url` is
deliberately not defaulted** — with more than one org, an inherited default
silently authenticates a new entry against the wrong realm. Leaving it required
means a forgotten `auth_url` fails loudly instead of succeeding wrongly.

### Realms

The org slug in the SSO URL (`https://tencentcloudssointl.com/**myorg**/login`) is
the realm name. It is the unit of authentication: one approval covers one realm,
however many accounts sit behind it. `--sso myorg` selects by it, and `tcloud ls`
shows it in the `SSO` column so the valid values are discoverable.

---

## Commands

### Registering a new org

A profile needs a `uin`, but a UIN is only knowable *after* an approval. `discover`
is that step, made repeatable:

```bash
tcloud discover https://tencentcloudssointl.com/myorg/login
```

One approval, then for every account behind that realm it prints the UIN, display
name, **the roles actually available in that account**, and a paste-ready block:

```
ACCOUNT              UIN           PROFILE  ROLES
app-dev              200000000001  -        ReadOnly
egress-prod          200000000002  -        ReadOnly, Administrator

· not in ~/.tccli/accounts.conf — paste and rename to taste

[profile app-dev]
uin      = 200000000001
auth_url = https://tencentcloudssointl.com/myorg/login
role     = ReadOnly
```

Roles are listed per account because a wrong `role` name is not caught until login
— i.e. *after* the browser approval has already been spent on it. Accounts already
in the registry are marked rather than re-suggested.

### Logging in

```bash
tcloud login --all              # every realm: one approval each
tcloud login --sso myorg        # one realm, one approval, all its profiles
tcloud login --sso a --sso b    # repeatable
tcloud login app-dev            # a single profile (costs its own approval)
```

`--all` and `--sso` fan one approval out across every profile in the realm. A
failure after approval is per-profile, never fatal — aborting would cost the
survivors another round trip. An approval nobody acts on gives up after 10 minutes
(`--timeout SEC`, `0` to wait forever).

> A bare profile name shells out to `tccli` and spends a full approval on that one
> profile. `--sso myorg` is strictly cheaper, even for a single-account realm.

Profiles with `env = prod` are shown in red by `tcloud ls` and tagged `[prod]` in
login output.

### Refreshing without a browser

The login token outlives the role credentials derived from it and is stored on
disk, so extending a session needs no approval at all:

```bash
tcloud refresh --sso myorg      # re-mint that realm
tcloud refresh --all
tcloud refresh app-dev
```

Profiles are grouped by token so one verification covers the whole set, and a dead
token is reported once instead of as N identical errors. `tcloud ls` distinguishes
`REFRESH` (recoverable by this command) from `EXPIRED` (needs a browser).

### Scope: the three ways to say "which"

`login`, `refresh` and `logout` all route through one selector, so these mean the
same thing in each (`ls` takes `--sso`):

| Form | Scope |
|---|---|
| `<profile>` | that one profile |
| `--sso <org>` | every profile in that realm — repeatable |
| `--all` | every profile in the registry |

`--all` and `--sso` are mutually exclusive; combining either with a profile name is
an error; an unknown realm dies listing the known ones.

### Identity and teardown

```bash
tcloud who                  # live GetCallerIdentity for every profile
tcloud who app-dev
tcloud logout app-dev       # delete that profile's local credential file
tcloud logout --sso myorg   # or a whole realm (also --all)
```

`who` makes a real API call per profile rather than trusting the credential files —
use it to *prove* a login worked, not just that a file was written.

`logout` is **local only**. It deletes files and tells Tencent nothing, so a login
token copied before logout stays usable until it expires. See
[SECURITY.md](SECURITY.md).

### Resource scanners

```bash
tcloud cvm ls                       # first profile in the registry
tcloud vpc ls --all --home-region   # every profile, its configured region only
tcloud tke nodes --cluster-id cls-xxxx
tcloud stock ls --charge SPOTPAID --zone ap-singapore-2
tcloud privatedns ls --sso myorg                   # zones in one realm, with their uin
tcloud privatedns ls --all --vpc vpc-xxxx          # which zones does this vpc resolve?
tcloud privatedns ls --all --records               # recount records per zone
tcloud privatedns records --profile app-dev --zone-id zone-xxxx
```

| Command | Lists | Scope |
|---|---|---|
| `cvm ls` | instances | regional |
| `vpc ls` | VPCs | regional |
| `subnet ls` | subnets, free/total IPs, zone, route table | regional |
| `route ls` | route tables, route + association counts | regional |
| `nat ls` | NAT gateways | regional |
| `clb ls` | load balancers | regional |
| `stock ls` | instance-type availability | regional |
| `tke ls\|addons\|nodes` | TKE clusters, their addons, their nodes | regional |
| `ccn ls\|routes\|attachments` | cloud connect networks | **global** |
| `privatedns ls\|records` | private DNS zones with their bound VPCs, and their records | **global** |

Shared flags: `--profile NAME` (repeatable), `--sso ORG` (repeatable), `--all`,
`--region` (repeatable), `--home-region` to skip the all-region fan-out, `--state`
to filter, `--json`, `--workers N`.

They all default to the **first profile in the registry**, not to everything —
`--profile`, `--sso` or `--all` widens it.

`privatedns ls` lists own-account bindings (`VPCS`) and cross-account ones
(`ACCOUNT-VPCS`, as `uin:vpc`) separately. The API has no lookup from a VPC to its
zones, so `--vpc` filters client-side across both. A zone shadows its whole apex
inside every VPC it is bound to. `--records` replaces the zone's own `RecordCount`
with a count from `DescribePrivateZoneRecordList`, at one extra call per zone.

**Every scan prints its denominator:**

```
0 vpc(s) from 20 profile×region probe(s), 0 error(s)
```

An empty fleet and a failed scan must never look alike.

---

## Layout

| Path | Purpose |
|---|---|
| `src/tcloud/__init__.py` | the tool, a single Python file whose only dependency is `tccli` |
| `tests/` | offline tests, plus a contract test for the tccli-private functions |
| `accounts.conf.example` | registry template; copy to `~/.tccli/accounts.conf` |
| `CONTRIBUTING.md` | development setup, adding a scanner, tccli quirks |
| `~/.tccli/accounts.conf` | your real registry (never committed) |
| `~/.tccli/<profile>.credential` | tokens and role credentials, written by `tccli` |

**Nothing secret lives in this repo.** Real UINs, account names and credentials
stay in `~/.tccli/`, which `.gitignore` keeps out regardless.

---

## Security

Credential files are owner-only, profile names and SSO urls are validated, and
nothing is sent anywhere except Tencent. The threat model, and how to report a
vulnerability, are in [SECURITY.md](SECURITY.md).

## How this was built

Developed with AI assistance (Claude Code). **The code was reviewed by AI, not by a
human.** An AI code review of the whole tool found nine issues, and each one was fixed
with a regression test. The offline test suite covers every change, a contract test
pins the tccli-private functions it relies on, and the scanners were checked against
live Tencent Cloud accounts before release. Use at your own risk: see the notice at
the top.

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md).

## License

Apache-2.0. See [LICENSE](LICENSE) and [NOTICE](NOTICE).
