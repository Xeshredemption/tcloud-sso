# Security

## Reporting a vulnerability

Please report it privately with GitHub's **Report a vulnerability** button on this
repository's Security tab. Do not open a public issue. Reports are handled on a
best-effort basis, as soon as practical.

Only the latest release is supported.

## Threat model

tcloud manages credentials that reach every account an SSO user can access, so it
helps to know exactly what is at stake.

### What is on disk

`~/.tccli/<profile>.credential` holds two different things:

| Secret | Scope | Lifetime |
|---|---|---|
| `secretId` / `secretKey` / `token` | one account, one role | up to 12h |
| `sso.token`, the SSO login token | **every account in the realm** that the SSO user can reach | until Tencent expires it |

**One stolen credential file is worth a whole realm, not one profile.** The login
token is realm-wide: tcloud's `refresh` itself shows it can mint fresh credentials
for any account, with no browser and no MFA, for as long as it lives.

### What tcloud does about it

- **Owner-only files.** tccli writes credential files with the process umask,
  commonly `022`, which leaves them readable by every local user. tcloud sets umask
  `077` before it writes anything or starts tccli, so they are created `0600`.
  `tcloud ls` flags any older file that is still readable by others.
- **Validated profile names.** Registry names become file names, so anything that
  could leave `~/.tccli` is refused.
- **https-only SSO urls.** An SSO host other than Tencent's is warned about before
  the browser opens. The login token is never sent to that host, but the approval
  page is where a phishing url would do its damage.
- **Unguessable login nonce.** It comes from `secrets`.
- **Bounded wait.** An approval nobody acts on gives up after `--timeout` (default
  10 minutes) instead of waiting forever.
- **Throwaway kubeconfigs.** `tke ingress` fetches a cluster kubeconfig, which holds a
  client credential, into a private temp directory (`0700`, file `0600`) for one
  `kubectl` call and deletes it straight after. `~/.kube/config` is never read or
  changed.
- **No telemetry.** tcloud talks only to Tencent Cloud endpoints, through tccli, and
  opens your SSO url in a browser. `tke ingress` also calls the cluster's own
  Kubernetes API through kubectl. Nothing else.

### What tcloud cannot do

- **`tcloud logout` is local only.** It deletes files and tells Tencent nothing.
  A token copied before logout stays valid until it expires. If you think a
  credential file has leaked, ask your Tencent Cloud SSO administrator to revoke or
  disable the user. tcloud has no way to do that.
- **Malware running as your user can read the files** whatever their permissions.
  Use full-disk encryption, and do not run `tcloud login` on shared hosts or CI
  runners.

## Supply chain

- tcloud calls functions that are **private to tccli** (`tccli.sso`,
  `tccli.plugins.sso`). The supported tccli versions are capped below the next
  minor release, and `tests/test_tccli_contract.py` checks every function signature
  against `tccli-intl-en` in CI.
- tcloud runs the `tccli` installed beside its own interpreter, so the command and
  the imported library are always the same install.
- CI actions are pinned to full commit SHAs and updated by Dependabot. Workflows
  default to read-only tokens.
- Releases are published through PyPI Trusted Publishing (OIDC), with build
  attestations. No long-lived PyPI token exists.
