# Changelog

All notable changes to this project are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and the project uses
[Semantic Versioning](https://semver.org/).

## [0.1.0] - unreleased

Initial public release.

### Features

- International Tencent Cloud site only (`tencentcloudssointl.com`).
- A declarative registry at `~/.tccli/accounts.conf` for every account reachable
  through Tencent Cloud SSO.
- `login --sso ORG` and `login --all`: one browser approval per SSO realm mints
  credentials for every profile in it.
- `refresh`: re-mints credentials from the stored login token, with no browser.
- `discover`: lists the accounts and roles behind an SSO url, with paste-ready
  registry entries.
- `ls`, `who`, and `logout` for a profile, a realm, or everything.
- Resource scanners for `cvm`, `vpc`, `subnet`, `route`, `nat`, `clb`, `stock`, `tke`
  and `ccn`, with region fan-out, `--json` output, and a probe and error count on
  every scan.
- `--timeout` for logins, counted in wall-clock time so it still fires after the
  machine sleeps.

### Security

- Credential files are written owner-only (`0600`), and `ls` flags any that are
  readable by others.
- Profile names are validated. SSO urls must be `https`, and an unknown SSO host is
  warned about.
- The login nonce comes from `secrets`.
- No telemetry.
