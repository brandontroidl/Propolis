<!--
title: Secret management
audience: operator
status: current
owner: maintainer
applies-to: 0.4.0 (untagged; latest tag v0.1.0)
last-verified: 2026-08-26
-->

# Secret management

Every Propolis secret is supplied through an operator-authored environment file
and read from the process environment at startup. No secret is created by the
installer, read from argv, or written back to disk by the platform.

## Where secrets live

All secrets are set in the per-service files under `/etc/propolis/`:

- Files are mode `0600`, owned by the service user (`install.sh` creates the
  users; the `.env` files themselves are authored by hand - `crates/propolis/src/config.rs` reads them, `deploy/install.sh#OPERATOR-owned`).
- `deploy/install.sh` **does not create or edit any operator-owned `.env` file** -
  the script "has no business fabricating" secret-bearing files; its only
  generated env file, `/etc/propolis/fleet-listeners.env`, carries no secret
  (`deploy/install.sh#has no business fabricating`, `deploy/install.sh#fleet-listeners.sh`).
- Configuration is parsed from environment variables only; **no secret is read
  from argv** (all via `env::var`), so secrets do not appear in process listings
  or shell history.

> The repository root contains a dev-only `.env` (for the local podman
> PostgreSQL); it is gitignored and is not the deployment config. Keep all
> `/etc/propolis/*.env` files out of version control.

## The secrets

Exact defaults, required/optional status, and validation are owned by
[../reference/environment-variables.md](../reference/environment-variables.md);
this page describes each secret's handling.

### `DATABASE_URL` (required)

The PostgreSQL connection string, which carries the database password inline. It
is required by every binary that touches Postgres; absent or empty aborts
startup (`require_env`, `crates/propolis/src/config.rs#require_env`). Because the password is embedded in the URL,
protect the `.env` file's `0600` mode and prefer a dedicated, least-privilege
database role. Do not use `trust` auth (`host all all all trust`) for a
network-reachable PostgreSQL.

### `PROPOLIS_CONSOLE_PASSWORD` (required)

The operator console login password. It is **hashed with Argon2id (default
params) at startup and the plaintext is dropped immediately**; only the PHC hash
string is retained in memory, and logins are verified against that hash
(`PasswordStore`, `crates/console/src/auth.rs#PasswordStore`). The plaintext still lives in the
`.env` file, so that file's permissions are the real control. Generate a strong
value, for example:

```
openssl rand -base64 24      # example - any strong secret works
```

Startup aborts if the variable is missing or empty (`crates/propolis/src/config.rs#load_config`).

### `PROPOLIS_CONSOLE_SESSION_SECRET` (optional)

Signs console sessions. If set it must be **exactly 64 hex characters (32
bytes)** or startup fails; if unset or empty, a fresh random 32-byte key is
generated on every start (`load_session_secret`, `crates/propolis/src/config.rs#load_session_secret`). Sessions are in-memory only, so
a per-restart key merely invalidates existing sessions - which a restart drops
anyway. Set it explicitly only if you want session-signing stability documented
and controlled. Example generator:

```
openssl rand -hex 32         # example - produces the required 64 hex chars
```

### Vendor API keys (optional, opt-in)

`PROPOLIS_VENDOR_{ABUSEIPDB,DSHIELD,OTX}_KEY` hold the abuse-report submitter
credentials; DShield also uses `PROPOLIS_VENDOR_DSHIELD_USER`, composed as
`user:key` into the single key slot (`crates/propolis/src/config.rs#load_config`). A vendor with
`*_ENABLED=true` but an empty key is **forced disabled** (fail-closed, logged
warning - `load_vendor_config`, `crates/propolis/src/config.rs#load_vendor_config`). These submitters produce outbound requests and
default off; see [../security/outbound-controls.md](../security/outbound-controls.md).

### `PROPOLIS_VT_KEY` (optional, opt-in)

The VirusTotal API key. `PROPOLIS_VT_ENABLED` is honored only when the key is
non-empty (`crates/propolis/src/config.rs#load_config`) - enabling VirusTotal requires both. VirusTotal
scanning is outbound egress and defaults off.

### `PROPOLIS_OPS_NTFY_TOKEN` (optional)

An optional bearer token for a protected ntfy topic used by operational
self-alerting (`crates/propolis/src/ops_alert/config.rs#parse_ops_alert`). Only relevant
when `PROPOLIS_OPS_ENABLED=true`.

## Handling rules

- **Never in argv:** all secrets are read from the environment; do not pass them
  on a command line.
- **Never in logs:** the console password is stored only as an Argon2id hash;
  keep `DATABASE_URL` and API keys out of any log by protecting the `.env`
  files. The platform does not echo these values.
- **`.env` files gitignored:** treat `/etc/propolis/*.env` and the dev-root
  `.env` as never-committed.
- **Rotation:** to rotate, edit the `.env` file and restart the affected unit;
  the console re-hashes its password on the next start.

## Related

- [configuration.md](configuration.md) - the overall configuration model
- [../security/authn-authz.md](../security/authn-authz.md) - console
  authentication and sessions
- [../security/outbound-controls.md](../security/outbound-controls.md) - the
  gated egress paths the vendor/VirusTotal/ops keys enable
