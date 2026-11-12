<!--
title: Database roles
audience: operator
status: current
owner: maintainer
applies-to: 0.4.0 (untagged; latest tag v0.1.0)
last-verified: 2026-11-12
-->

# Database roles

Propolis can run with **two PostgreSQL roles**: an owner role that changes the schema and a
runtime role the daemon connects as, which can append to the event ledger and cannot change
it. This page is the procedure. The reasoning is in
[filesystem and database protections](../security/filesystem-and-db-protections.md#database-layer-protections).

A node with one role keeps working unchanged. The daemon then says at every start that the
ledger's append-only control does not bind its own role, which is the reason to split.

## Why two roles

The ledger's append-only control is a `REVOKE UPDATE, DELETE, TRUNCATE ON event`. PostgreSQL
applies a revoke to every role except the table's owner: the owner can grant the privilege back,
disable the chain trigger, or drop the table. A daemon that connects as the role that ran the
migrations is that owner.

| | Owner role (`propolis_owner`) | Runtime role (`propolis`) |
|---|---|---|
| Used by | `propolis migrate`, run by root | the daemon, the backup, `config-check.sh` |
| Credential in | `/etc/propolis/migrate.env` | `/etc/propolis/propolis.env` (`DATABASE_URL`) |
| Read by | root only; no unit loads it, and the daemon's and every sensor's unit deny it by mount | the daemon's unit |
| Owns the tables | yes | no |
| `event` | everything | `SELECT`, `INSERT` |
| Other tables | everything | `SELECT`, `INSERT`, `UPDATE`, `DELETE` |
| Migration history tables | everything | `SELECT` |
| Create, alter or drop objects | yes | no |

The runtime role's privileges are defined in one place
(`crates/propolis/src/db_roles.rs#reconcile_runtime_grants`) and reset after every migration,
so a table a migration adds is covered and a privilege granted by hand does not survive.

The owner role must not be named `propolis`: an applied migration revokes ledger privileges from
a role of that name. Keep `propolis` as the runtime role.

## Splitting the roles on an existing node

Plan a few minutes with the daemon stopped. Sensors keep writing their logs; intake catches up
when the daemon starts again.

1. **Upgrade first**, so the installed binary and `/usr/local/sbin/propolis-migrate` are the
   release that has `propolis migrate` ([upgrade](upgrade-rollback-and-dr.md)).
2. **Stop the daemon.** The step below refuses while the runtime role has connections open.

   ```
   # Example - run as root.
   systemctl stop propolis.service
   ```

3. **Move ownership**, as a PostgreSQL superuser. This creates `propolis_owner` if it does not
   exist and hands it the database and everything `propolis` owns in it. It is one transaction
   and safe to repeat.

   ```
   # Example - run as root; connects as the postgres superuser over the local socket.
   sudo -u postgres env \
     PROPOLIS_ADMIN_DATABASE_URL='postgres://postgres@%2Fvar%2Frun%2Fpostgresql/propolis' \
     /usr/local/bin/propolis migrate --init-roles --owner propolis_owner --runtime propolis
   ```

4. **Give the owner role a way to log in.** With password authentication (or skip this and
   the password in step 5 and use [peer authentication](#without-passwords)):

   ```
   # Example - run as root; psql prompts for the new password.
   sudo -u postgres psql -c '\password propolis_owner'
   ```

5. **Write the owner's URL** where only root reads it. `deploy/env-files.sh`, run by every
   install and upgrade, keeps the file closed to group and other; `propolis-migrate` refuses it
   otherwise.

   ```
   # Example - run as root; replace the password.
   install -m 0600 -o root -g root /dev/null /etc/propolis/migrate.env
   echo 'PROPOLIS_MIGRATE_DATABASE_URL=postgres://propolis_owner:CHANGE_ME@localhost:5432/propolis' \
     > /etc/propolis/migrate.env
   ```

6. **Migrate as the owner and set the runtime role's grants.** Until this runs the runtime role
   cannot read a table, and the daemon refuses to start.

   ```
   # Example - run as root.
   propolis-migrate
   ```

7. **Check, then start.** The check connects as the daemon's role and exits 0 only when the
   schema is current and that role can append to the ledger and do nothing else to it.

   ```
   # Example - run as root.
   propolis-migrate --check
   systemctl start propolis.service
   ```

   `deploy/config-check.sh` reports the same thing among its findings: `ledger-owner` while the
   daemon's role still owns the ledger, nothing once it does not
   ([configuration check](service-lifecycle.md#configuration-check)).

   Expected output of the check:

   ```
   role: propolis
   schema: current
   ledger: protected (this role can append and read, nothing else)
   ```

## A new node

Create both roles and a database the owner role owns, then follow steps 4 to 7 above. Step 3 is
not needed: nothing is owned by the runtime role yet.

```
# Example - run as a PostgreSQL superuser.
psql -c 'CREATE ROLE propolis_owner LOGIN' -c 'CREATE ROLE propolis LOGIN'
psql -c 'CREATE DATABASE propolis OWNER propolis_owner TEMPLATE template0'
```

## Without passwords

On a node whose PostgreSQL is on the same host, neither role needs a password. PostgreSQL's
`peer` authentication accepts a connection over the Unix socket when the operating-system
account that opened it is allowed to be the role it asks for, so there is nothing in an env
file to steal, and a copied `DATABASE_URL` is useless from anywhere else.

Who may be which role is one map:

| OS account | May connect as | Used for |
|---|---|---|
| `propolis` (the daemon's unit) | `propolis` | the daemon |
| `root` | `propolis` | the backup, `config-check.sh`, `propolis-migrate --check` |
| `root` | `propolis_owner` | `propolis-migrate` |

The daemon's account is not mapped to the owner role, so it cannot connect as it. Every other
account is refused for both.

1. **`pg_hba.conf`**, above any other `local` line (the first matching line decides):

   ```
   # Example - PostgreSQL's pg_hba.conf.
   local   propolis   propolis,propolis_owner   peer map=propolis
   ```

2. **`pg_ident.conf`**:

   ```
   # Example - PostgreSQL's pg_ident.conf: map name, OS account, database role.
   propolis    propolis    propolis
   propolis    root        propolis
   propolis    root        propolis_owner
   ```

3. **Reload PostgreSQL**, then point both URLs at the socket. The role is named in the URL and
   the socket directory in `host=`; the host name before it is ignored. Use the directory and
   port your PostgreSQL listens on.

   ```
   # Example - /etc/propolis/propolis.env
   DATABASE_URL=postgres://propolis@localhost:5432/propolis?host=/var/run/postgresql

   # Example - /etc/propolis/migrate.env
   PROPOLIS_MIGRATE_DATABASE_URL=postgres://propolis_owner@localhost:5432/propolis?host=/var/run/postgresql
   ```

4. **Check as the daemon's own account**, then restart the daemon. The first command is what
   the daemon will do; the second shows the owner role is out of its reach, and must fail with
   `Peer authentication failed`.

   ```
   # Example - run as root.
   sudo -u propolis env 'DATABASE_URL=postgres://propolis@localhost:5432/propolis?host=/var/run/postgresql' \
     /usr/local/bin/propolis migrate --check
   sudo -u propolis env 'DATABASE_URL=postgres://propolis_owner@localhost:5432/propolis?host=/var/run/postgresql' \
     /usr/local/bin/propolis migrate --check
   propolis-migrate --check
   systemctl restart propolis.service
   ```

5. **Remove the passwords** the roles had, so the old way in is closed:

   ```
   # Example - run as root.
   sudo -u postgres psql -c 'ALTER ROLE propolis PASSWORD NULL' -c 'ALTER ROLE propolis_owner PASSWORD NULL'
   ```

`propolis migrate --init-roles` creates roles without passwords, so a node set up this way from
the start never has one. The daemon's unit already allows Unix sockets
(`deploy/propolis.service#RestrictAddressFamilies=AF_INET AF_INET6 AF_UNIX`). This does not
apply where PostgreSQL is on another host: there the roles authenticate over the network, with
a password or a client certificate.

## Upgrades afterwards

`deploy/upgrade.sh` sees the owner URL and, in place of restarting the daemon, stops it, runs
`propolis-migrate`, and starts it. A failed migration leaves the daemon stopped and ends the
upgrade with the error. The daemon itself never migrates on such a node: started against a
schema older or newer than its binary it exits, naming each migration that differs
(`crates/propolis/src/db_roles.rs#prepare_schema`).

## Restoring a dump

`pg_dump` records ownership and grants but not roles. Create **both** roles on the new server
before restoring, and make the owner role the database's owner; the grants then come back with
the dump ([restore procedure](backup-and-restore.md#restore-procedure)). Run
`propolis-migrate --check` afterwards.

## Going back to one role

Needed only to roll back to a release from before `propolis migrate` existed, whose daemon
migrates as the role it connects as. Stop the daemon, then as a superuser, in the database:

```
# Example - run as a PostgreSQL superuser, connected to the propolis database.
psql -d propolis -c 'REASSIGN OWNED BY propolis_owner TO propolis'
```

Remove `/etc/propolis/migrate.env` so upgrades stop using the owner role.

## What this does not cover

- **A compromised root account or PostgreSQL superuser.** Either can read the owner's
  credential or change the ledger directly. The control against that is the chain head recorded
  in backups held off the host
  ([backup and restore](backup-and-restore.md#when-the-ledger-does-not-match-a-backup)).
- **Authentication over the network.** [Without passwords](#without-passwords) covers a
  PostgreSQL on the same host. For one on another host, how each role logs in (password or
  client certificate) is set in its `pg_hba.conf` and is the operator's choice.
- **Deleting rows from other tables.** The runtime role needs that for the review queue and
  retention. Only `event` is append-only.

## Related

- [Filesystem and database protections](../security/filesystem-and-db-protections.md)
- [Backup and restore](backup-and-restore.md)
- [Upgrade, rollback and DR](upgrade-rollback-and-dr.md)
- [Environment variables](../reference/environment-variables.md)
