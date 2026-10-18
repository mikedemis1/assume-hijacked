"""Give every workload database role a new password and store it in that workload's Key Vault.

Run by the Azure database setup Job (deploy/helm/assume-hijacked/templates/db-migrate.yaml) at
install and by the explicit rotation step, never on a plain chart upgrade:

    python -m app.dbsetup.passwords

The Job logs in to PostgreSQL as an Entra administrator and holds a Key Vault access token; both
tokens were fetched by an earlier container and arrive as files. Settings (environment):

    DB_HOST, DB_PORT, DB_NAME      the flexible server and database
    DB_ADMIN_USER                  the Entra principal; its access token is the password
    DB_ACCESS_TOKEN_FILE           file with the PostgreSQL access token
    KEY_VAULT_ACCESS_TOKEN_FILE    file with the Key Vault access token
    DB_PASSWORD_VAULTS             JSON {role: {"vault": <vault name>, "secret": "db-password-<role>"}}
    DB_SSLMODE                     require (default), verify-ca or verify-full; DB_SSLROOTCERT optional

For each role, in this order: write a new random password to the vault, set it on the role
(creating the role with login and no privileges if a later upgrade added it), then log in with it.
The vault comes first on purpose: if it fails, the database is untouched and the pods that still
hold the old password keep working; if the database step fails afterwards, the run says so and a
rerun replaces both. Nothing is skipped on a rerun, so a rerun always ends with every role and
vault entry matching (or a non-zero exit that names the roles still unfinished).

Everything is checked before anything is written: one malformed entry, or a role the Job must not
touch (the administrator, pg_* and azure_* roles, a role that cannot log in, or one that holds
SUPERUSER, CREATEROLE, CREATEDB, REPLICATION or BYPASSRLS) stops the whole run with exit 2.

Logs name roles and error classes only. Never a password, a token, a statement or a response body.

Exit codes: 0 all roles done, 1 at least one role unfinished or the database unreachable,
2 configuration or role refused (nothing was changed).
"""

from __future__ import annotations

import json
import os
import re
import secrets
import sys
import time
from collections.abc import Callable, Mapping
from dataclasses import dataclass
from pathlib import Path

import httpx2
import psycopg
from psycopg import sql

from app.common.events import security_event

KEY_VAULT_API_VERSION = "7.4"
VAULT_SUFFIX = ".vault.azure.net"
_ROLE = re.compile(r"[a-z][a-z0-9_]{1,40}")
# Key Vault names: 3-24 characters, letters, digits and hyphens, start with a letter, no
# trailing hyphen (Azure naming rules for vaults).
_VAULT = re.compile(r"[A-Za-z][A-Za-z0-9-]{1,22}[A-Za-z0-9]")
_DB_NAME = re.compile(r"[A-Za-z0-9_][A-Za-z0-9_-]{0,62}")
_SSL_MODES = ("require", "verify-ca", "verify-full")
_RETRY_STATUS = {408, 429, 500, 502, 503, 504}
_ATTEMPTS = 3
# A login role made by this step can open a few connections, like the roles in db/sql/02-roles.sql.
_NEW_ROLE_CONNECTION_LIMIT = 5


class ConfigError(Exception):
    """The settings or a role are not acceptable. The message never holds a secret."""


@dataclass(frozen=True)
class Target:
    role: str
    vault: str
    secret: str


@dataclass(frozen=True)
class Config:
    host: str
    port: int
    dbname: str
    admin: str
    db_token: str
    vault_token: str
    sslmode: str
    sslrootcert: str | None
    targets: tuple[Target, ...]


def secret_name(role: str) -> str:
    return "db-password-" + role.replace("_", "-")


def _no_duplicates(pairs):
    keys = [k for k, _ in pairs]
    if len(keys) != len(set(keys)):
        raise ConfigError("DB_PASSWORD_VAULTS names a role twice")
    return dict(pairs)


def _text(env: Mapping[str, str], name: str) -> str:
    value = env.get(name, "")
    if not value.strip() or any(ord(c) < 32 for c in value) or len(value) > 253:
        raise ConfigError(f"{name} is missing or malformed")
    return value.strip()


def _token(env: Mapping[str, str], name: str) -> str:
    path = Path(_text(env, name))
    try:
        if path.stat().st_size > 16384:
            raise ConfigError(f"{name}: file is too large")
        value = path.read_text(encoding="utf-8").strip()
    except OSError:
        raise ConfigError(f"{name}: file cannot be read") from None
    if not value:
        raise ConfigError(f"{name}: file is empty")
    return value


def parse_targets(raw: str, admin: str) -> tuple[Target, ...]:
    try:
        data = json.loads(raw, object_pairs_hook=_no_duplicates)
    except ConfigError:
        raise
    except ValueError:
        raise ConfigError("DB_PASSWORD_VAULTS is not JSON") from None
    if not isinstance(data, dict) or not data:
        raise ConfigError("DB_PASSWORD_VAULTS must be a non-empty object")
    targets = []
    for role, entry in data.items():
        if not _ROLE.fullmatch(role) or role.startswith(("pg_", "azure_")) or role in {"postgres", admin.lower()}:
            raise ConfigError("DB_PASSWORD_VAULTS names a role this step does not handle")
        if not isinstance(entry, dict) or set(entry) != {"vault", "secret"}:
            raise ConfigError(f"DB_PASSWORD_VAULTS: entry for {role} must have exactly vault and secret")
        vault, secret = entry["vault"], entry["secret"]
        if not isinstance(vault, str) or not _VAULT.fullmatch(vault):
            raise ConfigError(f"DB_PASSWORD_VAULTS: vault of {role} is not a Key Vault name")
        if secret != secret_name(role):
            raise ConfigError(f"DB_PASSWORD_VAULTS: secret of {role} must be {secret_name(role)}")
        targets.append(Target(role, vault, secret))
    return tuple(sorted(targets, key=lambda t: t.role))


def load_config(env: Mapping[str, str]) -> Config:
    admin = _text(env, "DB_ADMIN_USER")
    port_text = _text(env, "DB_PORT")
    if not port_text.isdigit() or not 0 < int(port_text) < 65536:
        raise ConfigError("DB_PORT is not a port number")
    dbname = _text(env, "DB_NAME")
    if not _DB_NAME.fullmatch(dbname):
        raise ConfigError("DB_NAME is malformed")
    sslmode = env.get("DB_SSLMODE", "require")
    if sslmode not in _SSL_MODES:
        raise ConfigError("DB_SSLMODE must be require, verify-ca or verify-full")
    rootcert = env.get("DB_SSLROOTCERT") or None
    if rootcert is not None and not Path(rootcert).is_file():
        raise ConfigError("DB_SSLROOTCERT is not a file")
    return Config(
        host=_text(env, "DB_HOST"),
        port=int(port_text),
        dbname=dbname,
        admin=admin,
        db_token=_token(env, "DB_ACCESS_TOKEN_FILE"),
        vault_token=_token(env, "KEY_VAULT_ACCESS_TOKEN_FILE"),
        sslmode=sslmode,
        sslrootcert=rootcert,
        targets=parse_targets(env.get("DB_PASSWORD_VAULTS", ""), admin),
    )


def new_password() -> str:
    return secrets.token_hex(24)


def _failure(error: BaseException) -> dict[str, str]:
    """What may be logged about a failure: the class and, for the database, the SQLSTATE."""
    out = {"error": type(error).__name__}
    state = getattr(error, "sqlstate", None)
    if state:
        out["sqlstate"] = state
    return out


class _VaultError(Exception):
    """A vault call that did not succeed. Holds a status or an error class, never a body."""


class _Run:
    def __init__(self, config: Config, connect: Callable, transport, sleep: Callable[[float], None],
                 generate: Callable[[], str]):
        self.config = config
        self._connect = connect
        self._transport = transport
        self._sleep = sleep
        self._generate = generate

    def connect(self, user: str, password: str):
        c = self.config
        kwargs = dict(host=c.host, port=c.port, dbname=c.dbname, user=user, password=password,
                      sslmode=c.sslmode, connect_timeout=15, autocommit=True)
        if c.sslrootcert:
            kwargs["sslrootcert"] = c.sslrootcert
        return self._connect(**kwargs)

    def preflight(self, admin_conn) -> dict[str, bool]:
        """Refuse the whole run if any listed role must not be touched. Returns which roles exist."""
        names = [t.role for t in self.config.targets]
        rows = admin_conn.execute(
            "SELECT rolname, rolcanlogin, rolsuper, rolcreaterole, rolcreatedb, rolreplication, "
            "rolbypassrls FROM pg_roles WHERE rolname = ANY(%s)", (names,)).fetchall()
        existing = set()
        for row in rows:
            name, canlogin, *privileged = tuple(row.values()) if isinstance(row, dict) else row
            if not canlogin or any(privileged):
                raise ConfigError(f"role {name} cannot log in or holds more than a workload may")
            existing.add(name)
        return {n: n in existing for n in names}

    def put_secret(self, target: Target, password: str) -> None:
        url = f"https://{target.vault}{VAULT_SUFFIX}/secrets/{target.secret}"
        headers = {"Authorization": f"Bearer {self.config.vault_token}"}
        with httpx2.Client(transport=self._transport, timeout=httpx2.Timeout(15.0),
                           follow_redirects=False) as client:
            for attempt in range(1, _ATTEMPTS + 1):
                try:
                    answer = client.put(url, params={"api-version": KEY_VAULT_API_VERSION},
                                        headers=headers, json={"value": password})
                except httpx2.TransportError as exc:
                    if attempt == _ATTEMPTS:
                        raise _VaultError(f"vault unreachable ({type(exc).__name__})") from None
                else:
                    if answer.status_code == 200:
                        return
                    if answer.status_code not in _RETRY_STATUS or attempt == _ATTEMPTS:
                        # The response body is not read: it can echo what was sent.
                        raise _VaultError(f"vault answered {answer.status_code}")
                self._sleep(2 ** (attempt - 1))

    def set_password(self, admin_conn, target: Target, password: str, exists: bool) -> None:
        role = sql.Identifier(target.role)
        if exists:
            statement = sql.SQL("ALTER ROLE {} PASSWORD {}").format(role, sql.Literal(password))
        else:
            statement = sql.SQL("CREATE ROLE {} LOGIN CONNECTION LIMIT {} PASSWORD {}").format(
                role, sql.Literal(_NEW_ROLE_CONNECTION_LIMIT), sql.Literal(password))
        admin_conn.execute(statement)

    def verify_login(self, target: Target, password: str) -> None:
        conn = self.connect(target.role, password)
        try:
            conn.execute("SELECT 1")
        finally:
            conn.close()

    def execute(self) -> int:
        try:
            admin_conn = self.connect(self.config.admin, self.config.db_token)
        except Exception as exc:  # noqa: BLE001 - any failure here is "database unreachable"
            security_event("db_passwords_failed", step="connect", **_failure(exc))
            return 1
        failed = []
        try:
            try:
                exists = self.preflight(admin_conn)
            except ConfigError as exc:
                security_event("db_passwords_refused", reason=str(exc))
                return 2
            except Exception as exc:  # noqa: BLE001
                security_event("db_passwords_failed", step="preflight", **_failure(exc))
                return 1
            for target in self.config.targets:
                step = "vault"
                try:
                    password = self._generate()
                    self.put_secret(target, password)
                    step = "database"
                    self.set_password(admin_conn, target, password, exists[target.role])
                    step = "login"
                    self.verify_login(target, password)
                except Exception as exc:  # noqa: BLE001 - one role failing must not stop the others
                    failed.append(target.role)
                    detail = _failure(exc)
                    if isinstance(exc, _VaultError):
                        detail["detail"] = str(exc)
                    security_event("db_password_failed", role=target.role, step=step, **detail)
                else:
                    security_event("db_password_set", role=target.role, vault=target.vault,
                                   created=not exists[target.role])
        finally:
            admin_conn.close()
        if failed:
            security_event("db_passwords_unfinished", roles=failed,
                           advice="run the step again; it replaces vault and database together")
            return 1
        security_event("db_passwords_done", roles=len(self.config.targets))
        return 0


def run(
    env: Mapping[str, str],
    *,
    connect: Callable = psycopg.connect,
    transport: httpx2.BaseTransport | None = None,
    sleep: Callable[[float], None] = time.sleep,
    generate: Callable[[], str] = new_password,
) -> int:
    """The whole step. `connect`, `transport`, `sleep` and `generate` exist for the tests, which
    use a fake vault and a throwaway database; main() passes none of them."""
    try:
        config = load_config(env)
    except ConfigError as exc:
        security_event("db_passwords_refused", reason=str(exc))
        return 2
    return _Run(config, connect, transport, sleep, generate).execute()


def main() -> int:
    return run(os.environ)


if __name__ == "__main__":
    sys.exit(main())
