"""The database password step of the Azure setup Job (python -m app.dbsetup.passwords).

It runs against the local test database (cluster-wide roles named pwtest_*, dropped after each
test, so no stack role is touched) and a fake Key Vault (an httpx2 MockTransport). No Azure token
exchange and no Key Vault call is ever made: the transport is always injected.
"""
from __future__ import annotations

import json
import logging
import os
import re
import secrets

import httpx2
import psycopg
import pytest

from app.dbsetup import passwords

ROLES = ("pwtest_alpha", "pwtest_beta", "pwtest_gamma")
VAULT = "kv-pwtest"
KV_TOKEN = "kvtoken-" + secrets.token_hex(12)


def _secret_name(role: str) -> str:
    return "db-password-" + role.replace("_", "-")


@pytest.fixture(autouse=True)
def throwaway_roles(admin):
    def drop():
        for role in ROLES + ("pwtest_bad", "pwtest_admin"):
            admin.execute(psycopg.sql.SQL("DROP ROLE IF EXISTS {}").format(psycopg.sql.Identifier(role)))

    drop()
    yield
    drop()


class FakeVault:
    """Key Vault's Set Secret call: PUT https://<vault>.vault.azure.net/secrets/<name>."""

    def __init__(self, fail: dict[str, int] | None = None, redirect: bool = False):
        self.requests: list[httpx2.Request] = []
        self.secrets: dict[tuple[str, str], str] = {}
        self.fail = fail or {}
        self.redirect = redirect

    def __call__(self, request: httpx2.Request) -> httpx2.Response:
        self.requests.append(request)
        name = request.url.path.rsplit("/", 1)[-1]
        body = json.loads(request.content)
        if self.redirect:
            return httpx2.Response(302, headers={"location": "https://evil.example/steal"})
        status = self.fail.get(name, 200)
        if status != 200:
            # A real error body can echo the request: the step must not print it.
            return httpx2.Response(status, json={"error": {"message": f"rejected {body['value']}"}})
        self.secrets[(request.url.host.split(".")[0], name)] = body["value"]
        return httpx2.Response(200, json={"value": body["value"], "id": str(request.url)})

    def transport(self) -> httpx2.MockTransport:
        return httpx2.MockTransport(self)

    def password(self, role: str) -> str:
        return self.secrets[(VAULT, _secret_name(role))]


class Connector:
    """psycopg.connect, recording what was asked. The local test database has no TLS, so the
    connection itself falls back to sslmode=disable after the request has been recorded."""

    def __init__(self, allow_plain: bool = True):
        self.calls: list[dict] = []
        self.allow_plain = allow_plain

    def __call__(self, **kwargs):
        self.calls.append(dict(kwargs))
        if self.allow_plain:
            kwargs = {**kwargs, "sslmode": "disable"}
        return psycopg.connect(**kwargs)


@pytest.fixture
def env(tmp_path, settings):
    db_token = tmp_path / "postgres"
    db_token.write_text(os.environ["POSTGRES_PASSWORD"] + "\n", encoding="utf-8")
    kv_token = tmp_path / "key-vault"
    kv_token.write_text(KV_TOKEN + "\n", encoding="utf-8")
    return {
        "APP_ENV": "azure",
        "DB_HOST": settings.db_host,
        "DB_PORT": str(settings.db_port),
        "DB_NAME": settings.db_name,
        "DB_ADMIN_USER": "postgres",
        "DB_ACCESS_TOKEN_FILE": str(db_token),
        "KEY_VAULT_ACCESS_TOKEN_FILE": str(kv_token),
        "DB_PASSWORD_VAULTS": json.dumps(
            {r: {"vault": VAULT, "secret": _secret_name(r)} for r in ROLES}),
    }


def _login(settings, role: str, password: str) -> bool:
    try:
        psycopg.connect(host=settings.db_host, port=settings.db_port, dbname=settings.db_name,
                        user=role, password=password, sslmode="disable", connect_timeout=5).close()
    except psycopg.OperationalError:
        return False
    return True


def _run(env, vault, connector=None, **kw):
    return passwords.run(env, connect=connector or Connector(), transport=vault.transport(),
                         sleep=lambda _s: None, **kw)


# --- success ---------------------------------------------------------------------------------

def test_every_role_gets_the_password_that_was_written_to_its_vault(env, settings):
    vault = FakeVault()
    assert _run(env, vault) == 0
    for role in ROLES:
        assert _login(settings, role, vault.password(role)), role
    # Each role has its own password.
    assert len({vault.password(r) for r in ROLES}) == len(ROLES)


def test_an_existing_role_gets_a_new_password_and_the_old_one_stops_working(env, settings, admin):
    admin.execute("CREATE ROLE pwtest_alpha LOGIN PASSWORD 'old-password'")
    assert _login(settings, "pwtest_alpha", "old-password")
    vault = FakeVault()
    assert _run(env, vault) == 0
    assert not _login(settings, "pwtest_alpha", "old-password")
    assert _login(settings, "pwtest_alpha", vault.password("pwtest_alpha"))


def test_a_role_that_a_later_upgrade_adds_is_created_with_login_only(env, settings, admin):
    """A role that is not in the database yet is created: login, a small connection limit and no
    privileges at all (grants come from db/sql, never from this step)."""
    vault = FakeVault()
    assert _run(env, vault) == 0
    row = admin.execute("SELECT rolcanlogin, rolsuper, rolcreaterole, rolcreatedb, rolreplication, "
                        "rolbypassrls, rolconnlimit FROM pg_roles WHERE rolname = 'pwtest_beta'").fetchone()
    assert row == {"rolcanlogin": True, "rolsuper": False, "rolcreaterole": False,
                   "rolcreatedb": False, "rolreplication": False, "rolbypassrls": False,
                   "rolconnlimit": 5}
    granted = admin.execute("SELECT count(*) AS n FROM information_schema.role_table_grants "
                            "WHERE grantee = 'pwtest_beta'").fetchone()["n"]
    assert granted == 0


def test_passwords_are_long_random_and_new_on_every_run(env):
    first, second = FakeVault(), FakeVault()
    assert _run(env, first) == 0
    assert _run(env, second) == 0
    for role in ROLES:
        assert re.fullmatch(r"[0-9a-f]{48}", first.password(role))
        assert first.password(role) != second.password(role)


def test_vault_request_shape(env):
    vault = FakeVault()
    assert _run(env, vault) == 0
    assert len(vault.requests) == len(ROLES)
    for request in vault.requests:
        assert request.method == "PUT"
        assert request.url.scheme == "https"
        assert request.url.host == f"{VAULT}.vault.azure.net"
        assert request.url.path.startswith("/secrets/db-password-pwtest-")
        assert request.url.params["api-version"]
        assert request.headers["authorization"] == f"Bearer {KV_TOKEN}"
        assert set(json.loads(request.content)) == {"value"}


def test_a_vault_redirect_is_not_followed(env):
    vault = FakeVault(redirect=True)
    assert _run(env, vault) == 1
    assert len(vault.requests) == len(ROLES)  # nothing went to the redirect target
    assert {r.url.host for r in vault.requests} == {f"{VAULT}.vault.azure.net"}


# --- refused configuration -------------------------------------------------------------------

def _vaults(**roles) -> str:
    return json.dumps(roles)


GOOD = {"vault": VAULT, "secret": _secret_name("pwtest_alpha")}


@pytest.mark.parametrize("change", [
    {"DB_PASSWORD_VAULTS": "not json"},
    {"DB_PASSWORD_VAULTS": "[]"},
    {"DB_PASSWORD_VAULTS": "{}"},
    {"DB_PASSWORD_VAULTS": '{"pwtest_alpha": "kv-pwtest"}'},
    {"DB_PASSWORD_VAULTS": _vaults(pwtest_alpha={**GOOD, "extra": "x"})},
    {"DB_PASSWORD_VAULTS": _vaults(pwtest_alpha={"vault": VAULT})},
    {"DB_PASSWORD_VAULTS": _vaults(pwtest_alpha={**GOOD, "secret": "db-password-other"})},
    {"DB_PASSWORD_VAULTS": _vaults(pwtest_alpha={**GOOD, "secret": "x/../y"})},
    {"DB_PASSWORD_VAULTS": _vaults(pwtest_alpha={**GOOD, "vault": "evil.example/x"})},
    {"DB_PASSWORD_VAULTS": _vaults(pwtest_alpha={**GOOD, "vault": "kv-pwtest.vault.azure.net"})},
    {"DB_PASSWORD_VAULTS": _vaults(pwtest_alpha={**GOOD, "vault": "ab"})},
    {"DB_PASSWORD_VAULTS": _vaults(pwtest_alpha={**GOOD, "vault": "-kv-pwtest"})},
    {"DB_PASSWORD_VAULTS": _vaults(pwtest_alpha={**GOOD, "vault": "kv@evil"})},
    {"DB_PASSWORD_VAULTS": _vaults(**{"Pwtest_Alpha": {**GOOD, "secret": "db-password-Pwtest-Alpha"}})},
    {"DB_PASSWORD_VAULTS": _vaults(**{'x"; DROP ROLE y; --': {**GOOD, "secret": "db-password-x"}})},
    {"DB_PASSWORD_VAULTS": _vaults(**{"pg_read_all_data": {**GOOD, "secret": "db-password-pg-read-all-data"}})},
    {"DB_PASSWORD_VAULTS": _vaults(**{"azure_pg_admin": {**GOOD, "secret": "db-password-azure-pg-admin"}})},
    {"DB_PASSWORD_VAULTS": _vaults(**{"postgres": {**GOOD, "secret": "db-password-postgres"}})},
    {"DB_PASSWORD_VAULTS": '{"pwtest_alpha": %s, "pwtest_alpha": %s}' % (json.dumps(GOOD), json.dumps(GOOD))},
    {"DB_PASSWORD_VAULTS": ""},
    {"DB_HOST": ""},
    {"DB_PORT": "0"},
    {"DB_PORT": "five"},
    {"DB_NAME": "supplier; DROP"},
    {"DB_ADMIN_USER": ""},
    {"DB_ACCESS_TOKEN_FILE": "/nonexistent/token"},
    {"KEY_VAULT_ACCESS_TOKEN_FILE": "/nonexistent/token"},
    {"DB_SSLMODE": "disable"},
    {"DB_SSLMODE": "prefer"},
    {"DB_SSLMODE": "allow"},
    {"DB_SSLMODE": "verify_full"},
])
def test_malformed_or_unknown_configuration_is_refused_before_anything_happens(env, admin, change):
    roles_before = admin.execute("SELECT array_agg(rolname ORDER BY rolname) AS r FROM pg_roles").fetchone()
    config = {**env, **change}
    vault, connector = FakeVault(), Connector()
    assert _run(config, vault, connector) == 2
    assert vault.requests == [] and connector.calls == []
    assert admin.execute("SELECT array_agg(rolname ORDER BY rolname) AS r FROM pg_roles").fetchone() == roles_before


def test_an_empty_token_file_is_refused(env, tmp_path):
    empty = tmp_path / "empty"
    empty.write_text("\n", encoding="utf-8")
    vault, connector = FakeVault(), Connector()
    assert _run({**env, "KEY_VAULT_ACCESS_TOKEN_FILE": str(empty)}, vault, connector) == 2
    assert _run({**env, "DB_ACCESS_TOKEN_FILE": str(empty)}, vault, connector) == 2
    assert vault.requests == [] and connector.calls == []


def test_the_admin_user_itself_is_refused(env):
    env["DB_PASSWORD_VAULTS"] = _vaults(postgres={"vault": VAULT, "secret": "db-password-postgres"})
    vault, connector = FakeVault(), Connector()
    assert _run(env, vault, connector) == 2
    assert vault.requests == [] and connector.calls == []


def test_the_administrator_named_in_the_settings_is_refused_whatever_its_name(env, settings, admin, tmp_path):
    """Not only the name postgres: the principal the step logs in as is never given a password by it."""
    admin.execute("CREATE ROLE pwtest_admin LOGIN SUPERUSER PASSWORD 'admin-pw'")
    token = tmp_path / "admin-token"
    token.write_text("admin-pw", encoding="utf-8")
    config = {**env, "DB_ADMIN_USER": "pwtest_admin", "DB_ACCESS_TOKEN_FILE": str(token),
              "DB_PASSWORD_VAULTS": _vaults(pwtest_admin={"vault": VAULT, "secret": _secret_name("pwtest_admin")})}
    vault, connector = FakeVault(), Connector()
    assert _run(config, vault, connector) == 2
    assert vault.requests == [] and connector.calls == []


@pytest.mark.parametrize("attribute", ["SUPERUSER", "CREATEROLE", "CREATEDB", "REPLICATION", "BYPASSRLS"])
def test_an_existing_role_with_extra_rights_is_refused_and_nothing_is_changed(env, settings, admin, attribute):
    """A role that can create roles or bypass row security must never be handed a new password
    by a step that runs with the database administrator's rights."""
    admin.execute(f"CREATE ROLE pwtest_bad LOGIN {attribute} PASSWORD 'untouched'")
    env["DB_PASSWORD_VAULTS"] = json.dumps({
        r: {"vault": VAULT, "secret": _secret_name(r)} for r in ("pwtest_alpha", "pwtest_bad")})
    vault = FakeVault()
    assert _run(env, vault) == 2
    assert vault.requests == []  # refused before any vault write
    assert _login(settings, "pwtest_bad", "untouched")
    assert admin.execute("SELECT 1 FROM pg_roles WHERE rolname = 'pwtest_alpha'").fetchone() is None


def test_an_existing_role_that_cannot_log_in_is_refused(env, admin):
    """The function owners (NOLOGIN) have no password and must not get one."""
    admin.execute("CREATE ROLE pwtest_bad NOLOGIN")
    env["DB_PASSWORD_VAULTS"] = json.dumps({"pwtest_bad": {"vault": VAULT, "secret": _secret_name("pwtest_bad")}})
    vault = FakeVault()
    assert _run(env, vault) == 2
    assert vault.requests == []
    assert admin.execute("SELECT rolcanlogin FROM pg_roles WHERE rolname = 'pwtest_bad'").fetchone() == {
        "rolcanlogin": False}


# --- partial failure and rerun ---------------------------------------------------------------

def test_a_vault_failure_leaves_that_roles_database_password_alone_and_a_rerun_finishes(env, settings, admin):
    admin.execute("CREATE ROLE pwtest_beta LOGIN PASSWORD 'old-beta'")
    broken = FakeVault(fail={_secret_name("pwtest_beta"): 503})
    assert _run(env, broken) == 1
    # The vault is written first: its failure means the database was not changed, so pods that
    # still hold the old password keep working.
    assert _login(settings, "pwtest_beta", "old-beta")
    assert _login(settings, "pwtest_alpha", broken.password("pwtest_alpha"))
    # One role failing does not stop the roles after it.
    assert _login(settings, "pwtest_gamma", broken.password("pwtest_gamma"))
    healthy = FakeVault()
    assert _run(env, healthy) == 0
    for role in ROLES:
        assert _login(settings, role, healthy.password(role))
    assert not _login(settings, "pwtest_beta", "old-beta")


def test_a_database_failure_after_the_vault_write_is_reported_and_a_rerun_makes_both_match(env, settings, admin):
    admin.execute("CREATE ROLE pwtest_beta LOGIN PASSWORD 'old-beta'")

    class FailsAlterOfBeta(Connector):
        def __call__(self, **kwargs):
            conn = super().__call__(**kwargs)
            if kwargs["user"] != "postgres":
                return conn
            real_execute = conn.execute

            def execute(query, *a, **k):
                if "pwtest_beta" in (query.as_string(conn) if hasattr(query, "as_string") else str(query)) \
                        and "ALTER ROLE" in (query.as_string(conn) if hasattr(query, "as_string") else str(query)):
                    raise psycopg.errors.InsufficientPrivilege("denied")
                return real_execute(query, *a, **k)

            conn.execute = execute
            return conn

    first = FakeVault()
    assert _run({**env}, first, FailsAlterOfBeta()) == 1
    # Beta's vault holds a password the database does not have: the rerun replaces both.
    assert not _login(settings, "pwtest_beta", first.password("pwtest_beta"))
    assert _login(settings, "pwtest_beta", "old-beta")
    second = FakeVault()
    assert _run(env, second) == 0
    for role in ROLES:
        assert _login(settings, role, second.password(role))


def test_a_vault_that_accepts_but_a_login_that_fails_is_a_failure(env, settings):
    """The step logs in as each role with the new password: a mismatch is never reported as done."""
    class WrongPassword(Connector):
        def __call__(self, **kwargs):
            if kwargs["user"] == "pwtest_gamma":
                kwargs = {**kwargs, "password": "not-the-one"}
            return super().__call__(**kwargs)

    assert _run(env, FakeVault(), WrongPassword()) == 1


# --- TLS -------------------------------------------------------------------------------------

def test_every_database_connection_asks_for_tls(env):
    connector = Connector()
    assert _run(env, FakeVault(), connector) == 0
    assert len(connector.calls) >= 1 + len(ROLES)  # the admin connection and a login per role
    assert {c["sslmode"] for c in connector.calls} == {"require"}


@pytest.mark.parametrize("mode", ["require", "verify-ca", "verify-full"])
def test_a_stricter_tls_mode_is_passed_through(env, mode):
    connector = Connector()
    _run({**env, "DB_SSLMODE": mode}, FakeVault(), connector)
    assert {c["sslmode"] for c in connector.calls} == {mode}


def test_without_tls_on_the_server_nothing_is_written(env):
    """Control for the wall: the local test database does not offer TLS, so the real connection
    (no fallback) fails and the step writes nothing."""
    vault = FakeVault()
    assert _run(env, vault, Connector(allow_plain=False)) == 1
    assert vault.requests == []


# --- no values in logs -----------------------------------------------------------------------

def _all_output(caplog, capsys) -> str:
    captured = capsys.readouterr()
    return caplog.text + captured.out + captured.err


@pytest.mark.parametrize("failure", [None, "vault", "database"])
def test_no_password_or_token_reaches_the_logs(env, settings, caplog, capsys, failure):
    caplog.set_level(logging.DEBUG)
    vault = FakeVault(fail={_secret_name("pwtest_beta"): 400} if failure == "vault" else None)
    connector = Connector(allow_plain=failure != "database")
    _run(env, vault, connector)
    text = _all_output(caplog, capsys)
    sensitive = {KV_TOKEN, os.environ["POSTGRES_PASSWORD"], *vault.secrets.values()}
    for request in vault.requests:
        sensitive.add(json.loads(request.content)["value"])
    for value in sensitive:
        assert value not in text
    assert text  # something is logged: the roles by name
    assert "pwtest_" in text or failure == "database"


def test_a_server_error_with_the_statement_in_it_is_not_printed(env, caplog, capsys):
    class Boom(Connector):
        def __call__(self, **kwargs):
            conn = super().__call__(**kwargs)
            real = conn.execute

            def execute(query, *a, **k):
                text = query.as_string(conn) if hasattr(query, "as_string") else str(query)
                if "ALTER ROLE" in text or "CREATE ROLE" in text:
                    raise psycopg.errors.SyntaxError(f"syntax error in: {text}")
                return real(query, *a, **k)

            conn.execute = execute
            return conn

    vault = FakeVault()
    assert _run(env, vault, Boom()) == 1
    text = _all_output(caplog, capsys)
    for request in vault.requests:
        assert json.loads(request.content)["value"] not in text


def test_the_module_never_builds_a_real_http_client_without_a_transport(env):
    """Guard for these tests: run() takes the transport as an argument; the default (a real
    TLS client) is built only by main()."""
    import inspect
    assert inspect.signature(passwords.run).parameters["transport"].default is None
