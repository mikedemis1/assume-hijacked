"""The database password step of the Azure setup Job (python -m app.dbsetup.passwords).

It runs against the local test database (cluster-wide roles named pwtest_*, dropped after each
test, so no stack role is touched) and a fake Key Vault (an httpx2 MockTransport). No Azure token
exchange and no Key Vault call is ever made: the transport is always injected.
"""
from __future__ import annotations

import json
import os
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


