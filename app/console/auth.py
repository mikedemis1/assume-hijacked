"""Server-held browser sessions and tenant-specific OpenID Connect code flow."""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
import os
import secrets
import time
from dataclasses import dataclass
from pathlib import Path
from urllib.parse import urlencode, urlsplit
from uuid import UUID

import httpx2
import jwt

SESSION_COOKIE = "ah_session"
FLOW_COOKIE = "ah_oidc"


@dataclass(frozen=True)
class Identity:
    oid: str
    role: str


@dataclass
class Session:
    identity: Identity | None
    csrf: str
    expires_at: float


@dataclass
class Pending:
    state: str
    nonce: str
    verifier: str
    expires_at: float


def identity(oid, roles) -> Identity:
    if not isinstance(oid, str) or not isinstance(roles, list) or not all(isinstance(r, str) for r in roles):
        raise ValueError("invalid identity")
    if "SeniorApprover" in roles:
        role = "SeniorApprover"
    elif "Approver" in roles:
        role = "Approver"
    else:
        raise ValueError("approver role required")
    return Identity(str(UUID(oid)), role)


def verify_id_token(token: str, jwks: dict, tenant: str, client: str, nonce: str) -> tuple[Identity, float]:
    try:
        header = jwt.get_unverified_header(token)
        if header.get("alg") != "RS256" or not isinstance(header.get("kid"), str):
            raise ValueError("invalid signing key")
        keys = [k for k in jwks["keys"] if k.get("kid") == header["kid"] and k.get("use", "sig") == "sig" and k.get("alg", "RS256") == "RS256"]
        if len(keys) != 1:
            raise ValueError("unknown signing key")
        key = jwt.PyJWK.from_dict(keys[0], algorithm="RS256").key
        claims = jwt.decode(token, key, algorithms=["RS256"], issuer=f"https://login.microsoftonline.com/{tenant}/v2.0", audience=client,
                            options={"require":["iss","aud","exp","iat","nonce","oid","tid","sub"]})
        if claims["tid"] != tenant or not isinstance(claims["nonce"], str) or not hmac.compare_digest(claims["nonce"], nonce):
            raise ValueError("invalid token binding")
        return identity(claims["oid"], claims.get("roles")), float(claims["exp"])
    except (jwt.PyJWTError, KeyError, TypeError, ValueError) as exc:
        raise ValueError("invalid identity token") from exc


class Auth:
    def __init__(self, transport=None):
        self.environment = os.environ.get("APP_ENV", "local")
        self.mode = os.environ.get("AUTH_MODE", "entra")
        if self.environment not in {"local", "kind", "azure"} or self.mode not in {"dev", "entra"}:
            raise ValueError("invalid console authentication configuration")
        if self.environment == "azure" and self.mode == "dev":
            raise ValueError("dev authentication is forbidden in azure")
        self.secure = self.environment != "local"
        self.sessions: dict[str, Session] = {}
        self.pending: dict[str, Pending] = {}
        self.transport = transport
        self.users = {}
        if self.mode == "dev":
            try:
                users = json.loads(os.environ.get("CONSOLE_DEV_USERS", "{}"))
                if not isinstance(users, dict) or not users:
                    raise ValueError("users required")
                self.users = {str(UUID(oid)): identity(oid, roles) for oid, roles in users.items()}
            except (ValueError, TypeError, AttributeError) as exc:
                raise ValueError("CONSOLE_DEV_USERS must map UUIDs to role lists") from exc
        else:
            self.tenant = str(UUID(os.environ.get("ENTRA_TENANT_ID", "")))
            self.client = str(UUID(os.environ.get("ENTRA_CLIENT_ID", "")))
            self.redirect = os.environ.get("CONSOLE_REDIRECT_URI", "")
            parsed = urlsplit(self.redirect)
            if (parsed.scheme != "https" and not (self.environment == "local" and parsed.scheme == "http" and parsed.hostname in {"127.0.0.1", "localhost"})) or parsed.path != "/auth/callback" or parsed.query or parsed.fragment or parsed.username or parsed.password:
                raise ValueError("CONSOLE_REDIRECT_URI must be an HTTPS callback (HTTP loopback locally)")
            secret_file = os.environ.get("CONSOLE_CLIENT_SECRET_FILE", "")
            if not secret_file:
                raise ValueError("CONSOLE_CLIENT_SECRET_FILE is required for the web client")
            self.client_secret = Path(secret_file).read_text(encoding="utf-8").strip()
            if not self.client_secret:
                raise ValueError("empty console client secret")
            self.authority = f"https://login.microsoftonline.com/{self.tenant}"

    def prune(self):
        now = time.time()
        for entries in (self.sessions, self.pending):
            for key in list(entries):
                if entries[key].expires_at <= now:
                    entries.pop(key, None)

    def session(self, cookie):
        self.prune()
        return self.sessions.get(cookie)

    def create_session(self, person: Identity | None, expires_at: float | None = None):
        self.prune()
        if len(self.sessions) >= 1000:
            raise ValueError("too many sessions")
        key = secrets.token_urlsafe(32)
        self.sessions[key] = Session(person, secrets.token_urlsafe(32), min(time.time()+1800, expires_at or float("inf")))
        return key

    def begin(self):
        self.prune()
        if len(self.pending) >= 1000:
            raise ValueError("too many pending logins")
        cookie = secrets.token_urlsafe(32)
        flow = Pending(secrets.token_urlsafe(32), secrets.token_urlsafe(32), secrets.token_urlsafe(48), time.time()+300)
        self.pending[cookie] = flow
        challenge = base64.urlsafe_b64encode(hashlib.sha256(flow.verifier.encode()).digest()).rstrip(b"=").decode()
        url = self.authority+"/oauth2/v2.0/authorize?"+urlencode(dict(client_id=self.client, response_type="code", response_mode="query", scope="openid", redirect_uri=self.redirect, state=flow.state, nonce=flow.nonce, code_challenge=challenge, code_challenge_method="S256"))
        return cookie, url

    async def complete(self, cookie, state, code):
        self.prune()
        flow = self.pending.pop(cookie, None)
        if flow is None or not isinstance(state, str) or not hmac.compare_digest(flow.state, state) or not code or len(code) > 8192:
            raise ValueError("invalid login state")
        async with httpx2.AsyncClient(transport=self.transport, timeout=5, follow_redirects=False, trust_env=False) as client:
            response = await client.post(self.authority+"/oauth2/v2.0/token", data=dict(grant_type="authorization_code",client_id=self.client,client_secret=self.client_secret,code=code,redirect_uri=self.redirect,code_verifier=flow.verifier))
            response.raise_for_status()
            token = response.json()["id_token"]
            keys = await client.get(self.authority+"/discovery/v2.0/keys")
            keys.raise_for_status()
            person, expiry = verify_id_token(token, keys.json(), self.tenant, self.client, flow.nonce)
        return self.create_session(person, expiry)
