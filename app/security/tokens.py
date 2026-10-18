"""The token the tool gateway signs for every tool call.

    iss = tool-gateway   aud = <the one tool it is for>   exp = iat + 60 s
    jti = a new random id each time   lease = the lease the call runs under

ES256 (ECDSA on P-256 with SHA-256): only the gateway holds the private key, every tool holds the
public one, so a hijacked tool can check tokens but cannot make them. A tool accepts a token once
(`jti`, kept for 120 s, twice the token's life) and only for its own name (`aud`). The lease is
inside the signed token, so it cannot be changed or chosen by the model.

https://datatracker.ietf.org/doc/html/rfc7519 (claims), https://datatracker.ietf.org/doc/html/rfc8725
(best practice: the verifier names the algorithm, it never reads it from the token).
"""

from __future__ import annotations

import threading
import uuid
from collections import OrderedDict
from pathlib import Path

import jwt
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec

ISSUER = "tool-gateway"
LIFETIME_S = 60
# A token issued a few seconds "in the future" is clock drift between two containers, not an attack.
CLOCK_SKEW_S = 5
JTI_TTL_S = 120
MAX_TOKEN_CHARS = 4096
MAX_LEASE_CHARS = 256
ALGORITHM = "ES256"
_REQUIRED = ("iss", "aud", "iat", "exp", "jti", "lease")


class TokenError(Exception):
    """The token is not acceptable. `reason` is a short category for the security log; the caller
    of the tool is told only "unauthorized"."""

    def __init__(self, reason: str) -> None:
        super().__init__(reason)
        self.reason = reason


class JtiCache:
    """The ids of tokens already used, each kept for `ttl_seconds`. Safe to share between threads."""

    def __init__(self, ttl_seconds: int = JTI_TTL_S) -> None:
        self._ttl = ttl_seconds
        self._seen: OrderedDict[str, float] = OrderedDict()
        self._lock = threading.Lock()

    def __len__(self) -> int:
        with self._lock:
            return len(self._seen)

    def add(self, jti: str, now: float) -> bool:
        """Remember the id. False if it was already seen and is still remembered."""
        with self._lock:
            while self._seen:
                oldest, added = next(iter(self._seen.items()))
                if added + self._ttl > now:
                    break
                del self._seen[oldest]
            added = self._seen.get(jti)
            if added is not None and added + self._ttl > now:
                return False
            self._seen[jti] = now
            self._seen.move_to_end(jti)
            return True


def mint_tool_token(private_pem: bytes, tool: str, lease: str, now: float) -> str:
    claims = {
        "iss": ISSUER,
        "aud": tool,
        "iat": int(now),
        "exp": int(now) + LIFETIME_S,
        "jti": uuid.uuid4().hex,
        "lease": lease,
    }
    return jwt.encode(claims, private_pem, algorithm=ALGORITHM)


def verify_tool_token(public_pem: bytes, token: str, tool: str, now: float, seen: JtiCache) -> dict:
    """The claims of a token that is signed by the gateway, meant for `tool`, still live and new.

    Order: signature, then claims, then the replay cache last, so only a fully valid token is ever
    remembered (nobody can fill the cache with junk)."""
    if not isinstance(token, str) or not token or len(token) > MAX_TOKEN_CHARS or token.count(".") != 2:
        raise TokenError("malformed")
    try:
        # The algorithm comes from here, never from the token's own header (no "none", no HS256 with
        # the public key as the secret). PyJWT's time checks are off: `now` is the caller's clock.
        claims = jwt.decode(
            token,
            public_pem,
            algorithms=[ALGORITHM],
            options={"verify_exp": False, "verify_iat": False, "verify_nbf": False, "verify_aud": False,
                     "verify_iss": False, "require": []},
        )
    except (jwt.PyJWTError, ValueError, TypeError):
        # A bad signature, a wrong algorithm, a key of the wrong kind, undecodable text.
        raise TokenError("signature") from None
    if any(name not in claims for name in _REQUIRED):
        raise TokenError("claims")
    if claims["iss"] != ISSUER:
        raise TokenError("issuer")
    if claims["aud"] != tool:
        raise TokenError("audience")
    iat, exp, jti, lease = claims["iat"], claims["exp"], claims["jti"], claims["lease"]
    if not all(isinstance(n, int) and not isinstance(n, bool) for n in (iat, exp)):
        raise TokenError("claims")
    if not isinstance(jti, str) or not jti or not isinstance(lease, str) or not lease or len(lease) > MAX_LEASE_CHARS:
        raise TokenError("claims")
    if iat > now + CLOCK_SKEW_S:
        raise TokenError("claims")
    if exp <= now:
        raise TokenError("expired")
    if exp - iat > LIFETIME_S:
        raise TokenError("lifetime")
    if not seen.add(jti, now):
        raise TokenError("replayed")
    return claims


def _load(path: str | Path, private: bool) -> bytes:
    """The key file's bytes, after checking it is an EC P-256 key of the right kind. A component
    that starts with the wrong key fails at once instead of refusing every call later."""
    pem = Path(path).read_bytes()
    kind = "private" if private else "public"
    try:
        key = (
            serialization.load_pem_private_key(pem, password=None)
            if private
            else serialization.load_pem_public_key(pem)
        )
    except (ValueError, TypeError) as err:
        raise ValueError(f"{path} is not a PEM {kind} key") from err
    if not isinstance(key, (ec.EllipticCurvePrivateKey, ec.EllipticCurvePublicKey)) or not isinstance(
        key.curve, ec.SECP256R1
    ):
        raise ValueError(f"{path} is not an EC P-256 key")
    return pem


def load_public_key(path: str | Path) -> bytes:
    return _load(path, private=False)


def load_private_key(path: str | Path) -> bytes:
    return _load(path, private=True)
