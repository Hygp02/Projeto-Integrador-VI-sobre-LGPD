"""Primitivas de segurança: criptografia em repouso, senhas, tokens, rate limit."""
from __future__ import annotations

import hashlib
import hmac
import json
import secrets
import time
from collections import defaultdict, deque
from datetime import datetime, timedelta, timezone

import jwt
from cryptography.fernet import Fernet, InvalidToken


class Crypto:
    """Criptografia simétrica autenticada (Fernet = AES-128-CBC + HMAC-SHA256)."""

    def __init__(self, key: str):
        self._fernet = Fernet(key.encode())

    def encrypt(self, text: str | None) -> str | None:
        if text is None:
            return None
        return self._fernet.encrypt(text.encode()).decode()

    def decrypt(self, token: str | None) -> str | None:
        if token is None:
            return None
        try:
            return self._fernet.decrypt(token.encode()).decode()
        except InvalidToken as exc:  # dado adulterado ou chave errada
            raise ValueError("Falha ao descriptografar: dado corrompido ou chave incorreta") from exc

    def encrypt_json(self, data: dict | None) -> str | None:
        return None if data is None else self.encrypt(json.dumps(data, ensure_ascii=False))

    def decrypt_json(self, token: str | None) -> dict | None:
        text = self.decrypt(token)
        return None if text is None else json.loads(text)


# ---------------------------------------------------------------- senhas
_SCRYPT = dict(n=2**14, r=8, p=1, dklen=32)


def hash_password(password: str) -> str:
    salt = secrets.token_bytes(16)
    digest = hashlib.scrypt(password.encode(), salt=salt, **_SCRYPT)
    return f"scrypt${salt.hex()}${digest.hex()}"


def verify_password(password: str, stored: str) -> bool:
    try:
        scheme, salt_hex, digest_hex = stored.split("$")
        if scheme != "scrypt":
            return False
        digest = hashlib.scrypt(password.encode(), salt=bytes.fromhex(salt_hex), **_SCRYPT)
        return hmac.compare_digest(digest.hex(), digest_hex)
    except (ValueError, TypeError):
        return False


def validate_password_strength(password: str) -> str | None:
    """Retorna mensagem de erro, ou None se a senha é aceitável."""
    if len(password) < 10:
        return "A senha deve ter ao menos 10 caracteres."
    if password.lower() == password or password.upper() == password:
        return "A senha deve misturar letras maiúsculas e minúsculas."
    if not any(c.isdigit() for c in password):
        return "A senha deve conter ao menos um número."
    return None


# ---------------------------------------------------------------- JWT
def create_token(secret: str, subject: str, role: str, expire_minutes: int) -> str:
    now = datetime.now(timezone.utc)
    payload = {"sub": subject, "role": role, "iat": now, "exp": now + timedelta(minutes=expire_minutes)}
    return jwt.encode(payload, secret, algorithm="HS256")


def decode_token(secret: str, token: str) -> dict:
    return jwt.decode(token, secret, algorithms=["HS256"])


# ---------------------------------------------------------------- chave do denunciante
def new_tracking_key() -> str:
    """Chave de acompanhamento mostrada UMA vez ao denunciante (alta entropia)."""
    return secrets.token_urlsafe(18)


def hash_tracking_key(key: str) -> str:
    # A chave tem alta entropia, então SHA-256 simples é suficiente (sem necessidade de KDF lento).
    return hashlib.sha256(key.encode()).hexdigest()


def new_protocol(year: int) -> str:
    """Protocolo aleatório (não sequencial) para impedir enumeração de denúncias."""
    alphabet = "ABCDEFGHJKLMNPQRSTUVWXYZ23456789"
    return f"DEN-{year}-" + "".join(secrets.choice(alphabet) for _ in range(8))


# ---------------------------------------------------------------- rate limit
class RateLimiter:
    """Janela deslizante em memória, por chave (ex.: IP). Nada é persistido."""

    def __init__(self):
        self._hits: dict[str, deque] = defaultdict(deque)

    def allow(self, bucket: str, key: str, limit: int, window_seconds: int = 60) -> bool:
        now = time.monotonic()
        q = self._hits[f"{bucket}:{key}"]
        while q and now - q[0] > window_seconds:
            q.popleft()
        if len(q) >= limit:
            return False
        q.append(now)
        return True

    def reset(self) -> None:
        self._hits.clear()
