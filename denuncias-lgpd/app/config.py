"""Configuração do sistema.

Segredos (chave de criptografia e chave do JWT) vêm de variáveis de ambiente.
Em desenvolvimento, se não existirem, são gerados e gravados em `.secrets/`
(pasta ignorada pelo git) para que os dados continuem legíveis entre execuções.
"""
from __future__ import annotations

import os
import secrets
from dataclasses import dataclass, field
from pathlib import Path

from cryptography.fernet import Fernet

BASE_DIR = Path(__file__).resolve().parent.parent


def _load_or_create_secret(env_name: str, filename: str, generator) -> str:
    value = os.getenv(env_name)
    if value:
        return value
    secrets_dir = BASE_DIR / ".secrets"
    secrets_dir.mkdir(exist_ok=True)
    path = secrets_dir / filename
    if path.exists():
        return path.read_text().strip()
    value = generator()
    path.write_text(value)
    try:
        path.chmod(0o600)
    except OSError:  # pragma: no cover - Windows
        pass
    return value


@dataclass
class Settings:
    db_path: str = field(default_factory=lambda: os.getenv("DB_PATH", str(BASE_DIR / "denuncias.db")))
    encryption_key: str = field(
        default_factory=lambda: _load_or_create_secret(
            "APP_ENCRYPTION_KEY", "encryption.key", lambda: Fernet.generate_key().decode()
        )
    )
    jwt_secret: str = field(
        default_factory=lambda: _load_or_create_secret(
            "APP_JWT_SECRET", "jwt.key", lambda: secrets.token_urlsafe(48)
        )
    )
    jwt_expire_minutes: int = int(os.getenv("JWT_EXPIRE_MINUTES", "60"))
    # Retenção: denúncias encerradas há mais de N dias são eliminadas (princípio da necessidade).
    retention_days: int = int(os.getenv("RETENTION_DAYS", "365"))
    # Limites simples contra abuso (por IP, só em memória — nada é gravado).
    rate_limit_login: int = int(os.getenv("RATE_LIMIT_LOGIN", "5"))  # tentativas / minuto
    rate_limit_submit: int = int(os.getenv("RATE_LIMIT_SUBMIT", "10"))  # envios / minuto
    # Admin inicial opcional (criado no primeiro start se não houver usuários).
    admin_email: str | None = os.getenv("ADMIN_EMAIL")
    admin_password: str | None = os.getenv("ADMIN_PASSWORD")
