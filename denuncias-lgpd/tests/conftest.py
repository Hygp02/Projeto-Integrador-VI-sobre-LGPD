import os
import sys
import tempfile
from pathlib import Path

# Evita criar banco/segredos reais ao importar app.main durante os testes.
_tmp = tempfile.mkdtemp(prefix="den_test_")
os.environ.setdefault("DB_PATH", os.path.join(_tmp, "import.db"))
os.environ.setdefault("APP_ENCRYPTION_KEY", "uDmGZ0m5kW0O4m2nq4xYb7m6o2l8q9Zc3o5uJ1m3v7k=")
os.environ.setdefault("APP_JWT_SECRET", "segredo-de-teste-com-mais-de-32-caracteres-ok")

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import pytest
from cryptography.fernet import Fernet
from fastapi.testclient import TestClient

from app.config import Settings
from app.main import create_app

ADMIN = ("dpo@empresa.com", "SenhaForte123")
ANALISTA = ("analista@empresa.com", "OutraSenha456")


@pytest.fixture()
def ctx(tmp_path):
    settings = Settings(
        db_path=str(tmp_path / "t.db"),
        encryption_key=Fernet.generate_key().decode(),
        jwt_secret="x" * 48,
        admin_email=ADMIN[0],
        admin_password=ADMIN[1],
        rate_limit_login=5,
        rate_limit_submit=1000,
    )
    app = create_app(settings)
    client = TestClient(app)
    return client, settings, app


def login(client, creds):
    r = client.post("/api/auth/login", json={"email": creds[0], "senha": creds[1]})
    assert r.status_code == 200, r.text
    return {"Authorization": f"Bearer {r.json()['access_token']}"}


@pytest.fixture()
def admin_h(ctx):
    return login(ctx[0], ADMIN)


@pytest.fixture()
def analista_h(ctx, admin_h):
    client = ctx[0]
    r = client.post(
        "/api/admin/usuarios",
        headers=admin_h,
        json={"email": ANALISTA[0], "nome": "Ana Analista", "senha": ANALISTA[1], "papel": "analista"},
    )
    assert r.status_code == 201, r.text
    return login(client, ANALISTA)
