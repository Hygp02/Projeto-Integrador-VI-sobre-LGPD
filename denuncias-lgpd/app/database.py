"""Camada de banco de dados (SQLite) e trilha de auditoria encadeada por hash."""
from __future__ import annotations

import hashlib
import sqlite3
import threading
from contextlib import contextmanager
from datetime import datetime, timezone

SCHEMA = """
CREATE TABLE IF NOT EXISTS usuarios (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    email TEXT NOT NULL UNIQUE,
    nome TEXT NOT NULL,
    senha_hash TEXT NOT NULL,
    papel TEXT NOT NULL CHECK (papel IN ('admin', 'analista')),
    ativo INTEGER NOT NULL DEFAULT 1,
    criado_em TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS denuncias (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    protocolo TEXT NOT NULL UNIQUE,
    chave_hash TEXT NOT NULL,
    categoria TEXT NOT NULL,
    status TEXT NOT NULL DEFAULT 'recebida',
    anonima INTEGER NOT NULL,
    -- campos abaixo são armazenados CRIPTOGRAFADOS (Fernet)
    descricao_enc TEXT NOT NULL,
    empresa_enc TEXT,
    identidade_enc TEXT,
    consentimento_em TEXT,
    criado_em TEXT NOT NULL,
    atualizado_em TEXT NOT NULL,
    encerrado_em TEXT
);

CREATE TABLE IF NOT EXISTS movimentacoes (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    denuncia_id INTEGER NOT NULL REFERENCES denuncias(id) ON DELETE CASCADE,
    autor TEXT NOT NULL CHECK (autor IN ('sistema', 'equipe', 'denunciante')),
    visibilidade TEXT NOT NULL CHECK (visibilidade IN ('publica', 'interna')),
    texto_enc TEXT NOT NULL,
    status_resultante TEXT,
    criado_em TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS auditoria (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    ts TEXT NOT NULL,
    ator TEXT NOT NULL,
    acao TEXT NOT NULL,
    alvo TEXT,
    detalhe TEXT,
    hash_anterior TEXT NOT NULL,
    hash TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_den_status ON denuncias(status);
CREATE INDEX IF NOT EXISTS idx_mov_den ON movimentacoes(denuncia_id);
"""

GENESIS_HASH = "0" * 64


def now_iso() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


class Database:
    def __init__(self, path: str):
        self.path = path
        self._write_lock = threading.Lock()
        with self.connect() as conn:
            conn.executescript(SCHEMA)

    @contextmanager
    def connect(self):
        conn = sqlite3.connect(self.path, timeout=10, isolation_level=None)
        conn.row_factory = sqlite3.Row
        conn.execute("PRAGMA foreign_keys = ON")
        conn.execute("PRAGMA journal_mode = WAL")
        try:
            yield conn
        finally:
            conn.close()

    @contextmanager
    def transaction(self):
        """Transação de escrita (serializada) — commit ao sair, rollback em erro."""
        with self._write_lock, self.connect() as conn:
            conn.execute("BEGIN IMMEDIATE")
            try:
                yield conn
                conn.execute("COMMIT")
            except Exception:
                conn.execute("ROLLBACK")
                raise


# ---------------------------------------------------------------- auditoria
def _entry_hash(prev: str, ts: str, ator: str, acao: str, alvo: str | None, detalhe: str | None) -> str:
    payload = "|".join([prev, ts, ator, acao, alvo or "", detalhe or ""])
    return hashlib.sha256(payload.encode()).hexdigest()


def audit(conn: sqlite3.Connection, ator: str, acao: str, alvo: str | None = None, detalhe: str | None = None) -> None:
    """Registra um evento na trilha de auditoria (deve ser chamado dentro de uma transação).

    Cada registro inclui o hash do anterior: alterar ou apagar qualquer linha
    quebra a cadeia e é detectado por `verify_audit_chain`.
    NUNCA grava dados pessoais — apenas quem fez o quê e sobre qual protocolo.
    """
    row = conn.execute("SELECT hash FROM auditoria ORDER BY id DESC LIMIT 1").fetchone()
    prev = row["hash"] if row else GENESIS_HASH
    ts = now_iso()
    h = _entry_hash(prev, ts, ator, acao, alvo, detalhe)
    conn.execute(
        "INSERT INTO auditoria (ts, ator, acao, alvo, detalhe, hash_anterior, hash) VALUES (?,?,?,?,?,?,?)",
        (ts, ator, acao, alvo, detalhe, prev, h),
    )


def verify_audit_chain(conn: sqlite3.Connection) -> dict:
    prev = GENESIS_HASH
    count = 0
    for row in conn.execute("SELECT * FROM auditoria ORDER BY id ASC"):
        expected = _entry_hash(prev, row["ts"], row["ator"], row["acao"], row["alvo"], row["detalhe"])
        if row["hash_anterior"] != prev or row["hash"] != expected:
            return {"integra": False, "registros": count, "primeira_falha_id": row["id"]}
        prev = row["hash"]
        count += 1
    return {"integra": True, "registros": count, "primeira_falha_id": None}
