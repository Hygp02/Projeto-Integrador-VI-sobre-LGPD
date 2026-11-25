"""Linha de comando: criar usuários da equipe sem passar pela API.

Uso:
    python -m app.cli criar-usuario --email dpo@empresa.com --nome "Maria" --papel admin
"""
from __future__ import annotations

import argparse
import getpass
import sys

from .config import Settings
from .database import Database, audit, now_iso
from .security import hash_password, validate_password_strength


def main() -> int:
    parser = argparse.ArgumentParser(prog="app.cli")
    sub = parser.add_subparsers(dest="cmd", required=True)
    p = sub.add_parser("criar-usuario", help="Cria um usuário da equipe")
    p.add_argument("--email", required=True)
    p.add_argument("--nome", required=True)
    p.add_argument("--papel", choices=["admin", "analista"], default="analista")
    p.add_argument("--senha", help="(evite) senha na linha de comando; se omitida, será pedida")
    args = parser.parse_args()

    senha = args.senha or getpass.getpass("Senha: ")
    erro = validate_password_strength(senha)
    if erro:
        print(f"Erro: {erro}", file=sys.stderr)
        return 1

    db = Database(Settings().db_path)
    try:
        with db.transaction() as conn:
            conn.execute(
                "INSERT INTO usuarios (email, nome, senha_hash, papel, ativo, criado_em) VALUES (?,?,?,?,1,?)",
                (args.email.strip().lower(), args.nome, hash_password(senha), args.papel, now_iso()),
            )
            audit(conn, "sistema", "usuario_criado_cli", args.email.strip().lower(), args.papel)
    except Exception as exc:  # e-mail duplicado etc.
        print(f"Erro: {exc}", file=sys.stderr)
        return 1
    print(f"Usuário {args.email} criado com papel '{args.papel}'.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
