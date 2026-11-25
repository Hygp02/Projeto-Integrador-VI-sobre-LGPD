"""API do Sistema de Denúncias de Vazamento de Dados (LGPD).

Execução:  uvicorn app.main:app --reload
"""
from __future__ import annotations

import hmac
import sqlite3
from datetime import datetime, timedelta, timezone
from pathlib import Path

import jwt
from fastapi import Depends, FastAPI, HTTPException, Request
from fastapi.responses import FileResponse, JSONResponse
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from fastapi.staticfiles import StaticFiles

from .config import BASE_DIR, Settings
from .database import Database, audit, now_iso, verify_audit_chain
from .schemas import (
    CATEGORIAS,
    STATUS_FINAIS,
    AcessoIdentidadeIn,
    AcompanhamentoIn,
    DenunciaCriada,
    DenunciaIn,
    LoginIn,
    MensagemDenuncianteIn,
    StatusIn,
    UsuarioIn,
)
from .security import (
    Crypto,
    RateLimiter,
    create_token,
    decode_token,
    hash_password,
    hash_tracking_key,
    new_protocol,
    new_tracking_key,
    validate_password_strength,
    verify_password,
)

STATIC_DIR = BASE_DIR / "static"
_DUMMY_HASH = hash_password("senha-falsa-para-tempo-constante")
_INVALID_TRACKING = "Protocolo ou chave de acompanhamento inválidos."


def create_app(settings: Settings | None = None) -> FastAPI:
    settings = settings or Settings()
    db = Database(settings.db_path)
    crypto = Crypto(settings.encryption_key)
    limiter = RateLimiter()
    bearer = HTTPBearer(auto_error=False)

    app = FastAPI(
        title="Sistema de Denúncias de Vazamento de Dados",
        description="Canal seguro e confidencial, em conformidade com a LGPD (Lei 13.709/2018).",
        version="1.0.0",
    )
    app.state.settings = settings
    app.state.db = db
    app.state.limiter = limiter

    _bootstrap_admin(db, settings)

    # ------------------------------------------------------------ cabeçalhos de segurança
    @app.middleware("http")
    async def security_headers(request: Request, call_next):
        response = await call_next(request)
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["X-Frame-Options"] = "DENY"
        response.headers["Referrer-Policy"] = "no-referrer"
        response.headers["Content-Security-Policy"] = (
            "default-src 'self'; img-src 'self' data:; frame-ancestors 'none'; base-uri 'none'"
        )
        if request.url.path.startswith("/api"):
            response.headers["Cache-Control"] = "no-store"
        return response

    # ------------------------------------------------------------ utilidades
    def client_ip(request: Request) -> str:
        return request.client.host if request.client else "desconhecido"

    def throttle(request: Request, bucket: str, limit: int) -> None:
        if not limiter.allow(bucket, client_ip(request), limit):
            raise HTTPException(429, "Muitas tentativas. Aguarde um minuto e tente novamente.")

    def current_user(
        creds: HTTPAuthorizationCredentials | None = Depends(bearer),
    ) -> dict:
        if creds is None:
            raise HTTPException(401, "Autenticação necessária.")
        try:
            payload = decode_token(settings.jwt_secret, creds.credentials)
        except jwt.PyJWTError:
            raise HTTPException(401, "Token inválido ou expirado.")
        with db.connect() as conn:
            row = conn.execute(
                "SELECT id, email, nome, papel, ativo FROM usuarios WHERE email = ?", (payload["sub"],)
            ).fetchone()
        if row is None or not row["ativo"]:
            raise HTTPException(401, "Usuário inexistente ou desativado.")
        return dict(row)

    def require_admin(user: dict = Depends(current_user)) -> dict:
        if user["papel"] != "admin":
            raise HTTPException(403, "Acesso restrito ao encarregado (administrador).")
        return user

    def get_by_tracking(conn: sqlite3.Connection, protocolo: str, chave: str) -> sqlite3.Row:
        row = conn.execute("SELECT * FROM denuncias WHERE protocolo = ?", (protocolo.strip().upper(),)).fetchone()
        # compara sempre, mesmo se o protocolo não existir (evita revelar existência por tempo)
        stored = row["chave_hash"] if row else hash_tracking_key("inexistente")
        ok = hmac.compare_digest(stored, hash_tracking_key(chave.strip()))
        if row is None or not ok:
            raise HTTPException(404, _INVALID_TRACKING)
        return row

    def add_movement(conn, denuncia_id, autor, visibilidade, texto, status=None):
        conn.execute(
            "INSERT INTO movimentacoes (denuncia_id, autor, visibilidade, texto_enc, status_resultante, criado_em)"
            " VALUES (?,?,?,?,?,?)",
            (denuncia_id, autor, visibilidade, crypto.encrypt(texto), status, now_iso()),
        )

    # ============================================================ PÚBLICO — denunciante
    @app.get("/api/categorias")
    def categorias():
        return CATEGORIAS

    @app.post("/api/denuncias", response_model=DenunciaCriada, status_code=201)
    def criar_denuncia(body: DenunciaIn, request: Request):
        throttle(request, "submit", settings.rate_limit_submit)
        chave = new_tracking_key()
        agora = now_iso()
        ano = datetime.now(timezone.utc).year
        identidade = (
            crypto.encrypt_json(body.identificacao.model_dump()) if body.identificacao is not None else None
        )
        with db.transaction() as conn:
            for _ in range(5):  # colisão de protocolo é improvável; tenta de novo se ocorrer
                protocolo = new_protocol(ano)
                if not conn.execute("SELECT 1 FROM denuncias WHERE protocolo = ?", (protocolo,)).fetchone():
                    break
            cur = conn.execute(
                "INSERT INTO denuncias (protocolo, chave_hash, categoria, status, anonima, descricao_enc,"
                " empresa_enc, identidade_enc, consentimento_em, criado_em, atualizado_em)"
                " VALUES (?,?,?,?,?,?,?,?,?,?,?)",
                (
                    protocolo,
                    hash_tracking_key(chave),
                    body.categoria,
                    "recebida",
                    1 if body.anonima else 0,
                    crypto.encrypt(body.descricao),
                    crypto.encrypt(body.empresa_envolvida),
                    identidade,
                    agora if identidade else None,
                    agora,
                    agora,
                ),
            )
            add_movement(conn, cur.lastrowid, "sistema", "publica", "Denúncia recebida. Aguardando triagem.", "recebida")
            audit(conn, "denunciante", "denuncia_criada", protocolo, "anonima" if body.anonima else "identificada")
        return DenunciaCriada(
            protocolo=protocolo,
            chave_acompanhamento=chave,
            aviso="Guarde o protocolo e a chave: a chave é exibida apenas agora e não pode ser recuperada.",
        )

    @app.post("/api/acompanhamento")
    def acompanhar(body: AcompanhamentoIn, request: Request):
        throttle(request, "track", settings.rate_limit_submit * 3)
        with db.connect() as conn:
            row = get_by_tracking(conn, body.protocolo, body.chave)
            movs = conn.execute(
                "SELECT autor, texto_enc, status_resultante, criado_em FROM movimentacoes"
                " WHERE denuncia_id = ? AND visibilidade = 'publica' ORDER BY id",
                (row["id"],),
            ).fetchall()
            descricao = crypto.decrypt(row["descricao_enc"])
            empresa = crypto.decrypt(row["empresa_enc"])
            result = {
                "protocolo": row["protocolo"],
                "categoria": row["categoria"],
                "status": row["status"],
                "anonima": bool(row["anonima"]),
                "identificacao_registrada": row["identidade_enc"] is not None,
                "descricao": descricao,
                "empresa_envolvida": empresa,
                "criado_em": row["criado_em"],
                "atualizado_em": row["atualizado_em"],
                "movimentacoes": [
                    {
                        "autor": m["autor"],
                        "texto": crypto.decrypt(m["texto_enc"]),
                        "status": m["status_resultante"],
                        "data": m["criado_em"],
                    }
                    for m in movs
                ],
            }
        return result

    @app.post("/api/acompanhamento/mensagem", status_code=201)
    def mensagem_do_denunciante(body: MensagemDenuncianteIn, request: Request):
        throttle(request, "track", settings.rate_limit_submit * 3)
        with db.transaction() as conn:
            row = get_by_tracking(conn, body.protocolo, body.chave)
            if row["status"] in STATUS_FINAIS:
                raise HTTPException(409, "A denúncia já foi encerrada; não aceita novas mensagens.")
            add_movement(conn, row["id"], "denunciante", "publica", body.mensagem)
            conn.execute("UPDATE denuncias SET atualizado_em = ? WHERE id = ?", (now_iso(), row["id"]))
            audit(conn, "denunciante", "mensagem_denunciante", row["protocolo"])
        return {"ok": True}

    @app.post("/api/acompanhamento/revogar-identificacao")
    def revogar_identificacao(body: AcompanhamentoIn, request: Request):
        """Direito do titular (art. 18, IX e VI): revogar o consentimento e eliminar a identificação."""
        throttle(request, "track", settings.rate_limit_submit * 3)
        with db.transaction() as conn:
            row = get_by_tracking(conn, body.protocolo, body.chave)
            if row["identidade_enc"] is None:
                raise HTTPException(409, "Não há identificação registrada nesta denúncia.")
            conn.execute(
                "UPDATE denuncias SET identidade_enc = NULL, consentimento_em = NULL, anonima = 1,"
                " atualizado_em = ? WHERE id = ?",
                (now_iso(), row["id"]),
            )
            add_movement(
                conn, row["id"], "sistema", "publica",
                "Identificação eliminada a pedido do denunciante. A denúncia segue de forma anônima.",
            )
            audit(conn, "denunciante", "identificacao_eliminada", row["protocolo"], "revogacao_consentimento")
        return {"ok": True, "mensagem": "Sua identificação foi eliminada. A denúncia continua em análise, de forma anônima."}

    # ============================================================ AUTENTICAÇÃO
    @app.post("/api/auth/login")
    def login(body: LoginIn, request: Request):
        throttle(request, "login", settings.rate_limit_login)
        email = body.email.strip().lower()
        with db.connect() as conn:
            user = conn.execute("SELECT * FROM usuarios WHERE email = ?", (email,)).fetchone()
        ok = verify_password(body.senha, user["senha_hash"] if user else _DUMMY_HASH)
        if not (user and ok and user["ativo"]):
            with db.transaction() as conn:
                audit(conn, "sistema", "login_falha", email[:100])
            raise HTTPException(401, "E-mail ou senha incorretos.")
        with db.transaction() as conn:
            audit(conn, user["email"], "login_ok")
        token = create_token(settings.jwt_secret, user["email"], user["papel"], settings.jwt_expire_minutes)
        return {"access_token": token, "token_type": "bearer", "papel": user["papel"], "nome": user["nome"]}

    @app.get("/api/auth/me")
    def me(user: dict = Depends(current_user)):
        return {"email": user["email"], "nome": user["nome"], "papel": user["papel"]}

    # ============================================================ EQUIPE — denúncias
    @app.get("/api/admin/denuncias")
    def listar(status: str | None = None, categoria: str | None = None, user: dict = Depends(current_user)):
        sql = "SELECT id, protocolo, categoria, status, anonima, criado_em, atualizado_em FROM denuncias WHERE 1=1"
        params: list = []
        if status:
            sql += " AND status = ?"
            params.append(status)
        if categoria:
            sql += " AND categoria = ?"
            params.append(categoria)
        sql += " ORDER BY id DESC LIMIT 500"
        with db.connect() as conn:
            rows = [dict(r) for r in conn.execute(sql, params).fetchall()]
        for r in rows:
            r["anonima"] = bool(r["anonima"])
        return rows

    @app.get("/api/admin/denuncias/{denuncia_id}")
    def detalhe(denuncia_id: int, user: dict = Depends(current_user)):
        with db.transaction() as conn:
            row = conn.execute("SELECT * FROM denuncias WHERE id = ?", (denuncia_id,)).fetchone()
            if row is None:
                raise HTTPException(404, "Denúncia não encontrada.")
            movs = conn.execute(
                "SELECT autor, visibilidade, texto_enc, status_resultante, criado_em FROM movimentacoes"
                " WHERE denuncia_id = ? ORDER BY id",
                (denuncia_id,),
            ).fetchall()
            audit(conn, user["email"], "leitura_denuncia", row["protocolo"])
        return {
            "id": row["id"],
            "protocolo": row["protocolo"],
            "categoria": row["categoria"],
            "status": row["status"],
            "anonima": bool(row["anonima"]),
            "identificacao_disponivel": row["identidade_enc"] is not None,
            "descricao": crypto.decrypt(row["descricao_enc"]),
            "empresa_envolvida": crypto.decrypt(row["empresa_enc"]),
            "criado_em": row["criado_em"],
            "atualizado_em": row["atualizado_em"],
            "movimentacoes": [
                {
                    "autor": m["autor"],
                    "visibilidade": m["visibilidade"],
                    "texto": crypto.decrypt(m["texto_enc"]),
                    "status": m["status_resultante"],
                    "data": m["criado_em"],
                }
                for m in movs
            ],
        }

    @app.patch("/api/admin/denuncias/{denuncia_id}/status")
    def mudar_status(denuncia_id: int, body: StatusIn, user: dict = Depends(current_user)):
        with db.transaction() as conn:
            row = conn.execute("SELECT * FROM denuncias WHERE id = ?", (denuncia_id,)).fetchone()
            if row is None:
                raise HTTPException(404, "Denúncia não encontrada.")
            agora = now_iso()
            encerrado = agora if body.status in STATUS_FINAIS else None
            conn.execute(
                "UPDATE denuncias SET status = ?, atualizado_em = ?, encerrado_em = ? WHERE id = ?",
                (body.status, agora, encerrado, denuncia_id),
            )
            texto_pub = body.mensagem_publica or f"Status atualizado para: {body.status.replace('_', ' ')}."
            add_movement(conn, denuncia_id, "equipe", "publica", texto_pub, body.status)
            if body.nota_interna:
                add_movement(conn, denuncia_id, "equipe", "interna", body.nota_interna)
            audit(conn, user["email"], "status_alterado", row["protocolo"], f"{row['status']}->{body.status}")
        return {"ok": True, "status": body.status}

    @app.post("/api/admin/denuncias/{denuncia_id}/identidade")
    def ver_identidade(denuncia_id: int, body: AcessoIdentidadeIn, user: dict = Depends(require_admin)):
        """Acesso à identidade do denunciante: só o encarregado, com motivo, sempre auditado."""
        with db.transaction() as conn:
            row = conn.execute("SELECT * FROM denuncias WHERE id = ?", (denuncia_id,)).fetchone()
            if row is None:
                raise HTTPException(404, "Denúncia não encontrada.")
            if row["identidade_enc"] is None:
                raise HTTPException(404, "Esta denúncia não possui identificação registrada.")
            audit(conn, user["email"], "acesso_identidade", row["protocolo"], f"motivo: {body.motivo}")
        return crypto.decrypt_json(row["identidade_enc"])

    # ============================================================ ENCARREGADO — administração
    @app.get("/api/admin/usuarios")
    def listar_usuarios(user: dict = Depends(require_admin)):
        with db.connect() as conn:
            rows = conn.execute("SELECT id, email, nome, papel, ativo, criado_em FROM usuarios ORDER BY id").fetchall()
        return [{**dict(r), "ativo": bool(r["ativo"])} for r in rows]

    @app.post("/api/admin/usuarios", status_code=201)
    def criar_usuario(body: UsuarioIn, user: dict = Depends(require_admin)):
        erro = validate_password_strength(body.senha)
        if erro:
            raise HTTPException(422, erro)
        try:
            with db.transaction() as conn:
                conn.execute(
                    "INSERT INTO usuarios (email, nome, senha_hash, papel, ativo, criado_em) VALUES (?,?,?,?,1,?)",
                    (body.email, body.nome, hash_password(body.senha), body.papel, now_iso()),
                )
                audit(conn, user["email"], "usuario_criado", body.email, body.papel)
        except sqlite3.IntegrityError:
            raise HTTPException(409, "Já existe um usuário com esse e-mail.")
        return {"ok": True}

    @app.patch("/api/admin/usuarios/{usuario_id}/desativar")
    def desativar_usuario(usuario_id: int, user: dict = Depends(require_admin)):
        if usuario_id == user["id"]:
            raise HTTPException(409, "Você não pode desativar o próprio usuário.")
        with db.transaction() as conn:
            row = conn.execute("SELECT email FROM usuarios WHERE id = ?", (usuario_id,)).fetchone()
            if row is None:
                raise HTTPException(404, "Usuário não encontrado.")
            conn.execute("UPDATE usuarios SET ativo = 0 WHERE id = ?", (usuario_id,))
            audit(conn, user["email"], "usuario_desativado", row["email"])
        return {"ok": True}

    @app.get("/api/admin/auditoria")
    def listar_auditoria(limite: int = 200, user: dict = Depends(require_admin)):
        limite = max(1, min(limite, 1000))
        with db.connect() as conn:
            rows = conn.execute(
                "SELECT id, ts, ator, acao, alvo, detalhe FROM auditoria ORDER BY id DESC LIMIT ?", (limite,)
            ).fetchall()
        return [dict(r) for r in rows]

    @app.get("/api/admin/auditoria/verificar")
    def verificar_auditoria(user: dict = Depends(require_admin)):
        with db.connect() as conn:
            return verify_audit_chain(conn)

    @app.post("/api/admin/retencao/executar")
    def executar_retencao(user: dict = Depends(require_admin)):
        """Elimina denúncias encerradas há mais de RETENTION_DAYS (princípio da necessidade)."""
        limite = (datetime.now(timezone.utc) - timedelta(days=settings.retention_days)).isoformat(timespec="seconds")
        with db.transaction() as conn:
            alvos = conn.execute(
                "SELECT id, protocolo FROM denuncias WHERE encerrado_em IS NOT NULL AND encerrado_em < ?", (limite,)
            ).fetchall()
            for a in alvos:
                conn.execute("DELETE FROM denuncias WHERE id = ?", (a["id"],))
                audit(conn, user["email"], "denuncia_eliminada_retencao", a["protocolo"])
            audit(conn, user["email"], "retencao_executada", None, f"{len(alvos)} eliminada(s)")
        return {"eliminadas": len(alvos), "prazo_dias": settings.retention_days}

    # ============================================================ FRONT-END
    @app.get("/", include_in_schema=False)
    def index():
        return FileResponse(STATIC_DIR / "index.html")

    if STATIC_DIR.exists():
        app.mount("/static", StaticFiles(directory=STATIC_DIR), name="static")

    @app.exception_handler(Exception)
    async def unhandled(request: Request, exc: Exception):
        # Nunca devolve detalhes internos (que poderiam conter dados pessoais).
        return JSONResponse({"detail": "Erro interno do servidor."}, status_code=500)

    return app


def _bootstrap_admin(db: Database, settings: Settings) -> None:
    """Cria o primeiro administrador a partir de ADMIN_EMAIL / ADMIN_PASSWORD (se não houver usuários)."""
    with db.connect() as conn:
        total = conn.execute("SELECT COUNT(*) AS n FROM usuarios").fetchone()["n"]
    if total or not (settings.admin_email and settings.admin_password):
        return
    erro = validate_password_strength(settings.admin_password)
    if erro:
        raise RuntimeError(f"ADMIN_PASSWORD fraca: {erro}")
    with db.transaction() as conn:
        conn.execute(
            "INSERT INTO usuarios (email, nome, senha_hash, papel, ativo, criado_em) VALUES (?,?,?,?,1,?)",
            (settings.admin_email.strip().lower(), "Encarregado (DPO)", hash_password(settings.admin_password), "admin", now_iso()),
        )
        audit(conn, "sistema", "admin_inicial_criado", settings.admin_email)


app = create_app()
