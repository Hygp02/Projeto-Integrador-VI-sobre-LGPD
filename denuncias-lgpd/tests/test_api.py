import sqlite3
from datetime import datetime, timedelta, timezone

from tests.conftest import ADMIN, login

DESCRICAO = "Planilha com CPF de clientes foi enviada por e-mail para um endereço externo."
BASE = {"categoria": "vazamento_de_dados", "descricao": DESCRICAO, "anonima": True}


def criar(client, **extra):
    r = client.post("/api/denuncias", json={**BASE, **extra})
    assert r.status_code == 201, r.text
    return r.json()


def acompanhar(client, d):
    return client.post("/api/acompanhamento", json={"protocolo": d["protocolo"], "chave": d["chave_acompanhamento"]})


IDENT = {"nome": "Joana Souza", "email": "joana@empresa.com", "vinculo": "colaborador"}


# ------------------------------------------------------------------ denunciante
def test_denuncia_anonima_e_acompanhamento(ctx):
    client, *_ = ctx
    d = criar(client, empresa_envolvida="ACME")
    assert d["protocolo"].startswith("DEN-")
    r = acompanhar(client, d)
    assert r.status_code == 200
    body = r.json()
    assert body["status"] == "recebida"
    assert body["anonima"] is True and body["identificacao_registrada"] is False
    assert body["descricao"] == DESCRICAO and body["empresa_envolvida"] == "ACME"


def test_dados_criptografados_em_repouso(ctx):
    client, settings, _ = ctx
    criar(client, empresa_envolvida="EmpresaSecreta", anonima=False, identificacao=IDENT, consentimento=True)
    raw = open(settings.db_path, "rb").read()
    for segredo in (b"CPF de clientes", b"EmpresaSecreta", b"Joana Souza", b"joana@empresa.com"):
        assert segredo not in raw


def test_anonima_nao_armazena_identidade(ctx):
    client, settings, _ = ctx
    criar(client)
    conn = sqlite3.connect(settings.db_path)
    (ident,) = conn.execute("SELECT identidade_enc FROM denuncias").fetchone()
    assert ident is None


def test_regras_lgpd_de_identificacao(ctx):
    client, *_ = ctx
    # anônima + identificação => rejeita (minimização)
    r = client.post("/api/denuncias", json={**BASE, "identificacao": IDENT})
    assert r.status_code == 422
    # identificada sem consentimento => rejeita
    r = client.post("/api/denuncias", json={**BASE, "anonima": False, "identificacao": IDENT})
    assert r.status_code == 422
    # identificada sem dados => rejeita
    r = client.post("/api/denuncias", json={**BASE, "anonima": False, "consentimento": True})
    assert r.status_code == 422
    # identificada com consentimento => ok
    r = client.post("/api/denuncias", json={**BASE, "anonima": False, "identificacao": IDENT, "consentimento": True})
    assert r.status_code == 201


def test_chave_errada_e_protocolo_inexistente_dao_mesma_resposta(ctx):
    client, *_ = ctx
    d = criar(client)
    r1 = client.post("/api/acompanhamento", json={"protocolo": d["protocolo"], "chave": "chave-errada-123456"})
    r2 = client.post("/api/acompanhamento", json={"protocolo": "DEN-2026-XXXXXXXX", "chave": "chave-errada-123456"})
    assert r1.status_code == r2.status_code == 404
    assert r1.json() == r2.json()


def test_validacao_de_entrada(ctx):
    client, *_ = ctx
    assert client.post("/api/denuncias", json={**BASE, "descricao": "curta"}).status_code == 422
    assert client.post("/api/denuncias", json={**BASE, "categoria": "invalida"}).status_code == 422


def test_revogar_identificacao(ctx, admin_h):
    client, settings, _ = ctx
    d = criar(client, anonima=False, identificacao=IDENT, consentimento=True)
    body = {"protocolo": d["protocolo"], "chave": d["chave_acompanhamento"]}
    assert acompanhar(client, d).json()["identificacao_registrada"] is True
    assert client.post("/api/acompanhamento/revogar-identificacao", json=body).status_code == 200
    again = acompanhar(client, d).json()
    assert again["identificacao_registrada"] is False and again["anonima"] is True
    # segunda revogação: nada a eliminar
    assert client.post("/api/acompanhamento/revogar-identificacao", json=body).status_code == 409
    conn = sqlite3.connect(settings.db_path)
    assert conn.execute("SELECT identidade_enc FROM denuncias").fetchone()[0] is None


# ------------------------------------------------------------------ equipe
def test_endpoints_da_equipe_exigem_login(ctx):
    client, *_ = ctx
    assert client.get("/api/admin/denuncias").status_code == 401
    assert client.get("/api/admin/denuncias/1").status_code == 401
    assert client.get("/api/admin/auditoria").status_code == 401


def test_fluxo_de_tratamento_e_visibilidade(ctx, analista_h):
    client, *_ = ctx
    d = criar(client)
    lista = client.get("/api/admin/denuncias", headers=analista_h).json()
    assert len(lista) == 1 and "descricao" not in lista[0]
    det = client.get(f"/api/admin/denuncias/{lista[0]['id']}", headers=analista_h).json()
    assert det["descricao"] == DESCRICAO

    r = client.patch(
        f"/api/admin/denuncias/{det['id']}/status",
        headers=analista_h,
        json={"status": "em_analise", "mensagem_publica": "Estamos apurando.", "nota_interna": "Suspeito: TI"},
    )
    assert r.status_code == 200
    # equipe vê a nota interna…
    interno = client.get(f"/api/admin/denuncias/{det['id']}", headers=analista_h).json()
    assert any(m["visibilidade"] == "interna" for m in interno["movimentacoes"])
    # …o denunciante NÃO
    pub = acompanhar(client, d).json()
    assert pub["status"] == "em_analise"
    textos = " ".join(m["texto"] for m in pub["movimentacoes"])
    assert "Estamos apurando." in textos and "Suspeito" not in textos


def test_analista_nao_acessa_identidade_nem_admin(ctx, analista_h, admin_h):
    client, *_ = ctx
    criar(client, anonima=False, identificacao=IDENT, consentimento=True)
    did = client.get("/api/admin/denuncias", headers=analista_h).json()[0]["id"]
    detalhe = client.get(f"/api/admin/denuncias/{did}", headers=analista_h).json()
    assert detalhe["identificacao_disponivel"] is True and "Joana" not in str(detalhe)

    motivo = {"motivo": "Necessário para contatar o denunciante."}
    assert client.post(f"/api/admin/denuncias/{did}/identidade", headers=analista_h, json=motivo).status_code == 403
    assert client.get("/api/admin/usuarios", headers=analista_h).status_code == 403
    assert client.get("/api/admin/auditoria", headers=analista_h).status_code == 403

    ok = client.post(f"/api/admin/denuncias/{did}/identidade", headers=admin_h, json=motivo)
    assert ok.status_code == 200 and ok.json()["nome"] == "Joana Souza"
    # motivo é obrigatório
    assert client.post(f"/api/admin/denuncias/{did}/identidade", headers=admin_h, json={"motivo": "x"}).status_code == 422
    # acesso ficou registrado
    acoes = [a["acao"] for a in client.get("/api/admin/auditoria", headers=admin_h).json()]
    assert "acesso_identidade" in acoes


def test_mensagem_do_denunciante_e_encerramento(ctx, admin_h):
    client, *_ = ctx
    d = criar(client)
    msg = {"protocolo": d["protocolo"], "chave": d["chave_acompanhamento"], "mensagem": "Tenho mais um detalhe."}
    assert client.post("/api/acompanhamento/mensagem", json=msg).status_code == 201
    did = client.get("/api/admin/denuncias", headers=admin_h).json()[0]["id"]
    client.patch(f"/api/admin/denuncias/{did}/status", headers=admin_h, json={"status": "encerrada"})
    assert client.post("/api/acompanhamento/mensagem", json=msg).status_code == 409


# ------------------------------------------------------------------ auditoria / retenção / segurança
def test_trilha_de_auditoria_detecta_adulteracao(ctx, admin_h):
    client, settings, _ = ctx
    criar(client)
    did = client.get("/api/admin/denuncias", headers=admin_h).json()[0]["id"]
    client.get(f"/api/admin/denuncias/{did}", headers=admin_h)
    ok = client.get("/api/admin/auditoria/verificar", headers=admin_h).json()
    assert ok["integra"] is True and ok["registros"] >= 3

    conn = sqlite3.connect(settings.db_path)
    conn.execute("UPDATE auditoria SET ator = 'fantasma' WHERE id = 2")
    conn.commit()
    ruim = client.get("/api/admin/auditoria/verificar", headers=admin_h).json()
    assert ruim["integra"] is False and ruim["primeira_falha_id"] == 2


def test_auditoria_nao_grava_dados_pessoais(ctx, admin_h):
    client, *_ = ctx
    criar(client, anonima=False, identificacao=IDENT, consentimento=True)
    log = str(client.get("/api/admin/auditoria", headers=admin_h).json())
    assert "Joana" not in log and "joana@" not in log and "CPF" not in log


def test_retencao_elimina_somente_encerradas_antigas(ctx, admin_h):
    client, settings, _ = ctx
    velha, recente, aberta = criar(client), criar(client), criar(client)
    ids = {r["protocolo"]: r["id"] for r in client.get("/api/admin/denuncias", headers=admin_h).json()}
    for d in (velha, recente):
        client.patch(f"/api/admin/denuncias/{ids[d['protocolo']]}/status", headers=admin_h, json={"status": "encerrada"})
    antigo = (datetime.now(timezone.utc) - timedelta(days=settings.retention_days + 10)).isoformat(timespec="seconds")
    conn = sqlite3.connect(settings.db_path)
    conn.execute("UPDATE denuncias SET encerrado_em = ? WHERE protocolo = ?", (antigo, velha["protocolo"]))
    conn.commit()

    r = client.post("/api/admin/retencao/executar", headers=admin_h).json()
    assert r["eliminadas"] == 1
    assert acompanhar(client, velha).status_code == 404
    assert acompanhar(client, recente).status_code == 200
    assert acompanhar(client, aberta).status_code == 200


def test_login_rate_limit_e_mensagem_generica(ctx):
    client, *_ = ctx
    codigos = [
        client.post("/api/auth/login", json={"email": ADMIN[0], "senha": "errada"}).status_code for _ in range(7)
    ]
    assert codigos[:5] == [401] * 5 and codigos[5:] == [429, 429]


def test_senha_fraca_rejeitada_e_token_invalido(ctx, admin_h):
    client, *_ = ctx
    r = client.post("/api/admin/usuarios", headers=admin_h, json={"email": "a@b.com", "nome": "Fulano", "senha": "fraca"})
    assert r.status_code == 422
    assert client.get("/api/auth/me", headers={"Authorization": "Bearer lixo"}).status_code == 401
    assert client.get("/api/auth/me", headers=admin_h).json()["papel"] == "admin"


def test_usuario_desativado_perde_acesso(ctx, admin_h, analista_h):
    client, *_ = ctx
    uid = [u["id"] for u in client.get("/api/admin/usuarios", headers=admin_h).json() if u["papel"] == "analista"][0]
    assert client.patch(f"/api/admin/usuarios/{uid}/desativar", headers=admin_h).status_code == 200
    assert client.get("/api/auth/me", headers=analista_h).status_code == 401


def test_cabecalhos_de_seguranca(ctx):
    client, *_ = ctx
    r = client.get("/api/categorias")
    assert r.headers["x-content-type-options"] == "nosniff"
    assert r.headers["cache-control"] == "no-store"
    assert "default-src 'self'" in r.headers["content-security-policy"]
