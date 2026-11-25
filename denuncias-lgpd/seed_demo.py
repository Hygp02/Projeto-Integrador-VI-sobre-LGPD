"""Carrega dados de demonstração (só se o banco estiver vazio).

Cria: 1 admin (encarregado), 1 analista e 3 denúncias em estados diferentes.
Os acessos de demonstração são impressos no final.
"""
import os
import sys

os.environ.setdefault("ADMIN_EMAIL", "dpo@empresa.com")
os.environ.setdefault("ADMIN_PASSWORD", "SenhaForte123")

from fastapi.testclient import TestClient

from app.config import Settings
from app.main import create_app

settings = Settings()
app = create_app(settings)
client = TestClient(app)

with app.state.db.connect() as conn:
    if conn.execute("SELECT COUNT(*) FROM denuncias").fetchone()[0] > 0:
        print("Banco já possui denúncias; dados de demonstração não foram recriados.")
        sys.exit(0)

tok = client.post("/api/auth/login", json={"email": os.environ["ADMIN_EMAIL"], "senha": os.environ["ADMIN_PASSWORD"]})
if tok.status_code != 200:
    print("Admin não encontrado com essas credenciais; pulando demonstração.")
    sys.exit(0)
H = {"Authorization": "Bearer " + tok.json()["access_token"]}
client.post("/api/admin/usuarios", headers=H, json={
    "email": "analista@empresa.com", "nome": "Ana Analista", "senha": "Analista123456", "papel": "analista"})

d1 = client.post("/api/denuncias", json={
    "categoria": "vazamento_de_dados", "anonima": True, "empresa_envolvida": "ACME Ltda - Comercial",
    "descricao": "Planilha com dados de clientes foi enviada por e-mail para um endereço externo."}).json()
d2 = client.post("/api/denuncias", json={
    "categoria": "acesso_indevido", "anonima": False, "consentimento": True,
    "identificacao": {"nome": "Joana Souza", "email": "joana@empresa.com", "vinculo": "colaborador"},
    "descricao": "Um colega acessou prontuários de clientes sem necessidade para o seu cargo."}).json()
client.post("/api/denuncias", json={
    "categoria": "ma_pratica_seguranca", "anonima": True,
    "descricao": "Senhas de sistemas internos estão escritas em post-its na recepção do escritório."})

lista = client.get("/api/admin/denuncias", headers=H).json()
por_proto = {r["protocolo"]: r["id"] for r in lista}
client.patch(f"/api/admin/denuncias/{por_proto[d1['protocolo']]}/status", headers=H, json={
    "status": "em_analise", "mensagem_publica": "Recebemos sua denúncia e estamos apurando.",
    "nota_interna": "E-mail saiu da conta do comercial. Acionar a TI."})

print("\n=== DADOS DE DEMONSTRAÇÃO CRIADOS ===")
print("Equipe (admin / encarregado): dpo@empresa.com  /  SenhaForte123")
print("Equipe (analista):            analista@empresa.com  /  Analista123456")
print("Acompanhar denúncia de exemplo:")
print("   Protocolo:", d1["protocolo"])
print("   Chave:    ", d1["chave_acompanhamento"])
