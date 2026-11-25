# Sistema de Denúncias de Vazamento de Dados

**Projeto Integrador VI — B · 2026.2** (Direito e ética na computação + Programação Backend)

Canal seguro e confidencial para que colaboradores, parceiros e terceiros relatem vazamentos de dados,
práticas inadequadas de segurança ou atividades suspeitas. O sistema trata dados sensíveis, então **ele próprio
foi construído para cumprir a LGPD** (Lei nº 13.709/2018).

> **Da norma ao código:** cada exigência da lei virou um requisito e cada requisito virou uma decisão de código.
> A tabela "Mapa LGPD → código" abaixo mostra onde.

---

## Início rápido (para quem vai avaliar)

Requisito: **Python 3.10+** instalado ([python.org](https://www.python.org/downloads/); no Windows, marque *Add Python to PATH*).

1. Extraia o `.zip`.
2. **Windows:** dê duplo clique em `iniciar.bat`. **Linux/macOS:** no terminal, `./iniciar.sh`.
3. Aguarde a instalação (só na 1ª vez). O navegador abre em **http://localhost:8000** (se não abrir, digite o endereço).
4. Use os acessos de demonstração:

| Perfil | Onde | Login |
|---|---|---|
| Encarregado (admin) | aba **Equipe** | `dpo@empresa.com` / `SenhaForte123` |
| Analista | aba **Equipe** | `analista@empresa.com` / `Analista123456` |
| Denunciante | aba **Acompanhar** | protocolo e chave impressos na janela do terminal ao iniciar |

5. Para encerrar, feche a janela do terminal (ou `Ctrl+C`).

Os dados de exemplo (3 denúncias) são criados automaticamente na primeira execução.

---

## Como rodar manualmente

Requisitos: Python 3.10+.

```bash
pip install -r requirements.txt

# 1) Primeiro administrador (encarregado/DPO). A senha precisa ter 10+ caracteres, maiúscula, minúscula e número.
export ADMIN_EMAIL="dpo@empresa.com"
export ADMIN_PASSWORD="SenhaForte123"        # Windows (PowerShell): $env:ADMIN_EMAIL="..."

# 2) Subir o servidor
uvicorn app.main:app --reload
```

Abra **http://localhost:8000** (interface) ou **http://localhost:8000/docs** (documentação interativa da API).

- Na primeira execução, as chaves de criptografia e do JWT são geradas em `.secrets/` (ignorada pelo git).
  Em produção, defina `APP_ENCRYPTION_KEY` e `APP_JWT_SECRET` como variáveis de ambiente.
- Criar mais usuários pela linha de comando: `python -m app.cli criar-usuario --email ana@empresa.com --nome "Ana" --papel analista`
- Testes: `python -m pytest -q` (18 testes).

### Variáveis de ambiente

| Variável | Padrão | Função |
|---|---|---|
| `DB_PATH` | `denuncias.db` | Arquivo SQLite |
| `APP_ENCRYPTION_KEY` | gerada em `.secrets/` | Chave Fernet (criptografia em repouso) |
| `APP_JWT_SECRET` | gerada em `.secrets/` | Segredo do token de login |
| `JWT_EXPIRE_MINUTES` | 60 | Validade do login da equipe |
| `RETENTION_DAYS` | 365 | Prazo de retenção de denúncias encerradas |
| `ADMIN_EMAIL` / `ADMIN_PASSWORD` | — | Cria o 1º admin se não houver usuários |

> **Atenção:** se a chave de criptografia for perdida, os dados já gravados não podem ser recuperados.

---

## Como funciona

**Quem usa**

| Perfil | Acesso |
|---|---|
| **Denunciante** (sem conta) | Envia a denúncia (anônima ou identificada), acompanha com *protocolo + chave*, envia informações adicionais e pode eliminar a própria identificação. |
| **Analista** | Vê e trata as denúncias (descrição, histórico, status). **Não** vê a identidade do denunciante. |
| **Admin / Encarregado (DPO)** | Tudo do analista + identidade do denunciante (com motivo obrigatório), usuários, auditoria e retenção. |

**Fluxo de uma denúncia:** `recebida → em_analise → procedente / improcedente → encerrada`.
A equipe escreve mensagens **públicas** (o denunciante vê) e **notas internas** (só a equipe vê).

### Endpoints principais

| Método e rota | Quem | O que faz |
|---|---|---|
| `POST /api/denuncias` | público | Registra denúncia; devolve protocolo + chave (exibida 1 vez) |
| `POST /api/acompanhamento` | protocolo + chave | Consulta status, texto e andamento públicos |
| `POST /api/acompanhamento/mensagem` | protocolo + chave | Denunciante complementa a denúncia |
| `POST /api/acompanhamento/revogar-identificacao` | protocolo + chave | Revoga consentimento e elimina a identificação |
| `POST /api/auth/login` | equipe | Login (JWT) |
| `GET /api/admin/denuncias` · `GET /api/admin/denuncias/{id}` | equipe | Lista / detalhe (leitura auditada) |
| `PATCH /api/admin/denuncias/{id}/status` | equipe | Muda status, mensagem pública e nota interna |
| `POST /api/admin/denuncias/{id}/identidade` | **admin** | Revela identidade (exige motivo; auditado) |
| `GET/POST /api/admin/usuarios` · `PATCH .../desativar` | **admin** | Gestão da equipe |
| `GET /api/admin/auditoria` · `/verificar` | **admin** | Trilha de auditoria e verificação de integridade |
| `POST /api/admin/retencao/executar` | **admin** | Elimina denúncias encerradas além do prazo |

---

## Mapa LGPD → código

| Exigência (LGPD / ética) | Decisão de projeto | Onde está |
|---|---|---|
| **Segurança** (art. 6º, VII; art. 46) — proteger contra acesso indevido e vazamento | Descrição, empresa, identidade e mensagens são gravadas **criptografadas** (Fernet: AES + HMAC). Um teste confirma que o texto não aparece no arquivo do banco. | `app/security.py` (`Crypto`), `tests/test_api.py::test_dados_criptografados_em_repouso` |
| **Segurança** — controle de acesso | Login com JWT, senhas com *scrypt* + sal, política de senha forte, 2 papéis (RBAC), usuário desativado perde acesso na hora. | `app/main.py` (`current_user`, `require_admin`), `app/security.py` |
| **Necessidade / minimização** (art. 6º, III) | Denúncia **anônima não coleta identificação** (a API rejeita se vier). IP **não é gravado**. Auditoria **não guarda dados pessoais**. | `app/schemas.py` (`DenunciaIn._regras_lgpd`), `app/database.py` (`audit`) |
| **Finalidade** (art. 6º, I) | Identificação só serve para apurar a denúncia; acessar a identidade exige **motivo** registrado. | `ver_identidade` em `app/main.py` |
| **Consentimento** (art. 7º, I; art. 8º) | Denúncia identificada **só é aceita com consentimento explícito**, com data registrada (`consentimento_em`). | `app/schemas.py`, tabela `denuncias` |
| **Direitos do titular** (art. 18) — acesso, eliminação, revogação | O denunciante consulta tudo que enviou (livre acesso) e pode **eliminar a própria identificação** a qualquer momento. | `acompanhar`, `revogar_identificacao` |
| **Transparência** (art. 6º, VI) | O denunciante vê o andamento e as respostas da equipe; a tela explica o uso dos dados. | `static/index.html`, `movimentacoes` |
| **Responsabilização e prestação de contas** (art. 6º, X) | **Trilha de auditoria encadeada por hash** (como um blockchain simples): quem leu, alterou ou revelou o quê. Qualquer adulteração é detectada. | `app/database.py` (`audit`, `verify_audit_chain`), `test_trilha_de_auditoria_detecta_adulteracao` |
| **Término do tratamento** (art. 15 e 16) | **Política de retenção**: denúncias encerradas há mais de `RETENTION_DAYS` são eliminadas. | `executar_retencao` |
| **Proteção do denunciante** (ética: quem relata mais arrisca) | Chave de acompanhamento de alta entropia (guardada só como hash); protocolo **aleatório** (não dá para enumerar); resposta idêntica para "protocolo inexistente" e "chave errada"; notas internas nunca vazam; rate limit contra tentativa e erro. | `app/security.py`, `get_by_tracking` |
| **Boas práticas web** | Cabeçalhos CSP, `X-Frame-Options`, `nosniff`, `Cache-Control: no-store`; front sem `innerHTML` (sem XSS); erros 500 sem detalhes. | `security_headers` em `app/main.py`, `static/app.js` |

### Limitações conhecidas (e como evoluir)

Honestidade técnica também é ética profissional. Para um uso real, ainda faltaria:

- **HTTPS** (colocar atrás de um proxy reverso com TLS) — o projeto sobe em HTTP para desenvolvimento.
- **Anonimato de rede**: o servidor não grava IP, mas proxies/logs de infraestrutura podem gravar. Para anonimato forte, usar um canal acessível via Tor ou rede interna.
- **SQLite → PostgreSQL** e **chaves em um cofre** (KMS/Vault) com rotação.
- **Notificação** à ANPD/titulares em incidentes confirmados (art. 48) é um processo da empresa; o sistema registra, mas não envia.
- **Rate limit em memória** (por processo); em produção usar Redis.
- **Texto livre**: o denunciante pode digitar dados pessoais de terceiros no relato; por isso o texto é criptografado e a tela orienta a descrever o fato, não os dados.

---

## Estrutura

```
app/
  main.py       API (rotas, autenticação, regras de negócio)
  schemas.py    validação de entrada (regras LGPD nos modelos)
  security.py   criptografia, senhas, JWT, chave do denunciante, rate limit
  database.py   SQLite, transações e auditoria encadeada
  config.py     configuração e segredos
  cli.py        criação de usuários pela linha de comando
static/         front-end (HTML, CSS, JS sem dependências)
tests/          18 testes automatizados
```

## Roteiro rápido para a apresentação (demo de ~5 min)

1. **Problema:** vazamentos precisam ser relatados com segurança — e quem relata corre risco.
2. **Da norma ao código:** mostrar a tabela "Mapa LGPD → código".
3. **Demo:** (a) enviar denúncia anônima e guardar protocolo/chave; (b) entrar como analista, mudar status com mensagem pública e nota interna; (c) voltar em *Acompanhar* e mostrar que a nota interna **não** aparece; (d) como admin, revelar identidade de uma denúncia identificada (pede motivo) e abrir a **Auditoria**; (e) clicar em *Verificar integridade*.
4. **Prova técnica:** abrir o `.db` e mostrar que o conteúdo está ilegível (criptografado).
5. **Limitações e evolução** (seção acima).
