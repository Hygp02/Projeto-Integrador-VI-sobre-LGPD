"use strict";
// Front-end sem dependências. Todo texto vindo da API é inserido com textContent (sem innerHTML) => sem XSS.
// O token da equipe fica só em memória (some ao recarregar a página).

const $ = (id) => document.getElementById(id);
const STATUS_LABEL = { recebida: "Recebida", em_analise: "Em análise", procedente: "Procedente", improcedente: "Improcedente", encerrada: "Encerrada" };
const AUTOR_LABEL = { sistema: "Sistema", equipe: "Equipe", denunciante: "Você" };
let token = null, papel = null, track = null, detalheId = null;

function el(tag, props = {}, ...kids) {
  const n = document.createElement(tag);
  for (const [k, v] of Object.entries(props)) {
    if (k === "class") n.className = v; else if (k === "text") n.textContent = v; else n.setAttribute(k, v);
  }
  kids.forEach((c) => n.append(c));
  return n;
}
const fmt = (iso) => new Date(iso).toLocaleString("pt-BR", { dateStyle: "short", timeStyle: "short" });

async function api(path, { method = "GET", body, auth = false } = {}) {
  const headers = {};
  if (body) headers["Content-Type"] = "application/json";
  if (auth && token) headers["Authorization"] = "Bearer " + token;
  const res = await fetch(path, { method, headers, body: body ? JSON.stringify(body) : undefined });
  let data = null;
  try { data = await res.json(); } catch (_) { /* sem corpo */ }
  if (!res.ok) {
    let msg = (data && data.detail) || "Erro inesperado.";
    if (Array.isArray(msg)) msg = msg.map((e) => (e.msg || "").replace(/^Value error, /, "")).join(" ");
    if (res.status === 401 && auth) logout();
    throw new Error(msg);
  }
  return data;
}

// ---------------------------------------------------------------- abas
function showTab(name) {
  document.querySelectorAll("#nav button").forEach((b) => b.classList.toggle("ativo", b.dataset.tab === name));
  document.querySelectorAll(".aba").forEach((s) => (s.hidden = s.id !== "tab-" + name));
}
$("nav").addEventListener("click", (e) => e.target.dataset.tab && showTab(e.target.dataset.tab));

// ---------------------------------------------------------------- denunciar
api("/api/categorias").then((c) => {
  Object.entries(c).forEach(([k, v]) => $("d-categoria").append(el("option", { value: k, text: v })));
});
document.querySelectorAll("input[name=anon]").forEach((r) =>
  r.addEventListener("change", () => ($("bloco-ident").hidden = document.querySelector("input[name=anon]:checked").value === "1"))
);

$("form-denuncia").addEventListener("submit", async (e) => {
  e.preventDefault();
  $("d-erro").textContent = "";
  const anonima = document.querySelector("input[name=anon]:checked").value === "1";
  const body = {
    categoria: $("d-categoria").value,
    descricao: $("d-descricao").value.trim(),
    empresa_envolvida: $("d-empresa").value.trim() || null,
    anonima,
    consentimento: !anonima && $("d-consent").checked,
    identificacao: anonima ? null : { nome: $("d-nome").value.trim(), email: $("d-email").value.trim(), vinculo: $("d-vinculo").value },
  };
  try {
    const r = await api("/api/denuncias", { method: "POST", body });
    $("s-protocolo").textContent = r.protocolo;
    $("s-chave").textContent = r.chave_acompanhamento;
    $("form-denuncia").hidden = true;
    $("d-sucesso").hidden = false;
    $("form-denuncia").reset();
  } catch (err) { $("d-erro").textContent = err.message; }
});
$("s-copiar").addEventListener("click", async () => {
  const txt = `Protocolo: ${$("s-protocolo").textContent}\nChave: ${$("s-chave").textContent}`;
  try { await navigator.clipboard.writeText(txt); $("s-copiar").textContent = "Copiado!"; } catch (_) { $("s-copiar").textContent = "Selecione e copie manualmente"; }
});

// ---------------------------------------------------------------- acompanhar
function renderTimeline(ol, movs, mostrarVisibilidade) {
  ol.replaceChildren();
  movs.forEach((m) => {
    const autor = mostrarVisibilidade ? (m.autor[0].toUpperCase() + m.autor.slice(1)) : AUTOR_LABEL[m.autor];
    const tag = mostrarVisibilidade && m.visibilidade === "interna" ? " · nota interna" : "";
    const li = el("li", { class: mostrarVisibilidade && m.visibilidade === "interna" ? "interna" : "" },
      el("div", { class: "quando", text: `${fmt(m.data)} · ${autor}${tag}` }),
      el("div", { text: m.texto }));
    ol.append(li);
  });
}
function setSelo(node, status) { node.textContent = STATUS_LABEL[status] || status; node.className = "selo " + status; }

async function consultar() {
  const r = await api("/api/acompanhamento", { method: "POST", body: track });
  $("r-protocolo").textContent = r.protocolo;
  setSelo($("r-status"), r.status);
  $("r-meta").textContent = `Aberta em ${fmt(r.criado_em)} · ${r.anonima ? "Anônima" : "Identificada"}`;
  $("r-descricao").textContent = r.descricao;
  renderTimeline($("r-timeline"), r.movimentacoes, false);
  $("r-revogar-bloco").hidden = !r.identificacao_registrada;
  $("r-msg-bloco").hidden = r.status === "improcedente" || r.status === "encerrada";
  $("a-resultado").hidden = false;
}
$("form-acomp").addEventListener("submit", async (e) => {
  e.preventDefault();
  $("a-erro").textContent = "";
  track = { protocolo: $("a-protocolo").value.trim(), chave: $("a-chave").value.trim() };
  try { await consultar(); } catch (err) { $("a-resultado").hidden = true; $("a-erro").textContent = err.message; }
});
$("r-enviar").addEventListener("click", async () => {
  const mensagem = $("r-msg").value.trim();
  if (mensagem.length < 3) return;
  try { await api("/api/acompanhamento/mensagem", { method: "POST", body: { ...track, mensagem } }); $("r-msg").value = ""; await consultar(); }
  catch (err) { $("a-erro").textContent = err.message; }
});
$("r-revogar").addEventListener("click", async () => {
  if (!confirm("Eliminar sua identificação? Esta ação não pode ser desfeita.")) return;
  try { await api("/api/acompanhamento/revogar-identificacao", { method: "POST", body: track }); await consultar(); }
  catch (err) { $("a-erro").textContent = err.message; }
});

// ---------------------------------------------------------------- equipe: login
function logout() {
  token = papel = null; detalheId = null;
  $("painel-bloco").hidden = true; $("login-bloco").hidden = false;
}
$("form-login").addEventListener("submit", async (e) => {
  e.preventDefault();
  $("l-erro").textContent = "";
  try {
    const r = await api("/api/auth/login", { method: "POST", body: { email: $("l-email").value, senha: $("l-senha").value } });
    token = r.access_token; papel = r.papel;
    $("l-senha").value = "";
    $("p-usuario").textContent = `${r.nome} (${r.papel})`;
    document.querySelectorAll(".so-admin").forEach((n) => (n.hidden = papel !== "admin"));
    $("login-bloco").hidden = true; $("painel-bloco").hidden = false;
    showSub("denuncias");
  } catch (err) { $("l-erro").textContent = err.message; }
});
$("p-sair").addEventListener("click", logout);

function showSub(name) {
  document.querySelectorAll("#subnav button").forEach((b) => b.classList.toggle("ativo", b.dataset.sub === name));
  ["denuncias", "usuarios", "auditoria"].forEach((s) => ($("sub-" + s).hidden = s !== name));
  if (name === "denuncias") carregarDenuncias();
  if (name === "usuarios") carregarUsuarios();
  if (name === "auditoria") carregarAuditoria();
}
$("subnav").addEventListener("click", (e) => e.target.dataset.sub && showSub(e.target.dataset.sub));

// ---------------------------------------------------------------- equipe: denúncias
async function carregarDenuncias() {
  const st = $("f-status").value;
  const rows = await api("/api/admin/denuncias" + (st ? "?status=" + encodeURIComponent(st) : ""), { auth: true });
  const tb = $("t-denuncias").tBodies[0];
  tb.replaceChildren();
  rows.forEach((r) => {
    const tr = el("tr", { class: "clicavel" },
      el("td", { text: r.protocolo }), el("td", { text: r.categoria.replaceAll("_", " ") }),
      el("td", { text: STATUS_LABEL[r.status] }), el("td", { text: r.anonima ? "Sim" : "Não" }), el("td", { text: fmt(r.atualizado_em) }));
    tr.addEventListener("click", () => abrirDetalhe(r.id));
    tb.append(tr);
  });
  if (!rows.length) tb.append(el("tr", {}, el("td", { colspan: "5", text: "Nenhuma denúncia." })));
}
$("f-status").addEventListener("change", carregarDenuncias);

async function abrirDetalhe(id) {
  $("x-erro").textContent = "";
  const d = await api("/api/admin/denuncias/" + id, { auth: true });
  detalheId = id;
  $("x-protocolo").textContent = d.protocolo;
  setSelo($("x-status"), d.status);
  $("x-meta").textContent = `${d.categoria.replaceAll("_", " ")} · ${d.anonima ? "Anônima" : "Identificada"} · aberta em ${fmt(d.criado_em)}` + (d.empresa_envolvida ? ` · Empresa: ${d.empresa_envolvida}` : "");
  $("x-descricao").textContent = d.descricao;
  renderTimeline($("x-timeline"), d.movimentacoes, true);
  $("x-novo-status").value = d.status === "recebida" ? "em_analise" : d.status;
  $("x-pub").value = ""; $("x-int").value = ""; $("x-motivo").value = "";
  $("x-ident").hidden = true; $("x-ident").textContent = "";
  $("x-ident-bloco").hidden = !(papel === "admin" && d.identificacao_disponivel);
  $("detalhe").hidden = false;
  $("detalhe").scrollIntoView({ behavior: "smooth" });
}
$("x-salvar").addEventListener("click", async () => {
  $("x-erro").textContent = "";
  try {
    await api(`/api/admin/denuncias/${detalheId}/status`, { method: "PATCH", auth: true, body: {
      status: $("x-novo-status").value, mensagem_publica: $("x-pub").value.trim() || null, nota_interna: $("x-int").value.trim() || null } });
    await abrirDetalhe(detalheId); await carregarDenuncias();
  } catch (err) { $("x-erro").textContent = err.message; }
});
$("x-ver-ident").addEventListener("click", async () => {
  $("x-erro").textContent = "";
  try {
    const i = await api(`/api/admin/denuncias/${detalheId}/identidade`, { method: "POST", auth: true, body: { motivo: $("x-motivo").value.trim() } });
    $("x-ident").textContent = `Nome: ${i.nome}\nE-mail: ${i.email}\nVínculo: ${i.vinculo}`;
    $("x-ident").hidden = false;
  } catch (err) { $("x-erro").textContent = err.message; }
});

// ---------------------------------------------------------------- admin: usuários e auditoria
async function carregarUsuarios() {
  const rows = await api("/api/admin/usuarios", { auth: true });
  const tb = $("t-usuarios").tBodies[0];
  tb.replaceChildren();
  rows.forEach((u) => {
    const btn = u.ativo ? el("button", { class: "perigo", text: "Desativar" }) : el("span", { text: "—" });
    if (u.ativo) btn.addEventListener("click", async () => {
      try { await api(`/api/admin/usuarios/${u.id}/desativar`, { method: "PATCH", auth: true }); carregarUsuarios(); }
      catch (err) { $("u-erro").textContent = err.message; }
    });
    tb.append(el("tr", {}, el("td", { text: u.nome }), el("td", { text: u.email }), el("td", { text: u.papel }), el("td", { text: u.ativo ? "Sim" : "Não" }), el("td", {}, btn)));
  });
}
$("form-usuario").addEventListener("submit", async (e) => {
  e.preventDefault(); $("u-erro").textContent = "";
  try {
    await api("/api/admin/usuarios", { method: "POST", auth: true, body: { nome: $("u-nome").value, email: $("u-email").value, senha: $("u-senha").value, papel: $("u-papel").value } });
    e.target.reset(); carregarUsuarios();
  } catch (err) { $("u-erro").textContent = err.message; }
});
async function carregarAuditoria() {
  const rows = await api("/api/admin/auditoria?limite=200", { auth: true });
  const tb = $("t-auditoria").tBodies[0];
  tb.replaceChildren();
  rows.forEach((a) => tb.append(el("tr", {}, el("td", { text: fmt(a.ts) }), el("td", { text: a.ator }), el("td", { text: a.acao }), el("td", { text: a.alvo || "" }), el("td", { class: "livre", text: a.detalhe || "" }))));
}
$("au-verificar").addEventListener("click", async () => {
  const r = await api("/api/admin/auditoria/verificar", { auth: true });
  $("au-msg").textContent = r.integra ? `Trilha íntegra (${r.registros} registros).` : `ADULTERAÇÃO detectada a partir do registro ${r.primeira_falha_id}.`;
});
$("au-retencao").addEventListener("click", async () => {
  if (!confirm("Eliminar definitivamente as denúncias encerradas além do prazo de retenção?")) return;
  const r = await api("/api/admin/retencao/executar", { method: "POST", auth: true });
  $("au-msg").textContent = `${r.eliminadas} denúncia(s) eliminada(s) (prazo: ${r.prazo_dias} dias).`;
  carregarAuditoria();
});
