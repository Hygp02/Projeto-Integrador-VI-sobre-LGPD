"""Modelos de entrada/saída da API (validação e minimização de dados)."""
from __future__ import annotations

import re
from typing import Literal

from pydantic import BaseModel, Field, field_validator, model_validator

CATEGORIAS = {
    "vazamento_de_dados": "Vazamento de dados",
    "acesso_indevido": "Acesso indevido a informações",
    "compartilhamento_indevido": "Compartilhamento indevido de dados",
    "ma_pratica_seguranca": "Prática inadequada de segurança",
    "atividade_suspeita": "Atividade suspeita",
    "outro": "Outro",
}
Categoria = Literal[
    "vazamento_de_dados",
    "acesso_indevido",
    "compartilhamento_indevido",
    "ma_pratica_seguranca",
    "atividade_suspeita",
    "outro",
]

STATUS_VALIDOS = ("recebida", "em_analise", "procedente", "improcedente", "encerrada")
STATUS_FINAIS = ("improcedente", "encerrada")
Status = Literal["recebida", "em_analise", "procedente", "improcedente", "encerrada"]

_EMAIL_RE = re.compile(r"^[^@\s]+@[^@\s]+\.[^@\s]+$")


class Identificacao(BaseModel):
    nome: str = Field(min_length=2, max_length=120)
    email: str = Field(max_length=160)
    vinculo: Literal["colaborador", "parceiro", "terceiro"]

    @field_validator("email")
    @classmethod
    def _email(cls, v: str) -> str:
        if not _EMAIL_RE.match(v):
            raise ValueError("e-mail inválido")
        return v.strip().lower()


class DenunciaIn(BaseModel):
    categoria: Categoria
    descricao: str = Field(min_length=20, max_length=5000)
    empresa_envolvida: str | None = Field(default=None, max_length=200)
    anonima: bool = True
    identificacao: Identificacao | None = None
    consentimento: bool = False

    @model_validator(mode="after")
    def _regras_lgpd(self):
        if self.anonima and self.identificacao is not None:
            raise ValueError("Denúncia anônima não pode conter identificação (minimização de dados).")
        if not self.anonima:
            if self.identificacao is None:
                raise ValueError("Informe a identificação ou marque a denúncia como anônima.")
            if not self.consentimento:
                raise ValueError("É necessário o consentimento para tratar os dados de identificação.")
        return self


class DenunciaCriada(BaseModel):
    protocolo: str
    chave_acompanhamento: str
    aviso: str


class AcompanhamentoIn(BaseModel):
    protocolo: str = Field(min_length=5, max_length=40)
    chave: str = Field(min_length=10, max_length=80)


class MensagemDenuncianteIn(AcompanhamentoIn):
    mensagem: str = Field(min_length=3, max_length=2000)


class LoginIn(BaseModel):
    email: str = Field(max_length=160)
    senha: str = Field(max_length=200)


class UsuarioIn(BaseModel):
    email: str = Field(max_length=160)
    nome: str = Field(min_length=2, max_length=120)
    senha: str = Field(max_length=200)
    papel: Literal["admin", "analista"] = "analista"

    @field_validator("email")
    @classmethod
    def _email(cls, v: str) -> str:
        if not _EMAIL_RE.match(v):
            raise ValueError("e-mail inválido")
        return v.strip().lower()


class StatusIn(BaseModel):
    status: Status
    mensagem_publica: str | None = Field(default=None, max_length=2000)
    nota_interna: str | None = Field(default=None, max_length=2000)


class AcessoIdentidadeIn(BaseModel):
    motivo: str = Field(min_length=10, max_length=300)
