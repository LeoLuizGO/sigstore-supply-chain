"""Cliente mínimo (somente leitura) de registry OCI / Docker Registry v2.

Implementa o fluxo genérico de token Bearer anônimo:
  1. faz a requisição sem credencial;
  2. se vier 401 com `WWW-Authenticate: Bearer realm=...,service=...,scope=...`,
     pede um token anônimo em `realm?service=...&scope=...`;
  3. repete a requisição com `Authorization: Bearer <token>`.
Funciona em ghcr.io, Docker Hub (registry-1.docker.io), cgr.dev, quay.io etc.
"""

from __future__ import annotations

import hashlib
import os
import re
from dataclasses import dataclass

import requests

# Tipos de manifesto aceitos (OCI e Docker v2, inclusive listas/índices)
ACCEPT_MANIFESTOS = ", ".join([
    "application/vnd.oci.image.index.v1+json",
    "application/vnd.oci.image.manifest.v1+json",
    "application/vnd.docker.distribution.manifest.list.v2+json",
    "application/vnd.docker.distribution.manifest.v2+json",
])

TIMEOUT = 30


class ErroRegistry(Exception):
    """Erro de rede ou de protocolo ao falar com o registry."""


@dataclass
class Referencia:
    """Referência de imagem decomposta: host/repositório[:tag][@digest]."""

    host: str          # host "lógico" (ex.: docker.io, ghcr.io)
    repositorio: str   # ex.: kyverno/kyverno, library/nginx
    tag: str | None = None
    digest: str | None = None

    @property
    def host_api(self) -> str:
        # O Docker Hub atende a API v2 em outro host
        return "registry-1.docker.io" if self.host == "docker.io" else self.host

    @property
    def nome(self) -> str:
        return f"{self.host}/{self.repositorio}"

    def __str__(self) -> str:
        s = self.nome
        if self.tag:
            s += f":{self.tag}"
        if self.digest:
            s += f"@{self.digest}"
        return s


def analisa_referencia(ref: str) -> Referencia:
    """Decompõe 'host/repo:tag@sha256:...' seguindo as regras do Docker."""
    digest = None
    if "@" in ref:
        ref, digest = ref.split("@", 1)
        if not re.fullmatch(r"sha256:[0-9a-f]{64}", digest):
            raise ValueError(f"digest inválido: {digest}")
    tag = None
    ultimo = ref.rsplit("/", 1)[-1]
    if ":" in ultimo:
        ref, tag = ref.rsplit(":", 1)
    partes = ref.split("/", 1)
    if len(partes) == 1 or not ("." in partes[0] or ":" in partes[0] or partes[0] == "localhost"):
        host, repo = "docker.io", ref
    else:
        host, repo = partes
    if host in ("index.docker.io", "registry-1.docker.io"):
        host = "docker.io"
    if host == "docker.io" and "/" not in repo:
        repo = f"library/{repo}"
    if tag is None and digest is None:
        tag = "latest"
    return Referencia(host=host, repositorio=repo, tag=tag, digest=digest)


def _analisa_www_authenticate(valor: str) -> tuple[str, dict[str, str]]:
    esquema, _, resto = valor.partition(" ")
    params = dict(re.findall(r'(\w+)="([^"]*)"', resto))
    return esquema.lower(), params


class Registry:
    """Sessão anônima com um repositório de um registry."""

    def __init__(self, ref: Referencia, sessao: requests.Session | None = None):
        self.ref = ref
        self.sessao = sessao or requests.Session()
        self.sessao.headers.setdefault("User-Agent", "verificador-ufsc/1.0")
        self.token: str | None = None
        self.base = f"https://{ref.host_api}/v2/{ref.repositorio}"

    # ---- fluxo de autenticação Bearer -------------------------------------------------
    def _obtem_token(self, www_auth: str) -> None:
        esquema, p = _analisa_www_authenticate(www_auth)
        if esquema != "bearer" or "realm" not in p:
            raise ErroRegistry(f"autenticação não suportada: {www_auth}")
        params = {}
        if "service" in p:
            params["service"] = p["service"]
        # Alguns registries não mandam scope no 401 do HEAD; usamos o de pull do repositório
        params["scope"] = p.get("scope") or f"repository:{self.ref.repositorio}:pull"
        # Credenciais opcionais (ex.: no CI, antes de o pacote do GHCR virar público).
        # Sem elas, o token é anônimo.
        usuario = os.environ.get("VERIFICADOR_REGISTRY_USUARIO")
        senha = os.environ.get("VERIFICADOR_REGISTRY_SENHA")
        auth = (usuario, senha) if usuario and senha else None
        r = self.sessao.get(p["realm"], params=params, timeout=TIMEOUT, auth=auth)
        if r.status_code != 200:
            tipo = "autenticado" if auth else "anônimo"
            raise ErroRegistry(f"falha ao obter token {tipo} ({r.status_code}) em {p['realm']}")
        j = r.json()
        self.token = j.get("token") or j.get("access_token")
        if not self.token:
            raise ErroRegistry("resposta de token sem 'token'")

    def _requisicao(self, metodo: str, url: str, headers: dict | None = None) -> requests.Response:
        headers = dict(headers or {})
        for _ in range(2):
            if self.token:
                headers["Authorization"] = f"Bearer {self.token}"
            try:
                r = self.sessao.request(metodo, url, headers=headers, timeout=TIMEOUT,
                                        allow_redirects=True)
            except requests.RequestException as e:
                raise ErroRegistry(f"erro de rede: {e}") from e
            if r.status_code == 401 and "WWW-Authenticate" in r.headers and not self.token:
                self._obtem_token(r.headers["WWW-Authenticate"])
                continue
            return r
        return r

    # ---- operações ------------------------------------------------------------------
    def manifesto(self, referencia: str) -> tuple[bytes, str, str] | None:
        """GET do manifesto (tag ou digest). Retorna (bytes, mediaType, digest) ou None se 404."""
        r = self._requisicao("GET", f"{self.base}/manifests/{referencia}",
                             {"Accept": ACCEPT_MANIFESTOS})
        if r.status_code == 404:
            return None
        if r.status_code != 200:
            raise ErroRegistry(f"GET manifesto {referencia}: HTTP {r.status_code} {r.text[:200]}")
        corpo = r.content
        digest = "sha256:" + hashlib.sha256(corpo).hexdigest()
        cabecalho = r.headers.get("Docker-Content-Digest")
        if cabecalho and cabecalho != digest:
            raise ErroRegistry(f"Docker-Content-Digest {cabecalho} difere do SHA-256 do corpo {digest}")
        if referencia.startswith("sha256:") and referencia != digest:
            raise ErroRegistry(f"manifesto pedido {referencia} mas o corpo tem {digest}")
        tipo = r.headers.get("Content-Type", "").split(";")[0]
        return corpo, tipo, digest

    def resolve_tag(self, tag: str) -> str:
        """Resolve tag -> digest do manifesto (HEAD; se faltar o cabeçalho, GET e SHA-256)."""
        r = self._requisicao("HEAD", f"{self.base}/manifests/{tag}", {"Accept": ACCEPT_MANIFESTOS})
        if r.status_code == 200 and r.headers.get("Docker-Content-Digest"):
            return r.headers["Docker-Content-Digest"]
        if r.status_code not in (200, 405):
            raise ErroRegistry(f"HEAD manifesto {tag}: HTTP {r.status_code}")
        m = self.manifesto(tag)
        if m is None:
            raise ErroRegistry(f"tag não encontrada: {tag}")
        return m[2]

    def blob(self, digest: str) -> bytes:
        """Baixa um blob e confere que o SHA-256 bate com o digest pedido."""
        r = self._requisicao("GET", f"{self.base}/blobs/{digest}")
        if r.status_code != 200:
            raise ErroRegistry(f"GET blob {digest}: HTTP {r.status_code}")
        calc = "sha256:" + hashlib.sha256(r.content).hexdigest()
        if calc != digest:
            raise ErroRegistry(f"blob {digest} com conteúdo de SHA-256 {calc}")
        return r.content


def tag_cosign(digest: str, sufixo: str) -> str:
    """Tag do esquema legado do Cosign: sha256:abc -> sha256-abc.<sufixo>."""
    alg, hexa = digest.split(":", 1)
    return f"{alg}-{hexa}.{sufixo}"
