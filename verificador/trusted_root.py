"""Leitura do `trusted_root.json` do Sigstore (formato dev.sigstore.trustedroot.v0.1).

Usamos duas partes dele:
  * certificateAuthorities: cadeias do Fulcio ([intermediária, ..., raiz]) com janela validFor;
  * tlogs: chaves públicas dos logs de transparência (Rekor), identificadas pelo logId,
    que é o SHA-256 do DER (SubjectPublicKeyInfo) da chave.
A atualização desse arquivo via TUF está fora do escopo: o arquivo é fixado no repositório.
"""

from __future__ import annotations

import base64
import hashlib
import json
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path

from cryptography import x509
from cryptography.hazmat.primitives import serialization

CAMINHO_PADRAO = Path(__file__).with_name("trusted_root.json")


def _data(s: str | None) -> datetime | None:
    if not s:
        return None
    return datetime.fromisoformat(s.replace("Z", "+00:00")).astimezone(timezone.utc)


@dataclass
class Janela:
    inicio: datetime | None
    fim: datetime | None

    def contem(self, t: datetime) -> bool:
        return (self.inicio is None or t >= self.inicio) and (self.fim is None or t <= self.fim)

    def __str__(self) -> str:
        return f"[{self.inicio or '-inf'}, {self.fim or 'aberta'}]"


@dataclass
class AutoridadeCertificadora:
    uri: str
    cadeia: list[x509.Certificate]          # [intermediária(s)..., raiz]
    janela: Janela


@dataclass
class ChaveDeLog:
    url: str
    log_id: bytes                           # SHA-256 do DER da chave
    chave: object                           # chave pública (cryptography)
    algoritmo: str
    janela: Janela


@dataclass
class RaizConfiavel:
    caminho: str
    sha256: str
    autoridades: list[AutoridadeCertificadora] = field(default_factory=list)
    logs: list[ChaveDeLog] = field(default_factory=list)

    def chave_do_log(self, log_id: bytes) -> ChaveDeLog | None:
        for c in self.logs:
            if c.log_id == log_id:
                return c
        return None


def carrega(caminho: str | Path | None = None, conteudo: bytes | None = None) -> RaizConfiavel:
    if conteudo is None:
        caminho = Path(caminho or CAMINHO_PADRAO)
        conteudo = caminho.read_bytes()
    dados = json.loads(conteudo)
    raiz = RaizConfiavel(caminho=str(caminho or "<memória>"),
                         sha256=hashlib.sha256(conteudo).hexdigest())
    for ca in dados.get("certificateAuthorities", []):
        certs = [x509.load_der_x509_certificate(base64.b64decode(c["rawBytes"]))
                 for c in ca["certChain"]["certificates"]]
        vf = ca.get("validFor", {})
        raiz.autoridades.append(AutoridadeCertificadora(
            uri=ca.get("uri", ""), cadeia=certs,
            janela=Janela(_data(vf.get("start")), _data(vf.get("end")))))
    for tl in dados.get("tlogs", []):
        pk = tl["publicKey"]
        der = base64.b64decode(pk["rawBytes"])
        chave = serialization.load_der_public_key(der)
        log_id = base64.b64decode(tl["logId"]["keyId"])
        # Conferência de sanidade: no Rekor v1 (ECDSA) o logId é o SHA-256 do DER da chave.
        # (Os logs Rekor v2/Ed25519 usam outra derivação e não são suportados aqui.)
        if pk.get("keyDetails", "").startswith("PKIX_ECDSA") and hashlib.sha256(der).digest() != log_id:
            raise ValueError(f"trusted_root: logId não é SHA-256 da chave de {tl.get('baseUrl')}")
        vf = pk.get("validFor", {})
        raiz.logs.append(ChaveDeLog(url=tl.get("baseUrl", ""), log_id=log_id, chave=chave,
                                    algoritmo=pk.get("keyDetails", ""),
                                    janela=Janela(_data(vf.get("start")), _data(vf.get("end")))))
    return raiz
