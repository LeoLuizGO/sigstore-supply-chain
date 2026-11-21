"""Checkpoint do Rekor v1 (signed tree head no formato "signed note").

Formato:
    rekor.sigstore.dev - 1193050959916656506      <- origem (nome do log - ID da árvore)
    3911541028                                    <- tamanho da árvore
    zyBz1I+gi2+51i9AoaeEV7BUs3o72QTTl+PnNaBuJNg=  <- raiz (base64)
    [linhas de extensão opcionais]
                                                  <- linha em branco
    — rekor.sigstore.dev wNI9ajBEAiBQ...          <- "— <nome> <base64(hint[4] ‖ assinatura)>"

O texto assinado é o corpo até a linha em branco (inclusive o '\n' da última linha do corpo).
No Rekor v1 o "key hint" são os 4 primeiros bytes do logID (SHA-256 do DER da chave) e a
assinatura é ECDSA P-256/SHA-256 em DER.
"""

from __future__ import annotations

import base64
from dataclasses import dataclass, field

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec

TRAVESSAO = "—"  # "—" (em dash) que inicia as linhas de assinatura


class ErroCheckpoint(ValueError):
    pass


@dataclass
class LinhaAssinatura:
    nome: str
    hint: bytes
    assinatura: bytes


@dataclass
class Checkpoint:
    corpo: bytes                 # bytes exatamente assinados
    origem: str
    tamanho: int
    raiz: bytes
    extensoes: list[str] = field(default_factory=list)
    assinaturas: list[LinhaAssinatura] = field(default_factory=list)


def analisa(texto: str) -> Checkpoint:
    if "\n\n" not in texto:
        raise ErroCheckpoint("checkpoint sem linha em branco separando corpo e assinaturas")
    corpo, _, resto = texto.partition("\n\n")
    corpo += "\n"
    linhas = corpo.split("\n")[:-1]
    if len(linhas) < 3:
        raise ErroCheckpoint("corpo do checkpoint precisa de origem, tamanho e raiz")
    try:
        tamanho = int(linhas[1])
        raiz = base64.b64decode(linhas[2], validate=True)
    except ValueError as e:
        raise ErroCheckpoint(f"tamanho/raiz malformados: {e}") from e
    if len(raiz) != 32:
        raise ErroCheckpoint("raiz não tem 32 bytes")
    cp = Checkpoint(corpo=corpo.encode("utf-8"), origem=linhas[0], tamanho=tamanho, raiz=raiz,
                    extensoes=linhas[3:])
    for linha in resto.split("\n"):
        if not linha:
            continue
        if not linha.startswith(TRAVESSAO + " "):
            raise ErroCheckpoint(f"linha de assinatura malformada: {linha[:40]!r}")
        partes = linha[2:].split(" ")
        if len(partes) != 2:
            raise ErroCheckpoint("linha de assinatura deve ter nome e base64")
        bruto = base64.b64decode(partes[1])
        if len(bruto) < 5:
            raise ErroCheckpoint("assinatura curta demais")
        cp.assinaturas.append(LinhaAssinatura(nome=partes[0], hint=bruto[:4], assinatura=bruto[4:]))
    if not cp.assinaturas:
        raise ErroCheckpoint("checkpoint sem assinaturas")
    return cp


def verifica(cp: Checkpoint, chave: ec.EllipticCurvePublicKey, log_id: bytes) -> tuple[bool, str]:
    """Procura a linha de assinatura cujo hint == logID[:4] e verifica o ECDSA sobre o corpo."""
    nome_log = cp.origem.split(" ")[0]
    for a in cp.assinaturas:
        if a.hint != log_id[:4]:
            continue
        if a.nome != nome_log:
            return False, f"nome da assinatura {a.nome!r} difere da origem {nome_log!r}"
        try:
            chave.verify(a.assinatura, cp.corpo, ec.ECDSA(hashes.SHA256()))
        except InvalidSignature:
            return False, f"assinatura ECDSA de {a.nome} (hint {a.hint.hex()}) inválida"
        return True, f"assinado por {a.nome} (hint {a.hint.hex()} = logID[:4])"
    return False, f"nenhuma assinatura com hint {log_id[:4].hex()} (logID do trusted_root)"
