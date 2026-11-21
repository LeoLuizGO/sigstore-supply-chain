"""Casos do experimento E3: cenários sintéticos (um por motivo de rejeição) e adulterações
de evidências reais. Usados por `python -m verificador.experimentos.e3` e pelos testes."""

from __future__ import annotations

import base64
import copy
import json
from dataclasses import dataclass, field
from typing import Callable

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec

from .. import merkle, sintetico
from .. import verifica as V

ANOT_SIG = V.ANOT_ASSINATURA
ANOT_BUNDLE = V.ANOT_BUNDLE


@dataclass
class Caso:
    nome: str
    origem: str                              # "sintetico" | "real"
    evidencia: dict
    trusted_root: bytes | None               # None = o trusted_root fixado no pacote
    digest: str
    identidade: str
    emissor: str
    esperado: str | None                     # motivo esperado; None = válida
    notas: dict = field(default_factory=dict)  # dicas para o cross-check (cosign/sigstore)


def inverte_bit_b64(s: str, pos: int, bit: int = 0) -> str:
    b = bytearray(base64.b64decode(s))
    b[pos] ^= 1 << bit
    return base64.b64encode(bytes(b)).decode()


def _camada(ev: dict, i: int = 0) -> dict:
    return ev["manifesto_sig"]["conteudo"]["layers"][i]


def _entrada(ev: dict, i: int = 0) -> dict:
    idx = json.loads(_camada(ev, i)["annotations"][ANOT_BUNDLE])["Payload"]["logIndex"]
    return next(iter(ev["rekor"][str(idx)].values()))


def _troca_payload(ev: dict, novo: bytes, i: int = 0) -> None:
    ev["payloads"][_camada(ev, i)["digest"]] = base64.b64encode(novo).decode()


def _payload(ev: dict, i: int = 0) -> bytes:
    return base64.b64decode(ev["payloads"][_camada(ev, i)["digest"]])


# ---- adulterações genéricas (valem para evidência real e sintética) ------------------------
def adultera_byte_payload(ev: dict, i: int = 0) -> None:
    """Muda 1 byte do payload fora do digest (no docker-reference): o digest continua igual,
    então só o ECDSA pega."""
    p = bytearray(_payload(ev, i))
    pos = p.index(b'"docker-reference":"') + len('"docker-reference":"') + 2
    p[pos] ^= 0x01
    _troca_payload(ev, bytes(p), i)


def adultera_bit_assinatura(ev: dict, i: int = 0) -> None:
    a = _camada(ev, i)["annotations"]
    a[ANOT_SIG] = inverte_bit_b64(a[ANOT_SIG], 10)   # um bit no meio de r


def adultera_hash_prova(ev: dict, i: int = 0) -> None:
    prova = _entrada(ev, i)["verification"]["inclusionProof"]
    h = bytearray(bytes.fromhex(prova["hashes"][0]))
    h[0] ^= 0x01
    prova["hashes"][0] = h.hex()


def adultera_indice_prova(ev: dict, i: int = 0) -> None:
    prova = _entrada(ev, i)["verification"]["inclusionProof"]
    prova["logIndex"] += 1


def adultera_prova_truncada(ev: dict, i: int = 0) -> None:
    _entrada(ev, i)["verification"]["inclusionProof"]["hashes"].pop()


def adultera_assinatura_checkpoint(ev: dict, i: int = 0) -> None:
    prova = _entrada(ev, i)["verification"]["inclusionProof"]
    corpo, sep, linha = prova["checkpoint"].rstrip("\n").rpartition("\n")
    traco, nome, b64 = linha.split(" ")
    prova["checkpoint"] = f"{corpo}{sep}{traco} {nome} {inverte_bit_b64(b64, 12)}\n"


def adultera_raiz_checkpoint_e_prova(ev: dict, i: int = 0) -> None:
    """Atacante troca a raiz na prova e no texto do checkpoint (sem a chave do log)."""
    prova = _entrada(ev, i)["verification"]["inclusionProof"]
    falsa = bytearray(bytes.fromhex(prova["rootHash"]))
    falsa[0] ^= 0x01
    antiga_b64 = base64.b64encode(bytes.fromhex(prova["rootHash"])).decode()
    prova["checkpoint"] = prova["checkpoint"].replace(antiga_b64, base64.b64encode(bytes(falsa)).decode())
    prova["rootHash"] = bytes(falsa).hex()


def adultera_set_rekor(ev: dict, i: int = 0) -> None:
    v = _entrada(ev, i)["verification"]
    v["signedEntryTimestamp"] = inverte_bit_b64(v["signedEntryTimestamp"], 12)


def adultera_set_anotacao(ev: dict, i: int = 0) -> None:
    a = _camada(ev, i)["annotations"]
    b = json.loads(a[ANOT_BUNDLE])
    b["SignedEntryTimestamp"] = inverte_bit_b64(b["SignedEntryTimestamp"], 12)
    a[ANOT_BUNDLE] = json.dumps(b)


def adultera_tempo_anotacao(ev: dict, i: int = 0) -> None:
    a = _camada(ev, i)["annotations"]
    b = json.loads(a[ANOT_BUNDLE])
    b["Payload"]["integratedTime"] += 1
    a[ANOT_BUNDLE] = json.dumps(b)


def remove_certificado(ev: dict, i: int = 0) -> None:
    _camada(ev, i)["annotations"].pop(V.ANOT_CERT)
    _camada(ev, i)["annotations"].pop(V.ANOT_CADEIA, None)


# ---- casos sintéticos ----------------------------------------------------------------------
def casos_sinteticos() -> list[Caso]:
    casos: list[Caso] = []
    base = sintetico.gera()

    def add(nome: str, cen: sintetico.Cenario, esperado: str | None, **kw) -> None:
        casos.append(Caso(nome, "sintetico", cen.evidencia, cen.trusted_root,
                          kw.get("digest", cen.digest), kw.get("identidade", cen.identidade),
                          kw.get("emissor", cen.emissor), esperado))

    def variante(f: Callable[[dict], None]) -> sintetico.Cenario:
        c = base.copia()
        f(c.evidencia)
        return c

    add("legitima", base, None)
    add("arvore de 1 entrada", sintetico.gera(n_antes=0, n_depois=0), None)
    add("ultima entrada de arvore com 13 folhas", sintetico.gera(n_antes=12, n_depois=0), None)
    add("duas assinaturas: outra identidade + legitima",
        sintetico.gera(identidade_cert=sintetico.IDENTIDADE_ATAQUES, assinaturas_extras=[{}]), None)
    add("sem assinatura (E2.1)", variante(lambda ev: ev.update(manifesto_sig=None)), V.M_SEM_ASSINATURA)
    add("payload de outra imagem (troca de assinatura, E2.4)",
        sintetico.gera(digest_payload=sintetico.OUTRO_DIGEST), V.M_OUTRA_IMAGEM)
    add("evidencia de outra imagem para o digest esperado", base, V.M_OUTRA_IMAGEM,
        digest=sintetico.OUTRO_DIGEST)

    def assinatura_trocada(ev: dict) -> None:
        outro = sintetico.payload_simple_signing(sintetico.OUTRO_DIGEST)
        sig = base.chaves["folha"].sign(outro, ec.ECDSA(hashes.SHA256()))
        _camada(ev)["annotations"][ANOT_SIG] = base64.b64encode(sig).decode()
    add("assinatura trocada (mesma chave, outro payload)", variante(assinatura_trocada), V.M_ASSINATURA)
    add("1 bit alterado na assinatura", variante(adultera_bit_assinatura), V.M_ASSINATURA)
    add("1 byte alterado no payload", variante(adultera_byte_payload), V.M_ASSINATURA)
    add("identidade errada (outro workflow, E2.3a)",
        sintetico.gera(identidade_cert=sintetico.IDENTIDADE_ATAQUES), V.M_IDENTIDADE)
    add("emissor errado", sintetico.gera(emissor_cert="https://accounts.google.com"), V.M_EMISSOR)
    add("AC desconhecida", sintetico.gera(ac_conhecida=False), V.M_AC_DESCONHECIDA)
    add("certificado sem EKU codeSigning", sintetico.gera(eku=False), V.M_EKU)
    add("chave local sem certificado (E2.3b)", sintetico.gera(com_certificado=False), V.M_SEM_CERTIFICADO)
    add("certificado expirado no integratedTime", sintetico.gera(segundos_apos_emissao=3600), V.M_TEMPO)
    add("integratedTime antes do notBefore", sintetico.gera(segundos_apos_emissao=-60), V.M_TEMPO)
    add("hash da prova alterado", variante(adultera_hash_prova), V.M_INCLUSAO)
    add("indice errado na prova", variante(adultera_indice_prova), V.M_INCLUSAO)
    add("prova truncada", variante(adultera_prova_truncada), V.M_INCLUSAO)
    add("checkpoint com assinatura invalida", variante(adultera_assinatura_checkpoint), V.M_CHECKPOINT)

    def checkpoint_outra_chave(ev: dict) -> None:
        prova = _entrada(ev)["verification"]["inclusionProof"]
        intrusa = ec.generate_private_key(ec.SECP256R1())
        prova["checkpoint"] = base.chaves["log"].checkpoint(prova["treeSize"],
                                                            bytes.fromhex(prova["rootHash"]), intrusa)
    add("checkpoint assinado por outra chave", variante(checkpoint_outra_chave), V.M_CHECKPOINT)
    add("raiz falsa na prova e no checkpoint (sem a chave do log)",
        variante(adultera_raiz_checkpoint_e_prova), V.M_CHECKPOINT)

    def checkpoint_outra_raiz(ev: dict) -> None:
        prova = _entrada(ev)["verification"]["inclusionProof"]
        outra = merkle.hash_folha(b"outra arvore")
        prova["checkpoint"] = base.chaves["log"].checkpoint(prova["treeSize"], outra)
    add("raiz do checkpoint diferente (assinado pelo log)", variante(checkpoint_outra_raiz),
        V.M_CHECKPOINT_PROVA)

    def entrada_alheia(ev: dict) -> None:
        idx = json.loads(_camada(ev)["annotations"][ANOT_BUNDLE])["Payload"]["logIndex"]
        ev["rekor"][str(idx)] = copy.deepcopy(base.entradas[0])
    add("body do Rekor de outro artefato (prova e SET validos)", variante(entrada_alheia), V.M_ENTRADA)

    def body_alterado(ev: dict) -> None:
        e = _entrada(ev)
        corpo = json.loads(base64.b64decode(e["body"]))
        corpo["spec"]["data"]["hash"]["value"] = "0" * 64
        e["body"] = base64.b64encode(json.dumps(corpo, separators=(",", ":")).encode()).decode()
    add("body do Rekor alterado", variante(body_alterado), V.M_ENTRADA)
    add("entrada do Rekor ausente", variante(lambda ev: ev.update(rekor={})), V.M_SEM_REKOR)
    add("SET do Rekor invalido", variante(adultera_set_rekor), V.M_SET)
    add("SET da anotacao invalido", variante(adultera_set_anotacao), V.M_SET)
    add("bundle da anotacao com integratedTime alterado", variante(adultera_tempo_anotacao), V.M_BUNDLE)

    tr = json.loads(base.trusted_root)
    tr["tlogs"] = []
    sem_log = base.copia()
    sem_log.trusted_root = json.dumps(tr).encode()
    add("chave do log fora do trusted_root", sem_log, V.M_LOG_DESCONHECIDO)
    return casos


# ---- casos reais (adulterações sobre uma evidência baixada) --------------------------------
def casos_reais(nome: str, ev: dict, identidade: str, emissor: str) -> list[Caso]:
    digest = ev["digest"]
    casos: list[Caso] = []
    camadas = ev["manifesto_sig"]["conteudo"]["layers"]

    def add(rotulo: str, f: Callable[[dict, int], None] | None, esperado: str | None,
            so_primeira: bool = False, **kw) -> None:
        """Aplica a adulteração em TODAS as assinaturas (a imagem só é rejeitada se nenhuma
        passar), ou só na primeira se so_primeira=True. Camadas com o mesmo payload (mesmo
        digest) compartilham os bytes, então o payload é alterado uma vez só."""
        e = copy.deepcopy(ev)
        if f:
            vistos = set()
            for i, c in enumerate(camadas[:1] if so_primeira else camadas):
                if f is adultera_byte_payload:
                    if c["digest"] in vistos:
                        continue
                    vistos.add(c["digest"])
                f(e, i)
        casos.append(Caso(f"{nome}: {rotulo}", "real", e, kw.get("trusted_root"),
                          kw.get("digest", digest), kw.get("identidade", identidade),
                          kw.get("emissor", emissor), esperado, kw.get("notas", {})))

    add("legitima", None, None, notas={"cosign_online": True})
    add("identidade esperada errada", None, V.M_IDENTIDADE,
        identidade=sintetico.IDENTIDADE, notas={"cosign_online": True})
    add("emissor esperado errado", None, V.M_EMISSOR, emissor="https://accounts.google.com",
        notas={"cosign_online": True})
    add("digest esperado de outra imagem", None, V.M_OUTRA_IMAGEM, digest=sintetico.OUTRO_DIGEST,
        notas={"cross": "n/a"})
    add("1 byte alterado no payload", adultera_byte_payload, V.M_ASSINATURA)
    add("1 bit alterado na assinatura", adultera_bit_assinatura, V.M_ASSINATURA)
    add("1 hash da prova alterado", adultera_hash_prova, V.M_INCLUSAO)
    add("indice da prova errado", adultera_indice_prova, V.M_INCLUSAO)
    add("raiz falsa na prova e no checkpoint", adultera_raiz_checkpoint_e_prova, V.M_CHECKPOINT)
    add("assinatura do checkpoint alterada", adultera_assinatura_checkpoint, V.M_CHECKPOINT)
    add("SET alterado", adultera_set_rekor, V.M_SET)
    add("sem certificado (como chave local)", remove_certificado, V.M_SEM_CERTIFICADO,
        notas={"cross": "n/a"})
    if len(camadas) > 1:
        add("so a 1a de varias assinaturas adulterada", adultera_bit_assinatura, None,
            so_primeira=True, notas={"cross": "n/a"})
    return casos
