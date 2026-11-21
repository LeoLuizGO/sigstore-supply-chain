"""Núcleo do verificador: a função VERIFICA da Seção 3.3 do relatório, passo a passo.

Entrada: uma evidência (ver evidencia.py), o digest esperado, a identidade (SAN) e o emissor
OIDC esperados e o trusted_root fixado. Cada camada do manifesto `sha256-<hex>.sig` é uma
assinatura independente; a imagem é aceita se ao menos uma passar em todas as etapas.
Tudo aqui é offline.
"""

from __future__ import annotations

import base64
import binascii
import hashlib
import json
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone

from cryptography import x509
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec

from . import certificado as certmod
from . import checkpoint as cpmod
from . import ecdsa_p256, merkle
from .rekor import payload_set
from .trusted_root import RaizConfiavel

# ---- motivos de rejeição (um por checagem) ----------------------------------------------
M_SEM_ASSINATURA = "nenhuma assinatura encontrada"
M_FORMATO = "formato de assinatura não suportado"
M_SEM_CERTIFICADO = "assinatura sem certificado Fulcio (chave própria, não keyless)"
M_PAYLOAD_MALFORMADO = "payload malformado"
M_OUTRA_IMAGEM = "assinatura é de outra imagem"
M_AC_DESCONHECIDA = "AC desconhecida"
M_AC_FORA_VALIDADE = "cadeia da AC fora da validade"
M_EKU = "certificado sem EKU codeSigning"
M_EMISSOR = "emissor errado"
M_IDENTIDADE = "identidade errada"
M_ASSINATURA = "assinatura inválida"
M_SEM_REKOR = "entrada do Rekor ausente"
M_TIPO_ENTRADA = "tipo de entrada do Rekor não suportado"
M_ENTRADA = "entrada do Rekor não confere"
M_LOG_DESCONHECIDO = "log de transparência desconhecido"
M_CHECKPOINT = "checkpoint inválido"
M_CHECKPOINT_PROVA = "checkpoint não confere com a prova"
M_INCLUSAO = "prova de inclusão inválida"
M_SET = "SET inválido"
M_BUNDLE = "bundle do registry não confere com o Rekor"
M_TEMPO = "assinatura fora da validade do certificado"

TIPO_SIMPLE_SIGNING = "application/vnd.dev.cosign.simplesigning.v1+json"
TIPO_PAYLOAD = "cosign container image signature"
ANOT_ASSINATURA = "dev.cosignproject.cosign/signature"
ANOT_CERT = "dev.sigstore.cosign/certificate"
ANOT_CADEIA = "dev.sigstore.cosign/chain"
ANOT_BUNDLE = "dev.sigstore.cosign/bundle"
ANOT_RFC3161 = "dev.sigstore.cosign/rfc3161timestamp"

MODOS_ECDSA = ("biblioteca", "manual", "ambos")


class DivergenciaECDSA(RuntimeError):
    """As duas implementações de ECDSA discordaram (seria um bug nosso)."""


@dataclass
class Etapa:
    nome: str
    ok: bool | None              # None = não executada (dependência falhou)
    detalhe: str = ""
    motivo: str | None = None


@dataclass
class ResultadoAssinatura:
    camada: str
    valida: bool = False
    motivo: str | None = None
    etapas: list[Etapa] = field(default_factory=list)
    info: dict = field(default_factory=dict)
    avisos: list[str] = field(default_factory=list)


@dataclass
class Relatorio:
    imagem: str
    digest: str
    identidade: str
    emissor: str
    trusted_root_sha256: str
    ecdsa: str
    valida: bool = False
    motivo: str | None = None
    assinaturas: list[ResultadoAssinatura] = field(default_factory=list)
    avisos: list[str] = field(default_factory=list)

    def para_dict(self) -> dict:
        return asdict(self)


def _ts(t: int | float) -> datetime:
    return datetime.fromtimestamp(int(t), tz=timezone.utc)


def _b64(s: str) -> bytes:
    return base64.b64decode(s, validate=True)


def ecdsa_verifica(chave: ec.EllipticCurvePublicKey, assinatura: bytes, mensagem: bytes,
                   modo: str = "ambos") -> tuple[bool, str]:
    """ECDSA P-256/SHA-256 pela biblioteca, pela implementação manual ou pelas duas."""
    res = {}
    if modo in ("biblioteca", "ambos"):
        try:
            chave.verify(assinatura, mensagem, ec.ECDSA(hashes.SHA256()))
            res["biblioteca"] = True
        except InvalidSignature:
            res["biblioteca"] = False
    if modo in ("manual", "ambos"):
        q = chave.public_bytes(serialization.Encoding.X962,
                               serialization.PublicFormat.UncompressedPoint)
        try:
            res["manual"] = ecdsa_p256.verifica(q, mensagem, assinatura)
        except ecdsa_p256.ErroECDSA as e:
            res["manual"] = False
            res["manual_erro"] = str(e)
    valores = {k: v for k, v in res.items() if k in ("biblioteca", "manual")}
    if len(set(valores.values())) > 1:
        raise DivergenciaECDSA(f"biblioteca e implementação manual discordam: {res}")
    ok = all(valores.values())
    detalhe = ", ".join(f"{k}={'ok' if v else 'falhou'}" for k, v in valores.items())
    if "manual_erro" in res:
        detalhe += f" ({res['manual_erro']})"
    return ok, detalhe


def verifica_camada(camada: dict, payload: bytes | None, entradas_rekor: dict,
                    digest_esperado: str, identidade: str, emissor: str,
                    raiz: RaizConfiavel, modo_ecdsa: str = "ambos") -> ResultadoAssinatura:
    res = ResultadoAssinatura(camada=camada.get("digest", "?"))
    etapas = res.etapas

    def registra(nome: str, ok: bool | None, detalhe: str = "", motivo: str | None = None):
        etapas.append(Etapa(nome, ok, detalhe, motivo if ok is False else None))

    anot = camada.get("annotations", {}) or {}

    # ---- 0. formato ------------------------------------------------------------------
    assinatura = cert = None
    problemas = []
    if camada.get("mediaType") != TIPO_SIMPLE_SIGNING:
        problemas.append(f"mediaType {camada.get('mediaType')}")
    try:
        assinatura = _b64(anot.get(ANOT_ASSINATURA, ""))
        if not assinatura:
            problemas.append("anotação de assinatura vazia")
    except (binascii.Error, ValueError):
        problemas.append("assinatura não é base64")
    if payload is None:
        problemas.append("payload ausente na evidência")
    elif hashlib.sha256(payload).hexdigest() != res.camada.split(":")[-1]:
        res.avisos.append("SHA-256 do payload difere do digest da camada no manifesto .sig")
    if problemas:
        registra("formato", False, "; ".join(problemas), M_FORMATO)
    elif ANOT_CERT not in anot:
        registra("formato", False, "camada sem dev.sigstore.cosign/certificate", M_SEM_CERTIFICADO)
    else:
        try:
            cert = certmod.carrega_pem(anot[ANOT_CERT])
            registra("formato", True, "simple signing + assinatura + certificado PEM")
        except ValueError as e:
            registra("formato", False, f"certificado PEM inválido: {e}", M_FORMATO)

    # ---- bundle da anotação e entrada do Rekor (para obter o instante t) --------------
    bundle = None
    if ANOT_BUNDLE in anot:
        try:
            bundle = json.loads(anot[ANOT_BUNDLE])
            _ = bundle["Payload"]["logIndex"]
        except (ValueError, KeyError, TypeError):
            bundle = None
            res.avisos.append("anotação dev.sigstore.cosign/bundle malformada")
    uuid = entrada = None
    if bundle is not None:
        resp = entradas_rekor.get(str(bundle["Payload"]["logIndex"]))
        if resp:
            uuid, entrada = next(iter(resp.items()))
    t = None
    if entrada is not None:
        t = _ts(entrada["integratedTime"])
    elif bundle is not None:
        t = _ts(bundle["Payload"]["integratedTime"])
        res.avisos.append("instante t tirado da anotação (sem entrada do Rekor na evidência)")
    if ANOT_RFC3161 in anot:
        res.avisos.append("carimbo RFC 3161 presente e IGNORADO (extensão opcional não implementada); "
                          "o tempo usado é o integratedTime do Rekor")

    # ---- 1. payload: digest assinado == digest esperado -------------------------------
    if payload is None:
        registra("payload", None)
    else:
        try:
            p = json.loads(payload)
            tipo = p["critical"]["type"]
            dig = p["critical"]["image"]["docker-manifest-digest"]
            refdocker = p["critical"]["identity"]["docker-reference"]
            res.info["payload"] = {"docker-manifest-digest": dig, "docker-reference": refdocker,
                                   "optional": p.get("optional")}
            if tipo != TIPO_PAYLOAD:
                registra("payload", False, f"critical.type = {tipo!r}", M_PAYLOAD_MALFORMADO)
            elif dig != digest_esperado:
                registra("payload", False, f"payload assina {dig}, esperado {digest_esperado}",
                         M_OUTRA_IMAGEM)
            else:
                registra("payload", True, f"docker-manifest-digest = {dig}")
        except (ValueError, KeyError, TypeError) as e:
            registra("payload", False, f"JSON simple signing inválido: {e!r}", M_PAYLOAD_MALFORMADO)

    # ---- 2. certificado: cadeia, EKU, emissor, identidade -----------------------------
    if cert is None:
        for n in ("cadeia X.509", "EKU codeSigning", "emissor OIDC", "identidade (SAN)"):
            registra(n, None)
    else:
        san = certmod.identidades_san(cert)
        iss, oid_iss = certmod.emissor_oidc(cert)
        res.info["certificado"] = {
            "serial": format(cert.serial_number, "x"),
            "emissor_x509": cert.issuer.rfc4514_string(),
            "not_before": cert.not_valid_before_utc.isoformat(),
            "not_after": cert.not_valid_after_utc.isoformat(),
            "san": san,
            "emissor_oidc": iss,
            "oid_emissor": oid_iss,
            "extensoes": certmod.extensoes_sigstore(cert),
        }
        t_cadeia = t
        if t_cadeia is None:
            t_cadeia = cert.not_valid_before_utc
            res.avisos.append("sem integratedTime: validade da cadeia conferida em notBefore da folha")
        ok, det, ac = certmod.valida_cadeia(cert, raiz, t_cadeia)
        registra("cadeia X.509", ok, det, M_AC_DESCONHECIDA if ac is None else M_AC_FORA_VALIDADE)
        if ANOT_CADEIA in anot:
            try:
                cadeia_anot = certmod.carrega_cadeia_pem(anot[ANOT_CADEIA])
                if ac is not None and [c.fingerprint(hashes.SHA256()) for c in cadeia_anot] != \
                        [c.fingerprint(hashes.SHA256()) for c in ac.cadeia]:
                    res.avisos.append("cadeia da anotação difere da do trusted_root (usada a do trusted_root)")
            except ValueError:
                res.avisos.append("anotação dev.sigstore.cosign/chain malformada (ignorada)")
        registra("EKU codeSigning", certmod.tem_eku_code_signing(cert),
                 "ExtendedKeyUsage contém codeSigning (1.3.6.1.5.5.7.3.3)", M_EKU)
        registra("emissor OIDC", iss == emissor,
                 f"{iss!r} (extensão {oid_iss or 'ausente'}); esperado {emissor!r}", M_EMISSOR)
        registra("identidade (SAN)", identidade in san,
                 f"SAN = {san}; esperado {identidade!r}", M_IDENTIDADE)

    # ---- 3. ECDSA sobre os bytes exatos do payload ------------------------------------
    chave = None
    if cert is None or assinatura is None or payload is None:
        registra("ECDSA P-256", None)
    else:
        try:
            chave = certmod.chave_publica_p256(cert)
            ok, det = ecdsa_verifica(chave, assinatura, payload, modo_ecdsa)
            registra("ECDSA P-256", ok, det, M_ASSINATURA)
        except certmod.ErroCertificado as e:
            registra("ECDSA P-256", False, str(e), M_ASSINATURA)

    # ---- 4. Rekor: correspondência, checkpoint, prova de inclusão, SET ----------------
    corpo_bytes = None
    chave_log = None
    cp = None
    if bundle is None:
        registra("entrada do Rekor", False, "camada sem anotação de bundle (logIndex desconhecido)",
                 M_SEM_REKOR)
    elif entrada is None:
        registra("entrada do Rekor", False,
                 f"logIndex {bundle['Payload']['logIndex']} não está na evidência", M_SEM_REKOR)
    else:
        prova = entrada.get("verification", {}).get("inclusionProof", {})
        res.info["rekor"] = {
            "uuid": uuid, "logIndex": entrada.get("logIndex"),
            "logIndex_na_arvore": prova.get("logIndex"), "treeSize": prova.get("treeSize"),
            "integratedTime": entrada.get("integratedTime"),
            "integratedTime_utc": t.isoformat() if t else None, "logID": entrada.get("logID"),
        }
        try:
            corpo_bytes = _b64(entrada["body"])
            corpo = json.loads(corpo_bytes)
            if (corpo.get("kind"), corpo.get("apiVersion")) != ("hashedrekord", "0.0.1"):
                registra("entrada do Rekor", False,
                         f"kind={corpo.get('kind')} apiVersion={corpo.get('apiVersion')}", M_TIPO_ENTRADA)
            else:
                spec = corpo["spec"]
                difs = []
                h = spec["data"]["hash"]
                if h.get("algorithm") != "sha256" or payload is None or \
                        h.get("value") != hashlib.sha256(payload).hexdigest():
                    difs.append("spec.data.hash != SHA-256 do payload")
                if assinatura is None or _b64(spec["signature"]["content"]) != assinatura:
                    difs.append("spec.signature.content != assinatura da anotação")
                pem_log = _b64(spec["signature"]["publicKey"]["content"])
                try:
                    cert_log = x509.load_pem_x509_certificate(pem_log)
                    if cert is None or cert_log.public_bytes(serialization.Encoding.DER) != \
                            cert.public_bytes(serialization.Encoding.DER):
                        difs.append("spec.signature.publicKey != certificado da anotação")
                except ValueError:
                    difs.append("spec.signature.publicKey não é um certificado PEM")
                if entrada.get("logIndex") != bundle["Payload"]["logIndex"]:
                    difs.append("logIndex da resposta difere do pedido")
                if difs:
                    registra("entrada do Rekor", False, "; ".join(difs), M_ENTRADA)
                else:
                    registra("entrada do Rekor", True,
                             "hashedrekord v0.0.1: hash do payload, assinatura e certificado conferem")
        except (ValueError, KeyError, TypeError, binascii.Error) as e:
            registra("entrada do Rekor", False, f"body malformado: {e!r}", M_ENTRADA)

        # checkpoint
        try:
            log_id = bytes.fromhex(entrada["logID"])
        except (KeyError, ValueError):
            log_id = b""
        chave_log = raiz.chave_do_log(log_id)
        if chave_log is None:
            registra("checkpoint", False, f"logID {entrada.get('logID')} não está no trusted_root",
                     M_LOG_DESCONHECIDO)
        else:
            try:
                cp = cpmod.analisa(prova["checkpoint"])
                ok, det = cpmod.verifica(cp, chave_log.chave, log_id)
                if not ok:
                    registra("checkpoint", False, det, M_CHECKPOINT)
                elif cp.tamanho != prova.get("treeSize") or cp.raiz.hex() != prova.get("rootHash"):
                    registra("checkpoint", False,
                             f"checkpoint (tamanho {cp.tamanho}, raiz {cp.raiz.hex()[:16]}…) != prova "
                             f"(treeSize {prova.get('treeSize')}, rootHash {str(prova.get('rootHash'))[:16]}…)",
                             M_CHECKPOINT_PROVA)
                elif t is not None and not chave_log.janela.contem(t):
                    registra("checkpoint", False,
                             f"chave do log fora da janela {chave_log.janela} em {t}", M_LOG_DESCONHECIDO)
                else:
                    registra("checkpoint", True,
                             f"{det}; origem {cp.origem!r}, tamanho {cp.tamanho}, raiz {cp.raiz.hex()[:16]}…")
            except (cpmod.ErroCheckpoint, KeyError, ValueError, binascii.Error) as e:
                cp = None
                registra("checkpoint", False, f"checkpoint malformado: {e}", M_CHECKPOINT)

        # prova de inclusão (RFC 9162 §2.1.3.2) com o índice LOCAL da árvore
        if corpo_bytes is None:
            registra("prova de inclusão", None)
        else:
            try:
                folha = merkle.hash_folha(corpo_bytes)
                caminho = [bytes.fromhex(x) for x in prova["hashes"]]
                raiz_assinada = cp.raiz if cp is not None else bytes.fromhex(prova["rootHash"])
                calc = merkle.calcula_raiz(folha, int(prova["logIndex"]), int(prova["treeSize"]), caminho)
                det = (f"folha {folha.hex()[:16]}…, índice {prova['logIndex']} de {prova['treeSize']}, "
                       f"{len(caminho)} hashes -> raiz {calc.hex()[:16] + '…' if calc else 'n/d'}")
                registra("prova de inclusão", calc is not None and calc == raiz_assinada, det, M_INCLUSAO)
                if uuid and not uuid.endswith(folha.hex()):
                    res.avisos.append("UUID da entrada não termina com o hash da folha")
            except (KeyError, ValueError, TypeError) as e:
                registra("prova de inclusão", False, f"prova malformada: {e!r}", M_INCLUSAO)

        # SET da resposta do Rekor
        if chave_log is None:
            registra("SET (Rekor)", None)
        else:
            try:
                msg = payload_set(entrada["body"], entrada["integratedTime"], entrada["logID"],
                                  entrada["logIndex"])
                set_ = _b64(entrada["verification"]["signedEntryTimestamp"])
                chave_log.chave.verify(set_, msg, ec.ECDSA(hashes.SHA256()))
                registra("SET (Rekor)", True, "ECDSA do log sobre {body, integratedTime, logID, logIndex}")
            except (InvalidSignature, KeyError, ValueError, binascii.Error) as e:
                registra("SET (Rekor)", False, f"SET da resposta do Rekor não verifica ({type(e).__name__})",
                         M_SET)

        # bundle da anotação (o que o cosign usa offline) x entrada do Rekor
        if chave_log is None:
            registra("bundle da anotação", None)
        else:
            bp = bundle["Payload"]
            difs = [k for k in ("body", "integratedTime", "logIndex", "logID") if bp.get(k) != entrada.get(k)]
            if difs:
                registra("bundle da anotação", False, f"campos diferentes do Rekor: {difs}", M_BUNDLE)
            else:
                try:
                    msg = payload_set(bp["body"], bp["integratedTime"], bp["logID"], bp["logIndex"])
                    chave_log.chave.verify(_b64(bundle["SignedEntryTimestamp"]), msg,
                                           ec.ECDSA(hashes.SHA256()))
                    igual = bundle["SignedEntryTimestamp"] == entrada["verification"]["signedEntryTimestamp"]
                    registra("bundle da anotação", True,
                             "Payload igual ao do Rekor e SET da anotação válido"
                             + ("" if igual else " (SET com bytes diferentes do atual: ECDSA é aleatorizado)"))
                except (InvalidSignature, KeyError, ValueError, binascii.Error) as e:
                    registra("bundle da anotação", False, f"SET da anotação não verifica ({type(e).__name__})",
                             M_SET)

    # ---- 5. tempo: integratedTime dentro da validade do certificado --------------------
    if cert is None or entrada is None:
        registra("tempo", None)
    else:
        nb, na = cert.not_valid_before_utc, cert.not_valid_after_utc
        registra("tempo", nb <= t <= na, f"integratedTime {t.isoformat()} em [{nb.isoformat()}, {na.isoformat()}]",
                 M_TEMPO)

    falhas = [e for e in etapas if e.ok is False]
    res.valida = bool(etapas) and all(e.ok is True for e in etapas)
    res.motivo = falhas[0].motivo if falhas else (None if res.valida else "etapa não executada")
    return res


def verifica_evidencia(ev: dict, digest_esperado: str, identidade: str, emissor: str,
                       raiz: RaizConfiavel, modo_ecdsa: str = "ambos") -> Relatorio:
    if modo_ecdsa not in MODOS_ECDSA:
        raise ValueError(f"modo ECDSA inválido: {modo_ecdsa}")
    rel = Relatorio(imagem=ev.get("imagem", "?"), digest=digest_esperado, identidade=identidade,
                    emissor=emissor, trusted_root_sha256=raiz.sha256, ecdsa=modo_ecdsa)
    rel.avisos.extend(ev.get("erros", []))
    if ev.get("digest") != digest_esperado:
        rel.avisos.append(f"a evidência foi baixada para {ev.get('digest')}, mas o digest esperado é "
                          f"{digest_esperado}")
    ms = ev.get("manifesto_sig")
    camadas = (ms or {}).get("conteudo", {}).get("layers", []) if ms else []
    if not camadas:
        rel.motivo = M_SEM_ASSINATURA
        rel.avisos.append("manifesto sha256-<hex>.sig ausente ou sem camadas (assinaturas no formato novo "
                           "do cosign, bundle via OCI referrers, não são suportadas)")
        return rel
    for camada in camadas:
        b64 = ev.get("payloads", {}).get(camada.get("digest"))
        payload = base64.b64decode(b64) if b64 is not None else None
        rel.assinaturas.append(verifica_camada(camada, payload, ev.get("rekor", {}), digest_esperado,
                                               identidade, emissor, raiz, modo_ecdsa))
    validas = [a for a in rel.assinaturas if a.valida]
    rel.valida = bool(validas)
    rel.motivo = None if rel.valida else rel.assinaturas[0].motivo
    return rel


# ---- saída em texto ---------------------------------------------------------------------
def formata(rel: Relatorio) -> str:
    L = [f"Imagem:              {rel.imagem}@{rel.digest}",
         f"Identidade esperada: {rel.identidade}",
         f"Emissor esperado:    {rel.emissor}",
         f"trusted_root:        sha256 {rel.trusted_root_sha256[:16]}…   ECDSA: {rel.ecdsa}"]
    for a in rel.avisos:
        L.append(f"aviso: {a}")
    for i, s in enumerate(rel.assinaturas, 1):
        L.append("")
        L.append(f"Assinatura {i}/{len(rel.assinaturas)} (camada {s.camada[:19]}…): "
                 + ("VÁLIDA" if s.valida else f"REJEITADA — {s.motivo}"))
        for e in s.etapas:
            marca = {True: "ok   ", False: "FALHA", None: "  -  "}[e.ok]
            L.append(f"  [{marca}] {e.nome:<20} {e.detalhe}")
        c = s.info.get("certificado")
        if c:
            L.append(f"  certificado: serial {c['serial'][:16]}…, válido [{c['not_before']}, {c['not_after']}]")
            for oid, v in c["extensoes"].items():
                L.append(f"    {oid:<24} {v['nome']:<40} {v['valor']}")
        r = s.info.get("rekor")
        if r:
            L.append(f"  rekor: logIndex {r['logIndex']} (na árvore: {r['logIndex_na_arvore']} de "
                     f"{r['treeSize']}), integrado em {r['integratedTime_utc']}, uuid {str(r['uuid'])[:24]}…")
        for a in s.avisos:
            L.append(f"  aviso: {a}")
    L.append("")
    n = sum(a.valida for a in rel.assinaturas)
    if rel.valida:
        L.append(f"RESULTADO: VÁLIDA ({n} de {len(rel.assinaturas)} assinatura(s) válida(s))")
    else:
        L.append(f"RESULTADO: REJEITADA — {rel.motivo}")
    return "\n".join(L)
