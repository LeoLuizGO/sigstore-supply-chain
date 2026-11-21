"""Cenário sintético completo e offline: uma "mini-infraestrutura Sigstore" falsa.

Gera, com chaves novas a cada chamada:
  * AC raiz e intermediária (ECDSA P-384, como as do Fulcio) e um certificado folha P-256
    com SAN, EKU codeSigning e as extensões 1.3.6.1.4.1.57264.1.* do Fulcio;
  * o payload simple signing e a assinatura ECDSA;
  * um "Rekor" de teste: chave do log (P-256), uma árvore de Merkle com várias entradas
    hashedrekord (a nossa e outras), checkpoint assinado, prova de inclusão e SET;
  * o manifesto `.sig` com as anotações do cosign e um trusted_root.json de teste.
O resultado tem exatamente o mesmo formato da evidência baixada de um registry real, então o
mesmo código de verificação é exercitado. Nada aqui é publicado em lugar nenhum.
"""

from __future__ import annotations

import base64
import copy
import hashlib
import json
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID

from . import merkle
from .evidencia import FORMATO
from .rekor import payload_set

IMAGEM = "ghcr.io/leoluizgo/sigstore-supply-chain"
DIGEST = "sha256:" + hashlib.sha256(b"imagem sintetica legitima").hexdigest()
OUTRO_DIGEST = "sha256:" + hashlib.sha256(b"imagem sintetica maliciosa").hexdigest()
EMISSOR = "https://token.actions.githubusercontent.com"
REPO = "https://github.com/LeoLuizGO/sigstore-supply-chain"
IDENTIDADE = f"{REPO}/.github/workflows/pipeline.yml@refs/heads/main"
IDENTIDADE_ATAQUES = f"{REPO}/.github/workflows/ataques.yml@refs/heads/main"
ORIGEM_LOG = "rekor.teste.ufsc"
TREE_ID = 4242
DESLOCAMENTO_SHARDS = 100_000   # índice global = índice na árvore + entradas de shards antigos
T0 = datetime(2026, 11, 20, 12, 0, 0, tzinfo=timezone.utc)


def _utf8string_der(s: str) -> bytes:
    b = s.encode()
    if len(b) < 0x80:
        return b"\x0c" + bytes([len(b)]) + b
    n = (len(b).bit_length() + 7) // 8
    return b"\x0c" + bytes([0x80 | n]) + len(b).to_bytes(n, "big") + b


def _b64(b: bytes) -> str:
    return base64.b64encode(b).decode()


def _der_pub(chave) -> bytes:
    return chave.public_key().public_bytes(serialization.Encoding.DER,
                                           serialization.PublicFormat.SubjectPublicKeyInfo)


def _cria_ac(nome: str, chave, emissor_nome=None, chave_emissor=None, pathlen=None):
    sujeito = x509.Name([x509.NameAttribute(NameOID.ORGANIZATION_NAME, "teste.ufsc"),
                         x509.NameAttribute(NameOID.COMMON_NAME, nome)])
    b = (x509.CertificateBuilder()
         .subject_name(sujeito)
         .issuer_name(emissor_nome or sujeito)
         .public_key(chave.public_key())
         .serial_number(x509.random_serial_number())
         .not_valid_before(datetime(2020, 1, 1, tzinfo=timezone.utc))
         .not_valid_after(datetime(2035, 1, 1, tzinfo=timezone.utc))
         .add_extension(x509.BasicConstraints(ca=True, path_length=pathlen), critical=True)
         .add_extension(x509.KeyUsage(digital_signature=False, content_commitment=False,
                                      key_encipherment=False, data_encipherment=False,
                                      key_agreement=False, key_cert_sign=True, crl_sign=True,
                                      encipher_only=False, decipher_only=False), critical=True))
    return b.sign(chave_emissor or chave, hashes.SHA384())


def _cria_folha(chave_folha, inter_cert, inter_chave, identidade: str, emissor: str,
                inicio: datetime, eku: bool = True):
    def ext(n: int, valor: bytes):
        return x509.UnrecognizedExtension(x509.ObjectIdentifier(f"1.3.6.1.4.1.57264.1.{n}"), valor)
    commit = hashlib.sha1(b"commit sintetico").hexdigest()
    b = (x509.CertificateBuilder()
         .subject_name(x509.Name([]))
         .issuer_name(inter_cert.subject)
         .public_key(chave_folha.public_key())
         .serial_number(x509.random_serial_number())
         .not_valid_before(inicio)
         .not_valid_after(inicio + timedelta(minutes=10))
         .add_extension(x509.KeyUsage(digital_signature=True, content_commitment=False,
                                      key_encipherment=False, data_encipherment=False,
                                      key_agreement=False, key_cert_sign=False, crl_sign=False,
                                      encipher_only=False, decipher_only=False), critical=True)
         .add_extension(x509.SubjectAlternativeName([x509.UniformResourceIdentifier(identidade)]),
                        critical=True)
         .add_extension(ext(1, emissor.encode()), critical=False)
         .add_extension(ext(8, _utf8string_der(emissor)), critical=False)
         .add_extension(ext(9, _utf8string_der(identidade)), critical=False)
         .add_extension(ext(10, _utf8string_der(commit)), critical=False)
         .add_extension(ext(11, _utf8string_der("github-hosted")), critical=False)
         .add_extension(ext(12, _utf8string_der(REPO)), critical=False)
         .add_extension(ext(13, _utf8string_der(commit)), critical=False)
         .add_extension(ext(14, _utf8string_der("refs/heads/main")), critical=False)
         .add_extension(ext(20, _utf8string_der("push")), critical=False)
         .add_extension(ext(21, _utf8string_der(f"{REPO}/actions/runs/1/attempts/1")), critical=False))
    if eku:
        b = b.add_extension(x509.ExtendedKeyUsage([ExtendedKeyUsageOID.CODE_SIGNING]), critical=False)
    return b.sign(inter_chave, hashes.SHA384())


def payload_simple_signing(digest: str, imagem: str = IMAGEM) -> bytes:
    # mesma serialização do cosign (chaves em ordem alfabética, sem espaços)
    return json.dumps({"critical": {"identity": {"docker-reference": imagem},
                                    "image": {"docker-manifest-digest": digest},
                                    "type": "cosign container image signature"},
                       "optional": None}, separators=(",", ":")).encode()


def corpo_hashedrekord(payload: bytes, assinatura: bytes, cert_pem: bytes) -> bytes:
    return json.dumps({"apiVersion": "0.0.1", "kind": "hashedrekord",
                       "spec": {"data": {"hash": {"algorithm": "sha256",
                                                  "value": hashlib.sha256(payload).hexdigest()}},
                                "signature": {"content": _b64(assinatura),
                                              "publicKey": {"content": _b64(cert_pem)}}}},
                      separators=(",", ":")).encode()


@dataclass
class Cenario:
    evidencia: dict
    trusted_root: bytes
    digest: str = DIGEST
    identidade: str = IDENTIDADE
    emissor: str = EMISSOR
    chaves: dict = field(default_factory=dict)      # para as adulterações que re-assinam
    entradas: list = field(default_factory=list)    # todas as entradas do "Rekor" de teste

    def copia(self) -> "Cenario":
        return Cenario(copy.deepcopy(self.evidencia), self.trusted_root, self.digest,
                       self.identidade, self.emissor, self.chaves, self.entradas)

    # atalhos para adulterar a evidência
    @property
    def camada(self) -> dict:
        return self.evidencia["manifesto_sig"]["conteudo"]["layers"][0]

    @property
    def entrada(self) -> dict:
        return next(iter(next(iter(self.evidencia["rekor"].values())).values()))


class Log:
    """Rekor de teste: árvore de Merkle + chave do log."""

    def __init__(self):
        self.chave = ec.generate_private_key(ec.SECP256R1())
        self.der = _der_pub(self.chave)
        self.log_id = hashlib.sha256(self.der).digest()
        self.corpos: list[bytes] = []
        self.tempos: list[int] = []

    def adiciona(self, corpo: bytes, t: int) -> int:
        self.corpos.append(corpo)
        self.tempos.append(t)
        return len(self.corpos) - 1

    def checkpoint(self, tamanho: int, raiz: bytes, chave=None) -> str:
        corpo = f"{ORIGEM_LOG} - {TREE_ID}\n{tamanho}\n{_b64(raiz)}\n"
        sig = (chave or self.chave).sign(corpo.encode(), ec.ECDSA(hashes.SHA256()))
        return corpo + "\n" + f"— {ORIGEM_LOG} {_b64(self.log_id[:4] + sig)}\n"

    def entrada(self, i: int) -> dict:
        """Resposta do GET /api/v1/log/entries?logIndex=<global> para a entrada i."""
        folhas = [merkle.hash_folha(c) for c in self.corpos]
        raiz = merkle.raiz_referencia(folhas)
        prova = merkle.prova_referencia(folhas, i)
        corpo_b64 = _b64(self.corpos[i])
        global_ = i + DESLOCAMENTO_SHARDS
        set_ = self.chave.sign(payload_set(corpo_b64, self.tempos[i], self.log_id.hex(), global_),
                               ec.ECDSA(hashes.SHA256()))
        uuid = format(TREE_ID, "016x") + folhas[i].hex()
        return {uuid: {
            "body": corpo_b64, "integratedTime": self.tempos[i], "logID": self.log_id.hex(),
            "logIndex": global_,
            "verification": {
                "inclusionProof": {"checkpoint": self.checkpoint(len(folhas), raiz),
                                   "hashes": [h.hex() for h in prova], "logIndex": i,
                                   "rootHash": raiz.hex(), "treeSize": len(folhas)},
                "signedEntryTimestamp": _b64(set_)}}}


def gera(*, digest_payload: str = DIGEST, identidade_cert: str = IDENTIDADE,
         emissor_cert: str = EMISSOR, ac_conhecida: bool = True, eku: bool = True,
         segundos_apos_emissao: int = 2, n_antes: int = 5, n_depois: int = 1,
         com_certificado: bool = True, assinaturas_extras: list[dict] | None = None) -> Cenario:
    """Gera o cenário. Por padrão, tudo é legítimo; os parâmetros criam variações coerentes
    (re-assinadas) para cada motivo de rejeição. `n_antes`/`n_depois` controlam quantas
    entradas alheias ficam antes/depois da nossa (tamanho da árvore = n_antes + 1 + n_depois)."""
    raiz_chave = ec.generate_private_key(ec.SECP384R1())
    raiz_cert = _cria_ac("raiz-teste", raiz_chave, pathlen=1)
    inter_chave = ec.generate_private_key(ec.SECP384R1())
    inter_cert = _cria_ac("intermediaria-teste", inter_chave, raiz_cert.subject, raiz_chave, pathlen=0)
    log = Log()

    trusted = {
        "mediaType": "application/vnd.dev.sigstore.trustedroot+json;version=0.1",
        "tlogs": [{"baseUrl": f"https://{ORIGEM_LOG}", "hashAlgorithm": "SHA2_256",
                   "publicKey": {"rawBytes": _b64(log.der), "keyDetails": "PKIX_ECDSA_P256_SHA_256",
                                 "validFor": {"start": "2020-01-01T00:00:00Z"}},
                   "logId": {"keyId": _b64(log.log_id)}}],
        "certificateAuthorities": [{
            "subject": {"organization": "teste.ufsc", "commonName": "raiz-teste"},
            "uri": "https://fulcio.teste.ufsc",
            "certChain": {"certificates": [
                {"rawBytes": _b64(inter_cert.public_bytes(serialization.Encoding.DER))},
                {"rawBytes": _b64(raiz_cert.public_bytes(serialization.Encoding.DER))}]},
            "validFor": {"start": "2020-01-01T00:00:00Z"}}],
    }

    # Uma AC "do atacante", fora do trusted_root, com os mesmos nomes
    if not ac_conhecida:
        raiz_chave = ec.generate_private_key(ec.SECP384R1())
        raiz_cert = _cria_ac("raiz-teste", raiz_chave, pathlen=1)
        inter_chave = ec.generate_private_key(ec.SECP384R1())
        inter_cert = _cria_ac("intermediaria-teste", inter_chave, raiz_cert.subject, raiz_chave, pathlen=0)

    def entrada_alheia(k: int) -> None:
        ch = ec.generate_private_key(ec.SECP256R1())
        p = f"artefato alheio {k}".encode()
        pem = b"-----BEGIN PUBLIC KEY-----\n(teste)\n-----END PUBLIC KEY-----\n"
        log.adiciona(corpo_hashedrekord(p, ch.sign(p, ec.ECDSA(hashes.SHA256())), pem),
                     int((T0 - timedelta(minutes=30 - k)).timestamp()))

    def assinatura(digest: str, identidade: str, emissor: str, inicio: datetime, desloc: int) -> dict:
        chave = ec.generate_private_key(ec.SECP256R1())
        cert = _cria_folha(chave, inter_cert, inter_chave, identidade, emissor, inicio, eku)
        cert_pem = cert.public_bytes(serialization.Encoding.PEM)
        payload = payload_simple_signing(digest)
        sig = chave.sign(payload, ec.ECDSA(hashes.SHA256()))
        i = log.adiciona(corpo_hashedrekord(payload, sig, cert_pem), int((inicio + timedelta(seconds=desloc)).timestamp()))
        return {"chave": chave, "cert": cert, "cert_pem": cert_pem, "payload": payload, "sig": sig, "indice": i}

    for k in range(n_antes):
        entrada_alheia(k)
    principais = [assinatura(digest_payload, identidade_cert, emissor_cert, T0, segundos_apos_emissao)]
    for k, extra in enumerate(assinaturas_extras or []):
        principais.append(assinatura(extra.get("digest", DIGEST), extra.get("identidade", IDENTIDADE),
                                     extra.get("emissor", EMISSOR), T0 + timedelta(minutes=k + 1), 2))
    for k in range(n_depois):
        entrada_alheia(100 + k)

    cadeia_pem = (inter_cert.public_bytes(serialization.Encoding.PEM)
                  + raiz_cert.public_bytes(serialization.Encoding.PEM)).decode()
    camadas, payloads, rekor = [], {}, {}
    for a in principais:
        resp = log.entrada(a["indice"])
        e = next(iter(resp.values()))
        dig = "sha256:" + hashlib.sha256(a["payload"]).hexdigest()
        anot = {"dev.cosignproject.cosign/signature": _b64(a["sig"]),
                "dev.sigstore.cosign/bundle": json.dumps({
                    "SignedEntryTimestamp": e["verification"]["signedEntryTimestamp"],
                    "Payload": {"body": e["body"], "integratedTime": e["integratedTime"],
                                "logIndex": e["logIndex"], "logID": e["logID"]}}, separators=(",", ":"))}
        if com_certificado:
            anot["dev.sigstore.cosign/certificate"] = a["cert_pem"].decode()
            anot["dev.sigstore.cosign/chain"] = cadeia_pem
        camadas.append({"mediaType": "application/vnd.dev.cosign.simplesigning.v1+json",
                        "size": len(a["payload"]), "digest": dig, "annotations": anot})
        payloads[dig] = _b64(a["payload"])
        rekor[str(e["logIndex"])] = resp

    ev = {
        "formato": FORMATO, "imagem": IMAGEM, "digest": DIGEST,
        "baixado_em": T0.strftime("%Y-%m-%dT%H:%M:%SZ"), "rekor_url": f"https://{ORIGEM_LOG}",
        "manifesto_sig": {"tag": DIGEST.replace(":", "-") + ".sig", "digest": "sha256:" + "0" * 64,
                          "mediaType": "application/vnd.oci.image.manifest.v1+json",
                          "conteudo": {"schemaVersion": 2,
                                       "mediaType": "application/vnd.oci.image.manifest.v1+json",
                                       "config": {"mediaType": "application/vnd.oci.image.config.v1+json",
                                                  "size": 0, "digest": "sha256:" + "0" * 64},
                                       "layers": camadas}},
        "payloads": payloads, "rekor": rekor, "erros": [],
    }
    return Cenario(evidencia=ev, trusted_root=json.dumps(trusted, indent=1).encode(),
                   chaves={"log": log, "folha": principais[0]["chave"], "principais": principais},
                   entradas=[log.entrada(i) for i in range(len(log.corpos))])
