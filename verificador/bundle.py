"""Converte uma assinatura da evidência para um bundle Sigstore v0.3 (JSON do protobuf-specs).

Serve para o cross-check com o sigstore-python:
    sigstore verify identity --bundle X.sigstore.json --cert-identity SAN \
        --cert-oidc-issuer ISSUER payload.json
O "artefato" do bundle é o payload simple signing (é sobre ele que o hashedrekord foi feito).
"""

from __future__ import annotations

import base64
import hashlib
import json

from cryptography.hazmat.primitives import serialization

from .certificado import carrega_pem
from .verifica import ANOT_ASSINATURA, ANOT_BUNDLE, ANOT_CERT

TIPO_BUNDLE_V03 = "application/vnd.dev.sigstore.bundle.v0.3+json"


def _hex_para_b64(h: str) -> str:
    return base64.b64encode(bytes.fromhex(h)).decode()


def exporta(ev: dict, indice_camada: int = 0) -> tuple[dict, bytes]:
    """Retorna (bundle v0.3, bytes do payload) da camada `indice_camada` da evidência."""
    camadas = ev["manifesto_sig"]["conteudo"]["layers"]
    camada = camadas[indice_camada]
    anot = camada["annotations"]
    payload = base64.b64decode(ev["payloads"][camada["digest"]])
    log_index = json.loads(anot[ANOT_BUNDLE])["Payload"]["logIndex"]
    uuid, entrada = next(iter(ev["rekor"][str(log_index)].items()))
    prova = entrada["verification"]["inclusionProof"]
    corpo = json.loads(base64.b64decode(entrada["body"]))
    cert = carrega_pem(anot[ANOT_CERT])
    bundle = {
        "mediaType": TIPO_BUNDLE_V03,
        "verificationMaterial": {
            "certificate": {"rawBytes": base64.b64encode(
                cert.public_bytes(serialization.Encoding.DER)).decode()},
            "tlogEntries": [{
                "logIndex": str(entrada["logIndex"]),
                "logId": {"keyId": _hex_para_b64(entrada["logID"])},
                "kindVersion": {"kind": corpo["kind"], "version": corpo["apiVersion"]},
                "integratedTime": str(entrada["integratedTime"]),
                "inclusionPromise": {
                    "signedEntryTimestamp": entrada["verification"]["signedEntryTimestamp"]},
                "inclusionProof": {
                    "logIndex": str(prova["logIndex"]),
                    "rootHash": _hex_para_b64(prova["rootHash"]),
                    "treeSize": str(prova["treeSize"]),
                    "hashes": [_hex_para_b64(h) for h in prova["hashes"]],
                    "checkpoint": {"envelope": prova["checkpoint"]},
                },
                "canonicalizedBody": entrada["body"],
            }],
        },
        "messageSignature": {
            "messageDigest": {"algorithm": "SHA2_256",
                              "digest": base64.b64encode(hashlib.sha256(payload).digest()).decode()},
            "signature": anot[ANOT_ASSINATURA],
        },
    }
    return bundle, payload


def exporta_bundle_cosign(ev: dict, indice_camada: int = 0) -> tuple[dict, bytes]:
    """Bundle "legado" do cosign (LocalSignedPayload) para `cosign verify-blob --bundle`:
    {base64Signature, cert (base64 do PEM), rekorBundle {SignedEntryTimestamp, Payload}}.
    Repare que ele NÃO tem prova de inclusão: o cosign confia no SET."""
    camada = ev["manifesto_sig"]["conteudo"]["layers"][indice_camada]
    anot = camada["annotations"]
    payload = base64.b64decode(ev["payloads"][camada["digest"]])
    return {
        "base64Signature": anot[ANOT_ASSINATURA],
        "cert": base64.b64encode(anot[ANOT_CERT].encode()).decode(),
        "rekorBundle": json.loads(anot[ANOT_BUNDLE]),
    }, payload
