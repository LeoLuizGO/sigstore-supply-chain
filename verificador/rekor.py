"""Acesso (somente leitura) ao Rekor v1 e utilidades sobre as entradas."""

from __future__ import annotations

import json

import requests

REKOR_PADRAO = "https://rekor.sigstore.dev"
TIMEOUT = 30


class ErroRekor(Exception):
    pass


def busca_por_indice(log_index: int, url: str = REKOR_PADRAO,
                     sessao: requests.Session | None = None) -> dict:
    """GET /api/v1/log/entries?logIndex=N -> {uuid: {body, integratedTime, logID, logIndex,
    verification: {inclusionProof, signedEntryTimestamp}}}.

    O `logIndex` pedido é o índice GLOBAL (somado sobre todos os shards). O índice dentro da
    árvore atual vem em verification.inclusionProof.logIndex."""
    s = sessao or requests
    try:
        r = s.get(f"{url.rstrip('/')}/api/v1/log/entries", params={"logIndex": log_index},
                  timeout=TIMEOUT)
    except requests.RequestException as e:
        raise ErroRekor(f"erro de rede no Rekor: {e}") from e
    if r.status_code != 200:
        raise ErroRekor(f"Rekor respondeu HTTP {r.status_code}: {r.text[:200]}")
    dados = r.json()
    if not isinstance(dados, dict) or len(dados) != 1:
        raise ErroRekor("resposta inesperada do Rekor (esperado um objeto com 1 entrada)")
    return dados


def payload_set(body: str, integrated_time: int, log_id: str, log_index: int) -> bytes:
    """Bytes assinados no SignedEntryTimestamp (SET): JSON canônico (chaves ordenadas, sem
    espaços; equivale ao RFC 8785 para estes valores) de {body, integratedTime, logID, logIndex}."""
    return json.dumps({"body": body, "integratedTime": integrated_time, "logID": log_id,
                       "logIndex": log_index}, sort_keys=True, separators=(",", ":")).encode()
