"""Árvore de Merkle da RFC 6962 / RFC 9162 (a mesma usada pelo Rekor v1).

  leaf(d)    = SHA-256(0x00 ‖ d)
  node(l, r) = SHA-256(0x01 ‖ l ‖ r)

`verifica_inclusao` é a tradução literal do pseudocódigo VERIFICA_INCLUSAO da Seção 3.3
do relatório (RFC 9162, Seção 2.1.3.2). `raiz_referencia` e `prova_referencia` montam a
árvore inteira (definições recursivas MTH e PATH da RFC 6962, Seção 2.1) e servem só
como implementação de referência nos testes e no cenário sintético.
"""

from __future__ import annotations

import hashlib


def hash_folha(dados: bytes) -> bytes:
    return hashlib.sha256(b"\x00" + dados).digest()


def hash_no(esquerda: bytes, direita: bytes) -> bytes:
    return hashlib.sha256(b"\x01" + esquerda + direita).digest()


def calcula_raiz(folha: bytes, indice: int, tamanho: int, prova: list[bytes],
                 rastro: list | None = None) -> bytes | None:
    """Recalcula a raiz a partir da folha e do caminho; None se a prova for estruturalmente inválida."""
    if indice >= tamanho or indice < 0:
        return None
    fn = indice
    sn = tamanho - 1
    r = folha
    for p in prova:
        if sn == 0:
            return None                      # prova longa demais
        if fn % 2 == 1 or fn == sn:
            r = hash_no(p, r)                # r é filho da direita
            if rastro is not None:
                rastro.append(("node(p, r)", r.hex()))
            if fn % 2 == 0:
                # fn == sn e fn par: o nó é o último e sobe sem irmão; pula níveis
                while not (fn % 2 == 1 or fn == 0):
                    fn >>= 1
                    sn >>= 1
        else:
            r = hash_no(r, p)                # r é filho da esquerda
            if rastro is not None:
                rastro.append(("node(r, p)", r.hex()))
        fn >>= 1
        sn >>= 1
    if sn != 0:
        return None                          # prova curta demais
    return r


def verifica_inclusao(folha: bytes, indice: int, tamanho: int, prova: list[bytes],
                      raiz: bytes) -> bool:
    """VERIFICA_INCLUSAO(folha, indice, tamanho, prova, raiz) da Seção 3.3."""
    r = calcula_raiz(folha, indice, tamanho, prova)
    return r is not None and r == raiz


# ---- implementação de referência (monta a árvore inteira) ------------------------------
def _maior_potencia_de_2_menor_que(n: int) -> int:
    k = 1
    while k * 2 < n:
        k *= 2
    return k


def raiz_referencia(folhas: list[bytes]) -> bytes:
    """MTH(D[n]) da RFC 6962 §2.1, sobre hashes de folha já calculados."""
    n = len(folhas)
    if n == 0:
        return hashlib.sha256(b"").digest()
    if n == 1:
        return folhas[0]
    k = _maior_potencia_de_2_menor_que(n)
    return hash_no(raiz_referencia(folhas[:k]), raiz_referencia(folhas[k:]))


def prova_referencia(folhas: list[bytes], m: int) -> list[bytes]:
    """PATH(m, D[n]) da RFC 6962 §2.1.1: hashes irmãos da folha m até a raiz."""
    n = len(folhas)
    if n <= 1:
        return []
    k = _maior_potencia_de_2_menor_que(n)
    if m < k:
        return prova_referencia(folhas[:k], m) + [raiz_referencia(folhas[k:])]
    return prova_referencia(folhas[k:], m - k) + [raiz_referencia(folhas[:k])]
