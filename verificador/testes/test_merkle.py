"""Prova de inclusão (RFC 9162 §2.1.3.2) — mini-exemplo da Seção 2.8 e árvores de vários tamanhos."""

import random

import pytest

from verificador import merkle

# Valores da tabela da Seção 2.8 do relatório (16 primeiros dígitos hex)
TABELA = {
    "h0": "475dca70c1ec1537", "h1": "75f91a0150c85497", "h2": "44fb37b9be8db9bd",
    "h3": "4f18cddc25d2c1c1", "h01": "b2489a497d57cf8b", "h23": "af7a3e6321199414",
    "raiz": "5d5487109c0530dd",
}


def _mini():
    h = [merkle.hash_folha(f"entrada-{i}".encode()) for i in range(4)]
    h01, h23 = merkle.hash_no(h[0], h[1]), merkle.hash_no(h[2], h[3])
    return h, h01, h23, merkle.hash_no(h01, h23)


def test_mini_exemplo_tabela():
    h, h01, h23, raiz = _mini()
    calculado = {"h0": h[0], "h1": h[1], "h2": h[2], "h3": h[3], "h01": h01, "h23": h23, "raiz": raiz}
    for nome, prefixo in TABELA.items():
        assert calculado[nome].hex()[:16] == prefixo, nome


def test_mini_exemplo_prova_do_indice_2():
    h, h01, _, raiz = _mini()
    rastro = []
    r = merkle.calcula_raiz(h[2], 2, 4, [h[3], h01], rastro)
    # passos do "Processamento" da Seção 2.8
    assert rastro[0] == ("node(r, p)", merkle.hash_no(h[2], h[3]).hex())
    assert rastro[0][1][:16] == "af7a3e6321199414"
    assert rastro[1][0] == "node(p, r)"
    assert r == raiz and r.hex()[:16] == "5d5487109c0530dd"
    assert merkle.verifica_inclusao(h[2], 2, 4, [h[3], h01], raiz)
    assert merkle.raiz_referencia(h) == raiz
    assert merkle.prova_referencia(h, 2) == [h[3], h01]


def test_mini_exemplo_adulteracao():
    h, h01, _, raiz = _mini()
    falsa = merkle.hash_folha(b"entrada-2X")
    r = merkle.calcula_raiz(falsa, 2, 4, [h[3], h01])
    assert r.hex()[:16] == "fccd9c1003019f3e"
    assert not merkle.verifica_inclusao(falsa, 2, 4, [h[3], h01], raiz)


@pytest.mark.parametrize("n", list(range(1, 34)) + [63, 64, 65, 100, 127, 129, 1000])
def test_todos_os_indices_contra_referencia(n):
    folhas = [merkle.hash_folha(f"folha {i} de {n}".encode()) for i in range(n)]
    raiz = merkle.raiz_referencia(folhas)
    indices = range(n) if n <= 129 else random.Random(n).sample(range(n), 60)
    for i in indices:
        prova = merkle.prova_referencia(folhas, i)
        assert merkle.calcula_raiz(folhas[i], i, n, prova) == raiz
        assert merkle.verifica_inclusao(folhas[i], i, n, prova, raiz)
        # índice errado, tamanho errado, hash alterado, prova curta/longa: tudo falha
        if n > 1:
            assert not merkle.verifica_inclusao(folhas[i], (i + 1) % n, n, prova, raiz)
            assert not merkle.verifica_inclusao(folhas[(i + 1) % n], i, n, prova, raiz)
        if prova:
            alterada = list(prova)
            alterada[-1] = bytes([alterada[-1][0] ^ 1]) + alterada[-1][1:]
            assert not merkle.verifica_inclusao(folhas[i], i, n, alterada, raiz)
            assert not merkle.verifica_inclusao(folhas[i], i, n, prova[:-1], raiz)
        assert not merkle.verifica_inclusao(folhas[i], i, n, prova + [raiz], raiz)
        # Obs.: a mesma prova pode valer para outro tamanho (ex.: n=5 -> 6, índice 0). Por isso o
        # tamanho tem de vir do checkpoint ASSINADO, junto com a raiz.


def test_tamanho_diferente_nao_aceita_mesma_prova():
    folhas = [merkle.hash_folha(bytes([i])) for i in range(7)]
    raiz = merkle.raiz_referencia(folhas)
    prova = merkle.prova_referencia(folhas, 6)  # último nó, "sobe sem irmão"
    assert merkle.verifica_inclusao(folhas[6], 6, 7, prova, raiz)
    assert not merkle.verifica_inclusao(folhas[6], 6, 8, prova, raiz)
    assert not merkle.verifica_inclusao(folhas[6], 6, 6, prova, raiz)


def test_indice_fora_da_arvore():
    f = merkle.hash_folha(b"x")
    assert merkle.calcula_raiz(f, 1, 1, []) is None
    assert merkle.calcula_raiz(f, -1, 4, []) is None
    assert merkle.verifica_inclusao(f, 0, 1, [], f)   # árvore de 1 folha: raiz = folha


def test_prefixos_de_dominio():
    # leaf e node usam prefixos diferentes: um nó interno não é aceito como folha
    a, b = merkle.hash_folha(b"a"), merkle.hash_folha(b"b")
    assert merkle.hash_folha(a + b) != merkle.hash_no(a, b)
