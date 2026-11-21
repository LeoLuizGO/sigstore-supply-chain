"""Verificação ECDSA P-256/SHA-256 em Python puro (implementação didática).

Segue exatamente os passos da Seção 2.3 do relatório:
  1. verificar que r e s estão em [1, n-1];
  2. e = H(m) como inteiro; w = s^-1 mod n;
  3. u1 = e·w mod n; u2 = r·w mod n;
  4. X = u1·G + u2·Q;
  5. aceitar sse X não é o ponto no infinito e x(X) mod n == r.

Não use isto em produção: não é tempo constante (para *verificar* isso não é um
problema, pois só há dados públicos envolvidos) e é ~1000x mais lento que a
implementação em C da biblioteca `cryptography`. Serve para mostrar que não há
"mágica" na verificação e para conferir a biblioteca.
"""

from __future__ import annotations

import hashlib

# ---- Parâmetros da curva NIST P-256 (secp256r1), FIPS 186-4 / SEC 2 ---------------------
# Curva y^2 = x^3 + a·x + b sobre o corpo primo F_p
P = 0xFFFFFFFF00000001000000000000000000000000FFFFFFFFFFFFFFFFFFFFFFFF
A = P - 3
B = 0x5AC635D8AA3A93E7B3EBBD55769886BC651D06B0CC53B0F63BCE3C3E27D2604B
# Ponto gerador G e sua ordem prima n (cofator h = 1)
GX = 0x6B17D1F2E12C4247F8BCE6E563A440F277037D812DEB33A0F4A13945D898C296
GY = 0x4FE342E2FE1A7F9B8EE7EB4A7C0F9E162BCE33576B315ECECBB6406837BF51F5
N = 0xFFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551

G = (GX, GY)
INFINITO = None  # elemento neutro do grupo (ponto no infinito)


class ErroECDSA(ValueError):
    """Entrada malformada (DER inválido, ponto fora da curva etc.)."""


# ---- Aritmética de pontos (coordenadas afins) --------------------------------------
def inverso(x: int, m: int) -> int:
    """Inverso multiplicativo mod m (m primo). pow(x, -1, m) usa o algoritmo de Euclides
    estendido; daria o mesmo resultado que x^(m-2) mod m (pequeno teorema de Fermat)."""
    if x % m == 0:
        raise ZeroDivisionError("zero não tem inverso")
    return pow(x, -1, m)


def esta_na_curva(ponto) -> bool:
    if ponto is INFINITO:
        return True
    x, y = ponto
    return 0 <= x < P and 0 <= y < P and (y * y - (x * x * x + A * x + B)) % P == 0


def soma(p1, p2):
    """Soma de pontos P1 + P2 (regra da corda e da tangente)."""
    if p1 is INFINITO:
        return p2
    if p2 is INFINITO:
        return p1
    x1, y1 = p1
    x2, y2 = p2
    if x1 == x2:
        if (y1 + y2) % P == 0:
            return INFINITO          # P + (-P) = O
        return dobra(p1)             # P + P
    lam = (y2 - y1) * inverso(x2 - x1, P) % P       # inclinação da corda
    x3 = (lam * lam - x1 - x2) % P
    y3 = (lam * (x1 - x3) - y1) % P
    return (x3, y3)


def dobra(p1):
    """Dobra de ponto 2·P (reta tangente)."""
    if p1 is INFINITO:
        return INFINITO
    x1, y1 = p1
    if y1 == 0:
        return INFINITO
    lam = (3 * x1 * x1 + A) * inverso(2 * y1, P) % P  # inclinação da tangente
    x3 = (lam * lam - 2 * x1) % P
    y3 = (lam * (x1 - x3) - y1) % P
    return (x3, y3)


def multiplica(k: int, ponto):
    """Multiplicação escalar k·P pelo método "dobra e soma" (bits do mais significativo)."""
    resultado = INFINITO
    for bit in bin(k)[2:]:
        resultado = dobra(resultado)
        if bit == "1":
            resultado = soma(resultado, ponto)
    return resultado


# ---- Codificações ---------------------------------------------------------------------
def decodifica_der_assinatura(der: bytes) -> tuple[int, int]:
    """Decodifica a assinatura DER: SEQUENCE { INTEGER r, INTEGER s } (X9.62/RFC 3279)."""
    def le_tamanho(buf: bytes, i: int) -> tuple[int, int]:
        if i >= len(buf):
            raise ErroECDSA("DER truncado")
        t = buf[i]
        i += 1
        if t < 0x80:
            return t, i
        n = t & 0x7F
        if n == 0 or n > 2 or i + n > len(buf):
            raise ErroECDSA("tamanho DER inválido")
        valor = int.from_bytes(buf[i:i + n], "big")
        if valor < 0x80:
            raise ErroECDSA("tamanho DER não mínimo")
        return valor, i + n

    def le_inteiro(buf: bytes, i: int) -> tuple[int, int]:
        if i >= len(buf) or buf[i] != 0x02:
            raise ErroECDSA("esperado INTEGER (0x02)")
        tam, i = le_tamanho(buf, i + 1)
        if tam == 0 or i + tam > len(buf):
            raise ErroECDSA("INTEGER com tamanho inválido")
        bruto = buf[i:i + tam]
        if bruto[0] & 0x80:
            raise ErroECDSA("INTEGER negativo")
        if tam > 1 and bruto[0] == 0 and not (bruto[1] & 0x80):
            raise ErroECDSA("INTEGER com zero à esquerda desnecessário")
        return int.from_bytes(bruto, "big"), i + tam

    if len(der) < 8 or der[0] != 0x30:
        raise ErroECDSA("esperado SEQUENCE (0x30)")
    tam, i = le_tamanho(der, 1)
    if i + tam != len(der):
        raise ErroECDSA("tamanho da SEQUENCE não confere / bytes sobrando")
    r, i = le_inteiro(der, i)
    s, i = le_inteiro(der, i)
    if i != len(der):
        raise ErroECDSA("bytes sobrando após (r, s)")
    return r, s


def decodifica_ponto(dados: bytes):
    """Chave pública no formato SEC1 não comprimido: 0x04 ‖ X (32 bytes) ‖ Y (32 bytes)."""
    if len(dados) != 65 or dados[0] != 0x04:
        raise ErroECDSA("ponto não está no formato não comprimido de 65 bytes")
    q = (int.from_bytes(dados[1:33], "big"), int.from_bytes(dados[33:], "big"))
    if not esta_na_curva(q):
        raise ErroECDSA("ponto Q fora da curva P-256")
    return q


# ---- Verificação ------------------------------------------------------------------------
def verifica(q, mensagem: bytes, assinatura_der: bytes, passos: list | None = None) -> bool:
    """Verifica (r, s) sobre `mensagem` com a chave pública Q.

    `q` pode ser a tupla (x, y) ou os 65 bytes SEC1. Se `passos` for uma lista,
    os valores intermediários são anexados a ela (para o modo didático da CLI)."""
    if isinstance(q, (bytes, bytearray)):
        q = decodifica_ponto(bytes(q))
    elif not esta_na_curva(q) or q is INFINITO:
        raise ErroECDSA("ponto Q inválido")
    r, s = decodifica_der_assinatura(assinatura_der)
    anota = passos.append if passos is not None else (lambda _x: None)
    anota(("r", r))
    anota(("s", s))
    # 1. r, s em [1, n-1]
    if not (1 <= r < N and 1 <= s < N):
        anota(("faixa", "r ou s fora de [1, n-1]"))
        return False
    # 2. e = H(m) (SHA-256 tem 256 bits = tamanho de n, então não há truncamento)
    e = int.from_bytes(hashlib.sha256(mensagem).digest(), "big")
    w = inverso(s, N)
    # 3.
    u1 = e * w % N
    u2 = r * w % N
    anota(("e", e))
    anota(("w", w))
    anota(("u1", u1))
    anota(("u2", u2))
    # 4. X = u1·G + u2·Q
    x_ponto = soma(multiplica(u1, G), multiplica(u2, q))
    if x_ponto is INFINITO:
        anota(("X", "infinito"))
        return False
    anota(("X.x", x_ponto[0]))
    # 5. x(X) mod n == r
    return x_ponto[0] % N == r


def assina_didatico(d: int, mensagem: bytes, k: int) -> tuple[int, int]:
    """Assinatura ECDSA "de livro" (só para testes; o nonce k é fornecido pelo chamador).
    NUNCA reutilize k: veja a Seção 2.3 do relatório (caso PS3)."""
    e = int.from_bytes(hashlib.sha256(mensagem).digest(), "big")
    x1, _ = multiplica(k, G)
    r = x1 % N
    s = inverso(k, N) * (e + r * d) % N
    if r == 0 or s == 0:
        raise ValueError("escolha outro k")
    return r, s


def codifica_der_assinatura(r: int, s: int) -> bytes:
    def inteiro(v: int) -> bytes:
        b = v.to_bytes((v.bit_length() + 7) // 8 or 1, "big")
        if b[0] & 0x80:
            b = b"\x00" + b
        return b"\x02" + bytes([len(b)]) + b
    corpo = inteiro(r) + inteiro(s)
    return b"\x30" + bytes([len(corpo)]) + corpo
