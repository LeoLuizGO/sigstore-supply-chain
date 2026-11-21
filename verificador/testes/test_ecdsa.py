"""ECDSA P-256 manual (ecdsa_p256.py) contra a biblioteca cryptography."""

import hashlib
import random

import pytest
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.utils import decode_dss_signature, encode_dss_signature

from verificador import ecdsa_p256 as E
from verificador.verifica import ecdsa_verifica


def _q(chave):
    return chave.public_key().public_bytes(serialization.Encoding.X962,
                                           serialization.PublicFormat.UncompressedPoint)


def test_parametros_da_curva():
    assert E.esta_na_curva(E.G)
    assert E.multiplica(E.N, E.G) is E.INFINITO          # n·G = O
    assert E.multiplica(E.N - 1, E.G) == (E.GX, (-E.GY) % E.P)  # (n-1)·G = -G
    assert E.soma(E.G, E.multiplica(E.N - 1, E.G)) is E.INFINITO


def test_vetor_rfc6979_a25():
    """RFC 6979, A.2.5 (P-256, SHA-256, mensagem "sample")."""
    d = 0xC9AFA9D845BA75166B5C215767B1D6934E50C3DB36E89B127B8A622B120F6721
    k = 0xA6E3C57DD01ABE90086538398355DD4C3B17AA873382B0F24D6129493D8AAD60
    q = E.multiplica(d, E.G)
    assert q == (0x60FED4BA255A9D31C961EB74C6356D68C049B8923B61FA6CE669622E60F29FB6,
                 0x7903FE1008B8BC99A41AE9E95628BC64F2F1B20C2D7E9F5177A3C294D4462299)
    r, s = E.assina_didatico(d, b"sample", k)
    assert r == 0xEFD48B2AACB6A8FD1140DD9CD45E81D69D2C877B56AAF991C34D0EA84EAF3716
    assert s == 0xF7CB1C942D657C41D436C7A1B6E29F65F3E900DBB9AFF4064DC4AB2F843ACDA8
    der = E.codifica_der_assinatura(r, s)
    assert E.verifica(q, b"sample", der)
    pub = ec.EllipticCurvePublicNumbers(q[0], q[1], ec.SECP256R1()).public_key()
    pub.verify(der, b"sample", ec.ECDSA(hashes.SHA256()))   # a biblioteca também aceita


@pytest.mark.parametrize("semente", range(40))
def test_aleatorio_manual_igual_biblioteca(semente):
    rnd = random.Random(semente)
    chave = ec.generate_private_key(ec.SECP256R1())
    msg = rnd.randbytes(rnd.randint(0, 300))
    der = chave.sign(msg, ec.ECDSA(hashes.SHA256()))
    pub = chave.public_key()
    # válida
    assert E.verifica(_q(chave), msg, der)
    assert ecdsa_verifica(pub, der, msg, "ambos")[0]
    # mensagem alterada em 1 bit
    if msg:
        m2 = bytearray(msg)
        m2[rnd.randrange(len(m2))] ^= 1 << rnd.randrange(8)
        assert not E.verifica(_q(chave), bytes(m2), der)
        assert not ecdsa_verifica(pub, der, bytes(m2), "ambos")[0]
    # assinatura alterada: r+1 e s+1 (DER continua válido)
    r, s = decode_dss_signature(der)
    for r2, s2 in ((r + 1, s), (r, s + 1), (r, E.N - s)):
        der2 = encode_dss_signature(r2 % E.N or 1, s2 % E.N or 1)
        esperado = (r2, s2) == (r, E.N - s)  # (r, n-s) também é válida (maleabilidade do ECDSA)
        assert E.verifica(_q(chave), msg, der2) is esperado
        assert ecdsa_verifica(pub, der2, msg, "ambos")[0] is esperado
    # 1 bit qualquer do DER: as duas implementações têm de concordar (DivergenciaECDSA se não)
    b = bytearray(der)
    b[rnd.randrange(len(b))] ^= 1 << rnd.randrange(8)
    ok, _ = ecdsa_verifica(pub, bytes(b), msg, "ambos")
    assert not ok or bytes(b) == der
    # outra chave
    outra = ec.generate_private_key(ec.SECP256R1())
    assert not E.verifica(_q(outra), msg, der)


def test_assinatura_manual_aceita_pela_biblioteca():
    chave = ec.generate_private_key(ec.SECP256R1())
    d = chave.private_numbers().private_value
    for k in (3, 2**200 + 7, E.N - 2):
        r, s = E.assina_didatico(d, b"payload", k)
        chave.public_key().verify(E.codifica_der_assinatura(r, s), b"payload", ec.ECDSA(hashes.SHA256()))


def test_reuso_do_nonce_revela_a_chave():
    """Seção 2.3: com o mesmo k em duas mensagens, k e d saem por álgebra."""
    d, k = 0x1234567890ABCDEF ** 3 % E.N, 0xDEADBEEF ** 5 % E.N
    m1, m2 = b"mensagem 1", b"mensagem 2"
    r1, s1 = E.assina_didatico(d, m1, k)
    r2, s2 = E.assina_didatico(d, m2, k)
    assert r1 == r2
    e1 = int.from_bytes(hashlib.sha256(m1).digest(), "big")
    e2 = int.from_bytes(hashlib.sha256(m2).digest(), "big")
    k_rec = (e1 - e2) * pow(s1 - s2, -1, E.N) % E.N
    d_rec = (s1 * k_rec - e1) * pow(r1, -1, E.N) % E.N
    assert (k_rec, d_rec) == (k, d)


def test_r_s_fora_da_faixa():
    chave = ec.generate_private_key(ec.SECP256R1())
    for r, s in ((0, 1), (1, 0), (E.N, 1), (1, E.N)):
        assert not E.verifica(_q(chave), b"x", E.codifica_der_assinatura(r, s))
        with pytest.raises(InvalidSignature):
            chave.public_key().verify(E.codifica_der_assinatura(r, s), b"x", ec.ECDSA(hashes.SHA256()))


def test_der_malformado():
    with pytest.raises(E.ErroECDSA):
        E.decodifica_der_assinatura(b"\x30\x06\x02\x01\x01\x02\x01")       # truncado
    with pytest.raises(E.ErroECDSA):
        E.decodifica_der_assinatura(b"\x30\x07\x02\x02\x00\x01\x02\x01\x01")  # zero à esquerda
    with pytest.raises(E.ErroECDSA):
        E.decodifica_der_assinatura(b"\x30\x06\x02\x01\x01\x02\x01\x01\x00")  # byte sobrando
    assert E.decodifica_der_assinatura(b"\x30\x06\x02\x01\x01\x02\x01\x02") == (1, 2)


def test_ponto_fora_da_curva():
    with pytest.raises(E.ErroECDSA):
        E.decodifica_ponto(b"\x04" + (1).to_bytes(32, "big") + (1).to_bytes(32, "big"))
