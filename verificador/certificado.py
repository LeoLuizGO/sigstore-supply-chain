"""Certificado folha do Fulcio: cadeia até a raiz confiável, EKU, emissor OIDC, SAN e
extensões do Sigstore (OIDs 1.3.6.1.4.1.57264.1.*)."""

from __future__ import annotations

from datetime import datetime

from cryptography import x509
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import ExtendedKeyUsageOID, ExtensionOID

from .trusted_root import AutoridadeCertificadora, RaizConfiavel

PREFIXO_OID = "1.3.6.1.4.1.57264.1."

# Nomes das extensões do Fulcio (docs/oid-info.md do repositório sigstore/fulcio).
# 1.1 a 1.6 são as antigas (valor = bytes crus); de 1.8 em diante o valor é um UTF8String DER.
EXTENSOES_FULCIO = {
    1: "Issuer (obsoleta)",
    2: "GitHub Workflow Trigger (obsoleta)",
    3: "GitHub Workflow SHA (obsoleta)",
    4: "GitHub Workflow Name (obsoleta)",
    5: "GitHub Workflow Repository (obsoleta)",
    6: "GitHub Workflow Ref (obsoleta)",
    8: "Issuer (V2)",
    9: "Build Signer URI",
    10: "Build Signer Digest",
    11: "Runner Environment",
    12: "Source Repository URI",
    13: "Source Repository Digest",
    14: "Source Repository Ref",
    15: "Source Repository Identifier",
    16: "Source Repository Owner URI",
    17: "Source Repository Owner Identifier",
    18: "Build Config URI",
    19: "Build Config Digest",
    20: "Build Trigger",
    21: "Run Invocation URI",
    22: "Source Repository Visibility At Signing",
}


class ErroCertificado(ValueError):
    pass


def carrega_pem(pem: str | bytes) -> x509.Certificate:
    if isinstance(pem, str):
        pem = pem.encode()
    return x509.load_pem_x509_certificate(pem)


def carrega_cadeia_pem(pem: str | bytes) -> list[x509.Certificate]:
    if isinstance(pem, str):
        pem = pem.encode()
    return x509.load_pem_x509_certificates(pem) if pem.strip() else []


def decodifica_utf8string_der(valor: bytes) -> str:
    """Decodifica um UTF8String DER: tag 0x0C, tamanho (forma curta ou longa), conteúdo."""
    if len(valor) < 2 or valor[0] != 0x0C:
        raise ErroCertificado("extensão não é um UTF8String DER (tag 0x0C)")
    tam = valor[1]
    i = 2
    if tam & 0x80:
        n = tam & 0x7F
        if n == 0 or n > 4 or len(valor) < 2 + n:
            raise ErroCertificado("tamanho DER inválido")
        tam = int.from_bytes(valor[2:2 + n], "big")
        i = 2 + n
    if i + tam != len(valor):
        raise ErroCertificado("tamanho do UTF8String não confere")
    return valor[i:i + tam].decode("utf-8")


def extensoes_sigstore(cert: x509.Certificate) -> dict[str, dict]:
    """Todas as extensões 1.3.6.1.4.1.57264.1.* do certificado, decodificadas."""
    saida = {}
    for ext in cert.extensions:
        oid = ext.oid.dotted_string
        if not oid.startswith(PREFIXO_OID):
            continue
        sufixo = int(oid[len(PREFIXO_OID):].split(".")[0])
        bruto = ext.value.value  # UnrecognizedExtension -> bytes do extnValue
        if sufixo >= 8:
            try:
                valor = decodifica_utf8string_der(bruto)
            except (ErroCertificado, UnicodeDecodeError):
                valor = bruto.hex()
        else:
            valor = bruto.decode("utf-8", "replace")
        saida[oid] = {"nome": EXTENSOES_FULCIO.get(sufixo, "desconhecida"), "valor": valor}
    return saida


def emissor_oidc(cert: x509.Certificate) -> tuple[str | None, str]:
    """Emissor OIDC: extensão 1.8 (UTF8String DER) com fallback para a 1.1 (bytes crus).
    Retorna (emissor, oid usado)."""
    for oid, decod in ((PREFIXO_OID + "8", decodifica_utf8string_der),
                       (PREFIXO_OID + "1", lambda b: b.decode("utf-8"))):
        try:
            ext = cert.extensions.get_extension_for_oid(x509.ObjectIdentifier(oid))
        except x509.ExtensionNotFound:
            continue
        return decod(ext.value.value), oid
    return None, ""


def identidades_san(cert: x509.Certificate) -> list[str]:
    """URIs e e-mails do Subject Alternative Name."""
    try:
        san = cert.extensions.get_extension_for_oid(ExtensionOID.SUBJECT_ALTERNATIVE_NAME).value
    except x509.ExtensionNotFound:
        return []
    return (san.get_values_for_type(x509.UniformResourceIdentifier)
            + san.get_values_for_type(x509.RFC822Name))


def tem_eku_code_signing(cert: x509.Certificate) -> bool:
    try:
        eku = cert.extensions.get_extension_for_oid(ExtensionOID.EXTENDED_KEY_USAGE).value
    except x509.ExtensionNotFound:
        return False
    return ExtendedKeyUsageOID.CODE_SIGNING in eku


def _eh_ac(cert: x509.Certificate) -> bool:
    try:
        bc = cert.extensions.get_extension_for_oid(ExtensionOID.BASIC_CONSTRAINTS).value
    except x509.ExtensionNotFound:
        return False
    return bc.ca


def valida_cadeia(folha: x509.Certificate, raiz: RaizConfiavel, t: datetime
                  ) -> tuple[bool, str, AutoridadeCertificadora | None]:
    """Procura no trusted_root uma cadeia [intermediária..., raiz] que emitiu a folha.

    Para cada elo: verify_directly_issued_by (nome do emissor == nome do sujeito do
    elo seguinte e assinatura válida), o elo superior tem de ser AC, e as ACs têm de
    estar válidas no instante t. A raiz tem de ser autoassinada. A validade da própria
    folha no instante t é conferida depois, na etapa de tempo.
    Retorna (ok, detalhe, autoridade). Se a assinatura da cadeia confere mas alguma
    janela de validade não, ok=False e autoridade != None.
    """
    motivos = []
    for ac in raiz.autoridades:
        elos = [folha] + ac.cadeia
        try:
            for filho, pai in zip(elos, elos[1:]):
                filho.verify_directly_issued_by(pai)
                if not _eh_ac(pai):
                    raise ErroCertificado(f"{pai.subject.rfc4514_string()} não é AC")
            topo = ac.cadeia[-1]
            topo.verify_directly_issued_by(topo)
        except Exception as e:  # noqa: BLE001 - qualquer falha (assinatura, nome, tipo de chave) = não é esta AC
            motivos.append(f"{ac.uri} {ac.janela}: {type(e).__name__}: {e}")
            continue
        # cadeia criptograficamente ok: conferir janelas de validade no instante t
        nomes = " -> ".join(c.subject.rfc4514_string() for c in ac.cadeia)
        if not ac.janela.contem(t):
            return False, f"cadeia {nomes} fora da janela validFor {ac.janela} do trusted_root em {t}", ac
        for c in ac.cadeia:
            if not (c.not_valid_before_utc <= t <= c.not_valid_after_utc):
                return False, (f"{c.subject.rfc4514_string()} fora da validade "
                               f"[{c.not_valid_before_utc}, {c.not_valid_after_utc}] em {t}"), ac
        return True, f"folha -> {nomes} (AC do trusted_root {ac.uri}, validFor {ac.janela})", ac
    return False, "nenhuma AC do trusted_root emitiu este certificado; " + " | ".join(motivos), None


def chave_publica_p256(cert: x509.Certificate) -> ec.EllipticCurvePublicKey:
    chave = cert.public_key()
    if not isinstance(chave, ec.EllipticCurvePublicKey) or chave.curve.name != "secp256r1":
        raise ErroCertificado(f"chave do certificado não é ECDSA P-256 ({type(chave).__name__})")
    return chave
