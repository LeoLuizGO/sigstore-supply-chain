"""Verificação completa: cenário sintético (um caso por motivo de rejeição) e evidências reais
salvas em verificador/dados/ (offline)."""

import base64
import json
from pathlib import Path

import pytest

from verificador import bundle as bundlemod
from verificador import certificado, checkpoint, evidencia, sintetico
from verificador import trusted_root as trmod
from verificador.experimentos.casos import casos_reais, casos_sinteticos
from verificador.registry import analisa_referencia, tag_cosign
from verificador.rekor import payload_set
from verificador.verifica import verifica_evidencia

DADOS = Path(__file__).resolve().parent.parent / "dados"
EMISSOR = "https://token.actions.githubusercontent.com"
REAIS = {
    "fluxcd-source-controller-v1.7.0.json":
        "https://github.com/fluxcd/source-controller/.github/workflows/release.yml@refs/tags/v1.7.0",
    "external-secrets-v0.20.0.json":
        "https://github.com/external-secrets/external-secrets/.github/workflows/release.yml@refs/heads/main",
    "podinfo-6.9.0.json":
        "https://github.com/stefanprodan/podinfo/.github/workflows/release.yml@refs/tags/6.9.0",
}

CASOS = casos_sinteticos()


@pytest.mark.parametrize("caso", CASOS, ids=[c.nome for c in CASOS])
def test_caso_sintetico(caso):
    raiz = trmod.carrega(conteudo=caso.trusted_root)
    rel = verifica_evidencia(caso.evidencia, caso.digest, caso.identidade, caso.emissor, raiz, "ambos")
    assert rel.valida == (caso.esperado is None)
    assert rel.motivo == caso.esperado


def _casos_reais():
    out = []
    for arq, ident in REAIS.items():
        p = DADOS / arq
        if p.exists():
            out += casos_reais(p.stem, evidencia.carrega(str(p)), ident, EMISSOR)
    return out


CASOS_REAIS = _casos_reais()


@pytest.mark.skipif(not CASOS_REAIS, reason="sem evidências reais em verificador/dados/")
@pytest.mark.parametrize("caso", CASOS_REAIS, ids=[c.nome for c in CASOS_REAIS])
def test_caso_real_offline(caso):
    rel = verifica_evidencia(caso.evidencia, caso.digest, caso.identidade, caso.emissor,
                             trmod.carrega(), "biblioteca")
    assert rel.valida == (caso.esperado is None)
    assert rel.motivo == caso.esperado


def test_extensoes_do_certificado_sintetico():
    cen = sintetico.gera()
    pem = cen.camada["annotations"]["dev.sigstore.cosign/certificate"]
    cert = certificado.carrega_pem(pem)
    ext = certificado.extensoes_sigstore(cert)
    assert ext["1.3.6.1.4.1.57264.1.8"]["valor"] == EMISSOR
    assert ext["1.3.6.1.4.1.57264.1.1"]["valor"] == EMISSOR
    assert ext["1.3.6.1.4.1.57264.1.9"]["valor"] == sintetico.IDENTIDADE
    assert ext["1.3.6.1.4.1.57264.1.12"]["nome"] == "Source Repository URI"
    assert certificado.emissor_oidc(cert) == (EMISSOR, "1.3.6.1.4.1.57264.1.8")
    assert certificado.identidades_san(cert) == [sintetico.IDENTIDADE]


def test_utf8string_der_forma_longa():
    longo = "x" * 300
    assert certificado.decodifica_utf8string_der(sintetico._utf8string_der(longo)) == longo
    with pytest.raises(certificado.ErroCertificado):
        certificado.decodifica_utf8string_der(b"\x13\x01a")  # PrintableString, não UTF8String


def test_checkpoint_formato():
    cen = sintetico.gera()
    texto = cen.entrada["verification"]["inclusionProof"]["checkpoint"]
    cp = checkpoint.analisa(texto)
    assert cp.origem.startswith(sintetico.ORIGEM_LOG)
    assert cp.corpo.endswith(b"\n") and b"\n\n" not in cp.corpo
    assert cp.assinaturas[0].hint == cen.chaves["log"].log_id[:4]
    ok, _ = checkpoint.verifica(cp, cen.chaves["log"].chave.public_key(), cen.chaves["log"].log_id)
    assert ok


def test_payload_set_canonico():
    assert payload_set("QQ==", 5, "ab", 7) == b'{"body":"QQ==","integratedTime":5,"logID":"ab","logIndex":7}'


@pytest.mark.parametrize("ref,esperado", [
    ("ghcr.io/org/repo:v1", ("ghcr.io", "org/repo", "v1", None)),
    ("nginx", ("docker.io", "library/nginx", "latest", None)),
    ("localhost:5000/a/b@sha256:" + "a" * 64, ("localhost:5000", "a/b", None, "sha256:" + "a" * 64)),
    ("cgr.dev/chainguard/static:latest", ("cgr.dev", "chainguard/static", "latest", None)),
])
def test_analisa_referencia(ref, esperado):
    r = analisa_referencia(ref)
    assert (r.host, r.repositorio, r.tag, r.digest) == esperado


def test_tag_cosign():
    assert tag_cosign("sha256:abc", "sig") == "sha256-abc.sig"


def test_exporta_bundle_v03():
    cen = sintetico.gera()
    b, payload = bundlemod.exporta(cen.evidencia)
    assert b["mediaType"] == "application/vnd.dev.sigstore.bundle.v0.3+json"
    tl = b["verificationMaterial"]["tlogEntries"][0]
    assert tl["kindVersion"] == {"kind": "hashedrekord", "version": "0.0.1"}
    assert int(tl["logIndex"]) == int(tl["inclusionProof"]["logIndex"]) + sintetico.DESLOCAMENTO_SHARDS
    assert payload == sintetico.payload_simple_signing(sintetico.DIGEST)
    assert base64.b64decode(b["messageSignature"]["signature"]) == cen.chaves["principais"][0]["sig"]


def test_trusted_root_fixado():
    raiz = trmod.carrega()
    assert any("fulcio.sigstore.dev" in a.uri for a in raiz.autoridades)
    rekor = raiz.chave_do_log(bytes.fromhex(
        "c0d23d6ad406973f9559f3ba2d1ca01f84147d8ffc5b8445c224f98b9591801d"))
    assert rekor is not None and rekor.url == "https://rekor.sigstore.dev"


def test_evidencia_sem_rede_reproduz_json():
    # a evidência sintética passa pelo mesmo formato salvo/carregado do comando baixar
    cen = sintetico.gera()
    texto = json.dumps(cen.evidencia)
    assert json.loads(texto)["formato"] == evidencia.FORMATO
