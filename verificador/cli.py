"""Interface de linha de comando (contrato em docs/ESPEC.md).

Códigos de saída: 0 = válida, 1 = rejeitada, 2 = erro de uso/rede.
"""

from __future__ import annotations

import argparse
import json
import sys

from . import bundle as bundlemod
from . import evidencia, inspecionar
from . import trusted_root as trmod
from .registry import ErroRegistry, Registry, analisa_referencia
from .rekor import REKOR_PADRAO, ErroRekor
from .verifica import MODOS_ECDSA, DivergenciaECDSA, formata, verifica_evidencia


def _imprime_json(obj) -> None:
    json.dump(obj, sys.stdout, indent=2, ensure_ascii=False, default=str)
    sys.stdout.write("\n")


def _args_verificacao(p: argparse.ArgumentParser) -> None:
    p.add_argument("--identidade", required=True, help="SAN esperado (URI do workflow)")
    p.add_argument("--emissor", required=True, help="emissor OIDC esperado")
    p.add_argument("--trusted-root", default=None, help="trusted_root.json (padrão: o fixado no pacote)")
    p.add_argument("--ecdsa", choices=MODOS_ECDSA, default="ambos",
                   help="implementação de ECDSA (padrão: ambos, que precisam concordar)")
    p.add_argument("--json", action="store_true", help="saída em JSON")


def _verifica_e_imprime(ev: dict, digest: str, a) -> int:
    raiz = trmod.carrega(a.trusted_root)
    rel = verifica_evidencia(ev, digest, a.identidade, a.emissor, raiz, a.ecdsa)
    if a.json:
        _imprime_json(rel.para_dict())
    else:
        print(formata(rel))
    return 0 if rel.valida else 1


def cmd_digest(a) -> int:
    ref = analisa_referencia(a.imagem)
    reg = Registry(ref)
    if ref.digest:
        print(ref.digest)
        return 0
    corpo, tipo, digest = reg.manifesto(ref.tag) or (None, None, None)
    if corpo is None:
        print(f"erro: tag não encontrada: {a.imagem}", file=sys.stderr)
        return 2
    if a.json:
        man = json.loads(corpo)
        _imprime_json({"imagem": ref.nome, "tag": ref.tag, "digest": digest, "mediaType": tipo,
                       "plataformas": [{"digest": m["digest"], "platform": m.get("platform")}
                                       for m in man.get("manifests", [])]})
    else:
        print(digest)
    return 0


def cmd_baixar(a) -> int:
    ev = evidencia.baixar(a.imagem, a.rekor_url)
    evidencia.salva(ev, a.saida)
    n = len((ev.get("manifesto_sig") or {}).get("conteudo", {}).get("layers", []))
    print(f"evidência salva em {a.saida}: {ev['imagem']}@{ev['digest']}, {n} assinatura(s), "
          f"{len(ev['rekor'])} entrada(s) do Rekor", file=sys.stderr)
    for e in ev["erros"]:
        print(f"aviso: {e}", file=sys.stderr)
    return 0


def cmd_verificar(a) -> int:
    ev = evidencia.carrega(a.evidencia)
    return _verifica_e_imprime(ev, a.digest, a)


def cmd_imagem(a) -> int:
    ev = evidencia.baixar(a.imagem, a.rekor_url)
    if a.salvar_evidencia:
        evidencia.salva(ev, a.salvar_evidencia)
    return _verifica_e_imprime(ev, ev["digest"], a)


def cmd_inspecionar(a) -> int:
    info = inspecionar.inspeciona(a.imagem)
    if a.csv:
        inspecionar.escreve_csv(info, a.csv)
    if a.json:
        _imprime_json(info)
    else:
        print(inspecionar.formata(info))
    return 0


def cmd_exportar_bundle(a) -> int:
    ev = evidencia.carrega(a.evidencia)
    if a.formato == "v0.3":
        b, payload = bundlemod.exporta(ev, a.camada - 1)
    else:
        b, payload = bundlemod.exporta_bundle_cosign(ev, a.camada - 1)
    with open(a.saida, "w", encoding="utf-8") as f:
        json.dump(b, f, indent=2)
        f.write("\n")
    if a.payload:
        with open(a.payload, "wb") as f:
            f.write(payload)
    print(f"bundle {a.formato} salvo em {a.saida}" + (f"; payload em {a.payload}" if a.payload else ""),
          file=sys.stderr)
    return 0


def monta_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="python -m verificador",
                                description="Verificador independente de assinaturas Sigstore (cosign 2.x, formato .sig)")
    sub = p.add_subparsers(dest="comando", required=True)

    s = sub.add_parser("digest", help="resolve IMAGEM:TAG para o digest do manifesto")
    s.add_argument("imagem")
    s.add_argument("--json", action="store_true")
    s.set_defaults(func=cmd_digest)

    s = sub.add_parser("baixar", help="baixa a evidência (registry + Rekor) para um arquivo JSON")
    s.add_argument("imagem", help="IMAGEM@sha256:...")
    s.add_argument("-o", "--saida", required=True)
    s.add_argument("--rekor-url", default=REKOR_PADRAO)
    s.set_defaults(func=cmd_baixar)

    s = sub.add_parser("verificar", help="verifica uma evidência salva (offline)")
    s.add_argument("evidencia")
    s.add_argument("--digest", required=True, help="digest esperado da imagem (sha256:...)")
    _args_verificacao(s)
    s.set_defaults(func=cmd_verificar)

    s = sub.add_parser("imagem", help="baixar + verificar")
    s.add_argument("imagem", help="IMAGEM@sha256:...")
    s.add_argument("--rekor-url", default=REKOR_PADRAO)
    s.add_argument("--salvar-evidencia", default=None, metavar="ARQ")
    _args_verificacao(s)
    s.set_defaults(func=cmd_imagem)

    s = sub.add_parser("inspecionar", help="lista artefatos .sig/.att/.sbom e tamanhos")
    s.add_argument("imagem")
    s.add_argument("--json", action="store_true")
    s.add_argument("--csv", default=None, metavar="ARQ", help="escreve artefato,bytes (E4)")
    s.set_defaults(func=cmd_inspecionar)

    s = sub.add_parser("exportar-bundle", help="converte uma assinatura da evidência em bundle Sigstore")
    s.add_argument("evidencia")
    s.add_argument("-o", "--saida", required=True)
    s.add_argument("--payload", default=None, help="também grava o payload (artefato assinado)")
    s.add_argument("--camada", type=int, default=1, help="qual assinatura (1 = primeira)")
    s.add_argument("--formato", choices=("v0.3", "cosign"), default="v0.3",
                   help="v0.3 = bundle Sigstore (sigstore-python); cosign = bundle legado do verify-blob")
    s.set_defaults(func=cmd_exportar_bundle)
    return p


def main(argv: list[str] | None = None) -> int:
    # Windows: garantir UTF-8 na saída (acentos e o travessão do checkpoint)
    for fluxo in (sys.stdout, sys.stderr):
        try:
            fluxo.reconfigure(encoding="utf-8")
        except (AttributeError, ValueError):
            pass
    a = monta_parser().parse_args(argv)
    import cryptography
    if int(cryptography.__version__.split(".")[0]) < 42:
        print(f"erro: cryptography {cryptography.__version__} é antiga demais (precisa >= 42); "
              "use o venv: python -m pip install -r verificador/requirements.txt", file=sys.stderr)
        return 2
    try:
        return a.func(a)
    except (ErroRegistry, ErroRekor) as e:
        print(f"erro de rede/registry: {e}", file=sys.stderr)
        return 2
    except DivergenciaECDSA as e:
        print(f"erro interno: {e}", file=sys.stderr)
        return 2
    except (OSError, ValueError, KeyError) as e:
        print(f"erro: {type(e).__name__}: {e}", file=sys.stderr)
        return 2
