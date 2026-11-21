"""Experimento E3: roda o verificador nos casos sintéticos e reais e grava
resultados/e3-verificador.csv (caso,origem,nosso_verificador,cosign,sigstore_python,motivo).

Uso (da raiz do repositório):
  python -m verificador.experimentos.e3                              # só sintéticos
  python -m verificador.experimentos.e3 \
      --real verificador/dados/fluxcd-source-controller-v1.7.0.json=<SAN esperado> \
      --cosign C:/caminho/cosign.exe --sigstore verificador/.venv/Scripts/sigstore.exe

Cross-check (só leitura, nada é assinado):
  * cosign: `cosign verify IMAGEM@digest` (online, no registry) para os casos marcados como
    cosign_online; nos demais, `cosign verify-blob --new-bundle-format --bundle <v0.3>
    --trusted-root <arq>` sobre o bundle exportado da evidência adulterada;
  * sigstore-python: `sigstore verify identity --bundle <v0.3>` sobre o mesmo bundle.
Sai com código 1 se algum caso tiver resultado diferente do esperado.
"""

from __future__ import annotations

import argparse
import csv
import json
import os
import subprocess
import sys
import tempfile
from pathlib import Path

from .. import bundle as bundlemod
from .. import evidencia
from .. import trusted_root as trmod
from ..verifica import verifica_evidencia
from .casos import Caso, casos_reais, casos_sinteticos

EMISSOR_GH = "https://token.actions.githubusercontent.com"


def _roda(cmd: list[str]) -> tuple[str, str]:
    # COLUMNS largo: o sigstore-python (rich) não quebra as linhas de log
    env = dict(os.environ, COLUMNS="2000", NO_COLOR="1")
    try:
        p = subprocess.run(cmd, capture_output=True, text=True, timeout=180, encoding="utf-8",
                           errors="replace", env=env)
    except (OSError, subprocess.TimeoutExpired) as e:
        return "erro", str(e)
    linhas = [" ".join(l.split()) for l in (p.stderr + "\n" + p.stdout).splitlines() if l.strip()]
    if p.returncode == 0:
        msg = next((l for l in linhas if l.startswith(("OK", "Verified OK"))), linhas[-1] if linhas else "")
    else:
        # cosign: "error during command execution: ..."; sigstore-python: "ERROR <mensagem>"
        erros = [l for l in linhas if "error" in l.lower() and "FAIL:" not in l
                 and "--verbose" not in l]
        msg = erros[-1] if erros else (linhas[-1] if linhas else "")
        msg = msg.split("ERROR", 1)[-1].strip() if "ERROR" in msg else msg
    return ("valida" if p.returncode == 0 else "rejeitada"), msg[:220]


def _exporta(caso: Caso, pasta: str) -> tuple[str, str, str]:
    b, payload = bundlemod.exporta(caso.evidencia, 0)
    pb, pp = os.path.join(pasta, "bundle.sigstore.json"), os.path.join(pasta, "payload.json")
    Path(pb).write_text(json.dumps(b), encoding="utf-8")
    Path(pp).write_bytes(payload)
    tr = str(trmod.CAMINHO_PADRAO)
    if caso.trusted_root is not None:
        tr = os.path.join(pasta, "trusted_root.json")
        Path(tr).write_bytes(caso.trusted_root)
    return pb, pp, tr


def cross_cosign(caso: Caso, cosign: str | None) -> tuple[str, str]:
    if not cosign or caso.origem != "real" or caso.notas.get("cross") == "n/a":
        return "n/a", ""
    if caso.notas.get("cosign_online"):
        return _roda([cosign, "verify", f"{caso.evidencia['imagem']}@{caso.digest}",
                      "--certificate-identity", caso.identidade,
                      "--certificate-oidc-issuer", caso.emissor])
    with tempfile.TemporaryDirectory() as d:
        try:
            pb, pp, tr = _exporta(caso, d)
        except (KeyError, TypeError, IndexError, StopIteration):
            return "n/a", "evidência sem assinatura exportável para bundle"
        return _roda([cosign, "verify-blob", "--new-bundle-format", "--bundle", pb,
                      "--trusted-root", tr, "--certificate-identity", caso.identidade,
                      "--certificate-oidc-issuer", caso.emissor, pp])


def cross_sigstore(caso: Caso, sigstore: str | None) -> tuple[str, str]:
    if not sigstore or caso.origem != "real" or caso.notas.get("cross") == "n/a" \
            or caso.trusted_root is not None:
        return "n/a", ""
    with tempfile.TemporaryDirectory() as d:
        try:
            pb, pp, _ = _exporta(caso, d)
        except (KeyError, TypeError, IndexError, StopIteration):
            return "n/a", "evidência sem assinatura exportável para bundle"
        return _roda([sigstore, "verify", "identity", "--bundle", pb, "--cert-identity",
                      caso.identidade, "--cert-oidc-issuer", caso.emissor, pp])


def main(argv: list[str] | None = None) -> int:
    for fluxo in (sys.stdout, sys.stderr):
        try:
            fluxo.reconfigure(encoding="utf-8")
        except (AttributeError, ValueError):
            pass
    p = argparse.ArgumentParser(prog="python -m verificador.experimentos.e3")
    p.add_argument("--saida", default="resultados/e3-verificador.csv")
    p.add_argument("--real", action="append", default=[], metavar="EVIDENCIA=IDENTIDADE",
                   help="evidência real (de `baixar`) e o SAN esperado; pode repetir")
    p.add_argument("--caso-real", nargs=4, action="append", default=[],
                   metavar=("NOME", "EVIDENCIA", "IDENTIDADE", "ESPERADO"),
                   help="evidência real verificada sem adulteração (ex.: tags do E2); ESPERADO = "
                        "'valida' ou o motivo de rejeição esperado; cosign verifica online no registry")
    p.add_argument("--emissor", default=EMISSOR_GH)
    p.add_argument("--cosign", default=None, help="binário do cosign 2.x para o cross-check")
    p.add_argument("--sigstore", default=None, help="CLI do sigstore-python para o cross-check")
    p.add_argument("--ecdsa", default="ambos", choices=("biblioteca", "manual", "ambos"))
    a = p.parse_args(argv)

    casos = casos_sinteticos()
    for item in a.real:
        arq, _, ident = item.partition("=")
        nome = Path(arq).stem
        casos += casos_reais(nome, evidencia.carrega(arq), ident, a.emissor)
    for nome, arq, ident, esperado in a.caso_real:
        ev = evidencia.carrega(arq)
        casos.append(Caso(nome, "real", ev, None, ev["digest"], ident, a.emissor,
                          None if esperado == "valida" else esperado, {"cosign_online": True}))

    raiz_padrao = trmod.carrega()
    linhas, divergencias = [], 0
    for c in casos:
        raiz = raiz_padrao if c.trusted_root is None else trmod.carrega(conteudo=c.trusted_root)
        rel = verifica_evidencia(c.evidencia, c.digest, c.identidade, c.emissor, raiz, a.ecdsa)
        nosso = "valida" if rel.valida else "rejeitada"
        conf = rel.motivo == c.esperado and rel.valida == (c.esperado is None)
        divergencias += not conf
        cos, cos_msg = cross_cosign(c, a.cosign)
        sig, sig_msg = cross_sigstore(c, a.sigstore)
        linhas.append([c.nome, c.origem, nosso, cos, sig, rel.motivo or ""])
        print(f"[{'ok' if conf else 'DIVERGE'}] {c.origem:<9} {c.nome:<62} nosso={nosso:<9} "
              f"motivo={rel.motivo or '-'}" + ("" if conf else f"  (esperado: {c.esperado})"))
        if cos != "n/a":
            print(f"            cosign={cos:<9} {cos_msg}")
        if sig != "n/a":
            print(f"            sigstore-python={sig:<9} {sig_msg}")

    Path(a.saida).parent.mkdir(parents=True, exist_ok=True)
    with open(a.saida, "w", newline="", encoding="utf-8") as f:
        w = csv.writer(f)
        w.writerow(["caso", "origem", "nosso_verificador", "cosign", "sigstore_python", "motivo"])
        w.writerows(linhas)
    print(f"\n{len(casos)} casos, {divergencias} divergência(s) do esperado; CSV em {a.saida}")
    return 1 if divergencias else 0


if __name__ == "__main__":
    sys.exit(main())
