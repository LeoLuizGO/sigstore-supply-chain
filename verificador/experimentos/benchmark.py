"""Microbenchmark (E4): tempo de cada etapa da verificação offline.

Uso: python -m verificador.experimentos.benchmark [EVIDENCIA] [--n 200] [--n-manual 30] [--csv ARQ]
Sem EVIDENCIA, usa verificador/dados/fluxcd-source-controller-v1.7.0.json.
"""

from __future__ import annotations

import argparse
import base64
import csv
import json
import platform
import statistics
import sys
import time
from pathlib import Path

import cryptography
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec

from .. import certificado, checkpoint, evidencia, merkle
from .. import trusted_root as trmod
from ..rekor import payload_set
from ..verifica import ANOT_ASSINATURA, ANOT_BUNDLE, ANOT_CERT, ecdsa_verifica, verifica_evidencia

PADRAO = Path(__file__).resolve().parent.parent / "dados" / "fluxcd-source-controller-v1.7.0.json"


def mede(f, n: int) -> list[float]:
    f()  # aquecimento
    tempos = []
    for _ in range(n):
        t0 = time.perf_counter_ns()
        f()
        tempos.append((time.perf_counter_ns() - t0) / 1e6)
    return tempos


def main(argv: list[str] | None = None) -> int:
    try:
        sys.stdout.reconfigure(encoding="utf-8")
    except (AttributeError, ValueError):
        pass
    p = argparse.ArgumentParser(prog="python -m verificador.experimentos.benchmark")
    p.add_argument("evidencia", nargs="?", default=str(PADRAO))
    p.add_argument("--identidade", default=None, help="SAN esperado (padrão: o do próprio certificado)")
    p.add_argument("--emissor", default="https://token.actions.githubusercontent.com")
    p.add_argument("--n", type=int, default=200)
    p.add_argument("--n-manual", type=int, default=30)
    p.add_argument("--csv", default=None)
    a = p.parse_args(argv)

    ev = evidencia.carrega(a.evidencia)
    raiz = trmod.carrega()
    camada = ev["manifesto_sig"]["conteudo"]["layers"][0]
    anot = camada["annotations"]
    payload = base64.b64decode(ev["payloads"][camada["digest"]])
    sig = base64.b64decode(anot[ANOT_ASSINATURA])
    cert = certificado.carrega_pem(anot[ANOT_CERT])
    chave = cert.public_key()
    idx = json.loads(anot[ANOT_BUNDLE])["Payload"]["logIndex"]
    entrada = next(iter(ev["rekor"][str(idx)].values()))
    prova = entrada["verification"]["inclusionProof"]
    corpo = base64.b64decode(entrada["body"])
    caminho = [bytes.fromhex(h) for h in prova["hashes"]]
    raiz_arv = bytes.fromhex(prova["rootHash"])
    log_id = bytes.fromhex(entrada["logID"])
    chave_log = raiz.chave_do_log(log_id)
    from datetime import datetime, timezone
    t = datetime.fromtimestamp(entrada["integratedTime"], tz=timezone.utc)
    identidade = a.identidade or certificado.identidades_san(cert)[0]
    set_msg = payload_set(entrada["body"], entrada["integratedTime"], entrada["logID"], entrada["logIndex"])
    set_sig = base64.b64decode(entrada["verification"]["signedEntryTimestamp"])

    etapas = [
        ("ECDSA P-256 (biblioteca cryptography)", lambda: ecdsa_verifica(chave, sig, payload, "biblioteca"), a.n),
        ("ECDSA P-256 (manual, Python puro)", lambda: ecdsa_verifica(chave, sig, payload, "manual"), a.n_manual),
        ("certificado: parse PEM + extensões Fulcio",
         lambda: certificado.extensoes_sigstore(certificado.carrega_pem(anot[ANOT_CERT])), a.n),
        ("cadeia X.509 até a raiz do trusted_root", lambda: certificado.valida_cadeia(cert, raiz, t), a.n),
        (f"prova de inclusão ({len(caminho)} hashes)",
         lambda: merkle.verifica_inclusao(merkle.hash_folha(corpo), prova["logIndex"], prova["treeSize"],
                                          caminho, raiz_arv), a.n),
        ("checkpoint (parse + ECDSA do log)",
         lambda: checkpoint.verifica(checkpoint.analisa(prova["checkpoint"]), chave_log.chave, log_id), a.n),
        ("SET (JSON canônico + ECDSA do log)",
         lambda: chave_log.chave.verify(set_sig, set_msg, ec.ECDSA(hashes.SHA256())), a.n),
        ("verificação completa (ECDSA biblioteca)",
         lambda: verifica_evidencia(ev, ev["digest"], identidade, a.emissor, raiz, "biblioteca"), a.n),
        ("verificação completa (ECDSA ambos)",
         lambda: verifica_evidencia(ev, ev["digest"], identidade, a.emissor, raiz, "ambos"), a.n_manual),
    ]
    assert verifica_evidencia(ev, ev["digest"], identidade, a.emissor, raiz, "ambos").valida

    print(f"Evidência: {Path(a.evidencia).name}; Python {platform.python_version()}, cryptography "
          f"{cryptography.__version__}, {platform.processor() or platform.machine()}, {platform.system()} "
          f"{platform.release()}\n")
    print("| Etapa | n | média (ms) | desvio (ms) | mín (ms) | máx (ms) |")
    print("|---|---:|---:|---:|---:|---:|")
    linhas = []
    for nome, f, n in etapas:
        ts = mede(f, n)
        lin = [nome, n, statistics.mean(ts), statistics.stdev(ts) if n > 1 else 0.0, min(ts), max(ts)]
        linhas.append(lin)
        print(f"| {nome} | {n} | {lin[2]:.3f} | {lin[3]:.3f} | {lin[4]:.3f} | {lin[5]:.3f} |")
    if a.csv:
        with open(a.csv, "w", newline="", encoding="utf-8") as fh:
            w = csv.writer(fh)
            w.writerow(["etapa", "n", "media_ms", "desvio_ms", "min_ms", "max_ms"])
            w.writerows([[l[0], l[1]] + [f"{x:.4f}" for x in l[2:]] for l in linhas])
    return 0


if __name__ == "__main__":
    sys.exit(main())
