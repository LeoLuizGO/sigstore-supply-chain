#!/usr/bin/env python3
"""Conta as vulnerabilidades de relatórios JSON do Trivy por severidade (E4).

Uso:
  python3 scripts/ci/contar-cves.py SAIDA.csv NOME_IMAGEM=relatorio.json [NOME=relatorio.json ...]

Gera o CSV no formato da ESPEC (resultados/e4-cves-imagens-base.csv):
  imagem,critical,high,medium,low,unknown,total

Cada achado do Trivy (par vulnerabilidade x pacote) conta uma vez, como na tabela
de resumo do próprio Trivy. Um mesmo CVE que afeta dois pacotes binários conta duas vezes.
Só usa a biblioteca padrão.
"""

import csv
import json
import sys

SEVERIDADES = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "UNKNOWN"]


def contar(caminho):
    with open(caminho, encoding="utf-8") as arquivo:
        relatorio = json.load(arquivo)
    contagem = dict.fromkeys(SEVERIDADES, 0)
    for resultado in relatorio.get("Results") or []:
        for vuln in resultado.get("Vulnerabilities") or []:
            severidade = (vuln.get("Severity") or "UNKNOWN").upper()
            contagem[severidade if severidade in contagem else "UNKNOWN"] += 1
    return contagem


def main(argv):
    if len(argv) < 3:
        print(__doc__, file=sys.stderr)
        return 2
    saida = argv[1]
    linhas = []
    for par in argv[2:]:
        nome, sep, caminho = par.partition("=")
        if not sep:
            print(f"argumento inválido (esperado NOME=arquivo.json): {par}", file=sys.stderr)
            return 2
        contagem = contar(caminho)
        linhas.append(
            [nome]
            + [contagem[s] for s in SEVERIDADES]
            + [sum(contagem.values())]
        )
    with open(saida, "w", encoding="utf-8", newline="") as arquivo:
        escritor = csv.writer(arquivo, lineterminator="\n")
        escritor.writerow(["imagem", "critical", "high", "medium", "low", "unknown", "total"])
        escritor.writerows(linhas)
    for linha in linhas:
        print(",".join(str(c) for c in linha))
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
