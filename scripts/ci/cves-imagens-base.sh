#!/usr/bin/env bash
# E4 — versão local do workflow varredura-bases.yml (não bloqueante).
#
# Uso: scripts/ci/cves-imagens-base.sh
# Usa o binário "trivy" do PATH se for a versão 0.69.3; senão roda a imagem oficial do Trivy
# 0.69.3 fixada por digest (assinatura conferida em 21/11/2026, ver docs/pipeline.md) com Docker.
# Saída: resultados/e4-cves-imagens-base.csv (todas as CVEs, formato da ESPEC),
#        resultados/e4-cves-imagens-base-corrigiveis.csv (só com correção, --ignore-unfixed),
#        resultados/e4-cves-json/*.json (relatórios completos).
# Atenção: a imagem python:3.12 completa tem ~400 MB comprimidos (o Trivy baixa as camadas).
set -euo pipefail

RAIZ=$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)
cd "$RAIZ"
# shellcheck source=SCRIPTDIR/../../config.env
source config.env

TRIVY_IMAGEM="aquasec/trivy:0.69.3@sha256:bcc376de8d77cfe086a917230e818dc9f8528e3c852f7b1aff648949b6258d1c"
IMAGENS=(
  "python-3.12|python:3.12|python:3.12.16-trixie@sha256:5411fa1b302c43f510324381162b5f5d0d93b9ee2af538f09d944f0d290ee3cb"
  "python-3.12-slim|python:3.12-slim|python:3.12.16-slim-trixie@sha256:5e2bdb1b0d542d5039cffb8181c65930093949194a65c365dfb1b0fe13a4fa5b"
  "distroless-python3-debian12|gcr.io/distroless/python3-debian12|gcr.io/distroless/python3-debian12:latest@sha256:2fdb05402a2cf21cf78fdb3ba4c5db167241e9e498140f5bf689d7efb773731f"
)

PY=""
for c in python3 python; do
  if "$c" -c 'import sys; sys.exit(0 if sys.version_info >= (3, 8) else 1)' >/dev/null 2>&1; then PY="$c"; break; fi
done
[ -n "$PY" ] || { echo "Python 3 não encontrado" >&2; exit 1; }

if command -v trivy >/dev/null 2>&1 && trivy --version 2>/dev/null | grep -q 'Version: 0.69.3'; then
  rodar_trivy() { trivy "$@"; }
  echo "usando o trivy do PATH" >&2
else
  command -v docker >/dev/null 2>&1 || { echo "nem trivy 0.69.3 nem docker disponíveis" >&2; exit 1; }
  # Relatório sai pelo stdout (sem bind mount); o cache do banco fica num volume nomeado.
  # MSYS_NO_PATHCONV evita que o Git Bash reescreva /root/... como caminho do Windows.
  rodar_trivy() {
    MSYS_NO_PATHCONV=1 docker run --rm -v sigstore-trivy-cache:/root/.cache/trivy "$TRIVY_IMAGEM" "$@"
  }
  echo "usando ${TRIVY_IMAGEM} via docker" >&2
fi

mkdir -p resultados/e4-cves-json
todas=()
corrigiveis=()
for item in "${IMAGENS[@]}"; do
  IFS='|' read -r nome rotulo ref <<< "$item"
  echo "== ${ref}" >&2
  rodar_trivy image --quiet --image-src remote --platform linux/amd64 --scanners vuln --format json "$ref" \
    > "resultados/e4-cves-json/${nome}-todas.json"
  rodar_trivy image --quiet --image-src remote --platform linux/amd64 --scanners vuln --skip-db-update \
    --ignore-unfixed --format json "$ref" > "resultados/e4-cves-json/${nome}-corrigiveis.json"
  todas+=("${rotulo}=resultados/e4-cves-json/${nome}-todas.json")
  corrigiveis+=("${rotulo}=resultados/e4-cves-json/${nome}-corrigiveis.json")
done

"$PY" scripts/ci/contar-cves.py resultados/e4-cves-imagens-base.csv "${todas[@]}"
"$PY" scripts/ci/contar-cves.py resultados/e4-cves-imagens-base-corrigiveis.csv "${corrigiveis[@]}"
echo "gravado em resultados/e4-cves-imagens-base.csv e resultados/e4-cves-imagens-base-corrigiveis.csv" >&2
