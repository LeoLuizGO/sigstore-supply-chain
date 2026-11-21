#!/usr/bin/env bash
# Baixa os artifacts dos workflows para resultados/ (precisa do gh autenticado).
#
# Uso:
#   scripts/ci/baixar-evidencias.sh [RUN_ID]            E1: artifact evidencias-e1 do pipeline.yml -> resultados/e1-*
#   scripts/ci/baixar-evidencias.sh --ataques [RUN_ID]  E2: artifact ataques-digests do ataques.yml -> resultados/ataques-digests.json
#   scripts/ci/baixar-evidencias.sh --bases [RUN_ID]    E4: artifact e4-cves-imagens-base -> resultados/e4-cves-imagens-base*.csv
# Sem RUN_ID, usa a última execução bem-sucedida do workflow correspondente.
set -euo pipefail

RAIZ=$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)
cd "$RAIZ"
# shellcheck source=SCRIPTDIR/../../config.env
source config.env

REPO_GH="${OWNER}/${REPO}"
modo="e1"
case "${1:-}" in
  --ataques) modo="ataques"; shift ;;
  --bases) modo="bases"; shift ;;
  -h|--help) sed -n '2,8p' "$0"; exit 0 ;;
esac
RUN_ID="${1:-}"

case "$modo" in
  e1) workflow="pipeline.yml"; artifact="evidencias-e1" ;;
  ataques) workflow="ataques.yml"; artifact="ataques-digests" ;;
  bases) workflow="varredura-bases.yml"; artifact="e4-cves-imagens-base" ;;
esac

if [ -z "$RUN_ID" ]; then
  RUN_ID=$(gh run list -R "$REPO_GH" --workflow "$workflow" --status success --limit 1 \
    --json databaseId --jq '.[0].databaseId // empty')
  [ -n "$RUN_ID" ] || { echo "nenhuma execução bem-sucedida de ${workflow} em ${REPO_GH}" >&2; exit 1; }
fi
[[ "$RUN_ID" =~ ^[0-9]+$ ]] || { echo "RUN_ID inválido: $RUN_ID" >&2; exit 2; }

mkdir -p resultados
tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT
echo "baixando ${artifact} da execução ${RUN_ID} (${workflow})" >&2
gh run download "$RUN_ID" -R "$REPO_GH" -n "$artifact" -D "$tmp"

case "$modo" in
  e1)
    cp -f "$tmp"/e1-* resultados/
    echo "$RUN_ID" > resultados/e1-run-id.txt
    ls -1 resultados/e1-*
    if [ -f resultados/e1-rekor.json ]; then cat resultados/e1-rekor.json; fi
    ;;
  ataques)
    cp -f "$tmp/ataques-digests.json" resultados/ataques-digests.json
    for f in "$tmp"/ataque-*; do
      [ -e "$f" ] && cp -f "$f" "resultados/e2-$(basename "$f")"
    done
    ls -1 resultados/ataques-digests.json resultados/e2-ataque-* 2>/dev/null || true
    ;;
  bases)
    cp -f "$tmp"/e4-cves-imagens-base*.csv resultados/
    mkdir -p resultados/e4-cves-json
    cp -f "$tmp"/json/*.json resultados/e4-cves-json/
    cat resultados/e4-cves-imagens-base.csv
    ;;
esac
