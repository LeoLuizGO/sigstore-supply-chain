#!/usr/bin/env bash
# E4 — duração de cada etapa do pipeline.yml em N execuções bem-sucedidas.
#
# Uso: scripts/ci/metricas-pipeline.sh [N]      (padrão N=10; precisa do gh autenticado)
#      WORKFLOW=outro.yml scripts/ci/metricas-pipeline.sh [N]   (outro arquivo de workflow)
# Saída: resultados/e4-pipeline-etapas.csv  (etapa,n,media_s,desvio_s,min_s,max_s)
#        resultados/e4-pipeline-etapas-bruto.tsv (run_id, etapa, segundos), para conferência
#
# Etapas medidas:
#   - cada step cujo nome começa com "Etapa - " (ex.: "Etapa - Trivy bloqueante ...")
#   - cada job inteiro, como "job: <nome>" (inclui os jobs do slsa-github-generator)
#   - a execução inteira, como "workflow_total" (run_started_at -> updated_at)
# Os horários da API têm resolução de 1 s. O desvio é o desvio-padrão amostral (n-1).
set -euo pipefail

RAIZ=$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)
cd "$RAIZ"
# shellcheck source=SCRIPTDIR/../../config.env
source config.env

N="${1:-10}"
[[ "$N" =~ ^[0-9]+$ ]] && [ "$N" -ge 1 ] || { echo "N inválido: $N" >&2; exit 2; }
REPO_GH="${OWNER}/${REPO}"
WORKFLOW="${WORKFLOW:-pipeline.yml}"
mkdir -p resultados
BRUTO="resultados/e4-pipeline-etapas-bruto.tsv"
SAIDA="resultados/e4-pipeline-etapas.csv"

ids=$(gh api "repos/${REPO_GH}/actions/workflows/${WORKFLOW}/runs?status=success&branch=main&per_page=${N}" \
  --jq '.workflow_runs[] | select(.conclusion == "success") | .id') \
  || { echo "falha ao listar as execuções de ${WORKFLOW} em ${REPO_GH}" >&2; exit 1; }
RUNS=()
for id in $ids; do
  [[ "$id" =~ ^[0-9]+$ ]] && RUNS+=("$id")
done
[ "${#RUNS[@]}" -gt 0 ] || { echo "nenhuma execução bem-sucedida do ${WORKFLOW} em ${REPO_GH}" >&2; exit 1; }
echo "execuções analisadas: ${#RUNS[@]} (${RUNS[*]})" >&2

printf 'run_id\tetapa\tsegundos\n' > "$BRUTO"
for id in "${RUNS[@]}"; do
  gh api "repos/${REPO_GH}/actions/runs/${id}" \
    --jq '"\(.id)\tworkflow_total\t\((.updated_at | fromdateiso8601) - (.run_started_at | fromdateiso8601))"' >> "$BRUTO"
  gh api --paginate "repos/${REPO_GH}/actions/runs/${id}/jobs?per_page=100" --jq "
    .jobs[] | select(.conclusion == \"success\") | .name as \$job |
    ( \"${id}\tjob: \(\$job)\t\((.completed_at | fromdateiso8601) - (.started_at | fromdateiso8601))\" ),
    ( .steps[]? | select(.name | startswith(\"Etapa - \")) | select(.conclusion == \"success\") |
      \"${id}\t\(.name | ltrimstr(\"Etapa - \"))\t\((.completed_at | fromdateiso8601) - (.started_at | fromdateiso8601))\" )
  " >> "$BRUTO"
done

# Agrega por etapa (ordem de primeira aparição). Campos com vírgula vão entre aspas.
LC_ALL=C awk -F'\t' '
  NR == 1 { next }
  {
    e = $2; v = $3 + 0
    if (!(e in n)) { ordem[++k] = e; mn[e] = v; mx[e] = v }
    n[e]++; s[e] += v; ss[e] += v * v
    if (v < mn[e]) mn[e] = v
    if (v > mx[e]) mx[e] = v
  }
  END {
    print "etapa,n,media_s,desvio_s,min_s,max_s"
    for (i = 1; i <= k; i++) {
      e = ordem[i]; m = s[e] / n[e]
      d = (n[e] > 1) ? sqrt((ss[e] - n[e] * m * m) / (n[e] - 1)) : 0
      if (d != d || d < 0) d = 0
      nome = e
      if (index(nome, ",") || index(nome, "\"")) { gsub(/"/, "\"\"", nome); nome = "\"" nome "\"" }
      printf "%s,%d,%.1f,%.1f,%d,%d\n", nome, n[e], m, d, mn[e], mx[e]
    }
  }' "$BRUTO" > "$SAIDA"

cat "$SAIDA"
echo "gravado em ${SAIDA} (dados brutos em ${BRUTO})" >&2
