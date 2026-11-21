#!/usr/bin/env bash
# Faz o deploy da aplicação com a imagem dada e mostra a decisão do Kyverno.
#
# Uso: scripts/cluster/deploy.sh IMAGEM_REF [--dry-run] [--esperar]
#   IMAGEM_REF  ex.: ghcr.io/leoluizgo/sigstore-supply-chain@sha256:<digest>
#               ou   ghcr.io/leoluizgo/sigstore-supply-chain:main (o Kyverno troca por digest)
#   --dry-run   só pergunta ao API server (passa pelos webhooks, não grava nada)
#   --esperar   depois de admitido, espera o pod ficar pronto (readinessProbe em /saude)
#
# Saída: ADMITIDO/RECUSADO, o tempo da admissão (ida e volta do kubectl, em ms), a imagem
# final (com o digest colocado pelo mutateDigest) ou a mensagem do Kyverno.
# Código de saída: 0 admitido, 1 recusado, 2 erro.
set -euo pipefail
source "$(dirname "${BASH_SOURCE[0]}")/comum.sh"
exigir kubectl

ref=""; modo="real"; esperar=0
for arg in "$@"; do
  case "$arg" in
    --dry-run) modo="dry-run" ;;
    --esperar) esperar=1 ;;
    -h|--help) sed -n '2,13p' "$0"; exit 0 ;;
    -*) erro "opção desconhecida: $arg" ;;
    *) [[ -z "$ref" ]] || erro "só uma IMAGEM_REF"; ref="$arg" ;;
  esac
done
[[ -n "$ref" ]] || { sed -n '2,13p' "$0"; exit 2; }

k get namespace "$NAMESPACE" >/dev/null 2>&1 || erro "namespace $NAMESPACE não existe (rode scripts/cluster/criar-cluster.sh)"
ativas="$(k get clusterpolicy -o jsonpath='{.items[*].metadata.name}' 2>/dev/null || true)"
log "políticas ativas: ${ativas:-nenhuma}"

admitir "$ref" "$modo"

case "$ADM_RESULTADO" in
  admitido)
    echo "ADMITIDO em ${ADM_MS} ms ($modo)"
    echo "imagem final: $ADM_IMAGEM_FINAL"
    [[ -n "$ADM_MENSAGEM" ]] && echo "avisos: $ADM_MENSAGEM"
    if [[ "$modo" == "real" && $esperar -eq 1 ]]; then
      k -n "$NAMESPACE" rollout status "deploy/$NOME_DEPLOY" --timeout=180s
      k -n "$NAMESPACE" get pods -l app=loja -o wide
    fi
    exit 0 ;;
  recusado)
    echo "RECUSADO em ${ADM_MS} ms ($modo)"
    echo "mensagem: $ADM_MENSAGEM"
    exit 1 ;;
  *)
    echo "ERRO (não foi uma decisão do Kyverno) em ${ADM_MS} ms: $ADM_MENSAGEM" >&2
    exit 2 ;;
esac
