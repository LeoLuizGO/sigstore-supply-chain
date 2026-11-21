#!/usr/bin/env bash
# Apaga o cluster kind do projeto (nome em config.env: CLUSTER). Não mexe em outros clusters.
# Uso: scripts/cluster/destruir-cluster.sh
set -euo pipefail
source "$(dirname "${BASH_SOURCE[0]}")/comum.sh"
exigir kind

if kind get clusters 2>/dev/null | grep -qx "$CLUSTER"; then
  log "apagando o cluster kind $CLUSTER"
  kind delete cluster --name "$CLUSTER"
else
  log "cluster $CLUSTER não existe; nada a fazer"
fi
