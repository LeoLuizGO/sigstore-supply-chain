#!/usr/bin/env bash
# Cria o cluster kind (nome em config.env: CLUSTER), instala o Kyverno na versão fixada
# (manifesto oficial do release, com checksum conferido), espera tudo ficar pronto e
# cria o namespace da aplicação. É idempotente: se o cluster já existe, reaproveita.
#
# Uso: scripts/cluster/criar-cluster.sh [--recriar]
set -euo pipefail
source "$(dirname "${BASH_SOURCE[0]}")/comum.sh"
exigir docker kind kubectl curl sha256sum

recriar=0
[[ "${1:-}" == "--recriar" ]] && recriar=1

docker info >/dev/null 2>&1 || erro "o daemon do Docker não responde (inicie o Docker Desktop e tente de novo)"

# O node do kind (~1 GB) e as imagens do Kyverno (~0,4 GB) vão para o disco virtual do
# Docker Desktop, que cresce dentro de %LOCALAPPDATA%\Docker no C:. Com o C: cheio, o
# disco do Docker vira somente-leitura no meio do pull (aconteceu na validação; ver
# docs/cluster.md). Por isso conferimos o espaço livre antes.
livre_gb() { df -Pk "$1" 2>/dev/null | awk 'NR==2 {printf "%d", $4/1024/1024}'; }
case "$(uname -s)" in
  MINGW*|MSYS*|CYGWIN*) alvo_disco="${LOCALAPPDATA:-/c}" ;;
  *)                    alvo_disco="$(docker info --format '{{.DockerRootDir}}' 2>/dev/null || echo /)" ;;
esac
livre="$(livre_gb "$alvo_disco" || true)"
if [[ -n "$livre" ]] && (( livre < 5 )); then
  erro "só ${livre} GB livres em $alvo_disco; o kind + Kyverno precisam de ~3 GB no disco do Docker (libere ao menos 5 GB)"
fi

if kind get clusters 2>/dev/null | grep -qx "$CLUSTER"; then
  if (( recriar )); then
    log "apagando o cluster $CLUSTER (--recriar)"
    kind delete cluster --name "$CLUSTER"
  else
    log "cluster $CLUSTER já existe; reaproveitando"
  fi
fi
if ! kind get clusters 2>/dev/null | grep -qx "$CLUSTER"; then
  log "criando o cluster kind $CLUSTER"
  kind create cluster --name "$CLUSTER" --config "$RAIZ/k8s/kind-config.yaml" --wait 180s
fi
k cluster-info >/dev/null

# Kyverno: manifesto oficial do release, conferido antes de aplicar.
tmp="$(mktemp -d)"
trap 'rm -rf "$tmp"' EXIT
log "baixando o Kyverno $KYVERNO_VERSAO"
curl -fsSL --retry 3 -o "$tmp/install.yaml" "$KYVERNO_MANIFESTO_URL"
obtido="$(sha256sum < "$tmp/install.yaml" | awk '{print $1}')"
[[ "$obtido" == "$KYVERNO_MANIFESTO_SHA256" ]] \
  || erro "checksum do install.yaml do Kyverno não confere (esperado $KYVERNO_MANIFESTO_SHA256, obtido $obtido)"

# --server-side: os CRDs do Kyverno passam do limite de 256 KiB da anotação
# last-applied-configuration do apply comum; o create também funciona, mas não é idempotente.
log "instalando o Kyverno (kubectl apply --server-side)"
k apply --server-side --force-conflicts -f "$tmp/install.yaml" >/dev/null

log "esperando os controladores do Kyverno"
for d in kyverno-admission-controller kyverno-background-controller kyverno-cleanup-controller kyverno-reports-controller; do
  k -n kyverno rollout status "deploy/$d" --timeout=300s
done
# O admission controller só atende depois de registrar os webhooks e o certificado.
for _ in $(seq 1 60); do
  if k get validatingwebhookconfiguration kyverno-policy-validating-webhook-cfg >/dev/null 2>&1; then break; fi
  sleep 2
done

log "criando o namespace da aplicação"
k apply -f "$RAIZ/k8s/namespace.yaml"

log "pronto: contexto $CONTEXTO, Kyverno $KYVERNO_VERSAO"
k get nodes -o wide
k -n kyverno get pods
echo
echo "Próximo passo: scripts/cluster/aplicar-politicas.sh   (todas) ou com 01 02 / 01 02 03"
