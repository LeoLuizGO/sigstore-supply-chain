#!/usr/bin/env bash
# E4 — latência de admissão da imagem legítima, com cache de verificação frio e quente.
# Grava resultados/e4-latencia-admissao.csv (cenario,n,media_ms,desvio_ms,p50_ms,p95_ms) e
# as amostras brutas em resultados/e4-latencia-admissao-amostras.csv (cenario,i,ms).
#
# Uso: scripts/cluster/medir-latencia.sh IMAGEM_REF [-n 20] [--politicas "01 02 03"] [--frio flag|reinicio]
#
# Cada amostra é um `kubectl create --dry-run=server` do Deployment (passa pelos webhooks
# de mutação e de validação do Kyverno, nada é gravado), medido do lado do cliente
# (ida e volta do kubectl, em ms). Para separar o custo do kubectl/API server, mede também
# o mesmo pedido num namespace sem políticas ("base", só no arquivo de amostras).
#
# frio:   o Kyverno guarda verificações aprovadas num cache TTL em memória (flag
#         --imageVerifyCacheEnabled, padrão true, TTL 60 min). Modos:
#           flag     (padrão) reinicia o admission controller com --imageVerifyCacheEnabled=false:
#                    toda admissão verifica tudo (registry + Rekor) de novo;
#           reinicio reinicia o admission controller antes de CADA amostra (cache vazio, mas
#                    também conexões e trust root recarregados; ~1 min por amostra).
# quente: cache ligado; uma admissão de aquecimento é descartada antes das N medidas.
# Ao final o admission controller volta à configuração original.
#
# Atenção: entradas com `conditions` (política 03) NUNCA usam o cache no Kyverno 1.19;
# com a 03 ativa, quente ≈ frio para a parte dos atestados. Para ver o efeito do cache só
# na assinatura: --politicas "01 02" --saida resultados/e4-latencia-admissao-so-assinatura.csv
set -euo pipefail
source "$(dirname "${BASH_SOURCE[0]}")/comum.sh"
exigir kubectl python

ref=""; n=20; pols="01 02 03"; frio="flag"
saida="$RAIZ/resultados/e4-latencia-admissao.csv"
while (( $# )); do
  case "$1" in
    -n) n="$2"; shift 2 ;;
    --politicas) pols="$2"; shift 2 ;;
    --frio) frio="$2"; shift 2 ;;
    --saida) saida="$2"; shift 2 ;;
    -h|--help) sed -n '2,25p' "$0"; exit 0 ;;
    -*) erro "opção desconhecida: $1" ;;
    *) ref="$1"; shift ;;
  esac
done
[[ -n "$ref" ]] || erro "informe a IMAGEM_REF (de preferência por digest)"
[[ "$frio" == "flag" || "$frio" == "reinicio" ]] || erro "--frio deve ser flag ou reinicio"
amostras="${saida%.csv}-amostras.csv"

ADM=(-n kyverno deploy/kyverno-admission-controller)
FLAG_CACHE="--imageVerifyCacheEnabled=false"

reiniciar_admission() {
  k rollout restart "${ADM[@]}" >/dev/null
  k rollout status "${ADM[@]}" --timeout=300s >/dev/null
  # Espera o webhook voltar a responder (o primeiro pedido logo após o restart pode falhar).
  for _ in $(seq 1 30); do
    admitir "$ref" dry-run "loja-latencia"
    [[ "$ADM_RESULTADO" != "erro" ]] && return 0
    sleep 2
  done
  erro "o admission controller não voltou a responder: $ADM_MENSAGEM"
}

# Espera o webhook responder SEM verificar a imagem medida (não aquece o cache): manda uma
# imagem de outro registry, que a política 01 recusa sem consultar registry nem Rekor.
esperar_webhook_sem_aquecer() {
  for _ in $(seq 1 30); do
    admitir "docker.io/library/busybox:1.37" dry-run "loja-latencia"
    [[ "$ADM_RESULTADO" != "erro" ]] && return 0
    sleep 2
  done
  erro "o admission controller não voltou a responder: $ADM_MENSAGEM"
}

args_atuais() { k get "${ADM[@]}" -o jsonpath='{.spec.template.spec.containers[0].args}'; }

remover_flag_cache() {
  local idx
  idx="$(k get "${ADM[@]}" -o json | python -I -c '
import json, sys
a = json.load(sys.stdin)["spec"]["template"]["spec"]["containers"][0].get("args", [])
print(a.index(sys.argv[1]) if sys.argv[1] in a else "")' "$FLAG_CACHE" | tr -d '\r')"
  if [[ -n "$idx" ]]; then
    log "restaurando o admission controller (cache de verificação ligado)"
    k patch "${ADM[@]}" --type=json -p "[{\"op\":\"remove\",\"path\":\"/spec/template/spec/containers/0/args/$idx\"}]" >/dev/null
    k rollout status "${ADM[@]}" --timeout=300s >/dev/null
  fi
}
trap remover_flag_cache EXIT

# Políticas e pré-requisitos.
# shellcheck disable=SC2086
"$RAIZ/scripts/cluster/aplicar-politicas.sh" $pols >/dev/null
admitir "$ref" dry-run "loja-latencia"
[[ "$ADM_RESULTADO" == "admitido" ]] || erro "a imagem $ref não foi admitida com as políticas $pols: $ADM_MENSAGEM"

echo "cenario,i,ms" > "$amostras"
declare -a FRIO QUENTE BASE

medir() { # medir NOME_ARRAY CENARIO
  local -n alvo="$1"
  admitir "$ref" dry-run "loja-latencia"
  [[ "$ADM_RESULTADO" == "admitido" ]] || erro "amostra $2 recusada/erro: $ADM_MENSAGEM"
  alvo+=("$ADM_MS")
  echo "$2,${#alvo[@]},$ADM_MS" >> "$amostras"
  log "$2 #${#alvo[@]}: ${ADM_MS} ms"
}

# --- base: mesmo pedido num namespace sem políticas (custo do kubectl + API server) ---
NAMESPACE_ORIG="$NAMESPACE"
NAMESPACE="default"
for _ in $(seq 1 "$n"); do
  admitir "$ref" dry-run "loja-latencia"
  BASE+=("$ADM_MS"); echo "base,${#BASE[@]},$ADM_MS" >> "$amostras"
done
NAMESPACE="$NAMESPACE_ORIG"
log "base (sem políticas): ok"

# --- frio ---
if [[ "$frio" == "flag" ]]; then
  if ! args_atuais | grep -q -- "$FLAG_CACHE"; then
    log "desligando o cache de verificação ($FLAG_CACHE)"
    k patch "${ADM[@]}" --type=json -p "[{\"op\":\"add\",\"path\":\"/spec/template/spec/containers/0/args/-\",\"value\":\"$FLAG_CACHE\"}]" >/dev/null
  fi
  reiniciar_admission
  for _ in $(seq 1 "$n"); do medir FRIO frio; done
  remover_flag_cache
  reiniciar_admission
else
  for _ in $(seq 1 "$n"); do
    k rollout restart "${ADM[@]}" >/dev/null
    k rollout status "${ADM[@]}" --timeout=300s >/dev/null
    esperar_webhook_sem_aquecer
    medir FRIO frio
  done
fi

# --- quente --- (o reiniciar_admission acima já fez uma admissão de aquecimento)
admitir "$ref" dry-run "loja-latencia"
for _ in $(seq 1 "$n"); do medir QUENTE quente; done

estatisticas() { # estatisticas CENARIO valores...
  python -I -c '
import statistics as st, sys, math
nome = sys.argv[1]; v = sorted(int(x) for x in sys.argv[2:])
def pct(p):
    k = (len(v) - 1) * p; f = math.floor(k); c = math.ceil(k)
    return v[f] + (v[c] - v[f]) * (k - f)
dp = st.stdev(v) if len(v) > 1 else 0.0
print(f"{nome},{len(v)},{st.mean(v):.1f},{dp:.1f},{pct(0.5):.1f},{pct(0.95):.1f}")' "$@" | tr -d '\r'
}

{
  echo "cenario,n,media_ms,desvio_ms,p50_ms,p95_ms"
  estatisticas frio "${FRIO[@]}"
  estatisticas quente "${QUENTE[@]}"
} > "$saida"

echo
cat "$saida"
echo "(base sem políticas, só para referência)"
estatisticas base "${BASE[@]}"
echo
echo "políticas: $pols | frio: $frio | imagem: $ref"
echo "amostras: $amostras"
