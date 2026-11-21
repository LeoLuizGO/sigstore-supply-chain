#!/usr/bin/env bash
# Renderiza as políticas de politicas/*.yaml.tmpl com os valores de config.env e aplica
# no cluster. O conjunto escolhido passa a ser o conjunto ATIVO: as políticas do projeto
# que não foram escolhidas são removidas (use --manter-outras para não remover).
#
# Uso:
#   scripts/cluster/aplicar-politicas.sh                 # todas (01 02 03)
#   scripts/cluster/aplicar-politicas.sh 01 02           # só registry + assinatura (E2.5, 1ª parte)
#   scripts/cluster/aplicar-politicas.sh --imprimir 03   # só mostra o YAML renderizado
#   scripts/cluster/aplicar-politicas.sh --validar       # kubectl apply --dry-run=server
#   scripts/cluster/aplicar-politicas.sh --remover       # remove todas as políticas do projeto
#   CONFIG=outro.env scripts/cluster/aplicar-politicas.sh ...   # outra configuração
set -euo pipefail
source "$(dirname "${BASH_SOURCE[0]}")/comum.sh"

modo="aplicar"
manter_outras=0
escolhidas=()
for arg in "$@"; do
  case "$arg" in
    --imprimir)      modo="imprimir" ;;
    --validar)       modo="validar" ;;
    --remover)       modo="remover" ;;
    --manter-outras) manter_outras=1 ;;
    todas)           ;;
    -h|--help)       sed -n '2,14p' "$0"; exit 0 ;;
    [0-9][0-9])      escolhidas+=("$arg") ;;
    *) erro "argumento desconhecido: $arg (use números como 01 02 03, ou --help)" ;;
  esac
done

mapfile -t todos_arquivos < <(ls "$RAIZ"/politicas/[0-9][0-9]-*.yaml.tmpl)
(( ${#todos_arquivos[@]} > 0 )) || erro "nenhum template em politicas/"

nome_politica() { sed -n 's/^  name: *//p' "$1" | head -n1; }
numero() { basename "$1" | cut -c1-2; }

selecionado() {
  local n="$1" e
  (( ${#escolhidas[@]} == 0 )) && return 0
  for e in "${escolhidas[@]}"; do [[ "$e" == "$n" ]] && return 0; done
  return 1
}

for e in "${escolhidas[@]+"${escolhidas[@]}"}"; do
  ls "$RAIZ"/politicas/"$e"-*.yaml.tmpl >/dev/null 2>&1 || erro "não existe politicas/$e-*.yaml.tmpl"
done

if [[ "$modo" == "remover" ]]; then
  for arq in "${todos_arquivos[@]}"; do
    k delete clusterpolicy "$(nome_politica "$arq")" --ignore-not-found
  done
  exit 0
fi

if [[ "$modo" != "imprimir" ]]; then
  exigir kubectl
  k get crd clusterpolicies.kyverno.io >/dev/null 2>&1 || erro "Kyverno não instalado no contexto $CONTEXTO (rode scripts/cluster/criar-cluster.sh)"
fi

aplicadas=()
for arq in "${todos_arquivos[@]}"; do
  n="$(numero "$arq")"
  nome="$(nome_politica "$arq")"
  if selecionado "$n"; then
    case "$modo" in
      imprimir) echo "---"; renderizar "$arq" ;;
      validar)
        log "validando $nome (dry-run no servidor)"
        renderizar "$arq" | k apply --dry-run=server -f - ;;
      aplicar)
        log "aplicando $nome"
        renderizar "$arq" | k apply -f -
        aplicadas+=("$nome") ;;
    esac
  elif [[ "$modo" == "aplicar" && $manter_outras -eq 0 ]]; then
    if k get clusterpolicy "$nome" >/dev/null 2>&1; then
      log "removendo $nome (não está no conjunto escolhido)"
      k delete clusterpolicy "$nome"
    fi
  fi
done

if [[ "$modo" == "aplicar" ]]; then
  for nome in "${aplicadas[@]}"; do
    k wait --for=condition=Ready "clusterpolicy/$nome" --timeout=90s >/dev/null \
      || erro "a política $nome não ficou Ready (veja: kubectl describe clusterpolicy $nome)"
  done
  log "políticas ativas:"
  k get clusterpolicy -o custom-columns='NOME:.metadata.name,PRONTA:.status.conditions[?(@.type=="Ready")].status,REGRAS:.status.rulecount' 2>/dev/null \
    || k get clusterpolicy || true
  # Dá tempo para o Kyverno reconfigurar os webhooks antes do próximo deploy.
  sleep 3
fi
