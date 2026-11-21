#!/usr/bin/env bash
# E2 — roda os cenários de ataque da ESPEC contra o cluster e grava
# resultados/e2-ataques.csv (cenario,imagem,esperado,obtido,mensagem).
#
# Uso:
#   scripts/cluster/ataques.sh --json ataques-digests.json --digest-antigo sha256:<...>
#   scripts/cluster/ataques.sh --digest-legitimo sha256:<...> --digest-antigo sha256:<...>
# Opções:
#   --json ARQ             artifact "ataques-digests" do workflow ataques.yml (docs/pipeline.md);
#                          dele vêm o digest legítimo e as referências de cada cenário.
#   --digest-legitimo D    digest assinado pelo pipeline (se não houver --json).
#   --digest-antigo D      digest legítimo ANTIGO (rollback, E2.5). Sem ele, o E2.5 é pulado.
#   --real                 usa `kubectl apply` de verdade (padrão: --dry-run=server, que passa
#                          pelos mesmos webhooks do Kyverno sem criar nada no cluster).
#   --saida ARQ            CSV de saída (padrão: resultados/e2-ataques.csv).
# Variáveis: JANELA_VARREDURA=1h deixa a janela da política 03 mais curta (útil no E2.5 se
# o digest antigo foi varrido há menos de 24 h).
#
# Sem --json, as referências dos cenários são as tags da ESPEC (:ataque-*, :main).
# A política ativa em cada cenário: 01+02+03 (configuração completa), exceto E2.5a (01+02).
# Ao final, deixa as três políticas aplicadas.
set -euo pipefail
source "$(dirname "${BASH_SOURCE[0]}")/comum.sh"
exigir kubectl python

json=""; dig_leg=""; dig_antigo=""; modo="dry-run"; saida="$RAIZ/resultados/e2-ataques.csv"
while (( $# )); do
  case "$1" in
    --json) json="$2"; shift 2 ;;
    --digest-legitimo) dig_leg="$2"; shift 2 ;;
    --digest-antigo) dig_antigo="$2"; shift 2 ;;
    --real) modo="real"; shift ;;
    --saida) saida="$2"; shift 2 ;;
    -h|--help) sed -n '2,24p' "$0"; exit 0 ;;
    *) erro "opção desconhecida: $1" ;;
  esac
done

# Referências por cenário: do JSON do workflow de ataques, ou das tags da ESPEC.
declare -A REF=(
  [sem-assinatura]="$IMAGEM:ataque-sem-assinatura"
  [camada-alterada]="$IMAGEM:main"
  [outra-identidade]="$IMAGEM:ataque-outra-identidade"
  [chave-local]="$IMAGEM:ataque-chave-local"
  [troca-assinatura]="$IMAGEM:ataque-troca-assinatura"
)
if [[ -n "$json" ]]; then
  [[ -f "$json" ]] || erro "arquivo $json não encontrado"
  # Python (sempre disponível no projeto) no lugar do jq, que não vem no Git Bash.
  while IFS=$'\t' read -r chave valor; do
    case "$chave" in
      digest_legitimo) [[ -z "$dig_leg" ]] && dig_leg="$valor" ;;
      imagem) [[ "$valor" == "$IMAGEM" ]] || log "AVISO: imagem do JSON ($valor) difere de config.env ($IMAGEM)" ;;
      *) REF[$chave]="$valor" ;;
    esac
  done < <(python -I -c '
import json, sys
d = json.load(open(sys.argv[1], encoding="utf-8"))
print("imagem\t" + d["imagem"])
print("digest_legitimo\t" + d["digest_legitimo"])
for c in d.get("cenarios", []):
    # E2.2 é testado pela tag (o ataque é sobrescrever :main); os outros pelo digest exato.
    ref = c["referencia_tag"] if c["cenario"] == "camada-alterada" else c["referencia"]
    print(c["cenario"] + "\t" + ref)
' "$json" | tr -d '\r')
fi

[[ -z "$dig_leg" || "$dig_leg" =~ ^sha256:[0-9a-f]{64}$ ]] || erro "digest legítimo inválido: $dig_leg"
[[ -z "$dig_antigo" || "$dig_antigo" =~ ^sha256:[0-9a-f]{64}$ ]] || erro "digest antigo inválido: $dig_antigo"

# id | cenário (chave) | políticas | referência | esperado
CENARIOS=()
if [[ -n "$dig_leg" ]]; then
  CENARIOS+=("E2.0 controle: imagem legítima|legitima|01 02 03|$IMAGEM@$dig_leg|admitido")
else
  log "AVISO: sem digest legítimo (--json ou --digest-legitimo): o controle positivo E2.0 será pulado"
fi
CENARIOS+=(
  "E2.1 sem assinatura|sem-assinatura|01 02 03|${REF[sem-assinatura]}|recusado"
  "E2.2 camada alterada (tag main sobrescrita)|camada-alterada|01 02 03|${REF[camada-alterada]}|recusado"
  "E2.3a outra identidade (ataques.yml)|outra-identidade|01 02 03|${REF[outra-identidade]}|recusado"
  "E2.3b chave local (sem Fulcio)|chave-local|01 02 03|${REF[chave-local]}|recusado"
  "E2.4 troca de assinatura|troca-assinatura|01 02 03|${REF[troca-assinatura]}|recusado"
  "E2.x registry fora da lista|outro-registry|01 02 03|docker.io/library/nginx:1.27|recusado"
)
if [[ -n "$dig_antigo" ]]; then
  CENARIOS+=(
    "E2.5a rollback só com assinatura (01+02)|rollback|01 02|$IMAGEM@$dig_antigo|admitido"
    "E2.5b rollback com atestado de varredura (01+02+03)|rollback|01 02 03|$IMAGEM@$dig_antigo|recusado"
  )
else
  log "AVISO: sem --digest-antigo: o rollback (E2.5) será pulado"
fi

mkdir -p "$(dirname "$saida")"
echo "cenario,imagem,esperado,obtido,mensagem" > "$saida"

politicas_atuais=""
ok=0; total=0
for linha in "${CENARIOS[@]}"; do
  IFS='|' read -r nome _chave pols ref esperado <<<"$linha"
  if [[ "$pols" != "$politicas_atuais" ]]; then
    # shellcheck disable=SC2086
    "$RAIZ/scripts/cluster/aplicar-politicas.sh" $pols >/dev/null
    politicas_atuais="$pols"
  fi
  log "$nome -> $ref"
  admitir "$ref" "$modo" "loja-ataque"
  if [[ "$modo" == "real" && "$ADM_RESULTADO" == "admitido" ]]; then
    k -n "$NAMESPACE" delete deploy loja-ataque --ignore-not-found >/dev/null
  fi
  total=$((total + 1))
  [[ "$ADM_RESULTADO" == "$esperado" ]] && ok=$((ok + 1))
  msg="$ADM_MENSAGEM"
  [[ "$ADM_RESULTADO" == "admitido" ]] && msg="admitido em ${ADM_MS} ms; imagem final ${ADM_IMAGEM_FINAL}${msg:+; $msg}"
  printf '%s,%s,%s,%s,%s\n' "$(csv "$nome")" "$(csv "$ref")" "$esperado" "$ADM_RESULTADO" "$(csv "$msg")" >> "$saida"
  printf '  %-9s (esperado %-9s) %s\n' "$ADM_RESULTADO" "$esperado" "$(cut -c1-220 <<<"$msg")" >&2
done

# Deixa a configuração completa aplicada.
[[ "$politicas_atuais" == "01 02 03" ]] || "$RAIZ/scripts/cluster/aplicar-politicas.sh" 01 02 03 >/dev/null

echo
echo "$ok de $total cenários com o resultado esperado -> $saida"
echo "Obs.: o E2.6 (dependência vulnerável) é barrado no pipeline pelo Trivy, antes da assinatura;"
echo "      não passa pelo cluster (ver docs/pipeline.md)."
