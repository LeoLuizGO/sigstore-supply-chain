#!/usr/bin/env bash
# Valida a SEMÂNTICA das políticas sem cluster, com o Kyverno CLI (mesmo motor de
# verificação do admission controller, mesma versão v1.19.2), contra uma imagem pública
# de terceiros que já tem assinatura keyless, SBOM, atestado vuln e proveniência SLSA:
# ghcr.io/chipzoller/lariat (ver config-lariat.env).
#
# Faz acesso de rede real (ghcr.io, rekor.sigstore.dev, TUF do Sigstore): nenhuma
# verificação é simulada.
#
# Uso: scripts/cluster/teste/validar-cli.sh [ID...]      # sem argumentos: todos os casos
# Requer o Kyverno CLI: scripts/instalar-ferramentas.sh --kyverno-cli (ou KYVERNO_CLI=caminho).
set -euo pipefail
AQUI="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
RAIZ_PROJ="$(cd "$AQUI/../../.." && pwd)"
export CONFIG="$AQUI/config-lariat.env"

KYVERNO_CLI="${KYVERNO_CLI:-}"
if [[ -z "$KYVERNO_CLI" ]]; then
  for c in "$RAIZ_PROJ/bin/kyverno.exe" "$RAIZ_PROJ/bin/kyverno"; do [[ -x "$c" ]] && KYVERNO_CLI="$c"; done
fi
[[ -n "$KYVERNO_CLI" && -x "$KYVERNO_CLI" ]] || { echo "ERRO: Kyverno CLI não encontrado (scripts/instalar-ferramentas.sh --kyverno-cli)" >&2; exit 2; }

TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT

L=ghcr.io/chipzoller/lariat
D37="sha256:31832bbb8d887342115cbe1d4ad2ee03d289ae6b9970e362e8982384c330266a"
ID_ERRADA="https://github.com/chipzoller/lariat/.github/workflows/release.yaml@refs/heads/main"

# id | políticas | imagem | variáveis extras (VAR=valor;VAR=valor) | esperado | descrição
CASOS=(
  "T1|02|$L:0.0.37||admitido|assinatura keyless com a identidade certa"
  "T2|02|$L:0.0.37|IDENTIDADE_PIPELINE=$ID_ERRADA|recusado|mesma imagem, subject esperado diferente"
  "T3|02|$L:0.0.4||recusado|imagem sem assinatura no mesmo repositório"
  "T4|02|$L:0.0.12||recusado|imagem com atestados mas sem assinatura (.sig)"
  "T5|01|docker.io/library/nginx:1.27||recusado|registry fora da lista"
  "T6|02|docker.io/library/nginx:1.27||admitido|SEM a 01: imagem de outro registry nem é olhada pela 02"
  "T7|01|$L-falso:1.0||recusado|repositório vizinho com o mesmo prefixo"
  "T8|01 02|$L@$D37||admitido|01+02 com a imagem referenciada por digest"
  "T9|03|$L@$D37|JANELA_VARREDURA=100000h|admitido|SBOM + SLSA + vuln dentro da janela"
  "T10|03|$L@$D37|JANELA_VARREDURA=24h|recusado|vuln vencido (scanFinishedOn de 2024) com janela 24h"
  "T11|03|$L@$D37|JANELA_VARREDURA=100000h;URI_FONTE_ESPERADA=git+https://github.com/chipzoller/lariat@refs/heads/main|recusado|proveniência de outro ref"
  "T12|03|$L@$D37|JANELA_VARREDURA=100000h;IDENTIDADE_PIPELINE=$ID_ERRADA|recusado|SBOM/vuln assinados por outra identidade"
  "T13|02|$L:0.0.18||admitido|rollback: versão antiga assinada passa só com a 02"
  "T14|02 03|$L:0.0.18|JANELA_VARREDURA=24h;URI_FONTE_ESPERADA=git+https://github.com/chipzoller/lariat@refs/tags/*|recusado|rollback com a 03: varredura vencida"
)

filtro=("$@")
quer() { local id="$1" f; (( ${#filtro[@]} == 0 )) && return 0; for f in "${filtro[@]}"; do [[ "$f" == "$id" ]] && return 0; done; return 1; }

printf '%-4s %-6s %-9s %-9s %6s  %s\n' ID POLIT ESPERADO OBTIDO MS DESCRICAO
ok=0; total=0
for caso in "${CASOS[@]}"; do
  IFS='|' read -r id pols img extras esperado desc <<<"$caso"
  quer "$id" || continue
  total=$((total + 1))
  (
    set -euo pipefail
    if [[ -n "$extras" ]]; then
      IFS=';' read -r -a pares <<<"$extras"
      for p in "${pares[@]}"; do export "${p%%=*}=${p#*=}"; done
    fi
    # shellcheck source=../comum.sh disable=SC2034
    source "$RAIZ_PROJ/scripts/cluster/comum.sh"
    # shellcheck disable=SC2034  # usada por renderizar (comum.sh)
    IMAGEM_REF="$img"
    renderizar "$RAIZ_PROJ/k8s/deployment.yaml.tmpl" > "$TMP/$id-dep.yaml"
    args=()
    for n in $pols; do
      renderizar "$RAIZ_PROJ"/politicas/"$n"-*.yaml.tmpl > "$TMP/$id-p$n.yaml"
      args+=("$TMP/$id-p$n.yaml")
    done
    ini=$(agora_ms)
    set +e
    "$KYVERNO_CLI" apply "${args[@]}" --resource "$TMP/$id-dep.yaml" --registry \
      --detailed-results --remove-color -t > "$TMP/$id.out" 2>&1
    rc=$?
    set -e
    echo "$(( $(agora_ms) - ini ))" > "$TMP/$id.ms"
    echo "$rc" > "$TMP/$id.rc"
  )
  rc="$(<"$TMP/$id.rc")"; ms="$(<"$TMP/$id.ms")"
  # Com -t o CLI não imprime o resumo "pass: N, fail: N"; decide pelo código de saída e
  # pela ausência de linhas Fail/Error na tabela.
  if [[ "$rc" == 0 ]] && ! grep -qE '│ (Fail|Error) ' "$TMP/$id.out"; then obtido=admitido; else obtido=recusado; fi
  [[ "$obtido" == "$esperado" ]] && ok=$((ok + 1))
  printf '%-4s %-6s %-9s %-9s %6s  %s\n' "$id" "${pols// /+}" "$esperado" "$obtido" "$ms" "$desc"
  # Mensagem do Kyverno: junta as linhas quebradas da tabela do CLI e mostra as Fail/Error
  # (só a primeira, a do estágio de mutação; a segunda é o estágio de validação).
  awk -F'│' 'NF >= 8 && $2 !~ /ID/ {
      for (i = 2; i <= 8; i++) gsub(/^ +| +$/, "", $i)
      if ($2 != "") { if (linha != "") print linha; res = $6; linha = (res == "Fail" || res == "Error") ? $3 ": " $8 : "" }
      else if (linha != "") linha = linha " " $8
    } END { if (linha != "") print linha }' "$TMP/$id.out" | head -n1 | fold -w 160 | sed 's/^/       /' || true
  if [[ -n "${MOSTRAR_SAIDA:-}" ]]; then sed 's/^/       | /' "$TMP/$id.out"; fi
done
echo
echo "$ok de $total casos com o resultado esperado"
[[ "$ok" == "$total" ]]
