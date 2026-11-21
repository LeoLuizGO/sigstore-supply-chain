# shellcheck shell=bash
# As variáveis daqui são usadas pelos scripts que fazem `source` deste arquivo.
# shellcheck disable=SC2034
# Funções e variáveis compartilhadas pelos scripts de scripts/cluster/.
# Uso: source "$(dirname "${BASH_SOURCE[0]}")/comum.sh"
#
# Lê a configuração de config.env (ou do arquivo em $CONFIG, usado na validação com
# imagem pública de terceiros, ver scripts/cluster/teste/) e coloca ./bin na frente do
# PATH, para usar as versões fixadas por scripts/instalar-ferramentas.sh.

RAIZ="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
CONFIG="${CONFIG:-$RAIZ/config.env}"
if [[ ! -f "$CONFIG" ]]; then
  echo "ERRO: arquivo de configuração $CONFIG não encontrado" >&2
  exit 2
fi
# JANELA_VARREDURA pode ser sobrescrita pelo ambiente (ex.: JANELA_VARREDURA=1h para
# demonstrar o E2.5 sem esperar 24 h); o config.env a define incondicionalmente.
_janela_do_ambiente="${JANELA_VARREDURA-}"
# shellcheck source=../../config.env
source "$CONFIG"
if [[ -n "$_janela_do_ambiente" ]]; then JANELA_VARREDURA="$_janela_do_ambiente"; fi
unset _janela_do_ambiente

export PATH="$RAIZ/bin:$PATH"

# Versões fixadas (ver docs/cluster.md, seção "Versões fixadas").
KYVERNO_VERSAO="v1.19.2"
KYVERNO_MANIFESTO_URL="https://github.com/kyverno/kyverno/releases/download/${KYVERNO_VERSAO}/install.yaml"
# SHA-256 do install.yaml, conferido contra o checksums.txt do release em 21/11/2026.
KYVERNO_MANIFESTO_SHA256="4f785937dc7fe49a0731108b15def1538923c73d9236255bc69d94d498037969"

# Valores derivados usados nas políticas. Podem ser sobrescritos pelo arquivo de
# configuração (o de teste usa outro repositório/ref).
: "${URI_FONTE_ESPERADA:=git+https://github.com/${OWNER}/${REPO}@refs/heads/main}"
: "${ENTRYPOINT_ESPERADO:=.github/workflows/pipeline.yml}"
: "${BUILD_TYPE_SLSA:=https://github.com/slsa-framework/slsa-github-generator/container@v1}"
: "${NOME_DEPLOY:=loja}"

CONTEXTO="kind-${CLUSTER}"

k() { kubectl --context "$CONTEXTO" "$@"; }

log()  { printf '[%s] %s\n' "$(date +%H:%M:%S)" "$*" >&2; }
erro() { printf 'ERRO: %s\n' "$*" >&2; exit 1; }

exigir() {
  local c
  for c in "$@"; do
    command -v "$c" >/dev/null 2>&1 || erro "comando '$c' não encontrado (rode scripts/instalar-ferramentas.sh)"
  done
}

# Tempo atual em milissegundos (date +%s%N funciona no Git Bash e no Linux).
agora_ms() { echo $(( $(date +%s%N) / 1000000 )); }

# Variáveis que podem aparecer nos templates como ${NOME}.
VARIAVEIS_TEMPLATE=(
  OWNER REPO IMAGEM NAMESPACE EMISSOR_OIDC REKOR_URL
  IDENTIDADE_PIPELINE IDENTIDADE_REESCANEAR IDENTIDADE_PROVENIENCIA
  JANELA_VARREDURA URI_FONTE_ESPERADA ENTRYPOINT_ESPERADO BUILD_TYPE_SLSA
  IMAGEM_REF NOME_DEPLOY
)

# renderizar ARQUIVO: imprime o template com ${VAR} substituído pelos valores atuais.
# Não usa envsubst (pode faltar no Git Bash); a troca é literal, feita pelo próprio bash.
renderizar() {
  local arquivo="$1" conteudo var valor
  conteudo="$(<"$arquivo")"
  # No bash >= 5.2, '&' na substituição vira o texto casado; desligamos isso.
  shopt -u patsub_replacement 2>/dev/null || true
  for var in "${VARIAVEIS_TEMPLATE[@]}"; do
    valor="${!var-}"
    conteudo="${conteudo//"\${${var}}"/"$valor"}"
  done
  if grep -qE '\$\{[A-Z_]+\}' <<<"$conteudo"; then
    erro "variável sem valor no template $arquivo: $(grep -oE '\$\{[A-Z_]+\}' <<<"$conteudo" | sort -u | tr '\n' ' ')"
  fi
  printf '%s\n' "$conteudo"
}

# Junta uma mensagem de várias linhas em uma só (para CSV e para o terminal).
uma_linha() { tr '\r\n' '  ' | sed -E 's/[[:space:]]+/ /g; s/^ //; s/ $//'; }

# Escapa um campo para CSV (aspas duplas, aspas internas dobradas).
csv() {
  local s="${1//\"/\"\"}"
  printf '"%s"' "$s"
}

# admitir IMAGEM_REF [dry-run|real] [NOME_DEPLOY]
# Envia o Deployment ao API server e mede o tempo até a resposta (admitido ou recusado).
#   dry-run: `kubectl create --dry-run=server` — passa por TODOS os webhooks do Kyverno
#            (eles são registrados com sideEffects: NoneOnDryRun), mas nada é gravado.
#            Sempre é um CREATE, então o Kyverno sempre verifica (não há "unchanged").
#   real:    `kubectl apply --server-side` — grava o Deployment (o pedido sempre chega ao
#            servidor, mesmo sem mudanças).
# Define: ADM_RESULTADO (admitido|recusado), ADM_MS, ADM_MENSAGEM, ADM_IMAGEM_FINAL.
admitir() {
  local ref="$1" modo="${2:-dry-run}" nome="${3:-$NOME_DEPLOY}"
  local dir rc ini
  dir="$(mktemp -d)"
  IMAGEM_REF="$ref" NOME_DEPLOY="$nome" renderizar "$RAIZ/k8s/deployment.yaml.tmpl" > "$dir/dep.yaml"
  local -a cmd
  if [[ "$modo" == "real" ]]; then
    cmd=(apply --server-side --force-conflicts --field-manager=deploy-sh)
  else
    cmd=(create --dry-run=server)
  fi
  ini=$(agora_ms)
  set +e
  k "${cmd[@]}" -o 'jsonpath={.spec.template.spec.containers[0].image}' -f "$dir/dep.yaml" \
    > "$dir/out" 2> "$dir/err"
  rc=$?
  set -e
  ADM_MS=$(( $(agora_ms) - ini ))
  if (( rc == 0 )); then
    ADM_RESULTADO="admitido"
    ADM_IMAGEM_FINAL="$(<"$dir/out")"
    ADM_MENSAGEM="$(grep -v '^Warning: .*deprecated' "$dir/err" | uma_linha || true)"
  else
    ADM_RESULTADO="recusado"
    ADM_IMAGEM_FINAL=""
    # O texto útil do Kyverno vem depois de "denied the request:".
    ADM_MENSAGEM="$(uma_linha < "$dir/err" | sed -E 's/^.*denied the request: *//')"
    if ! grep -q 'denied the request' "$dir/err"; then
      ADM_RESULTADO="erro"
    fi
  fi
  rm -rf "$dir"
}
