#!/usr/bin/env bash
# Baixa para ./bin (ignorado pelo git) as ferramentas do lado do cluster, com versão
# fixa e checksum SHA-256 conferido: kind, cosign 2.x e kubectl.
#
# Uso: scripts/instalar-ferramentas.sh [--kyverno-cli]
#   --kyverno-cli  baixa também o Kyverno CLI v1.19.2 (~270 MB descompactado), usado só por
#                  scripts/cluster/teste/validar-cli.sh (validação das políticas sem cluster).
#
# Funciona no Git Bash (Windows amd64) e no Linux amd64. Os scripts de scripts/cluster/
# colocam ./bin na frente do PATH, então as versões daqui têm prioridade.
#
# Checksums conferidos em 21/11/2026:
#   - kind:    arquivos <binário>.sha256sum publicados no release do GitHub;
#   - cosign:  cosign_checksums.txt do release v2.6.5 (sigstore/cosign);
#   - kubectl: <binário>.sha256 publicado em dl.k8s.io;
#   - Kyverno CLI: checksums.txt do release v1.19.2 (kyverno/kyverno).
set -euo pipefail

com_kyverno_cli=0
for arg in "$@"; do
  case "$arg" in
    --kyverno-cli) com_kyverno_cli=1 ;;
    *) echo "uso: $0 [--kyverno-cli]" >&2; exit 2 ;;
  esac
done

RAIZ="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
BIN="$RAIZ/bin"

KIND_VERSAO="v0.33.0"
COSIGN_VERSAO="v2.6.5"
# Mesma versão menor do node do kind (kindest/node:v1.35.8): o kubectl só é suportado
# com no máximo 1 versão menor de diferença do API server.
KUBECTL_VERSAO="v1.35.8"
KYVERNO_CLI_VERSAO="v1.19.2"

case "$(uname -s)" in
  MINGW*|MSYS*|CYGWIN*) SO="windows"; EXT=".exe" ;;
  Linux*)               SO="linux";   EXT="" ;;
  *) echo "ERRO: sistema $(uname -s) não suportado (só Windows/Git Bash e Linux)" >&2; exit 2 ;;
esac
case "$(uname -m)" in
  x86_64|amd64) ARQ="amd64" ;;
  *) echo "ERRO: arquitetura $(uname -m) não suportada (só amd64)" >&2; exit 2 ;;
esac

declare -A SHA=(
  [kind-windows]="4b22adaa135368c5a465d56bbd8e520cbea87272a06ca00b6078e7b81515c9fc"
  [kind-linux]="aee6151561422756b764a4ae28e7f44cda5af5a9eead3cc9985112b1de8d8e0d"
  [cosign-windows]="19ec346d0050f59ffad9694da97ef9704be34ec60ddc41c5f1d16d8619385825"
  [cosign-linux]="c3b4f5410e608af03a5eb0aaac84a4313d8da131248e08ff1759ac70c79d1644"
  [kubectl-windows]="f675d70224b42b84e0442e8d7644efbe440e4451a4b02bdc5d95823a96316ba8"
  [kubectl-linux]="874d5e72dbb819f43cff16bcd1e4f8bac5b7f2361fe1e55049b0a6c676fb0cbf"
  [kyvernocli-windows]="c787cd56d2c2571e5470b1d070fff851c05d104513fcf5cb1652021bb187a1f6"
  [kyvernocli-linux]="357eaf1df8bc24ddd5a73979fadeaae6a032e8710f11af264229756e4956bf4a"
)

declare -A URL=(
  [kind]="https://github.com/kubernetes-sigs/kind/releases/download/${KIND_VERSAO}/kind-${SO}-${ARQ}"
  [cosign]="https://github.com/sigstore/cosign/releases/download/${COSIGN_VERSAO}/cosign-${SO}-${ARQ}${EXT}"
  [kubectl]="https://dl.k8s.io/release/${KUBECTL_VERSAO}/bin/${SO}/${ARQ}/kubectl${EXT}"
)

# Lê pela entrada padrão: a saída fica "<hash>  -", sem o '*' que o Git Bash põe no nome.
sha256_de() { sha256sum < "$1" | awk '{print $1}'; }

baixar() {
  local nome="$1"
  local destino="$BIN/${nome}${EXT}"
  local esperado="${SHA[${nome}-${SO}]}"

  if [[ -f "$destino" ]] && [[ "$(sha256_de "$destino")" == "$esperado" ]]; then
    echo "ok    $nome já está em bin/ com o checksum esperado"
    return 0
  fi

  echo "baixa $nome <- ${URL[$nome]}"
  local tmp="$destino.download"
  curl -fsSL --retry 3 -o "$tmp" "${URL[$nome]}"
  local obtido
  obtido="$(sha256_de "$tmp")"
  if [[ "$obtido" != "$esperado" ]]; then
    rm -f "$tmp"
    echo "ERRO: checksum de $nome não confere" >&2
    echo "  esperado: $esperado" >&2
    echo "  obtido:   $obtido" >&2
    exit 1
  fi
  mv -f "$tmp" "$destino"
  chmod +x "$destino"
  echo "ok    $nome instalado ($obtido)"
}

mkdir -p "$BIN"
baixar kind
baixar cosign

# kubectl: o do Docker Desktop serve se estiver a até 1 versão menor do cluster (1.34–1.36).
# O Docker Desktop instalado aqui traz o 1.28, fora da política de compatibilidade,
# então nesse caso baixamos o 1.35.8.
usar_kubectl_do_host=0
if [[ ! -f "$BIN/kubectl${EXT}" ]] && command -v kubectl >/dev/null 2>&1; then
  menor="$(kubectl version --client -o json 2>/dev/null | sed -n 's/.*"minor": *"\([0-9]*\).*/\1/p' | head -n1)"
  if [[ -n "$menor" ]] && (( menor >= 34 && menor <= 36 )); then
    usar_kubectl_do_host=1
    echo "ok    kubectl do host (1.$menor) é compatível com o cluster 1.35; não vou baixar"
  else
    echo "info  kubectl do host é 1.${menor:-?}, fora de 1.34–1.36: baixando $KUBECTL_VERSAO"
  fi
fi
if (( ! usar_kubectl_do_host )); then
  baixar kubectl
fi

if (( com_kyverno_cli )); then
  if [[ -x "$BIN/kyverno${EXT}" ]] && "$BIN/kyverno${EXT}" version 2>/dev/null | grep -q "Version: ${KYVERNO_CLI_VERSAO#v}"; then
    echo "ok    kyverno CLI ${KYVERNO_CLI_VERSAO} já está em bin/"
  else
    if [[ "$SO" == "windows" ]]; then pacote="kyverno-cli_${KYVERNO_CLI_VERSAO}_windows_x86_64.zip"; else pacote="kyverno-cli_${KYVERNO_CLI_VERSAO}_linux_x86_64.tar.gz"; fi
    tmpk="$(mktemp -d)"
    echo "baixa kyverno CLI <- $pacote"
    curl -fsSL --retry 3 -o "$tmpk/$pacote" "https://github.com/kyverno/kyverno/releases/download/${KYVERNO_CLI_VERSAO}/$pacote"
    obtido="$(sha256_de "$tmpk/$pacote")"
    if [[ "$obtido" != "${SHA[kyvernocli-${SO}]}" ]]; then
      rm -rf "$tmpk"; echo "ERRO: checksum do Kyverno CLI não confere ($obtido)" >&2; exit 1
    fi
    mkdir -p "$tmpk/x"
    if [[ "$SO" == "windows" ]]; then unzip -q "$tmpk/$pacote" -d "$tmpk/x"; else tar -xzf "$tmpk/$pacote" -C "$tmpk/x"; fi
    mv -f "$tmpk/x/kyverno${EXT}" "$BIN/kyverno${EXT}"
    chmod +x "$BIN/kyverno${EXT}"
    rm -rf "$tmpk"
    echo "ok    kyverno CLI instalado ($obtido)"
  fi
fi

echo
"$BIN/kind${EXT}" version
"$BIN/cosign${EXT}" version 2>/dev/null | grep -E '^GitVersion' || true
if [[ -f "$BIN/kubectl${EXT}" ]]; then "$BIN/kubectl${EXT}" version --client 2>/dev/null | head -n1; fi
if [[ -f "$BIN/kyverno${EXT}" ]]; then "$BIN/kyverno${EXT}" version 2>/dev/null | head -n1 | sed 's/^/kyverno CLI /'; fi
