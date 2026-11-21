#!/usr/bin/env bash
# Funções do workflow de ataques (E2), chamadas pelo .github/workflows/ataques.yml.
#
# Uso (no runner, depois de "docker login ghcr.io"):
#   ataques.sh construir CENARIO TAG       # imagem adulterada a partir do digest legítimo; imprime o digest
#   ataques.sh registrar CENARIO ID TAG DIGEST OBSERVACAO   # acrescenta a entrada em ataques-digests.json
#
# Variáveis exigidas: IMAGEM (ghcr.io/<owner>/<repo>, minúsculas), DIGEST_LEGITIMO (sha256:...).
# Opcional: SAIDA_JSON (padrão ataques-digests.json), GITHUB_RUN_ID.
#
# A "modificação maliciosa" é inofensiva: grava /app/MALICIOSO.txt e troca a mensagem da rota /
# (variável LOJA_MENSAGEM). Cada cenário/execução gera um digest diferente (o arquivo inclui o
# cenário e o id da execução), para que a assinatura de um cenário não contamine outro.
set -euo pipefail

: "${IMAGEM:?defina IMAGEM}"
: "${DIGEST_LEGITIMO:?defina DIGEST_LEGITIMO}"
SAIDA_JSON="${SAIDA_JSON:-ataques-digests.json}"

construir() {
  local cenario="$1" tag="$2"
  local dir
  dir=$(mktemp -d)
  cat > "$dir/Dockerfile" <<EOF
FROM ${IMAGEM}@${DIGEST_LEGITIMO}
ARG CENARIO
ARG EXECUCAO
USER root
RUN printf 'Arquivo inserido pelo workflow de ataques (modificacao inofensiva).\ncenario=%s\nexecucao=%s\n' "\$CENARIO" "\$EXECUCAO" > /app/MALICIOSO.txt
ENV LOJA_MENSAGEM="IMAGEM ADULTERADA (cenario ${cenario}) - nao deveria ser admitida pelo cluster"
LABEL org.opencontainers.image.description="Imagem adulterada do experimento E2 (${cenario})" \\
      ataque.cenario="${cenario}"
USER 10001:10001
EOF
  docker buildx build --platform linux/amd64 --provenance=false --sbom=false \
    --build-arg "CENARIO=${cenario}" --build-arg "EXECUCAO=${GITHUB_RUN_ID:-local}" \
    -t "${IMAGEM}:${tag}" --load "$dir" >&2
  docker push "${IMAGEM}:${tag}" >&2
  rm -rf "$dir"
  local digest
  digest=$(crane digest "${IMAGEM}:${tag}")
  [[ "$digest" =~ ^sha256:[0-9a-f]{64}$ ]] || { echo "digest inválido: $digest" >&2; exit 1; }
  if [ "$digest" = "$DIGEST_LEGITIMO" ]; then
    echo "a imagem adulterada ficou com o mesmo digest da legítima" >&2
    exit 1
  fi
  echo "$digest"
}

registrar() {
  local cenario="$1" id="$2" tag="$3" digest="$4" obs="$5"
  local tmp
  tmp=$(mktemp)
  jq --arg cenario "$cenario" --arg id "$id" --arg tag "$tag" --arg digest "$digest" \
     --arg imagem "$IMAGEM" --arg obs "$obs" \
     '.cenarios += [{cenario: $cenario, id: $id, tag: $tag, digest: $digest,
                     referencia: "\($imagem)@\($digest)", referencia_tag: "\($imagem):\($tag)",
                     observacao: $obs}]' "$SAIDA_JSON" > "$tmp"
  mv "$tmp" "$SAIDA_JSON"
}

comando="${1:-}"
shift || true
case "$comando" in
  construir) construir "$@" ;;
  registrar) registrar "$@" ;;
  *) echo "uso: $0 construir CENARIO TAG | registrar CENARIO ID TAG DIGEST OBSERVACAO" >&2; exit 2 ;;
esac
