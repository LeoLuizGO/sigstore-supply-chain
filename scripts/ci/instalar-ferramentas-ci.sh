#!/usr/bin/env bash
# Instala no runner do GitHub Actions (Linux x86_64) as ferramentas do pipeline,
# cada uma com versão fixa e verificação de integridade antes de executar qualquer binário.
#
# Uso: bash scripts/ci/instalar-ferramentas-ci.sh trivy syft crane
#
# Verificações:
#   trivy  0.69.3  SHA-256 fixado aqui + assinatura Sigstore do tarball (cosign verify-blob,
#                  identidade do workflow de release do Trivy na tag v0.69.3).
#                  0.69.3 é a última versão anterior ao incidente de 19/03/2026
#                  (GHSA-69fq-xp46-6x23: v0.69.4 maliciosa); publicada como release imutável.
#   syft   1.57.2  SHA-256 fixado aqui + assinatura Sigstore do checksums.txt da release
#                  (o hash fixado precisa constar no arquivo assinado).
#   crane  0.22.1  SHA-256 fixado aqui + proveniência SLSA da release (multiple.intoto.jsonl),
#                  assinada pelo slsa-github-generator v2.1.0, cujo subject precisa ser o tarball.
# As verificações por assinatura usam o cosign, que precisa estar no PATH
# (instalado antes pelo sigstore/cosign-installer, que verifica o próprio cosign).
set -euo pipefail

EMISSOR="https://token.actions.githubusercontent.com"

TRIVY_VERSAO="0.69.3"
TRIVY_SHA256="1816b632dfe529869c740c0913e36bd1629cb7688bd5634f4a858c1d57c88b75"
TRIVY_IDENTIDADE="https://github.com/aquasecurity/trivy/.github/workflows/reusable-release.yaml@refs/tags/v${TRIVY_VERSAO}"

SYFT_VERSAO="1.57.2"
SYFT_SHA256="ad92bd3ec1b94a3df01d4d0aec199afa9c42b72e86da436ff5f837914d32706b"
SYFT_IDENTIDADE="https://github.com/anchore/syft/.github/workflows/release.yaml@refs/heads/main"

CRANE_VERSAO="0.22.1"
CRANE_SHA256="0ab7a1d6932a213aed964ce97666c3077fe691c8606413674a8b3e0b9ec4cda0"
CRANE_IDENTIDADE="https://github.com/slsa-framework/slsa-github-generator/.github/workflows/generator_generic_slsa3.yml@refs/tags/v2.1.0"

DESTINO="${RUNNER_TEMP:-/tmp}/ferramentas"
mkdir -p "$DESTINO/bin" "$DESTINO/download"
cd "$DESTINO/download"

baixar() { # url arquivo
  curl --fail --silent --show-error --location --retry 5 --retry-delay 3 --retry-all-errors -o "$2" "$1"
}

conferir_sha256() { # arquivo hash
  echo "$2  $1" | sha256sum --check --strict -
}

exigir_cosign() {
  command -v cosign >/dev/null || { echo "cosign não está no PATH (rode o sigstore/cosign-installer antes)" >&2; exit 1; }
}

instalar_trivy() {
  exigir_cosign
  local base="https://github.com/aquasecurity/trivy/releases/download/v${TRIVY_VERSAO}"
  local arq="trivy_${TRIVY_VERSAO}_Linux-64bit.tar.gz"
  baixar "$base/$arq" "$arq"
  baixar "$base/$arq.sigstore.json" "$arq.sigstore.json"
  conferir_sha256 "$arq" "$TRIVY_SHA256"
  cosign verify-blob --new-bundle-format --bundle "$arq.sigstore.json" \
    --certificate-identity "$TRIVY_IDENTIDADE" --certificate-oidc-issuer "$EMISSOR" "$arq"
  tar -xzf "$arq" -C "$DESTINO/bin" trivy
  "$DESTINO/bin/trivy" --version
}

instalar_syft() {
  exigir_cosign
  local base="https://github.com/anchore/syft/releases/download/v${SYFT_VERSAO}"
  local arq="syft_${SYFT_VERSAO}_linux_amd64.tar.gz"
  local soma="syft_${SYFT_VERSAO}_checksums.txt"
  baixar "$base/$arq" "$arq"
  baixar "$base/$soma" "$soma"
  baixar "$base/$soma.sigstore.json" "$soma.sigstore.json"
  conferir_sha256 "$arq" "$SYFT_SHA256"
  cosign verify-blob --new-bundle-format --bundle "$soma.sigstore.json" \
    --certificate-identity "$SYFT_IDENTIDADE" --certificate-oidc-issuer "$EMISSOR" "$soma"
  grep -qE "^${SYFT_SHA256}[[:space:]]+${arq}\$" "$soma" \
    || { echo "hash do syft não confere com o checksums.txt assinado" >&2; exit 1; }
  tar -xzf "$arq" -C "$DESTINO/bin" syft
  "$DESTINO/bin/syft" version
}

instalar_crane() {
  exigir_cosign
  local base="https://github.com/google/go-containerregistry/releases/download/v${CRANE_VERSAO}"
  local arq="go-containerregistry_Linux_x86_64.tar.gz"
  baixar "$base/$arq" "$arq"
  baixar "$base/multiple.intoto.jsonl" "crane.intoto.jsonl"
  conferir_sha256 "$arq" "$CRANE_SHA256"
  cosign verify-blob-attestation --new-bundle-format --bundle crane.intoto.jsonl \
    --type slsaprovenance \
    --certificate-identity "$CRANE_IDENTIDADE" --certificate-oidc-issuer "$EMISSOR" "$arq"
  tar -xzf "$arq" -C "$DESTINO/bin" crane
  "$DESTINO/bin/crane" version
}

[ "$#" -gt 0 ] || { echo "uso: $0 trivy|syft|crane ..." >&2; exit 2; }
for ferramenta in "$@"; do
  case "$ferramenta" in
    trivy) instalar_trivy ;;
    syft) instalar_syft ;;
    crane) instalar_crane ;;
    *) echo "ferramenta desconhecida: $ferramenta" >&2; exit 2 ;;
  esac
done

if [ -n "${GITHUB_PATH:-}" ]; then
  echo "$DESTINO/bin" >> "$GITHUB_PATH"
fi
echo "ferramentas instaladas em $DESTINO/bin"
