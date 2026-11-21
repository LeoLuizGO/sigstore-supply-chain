# Imagem da loja de exemplo (artefato assinado pelo pipeline).
# Base fixada por tag exata + digest do índice multi-arquitetura. Em 21/11/2026
# python:3.12-slim == python:3.12.16-slim-trixie == sha256:5e2bdb1b... (Docker Hub).
# Para atualizar: consultar o digest novo e rodar o pipeline (o Trivy barra a troca
# se a base nova tiver CVE crítica com correção).
FROM python:3.12.16-slim-trixie@sha256:5e2bdb1b0d542d5039cffb8181c65930093949194a65c365dfb1b0fe13a4fa5b

# Repositório de origem: o GHCR usa este rótulo para ligar o pacote ao repositório.
ARG FONTE=https://github.com/LeoLuizGO/sigstore-supply-chain
ARG VERSAO=desconhecida
LABEL org.opencontainers.image.source="${FONTE}" \
      org.opencontainers.image.revision="${VERSAO}" \
      org.opencontainers.image.title="sigstore-supply-chain" \
      org.opencontainers.image.description="Loja de exemplo do trabalho de Segurança (UFSC): imagem assinada com Sigstore" \
      org.opencontainers.image.licenses="MIT"

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1 \
    LOJA_PORTA=8080 \
    LOJA_VERSAO=${VERSAO}

WORKDIR /app

# Dependências: só instala se houver alguma linha que não seja comentário.
# --require-hashes obriga cada pacote a vir com o hash SHA-256 conferido pelo pip.
COPY app/requirements.txt ./requirements.txt
RUN if grep -qvE '^[[:space:]]*(#|$)' requirements.txt; then \
        pip install --require-hashes --no-deps -r requirements.txt; \
    else \
        echo "requirements.txt sem dependências"; \
    fi

COPY app/loja.py ./loja.py

# Usuário sem privilégios (UID fixo para o securityContext do Kubernetes).
RUN groupadd --system --gid 10001 loja \
 && useradd --system --uid 10001 --gid loja --no-create-home --shell /usr/sbin/nologin loja
USER 10001:10001

EXPOSE 8080
CMD ["python", "/app/loja.py"]
