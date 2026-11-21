# Especificação compartilhada do projeto

Trabalho de Segurança em Computação (UFSC, Profs. Jean Martina e Thaís Bardini Idalino).
Tema: integridade da cadeia de suprimentos de software com assinaturas keyless (Sigstore),
transparency log (Rekor), política de admissão (Kyverno) e um verificador próprio em Python.
Relatório parcial entregue: ver `docs/relatorio-parcial.md` (texto integral). O código precisa
cumprir o que está descrito lá (Seções 3.2 a 3.4) — leia antes de começar.

Esta especificação é o contrato entre as partes. Não mude os valores nem as interfaces daqui;
se precisar de algo diferente, registre em `docs/<sua-area>.md`, na seção "Pedidos para outras áreas".

## Valores fixos (fonte única: `config.env`, que é um arquivo bash para `source`)

| Item | Valor |
|---|---|
| Repo local | `C:\Users\Leo\sigstore-supply-chain` (git, sem remote ainda) |
| Repo remoto (futuro, público) | `https://github.com/LeoLuizGO/sigstore-supply-chain` |
| Imagem | `ghcr.io/leoluizgo/sigstore-supply-chain` (pacote público, pull anônimo) |
| Tags do pipeline | `:sha-<7 primeiros do commit>` no push; `:main` só é movida para o digest **depois** de assinado |
| Identidade do pipeline (SAN) | `https://github.com/LeoLuizGO/sigstore-supply-chain/.github/workflows/pipeline.yml@refs/heads/main` |
| Identidade do reescaneamento | `.../.github/workflows/reescanear.yml@refs/heads/main` (só atesta `vuln`, nunca assina a imagem) |
| Identidade dos ataques | `.../.github/workflows/ataques.yml@refs/heads/main` |
| Identidade da proveniência | `https://github.com/slsa-framework/slsa-github-generator/.github/workflows/generator_container_slsa3.yml@refs/tags/v2.1.0` |
| Emissor OIDC | `https://token.actions.githubusercontent.com` |
| Rekor | `https://rekor.sigstore.dev` (v1; entradas `hashedrekord` para assinaturas, `intoto`/`dsse` para atestados) |
| Cosign | versão 2.x fixa (formato legado: assinatura em `sha256-<hex>.sig`, atestados em `sha256-<hex>.att`). Não usar o formato novo de bundle/referrers. |
| Tipos de atestado | SBOM `--type cyclonedx` (`https://cyclonedx.org/bom`); varredura `--type vuln` (`https://cosign.sigstore.dev/attestation/vuln/v1`); proveniência SLSA v0.2 (`https://slsa.dev/provenance/v0.2`) gerada pelo slsa-github-generator |
| Cluster | kind, nome `sigstore`; app no namespace `loja`, deployment `loja` |
| Janela do atestado de varredura | `24h` por padrão (configurável em `config.env`) |

## Tags produzidas pelo workflow de ataques (E2)

| Cenário | Tag / artefato | Como é produzido |
|---|---|---|
| E2.1 sem assinatura | `:ataque-sem-assinatura` | imagem modificada, publicada sem assinar |
| E2.2 camada alterada | `:main` (sobrescrita) | `FROM <imagem>@<digest legítimo>` + camada extra, publicada na mesma tag `main` |
| E2.3a outra identidade | `:ataque-outra-identidade` | assinada keyless pelo próprio `ataques.yml` (SAN diferente) |
| E2.3b chave local | `:ataque-chave-local` | assinada com par de chaves cosign gerado no job (sem certificado Fulcio) |
| E2.4 troca de assinatura | `:ataque-troca-assinatura` | imagem modificada; o manifesto `.sig` do digest legítimo é copiado para `sha256-<digest malicioso>.sig` |
| E2.5 rollback | digest legítimo antigo | nenhum workflow; testado com e sem a política de atestado de varredura |
| E2.6 dependência vulnerável | run do `pipeline.yml` com `incluir_dependencia_vulneravel=true` | o Trivy interrompe antes da assinatura |

## Divisão de responsabilidades (quem pode editar o quê)

- `verificador/` → agente **verificador**
- `app/`, `Dockerfile`, `.github/`, `scripts/ci/` → agente **pipeline**
- `k8s/`, `politicas/`, `scripts/cluster/`, `scripts/instalar-ferramentas.sh` → agente **cluster**
- `README.md`, `config.env`, `docs/ESPEC.md`, `.gitignore` → coordenador

Cada agente escreve `docs/<area>.md` (verificador.md, pipeline.md, cluster.md) com: o que foi feito, como rodar,
o que foi testado de verdade (com saídas), o que fica pendente para rodar no GitHub/cluster, e pedidos para outras áreas.

## Resultados dos experimentos (`resultados/`)

Nomes fixos (CSV com cabeçalho; separador vírgula; UTF-8):
- `e1-*.json|txt` — evidências do pipeline completo (digest, logIndex do Rekor, saída do cosign verify)
- `e2-ataques.csv` — cenario,imagem,esperado,obtido,mensagem
- `e3-verificador.csv` — caso,origem(real|sintetico),nosso_verificador,cosign,sigstore_python,motivo
- `e4-pipeline-etapas.csv` — etapa,n,media_s,desvio_s,min_s,max_s
- `e4-latencia-admissao.csv` — cenario(frio|quente),n,media_ms,desvio_ms,p50_ms,p95_ms
- `e4-cves-imagens-base.csv` — imagem,critical,high,medium,low,unknown,total
- `e4-tamanhos.csv` — artefato,bytes

## Contrato da CLI do verificador (rodar da raiz do repo)

```
python -m verificador digest IMAGEM:TAG                     # imprime sha256:... (resolve a tag no registry)
python -m verificador baixar IMAGEM@sha256:... -o evidencia.json
python -m verificador verificar evidencia.json --digest sha256:... --identidade SAN --emissor ISSUER [--trusted-root ARQ] [--json]
python -m verificador imagem IMAGEM@sha256:... --identidade SAN --emissor ISSUER [--json]   # baixar + verificar
python -m verificador inspecionar IMAGEM@sha256:... [--json]                                # artefatos .sig/.att e tamanhos
```
Códigos de saída: 0 = válida, 1 = rejeitada (motivo impresso), 2 = erro de uso/rede.
Dependências em `verificador/requirements.txt`.

## Regras para todos

1. **Nada de ação externa**: não fazer `git push`, não criar repositório, não publicar imagem, não assinar nada no Sigstore
   público (Rekor é permanente e público), não abrir issue/PR. Leitura de APIs públicas é liberada
   (`gh api` GET, `curl` no Rekor, registries, PyPI, Docker Hub).
2. **Versões fixas e conferidas**: toda ferramenta/action/imagem com versão exata, conferida via API antes de usar
   (não confiar na memória). GitHub Actions de terceiros fixadas por SHA completo do commit, com a tag em comentário
   (lição do caso tj-actions). Exceção documentada: o slsa-github-generator precisa ser referenciado por tag.
3. Host Windows 11 com Git Bash. Scripts em bash (`#!/usr/bin/env bash`, `set -euo pipefail`) que funcionem no Git Bash
   e no Linux. Python 3.11 disponível como `python`. Docker Desktop instalado (pode estar parado).
4. Comentários, mensagens e documentação em português.
5. Não editar arquivos de outra área.
