# Pipeline (área do agente pipeline)

Escopo: `app/`, `Dockerfile`, `.dockerignore`, `.github/workflows/`, `scripts/ci/` e este arquivo.
Tudo foi escrito e conferido localmente em 21/11/2026; **nada foi executado no GitHub** (não há
repositório remoto ainda). Versões, flags e saídas de cada ferramenta foram conferidas na fonte da
versão fixada (via `gh api`), não de memória.

## 1. Arquivos

| Arquivo | Função |
|---|---|
| `app/loja.py` | servidor HTTP só com biblioteca padrão; `GET /` (JSON com mensagem, versão e produtos) e `GET /saude` (`{"status":"ok"}`); porta `LOJA_PORTA` (8080) |
| `app/requirements.txt` | vazio (só comentários); o E2.6 acrescenta o Django no runner |
| `Dockerfile` | base `python:3.12.16-slim-trixie@sha256:5e2bdb1b…` (= `python:3.12-slim` em 21/11), usuário 10001 sem privilégios, porta 8080, rótulo `org.opencontainers.image.source` |
| `.dockerignore` | só `app/` entra no contexto de build |
| `.github/workflows/pipeline.yml` | E1 (e E2.6 via input) |
| `.github/workflows/reescanear.yml` | reescaneamento diário + novo atestado `vuln` (mitigação do rollback, E2.5) |
| `.github/workflows/ataques.yml` | E2.1 a E2.4: imagens adulteradas e `ataques-digests.json` |
| `.github/workflows/varredura-bases.yml` | E4: CVEs em três imagens base (não bloqueante) |
| `scripts/ci/instalar-ferramentas-ci.sh` | instala Trivy, Syft e crane no runner com hash fixo + assinatura/proveniência conferida |
| `scripts/ci/ataques.sh` | constrói a imagem adulterada de cada cenário e registra no JSON |
| `scripts/ci/contar-cves.py` | conta CVEs por severidade em relatórios JSON do Trivy (CSV da ESPEC) |
| `scripts/ci/metricas-pipeline.sh` | E4: duração das etapas em N execuções → `resultados/e4-pipeline-etapas.csv` |
| `scripts/ci/baixar-evidencias.sh` | baixa os artifacts para `resultados/` |
| `scripts/ci/cves-imagens-base.sh` | E4 local (mesma varredura do workflow) |

## 2. Workflows

Regras comuns: `permissions: {}` no topo e permissões mínimas por job; `persist-credentials: false`
em todo checkout; nada de `pull_request_target`; `shell: bash` padrão (com `-e -o pipefail`);
entradas de `workflow_dispatch` só entram nos scripts via `env:` (sem interpolar `${{ }}` dentro do
script) e digests são validados com `^sha256:[0-9a-f]{64}$`. Todos os jobs que assinam/atestam só
rodam em `refs/heads/main`, porque é essa a identidade que o cluster aceita.

### 2.1 `pipeline.yml` (E1)

Gatilhos: `push` na `main` e `workflow_dispatch` com `incluir_dependencia_vulneravel` (booleano, padrão false).
`concurrency` impede duas execuções simultâneas (a ordem em que `:main` é movida fica garantida).

| Job | Permissões | O que faz |
|---|---|---|
| `semgrep` | `contents: read` | Semgrep 1.186.0 (imagem fixada por digest) com `p/python` + `p/dockerfile`; falha só com achado de severidade `ERROR` |
| `build-e-varredura` | `contents: read`, `packages: write` | (E2.6) injeta Django; `docker buildx build --provenance=false --sbom=false`; push só da tag `sha-<7>`; digest resolvido no registry (`crane digest`) e conferido com o do `docker push`; **Trivy bloqueante** `--severity CRITICAL --ignore-unfixed --exit-code 1` no digest; Syft → `e1-sbom.cdx.json` (CycloneDX); Trivy `--format cosign-vuln` → `e1-vuln.json` |
| `assinar-e-atestar` | `id-token: write`, `packages: write` | `cosign sign --yes IMG@digest`; `cosign attest --yes --type cyclonedx`; `cosign attest --yes --type vuln` (único job com token OIDC além da proveniência; não faz checkout nem roda scanner) |
| `proveniencia` | `actions: read`, `id-token: write`, `packages: write` | `slsa-framework/slsa-github-generator/.github/workflows/generator_container_slsa3.yml@v2.1.0` com `image`, `digest`, `registry-username: github.actor` e o secret `registry-password: GITHUB_TOKEN` (inputs/secrets/permissões conferidos no `generator_container_slsa3.yml` da tag) |
| `promover-main` | `contents: read`, `packages: write` | só depois de assinar, atestar e gerar a proveniência: `crane tag IMG@digest main` (mesmo manifesto, mesmo digest) e confere `crane digest IMG:main` |
| `verificacao-independente` | `contents: read`, `packages: read` | `cosign verify` e `cosign verify-attestation` (`cyclonedx`, `vuln` com a identidade do pipeline; `slsaprovenance` com a identidade do gerador SLSA), verificador do grupo (`python -m verificador imagem … --json`, Python 3.12 via `actions/setup-python` + `pip install -r verificador/requirements.txt` num venv), confere `:main`; grava o resumo no `$GITHUB_STEP_SUMMARY` e o artifact **`evidencias-e1`**. Roda todas as verificações e só falha no fim, se alguma falhou |

Identidades usadas (exatas, `--certificate-identity` / `--certificate-oidc-issuer`):
- pipeline: `https://github.com/LeoLuizGO/sigstore-supply-chain/.github/workflows/pipeline.yml@refs/heads/main`
- proveniência: `https://github.com/slsa-framework/slsa-github-generator/.github/workflows/generator_container_slsa3.yml@refs/tags/v2.1.0`
- emissor: `https://token.actions.githubusercontent.com`

Conteúdo do artifact `evidencias-e1` (tudo com prefixo `e1-`, vai direto para `resultados/`):

| Arquivo | Conteúdo |
|---|---|
| `e1-imagem.txt`, `e1-digest.txt` | `IMG@sha256:…` e o digest |
| `e1-rekor.json` | `logIndex` **global** da assinatura (o que o `cosign sign` imprime: `tlog entry created with index: N`; se faltar, o do bundle do `cosign verify`), `url` `https://search.sigstore.dev/?logIndex=N`, a lista `{logIndex, integratedTime}` de todas as assinaturas válidas do digest e os índices dos atestados `cyclonedx`/`vuln` |
| `e1-cosign-verify.json` / `.txt` | stdout JSON (`[].optional.Bundle.Payload.logIndex`, `Subject`, `Issuer`…) / stderr do `cosign verify` |
| `e1-cosign-verify-attestation-{cyclonedx,vuln,slsaprovenance}.json` / `.txt` | envelopes DSSE verificados (uma linha JSON por atestado) / stderr |
| `e1-cosign-sign.txt`, `e1-cosign-attest-{cyclonedx,vuln}.txt` | saída da assinatura e dos atestados (com o índice no Rekor) |
| `e1-sbom.cdx.json`, `e1-vuln.json`, `e1-trivy-bloqueante.json` | SBOM, predicado cosign-vuln, varredura bloqueante |
| `e1-verificador.json` / `.txt` | saída `--json` / stderr do verificador do grupo |
| `e1-verificacoes.csv` | `imagem,digest,verificacao,resultado` (OK / FALHOU) |
| `e1-resumo.md`, `e1-semgrep.json` | resumo da execução e relatório do Semgrep |

**E2.6** (`incluir_dependencia_vulneravel=true`): acrescenta
`Django==3.2.12 --hash=sha256:9b06c289…d965` (hash do wheel no PyPI) ao `requirements.txt`. O pip
instala com `--require-hashes --no-deps`. A imagem é publicada com a tag `sha-<7>-vulneravel`
(sufixo para não sobrescrever a tag da imagem legítima do mesmo commit), o Trivy falha e os jobs de
assinatura, proveniência, promoção e verificação ficam *skipped*. O resumo da execução lista as CVEs.
Django 3.2.12 tem 5 CVEs CRITICAL com correção no banco do Trivy (conferido localmente, seção 6):
CVE-2022-28346 (GHSA-2gwj-7jmv-h26r, 9.8, corrigida em 3.2.13), CVE-2022-28347, CVE-2022-34265,
CVE-2023-31047, CVE-2025-64459.

### 2.2 `reescanear.yml`

Gatilhos: `workflow_dispatch` (input `digest`, vazio = digest atual de `:main`) e `schedule` diário
(`17 6 * * *`, 03:17 em Brasília). Permissões: `contents: read`, `id-token: write`, `packages: write`.
1. Resolve o digest e **exige assinatura válida do `pipeline.yml`** (não reatesta imagem adulterada que esteja em `:main`).
2. Trivy com a mesma regra bloqueante. Se reprovar: escreve o resumo, falha e **não atesta**.
3. Se aprovar: `trivy --format cosign-vuln` e `cosign attest --yes --replace --type vuln`.
   Conferido no código do cosign v2.6.5 (`pkg/cosign/remote/remote.go`, `NewReplaceOp`): `--replace`
   remove do manifesto `.att` só as camadas cujo `predicateType` é igual ao do novo atestado
   (`https://cosign.sigstore.dev/attestation/vuln/v1`) e acrescenta o novo; SBOM e proveniência ficam.
   O `.sig` não é tocado.
4. Confere o atestado novo com a identidade `.../reescanear.yml@refs/heads/main` e mostra o `scanFinishedOn`.

### 2.3 `ataques.yml` (E2)

Gatilho: `workflow_dispatch` com `cenario` (choice: `todos`, `sem-assinatura`, `camada-alterada`,
`outra-identidade`, `chave-local`, `troca-assinatura`) e `digest_legitimo` (vazio = digest atual de
`:main`) e `digest_antigo` (opcional, E2.5: digest legítimo anterior; é conferido, precisa ter
assinatura do pipeline, e só vai para o JSON, como pedido pelo cluster). Permissões: `contents: read`, `packages: write`, `id-token: write`.

O digest de partida precisa ter assinatura válida do pipeline (senão o job para e pede
`digest_legitimo`; isso cobre o caso de `:main` já ter sido sobrescrita por um E2.2 anterior).
A modificação é inofensiva: `FROM IMG@<legítimo>` + `RUN` que grava `/app/MALICIOSO.txt` (com cenário
e id da execução, então cada cenário tem digest próprio) + `ENV LOJA_MENSAGEM="IMAGEM ADULTERADA …"`
(a rota `/` passa a mostrar isso) + rótulo `ataque.cenario`.

| Cenário | Tag | Como |
|---|---|---|
| E2.1 `sem-assinatura` | `:ataque-sem-assinatura` | push sem assinar |
| E2.3a `outra-identidade` | `:ataque-outra-identidade` | `cosign sign --yes` keyless neste workflow (SAN `.../ataques.yml@refs/heads/main`) |
| E2.3b `chave-local` | `:ataque-chave-local` | `cosign generate-key-pair` (senha vazia) + `cosign sign --key` (vai para o Rekor como `hashedrekord` com chave pública, sem certificado Fulcio); o job confere `cosign verify --key` (assinatura válida para a chave do atacante), guarda só a chave pública (`ataque-chave-local.pub`) e apaga a privada |
| E2.4 `troca-assinatura` | `:ataque-troca-assinatura` | `crane copy IMG:sha256-<legítimo>.sig IMG:sha256-<malicioso>.sig` (cópia do manifesto sem nenhuma alteração) |
| E2.2 `camada-alterada` | `:main` (sobrescrita) | roda por último; deixa um aviso |

Saídas: tabela cenário → tag → digest no resumo e o artifact **`ataques-digests`** com
`ataques-digests.json` (+ logs `ataque-*.txt` e `ataque-chave-local.pub`). Formato:

```json
{
  "imagem": "ghcr.io/leoluizgo/sigstore-supply-chain",
  "digest_legitimo": "sha256:<64 hex>",
  "referencia_legitima": "ghcr.io/leoluizgo/sigstore-supply-chain@sha256:<64 hex>",
  "digest_antigo": null,
  "cenario_solicitado": "todos",
  "workflow_run": "https://github.com/LeoLuizGO/sigstore-supply-chain/actions/runs/<id>",
  "commit": "<sha do commit>",
  "gerado_em": "2026-11-21T16:19:04Z",
  "cenarios": [
    {
      "cenario": "sem-assinatura",
      "id": "E2.1",
      "tag": "ataque-sem-assinatura",
      "digest": "sha256:<64 hex>",
      "referencia": "ghcr.io/leoluizgo/sigstore-supply-chain@sha256:<64 hex>",
      "referencia_tag": "ghcr.io/leoluizgo/sigstore-supply-chain:ataque-sem-assinatura",
      "observacao": "imagem modificada publicada sem assinatura"
    }
  ]
}
```

`cenarios` é uma lista só com os cenários executados, na ordem E2.1, E2.3a, E2.3b, E2.4, E2.2;
`cenario` ∈ {`sem-assinatura`, `outra-identidade`, `chave-local`, `troca-assinatura`,
`camada-alterada`} e `id` ∈ {`E2.1`, `E2.3a`, `E2.3b`, `E2.4`, `E2.2`}. Para E2.2, `tag` é `main`.
`scripts/ci/baixar-evidencias.sh --ataques` grava o arquivo em `resultados/ataques-digests.json`.

Para voltar ao estado legítimo depois do E2.2: rodar o `pipeline.yml` de novo (novo digest assinado
em `:main`) ou `crane tag ghcr.io/leoluizgo/sigstore-supply-chain@<digest legítimo> main`.
E2.5 (rollback) não gera imagem: usa um digest legítimo antigo (ver `e1-digest.txt` de uma execução
anterior; pode ser passado em `digest_antigo` para ir no JSON). **Não** rode o `reescanear.yml` nesse
digest antigo, senão ele ganha atestado novo e o rollback deixa de ser recusado (o agendamento só
reescaneia o digest atual de `:main`). E2.6 é o input do `pipeline.yml`.

### 2.4 `varredura-bases.yml` (E4)

`workflow_dispatch`, só `contents: read`, nunca bloqueia nada. Trivy 0.69.3 com `--platform linux/amd64`
em três imagens fixadas por digest (21/11/2026):

| Rótulo no CSV | Referência |
|---|---|
| `python:3.12` | `python:3.12.16-trixie@sha256:5411fa1b302c43f510324381162b5f5d0d93b9ee2af538f09d944f0d290ee3cb` |
| `python:3.12-slim` | `python:3.12.16-slim-trixie@sha256:5e2bdb1b0d542d5039cffb8181c65930093949194a65c365dfb1b0fe13a4fa5b` |
| `gcr.io/distroless/python3-debian12` | `gcr.io/distroless/python3-debian12:latest@sha256:2fdb05402a2cf21cf78fdb3ba4c5db167241e9e498140f5bf689d7efb773731f` |

Cada uma com e sem `--ignore-unfixed`. Artifact `e4-cves-imagens-base`:
`e4-cves-imagens-base.csv` (todas as CVEs, formato da ESPEC), `e4-cves-imagens-base-corrigiveis.csv`
(mesmo formato, só com correção) e `json/*.json`. Conta achados (par CVE × pacote), como a tabela do Trivy.

## 3. Versões fixadas

### Actions (SHA completo conferido com `gh api repos/<repo>/git/ref/tags/<tag>`; todas são tags leves, sem desreferência; commits conferidos no histórico do repositório oficial)

| Action | Tag | Commit |
|---|---|---|
| `actions/checkout` | v7.0.1 | `3d3c42e5aac5ba805825da76410c181273ba90b1` |
| `actions/upload-artifact` | v7.0.2 | `cf430e030ddbb5b0abf93d22962f4752f3646cd9` |
| `actions/download-artifact` | v8.0.2 | `9000827ccba6bdab643e8b6fd33ac0654aef8333` |
| `actions/setup-python` | v7.1.0 | `6d4fd22b20465ccc0f7354476588e8df7c9ca0e0` |
| `sigstore/cosign-installer` | v4.1.3 (release imutável) | `756fe2d284c7292c4e9b62c8a28f1e5629c59532` |
| `slsa-framework/slsa-github-generator` (workflow reutilizável) | **v2.1.0 por tag** | a tag aponta para `f7dd8c54c2067bafc12ca7a55595d5ee9b75204a` |

Exceção documentada: o README do gerador (`internal/builders/container/README.md` da v2.1.0) diz que
ele **precisa** ser referenciado por `@vX.Y.Z` e falha se referenciado por hash (o gerador descobre a
própria versão pelo ref para baixar o binário do builder e verificar a proveniência dele). A tag
v2.1.0 não é release imutável; o risco é mitigado porque a identidade aceita no cluster é
`...generator_container_slsa3.yml@refs/tags/v2.1.0`.

Não usei `docker/*-action`, `aquasecurity/trivy-action`, `aquasecurity/setup-trivy` nem
`anchore/sbom-action`: o build é `docker buildx` do próprio runner e as ferramentas são binários
verificados (abaixo). Menos actions de terceiros = menos superfície (caso tj-actions e caso Trivy).

### Ferramentas

| Ferramenta | Versão | Como é verificada |
|---|---|---|
| cosign | **v2.6.5** (último 2.x) | `sigstore/cosign-installer` v4.1.3 com `cosign-release: v2.6.5`: baixa o cosign v3.1.4 de bootstrap (SHA-256 embutido na action), confere a chave `release-cosign.pub` (SHA-256 `f4cea466…f126`, embutido) e verifica a assinatura `.sig` do binário v2.6.5 com ela (para versões < 3.0.1 a action usa a assinatura por chave; conferido no `action.yml`). Localmente: `cosign-windows-amd64.exe` sha256 `19ec346d…19385825` = `cosign_checksums.txt`, e `cosign verify-blob --key release-cosign.pub` → `Verified OK` |
| Trivy | **0.69.3** | sha256 `1816b632…88b75` fixado + `cosign verify-blob --new-bundle-format --bundle trivy_0.69.3_Linux-64bit.tar.gz.sigstore.json` com identidade `https://github.com/aquasecurity/trivy/.github/workflows/reusable-release.yaml@refs/tags/v0.69.3` |
| Syft | 1.57.2 (release imutável) | sha256 `ad92bd3e…706b` fixado + assinatura Sigstore do `syft_1.57.2_checksums.txt` (identidade `https://github.com/anchore/syft/.github/workflows/release.yaml@refs/heads/main`) + o hash fixado precisa constar no arquivo assinado |
| crane (go-containerregistry) | 0.22.1 | sha256 `0ab7a1d6…cda0` fixado + `cosign verify-blob-attestation --type slsaprovenance` da proveniência SLSA da release (`multiple.intoto.jsonl`, assinada por `generator_generic_slsa3.yml@refs/tags/v2.1.0`), cujo subject é esse tarball |
| Semgrep | 1.186.0 | imagem `semgrep/semgrep:1.186.0@sha256:6e1b04340e60e910fbb4ddbf3c857ab0918f064417ad5ac530014ccb3cf8c8f1` (índice no Docker Hub); regras `p/python` e `p/dockerfile` do registry público |
| Imagem do Trivy (script local) | 0.69.3 | `aquasec/trivy:0.69.3@sha256:bcc376de…258d1c`; `cosign verify --new-bundle-format` com a identidade do release do Trivy → OK (Docker Hub e GHCR) |
| Python do verificador | 3.12 | `actions/setup-python`; dependências fixas em `verificador/requirements.txt` (área do verificador) |
| Runner | `ubuntu-24.04` | fixo (não `ubuntu-latest`) |

### Por que Trivy 0.69.3 (incidente de março de 2026)

O GHSA-69fq-xp46-6x23 / CVE-2026-33634 (Aqua, publicado em 21/03/2026) documenta: em 19/03/2026 um
atacante com credenciais comprometidas publicou o **Trivy v0.69.4 malicioso**, forçou o push de 76 de
77 tags de `aquasecurity/trivy-action` e de todas as 7 tags de `aquasecurity/setup-trivy` para commits
com um infostealer; em 22/03 publicou imagens maliciosas `aquasec/trivy:0.69.5` e `0.69.6` no Docker
Hub. O próprio advisory lista como seguras as versões 0.69.2 e 0.69.3. Escolhi a **0.69.3**: é a última
anterior ao incidente, foi publicada em 03/03/2026 como release **imutável** (recurso habilitado antes
dela), e o `integratedTime` da assinatura no Rekor é 2026-03-03 13:10:30 UTC (logIndex 1017902085),
antes do ataque. Usa o esquema 2 do banco (`trivy-db`), o mesmo das versões atuais (conferido no
`pkg/db/db.go`), então o banco de vulnerabilidades continua atualizado. A imagem por digest
`aquasec/trivy@sha256:bcc376de…` também é a do 03/03 (assinatura conferida).

## 4. Como rodar (usuário)

1. Criar o repositório público `LeoLuizGO/sigstore-supply-chain`, fazer o push da `main`
   (dispara o `pipeline.yml`). Em *Settings → Actions → General* basta o padrão (Actions habilitadas);
   as permissões vêm do YAML.
2. **Depois do primeiro push**, tornar o pacote público (o GHCR cria pacote privado e não herda a
   visibilidade do repositório): `https://github.com/users/LeoLuizGO/packages/container/sigstore-supply-chain/settings`
   → *Danger Zone* → *Change visibility* → *Public* → digitar o nome e confirmar. (Não dá para
   voltar a privado.) Conferir: `docker logout ghcr.io; crane digest ghcr.io/leoluizgo/sigstore-supply-chain:main`.
3. Se o job `verificacao-independente` da primeira execução falhar só no `verificador_do_grupo`
   (pull anônimo com o pacote ainda privado), depois do passo 2: `gh run rerun <run-id> --failed -R LeoLuizGO/sigstore-supply-chain`.

Comandos (`-R LeoLuizGO/sigstore-supply-chain` se não estiver dentro do clone):

```bash
# E1
gh workflow run pipeline.yml --ref main
gh run watch                                   # acompanha; resumo em gh run view <id> --web
scripts/ci/baixar-evidencias.sh                # resultados/e1-* (última execução bem-sucedida)
cat resultados/e1-rekor.json                   # logIndex + link do search.sigstore.dev

# E2.6 (deve falhar no Trivy, antes de assinar)
gh workflow run pipeline.yml --ref main -f incluir_dependencia_vulneravel=true

# E2.1–E2.4 (precisa de um E1 bem-sucedido antes; E2.2 sobrescreve :main)
gh workflow run ataques.yml --ref main -f cenario=todos
gh workflow run ataques.yml --ref main -f cenario=todos -f digest_antigo=sha256:...   # E2.5 no JSON
gh workflow run ataques.yml --ref main -f cenario=troca-assinatura -f digest_legitimo=sha256:...
scripts/ci/baixar-evidencias.sh --ataques      # resultados/ataques-digests.json

# E2.5: reescaneamento manual (o agendado roda todo dia)
gh workflow run reescanear.yml --ref main                       # digest atual de :main
gh workflow run reescanear.yml --ref main -f digest=sha256:...  # um digest específico

# E4
gh workflow run varredura-bases.yml --ref main
scripts/ci/baixar-evidencias.sh --bases        # resultados/e4-cves-imagens-base*.csv
scripts/ci/cves-imagens-base.sh                # alternativa local (trivy 0.69.3 no PATH ou Docker)
scripts/ci/metricas-pipeline.sh 10             # resultados/e4-pipeline-etapas.csv (N execuções ok)
```

`metricas-pipeline.sh` mede: cada step `Etapa - …` (Semgrep, build e push, Trivy bloqueante, SBOM,
relatório cosign-vuln, assinatura, atestados, mover :main, verificação), cada job (`job: <nome>`,
incluindo `proveniencia / generator`) e `workflow_total`. Grava também o bruto em
`resultados/e4-pipeline-etapas-bruto.tsv`. Para ter N amostras, rode o pipeline N vezes
(`gh workflow run pipeline.yml`); cada execução gera assinaturas novas no Rekor público.

## 5. Formatos conferidos na fonte

- `trivy --format cosign-vuln` existe na 0.69.3 (`pkg/types/report.go`: `FormatCosignVuln = "cosign-vuln"`).
  Predicado: `{invocation, scanner{uri,version,db,result}, metadata{scanStartedOn, scanFinishedOn}}`.
  O Trivy põe o mesmo instante nos dois campos.
- `cosign attest --type vuln` (v2.6.5, `pkg/cosign/attestation/attestation.go`): desserializa o predicado
  em `CosignVulnPredicate` e reserializa; `metadata.scanFinishedOn` é `time.Time` → **RFC 3339 com
  nanossegundos**, em UTC no runner (ex.: `2026-11-21T15:59:35.543721300Z`). `predicateType` =
  `https://cosign.sigstore.dev/attestation/vuln/v1`.
- `--type cyclonedx` → `https://cyclonedx.org/bom`; `--type slsaprovenance` → `https://slsa.dev/provenance/v0.2`
  (`cmd/cosign/cli/options/predicate.go`).
- Cosign 2.6.5: `sign` tem `--new-bundle-format=false`, `--use-signing-config=false`, `--tlog-upload=true`
  por padrão; `attest` idem e `--rekor-entry-type` padrão `dsse`. Logo a assinatura vai para a tag
  legada `sha256-<hex>.sig` e os atestados para `sha256-<hex>.att`; Rekor: `hashedrekord` (assinatura) e
  `dsse` (nossos atestados). O gerador SLSA usa o cosign v2.2.3 (fixado no workflow dele), que grava a
  proveniência como entrada `intoto`. Nenhum workflow usa `--new-bundle-format` nem referrers.
- `cosign verify` imprime no stdout um JSON `[{critical, optional{Bundle{Payload{logIndex, integratedTime,…}}, Subject, Issuer,…}}]`
  (`cmd/cosign/cli/verify/verify.go`, `PrintVerification`); `sign`/`attest` imprimem no stderr
  `tlog entry created with index: N` (`internal/pkg/cosign/rekor/signer.go`).
- `cosign verify-attestation` aceita atestados de identidades misturadas no mesmo `.att`: só falha se
  nenhum passar (`pkg/cosign/verify.go`, `ErrNoMatchingAttestations`), e filtra por `--type`.
- Rekor v1 (`rekor.sigstore.dev`) segue ativo para escrita: `treeSize` 3.911.598.489 em 21/11/2026, e
  a release do Syft de 16/11/2026 foi registrada nele (logIndex 3933780006).

## 6. O que foi validado localmente (21/11/2026)

Ferramentas locais baixadas numa pasta temporária (`D:\claude-tmp-sigstore\pipeline`, fora do
repositório, porque o disco C: estava sem espaço; apagada no fim) e verificadas como na tabela da seção 3.

- **actionlint 1.7.12** (sha256 do zip conferido com o `checksums.txt`): `actionlint .github/workflows/*.yml` → 0 erros.
  A integração com o shellcheck trava no Windows, então extraí cada bloco `run:` (trocando `${{ }}` por
  um marcador, como o actionlint faz) e rodei o **shellcheck 0.11.0** `-S style` em todos os 40 blocos
  e em `scripts/ci/*.sh` → 0 avisos (dois corrigidos: SC2319 e SC1091).
- **App**: `python app/loja.py` → `GET /` 200 com o JSON, `GET /saude` 200 `{"status": "ok"}`, `GET /xyz` 404;
  cabeçalho `Server: loja/1.0` (sem versão do Python).
- **Semgrep 1.186.0** (wheel do PyPI num venv): `semgrep scan --config p/python --config p/dockerfile --metrics off --json`
  no `app/` + `Dockerfile` → `Ran 158 rules on 2 files: 0 findings`. Controle negativo (Dockerfile sem
  `USER` e `subprocess.call(..., shell=True)`): 2 achados `ERROR`
  (`dockerfile.security.missing-user.missing-user`, `python.lang.security.audit.subprocess-shell-true`) →
  o gate dispararia. O `--severity` do CLI aceita `INFO|WARNING|ERROR` (conferido no `scan.py` da tag).
- **Trivy 0.69.3** na base fixada: `trivy image --severity CRITICAL --ignore-unfixed --exit-code 1` →
  0 vulnerabilidades em `debian 13.7` e no `pip-25.0.1` → exit 0 (a imagem da loja deve passar).
- **E2.6**: `pip install --require-hashes --no-deps` do Django 3.2.12 com o hash fixado → instalou;
  `trivy rootfs` (mesmo analisador `python-pkg` da varredura de imagem) no site-packages →
  exit 1 com 5 CRITICAL corrigíveis (CVE-2022-28346, CVE-2022-28347, CVE-2022-34265, CVE-2023-31047,
  CVE-2025-64459). GHSA confirma CVE-2022-28346 como `critical`, CVSS 9.8, corrigida em 3.2.13.
  A lógica do `Dockerfile` que pula o pip com `requirements.txt` só de comentários também foi testada.
- **cosign-vuln**: gerado com o Trivy local; chaves `invocation, scanner, metadata`, `scanner.uri =
  pkg:github/aquasecurity/trivy@0.69.3`.
- **Verificações de integridade** (cosign 2.6.5 local): `verify-blob` do tarball Linux e do zip Windows
  do Trivy, do `checksums.txt` do Syft, `verify-blob-attestation` do crane → todos `Verified OK`;
  `cosign verify` da imagem `aquasec/trivy@sha256:bcc376de…` e da distroless (`keyless@distroless.iam.gserviceaccount.com`) → OK.
- **Extração do logIndex**: `jq '[.[].optional.Bundle.Payload.logIndex] | last'` sobre um `cosign verify`
  real (distroless) → `1268530569`; montagem do `e1-rekor.json` testada com jq 1.8.2.
- **ataques.sh**: `registrar` testado (JSON acima e linhas da tabela do resumo); `construir` testado com
  `docker`/`crane` simulados (Dockerfile gerado conferido).
- **metricas-pipeline.sh**: testado contra um repositório público (`sigstore/cosign-installer`,
  workflow `test-action.yml`, 2 execuções) → CSV com médias/desvios coerentes; erro de workflow
  inexistente agora sai com código 1 e mensagem clara.
- **baixar-evidencias.sh**: tratamento de argumentos e de erro testados (o repositório ainda não existe).
- **cves-imagens-base.sh** (cópia temporária, trivy no PATH), resultado preliminar de 21/11/2026:

  | imagem | critical | high | medium | low | unknown | total |
  |---|---|---|---|---|---|---|
  | python:3.12 (todas) | 16 | 536 | 1218 | 1416 | 271 | 3457 |
  | python:3.12-slim (todas) | 0 | 51 | 103 | 79 | 7 | 240 |
  | distroless/python3-debian12 (todas) | 2 | 119 | 200 | 88 | 16 | 425 |
  | python:3.12 (com correção) | 13 | 175 | 341 | 32 | 6 | 567 |
  | python:3.12-slim (com correção) | 0 | 1 | 32 | 3 | 0 | 36 |
  | distroless/python3-debian12 (com correção) | 0 | 45 | 87 | 27 | 5 | 164 |

**Não validado localmente: o `docker build` da imagem.** O Docker Desktop estava parado e o disco C:
(onde fica o disco virtual do Docker/WSL) tinha só ~600 MB livres, então não iniciei o Docker para não
encher o disco. O `Dockerfile` usa só comandos padrão (`grep`, `pip`, `groupadd`/`useradd` do Debian)
e o primeiro push vai exercitá-lo. Para testar localmente quando houver espaço:
`docker build -t loja:teste . && docker run --rm -p 8080:8080 loja:teste` e `curl localhost:8080/saude`.

## 7. Riscos e pontos que só a execução no GitHub confirma

1. **Pacote privado na primeira execução**: Trivy, Syft, cosign e crane usam o login do `GITHUB_TOKEN`
   e funcionam com o pacote privado; o verificador do grupo hoje só faz pull anônimo (ver Pedidos), então
   o passo dele pode falhar até o pacote ficar público (rerun do job resolve).
2. **Gerador SLSA v2.1.0** (fev/2025) instala internamente o cosign v2.2.3 pelo cosign-installer v3.7.0
   e baixa o binário do builder da release; não achei issue aberta de quebra em 2026, mas é o componente
   mais antigo da cadeia. Se falhar, o `promover-main` não roda (proveniência é pré-requisito).
3. **Semgrep**: as regras `p/python`/`p/dockerfile` vêm do registry do Semgrep em tempo de execução
   (conteúdo não fixado; a imagem do CLI é). O container roda com outro UID; usei
   `GIT_CONFIG_*=safe.directory=*` e montagem somente leitura, mas isso só se confirma no runner.
4. **`docker push` se o runner usar o containerd image store** (padrão nas instalações novas do Docker Engine 29): com
   `--provenance=false --sbom=false` e uma plataforma, o resultado esperado é um manifesto simples. De
   qualquer forma o digest assinado é o que o registry devolve (`crane digest`), então assinatura,
   Trivy, Syft e Kyverno sempre olham o mesmo objeto.
5. **Banco do Trivy**: baixado de `mirror.gcr.io` com fallback para `ghcr.io` (padrão da 0.69.3); limite
   de taxa pode dar erro transitório → rerun.
6. **Agendamento** do `reescanear.yml`: o GitHub desativa `schedule` em repositório público sem
   atividade por 60 dias; o horário real pode atrasar.
7. Toda execução de `pipeline.yml`, `reescanear.yml` e `ataques.yml` (E2.3a/E2.3b) grava entradas
   **públicas e permanentes** no Rekor.
8. Repetir o `pipeline.yml` no mesmo commit refaz o build (digest novo, por causa dos timestamps) e
   move `:main`; o digest antigo continua assinado (útil para o E2.5).

## 8. Pedidos para outras áreas

Atendido do que o `docs/cluster.md` e o `docs/verificador.md` pediram ao pipeline: `USER 10001:10001`
numérico, porta 8080 e `GET /saude` → 200; a app não grava nada no disco (`PYTHONDONTWRITEBYTECODE=1`),
então roda com `readOnlyRootFilesystem`; cosign 2.6.5 no formato legado, sem `--new-bundle-format`
nem referrers; `--replace` no reescaneamento, que só reescaneia o digest de `:main`; proveniência
gerada a partir do `pipeline.yml` na `main` (`configSource.uri` = `git+https://github.com/LeoLuizGO/sigstore-supply-chain@refs/heads/main`,
`entryPoint` = `.github/workflows/pipeline.yml`); E2.4 copia o `.sig` sem alteração (`crane copy`);
digest e `logIndex` global em `resultados/e1-*`; `ataques-digests.json` com os campos lidos pelo
`scripts/cluster/ataques.sh` e o campo opcional `digest_antigo`; verificador rodado com Python 3.12 do
`actions/setup-python` e `pip install -r verificador/requirements.txt`.


- **verificador**: aceitar credenciais opcionais de registry por variável de ambiente, para o pull
  funcionar enquanto o pacote do GHCR ainda é privado. O pipeline já exporta
  `VERIFICADOR_REGISTRY_USUARIO` (= `github.actor`) e `VERIFICADOR_REGISTRY_SENHA` (= `GITHUB_TOKEN`
  com `packages: read`); no GHCR basta pedir o token do `realm` com HTTP Basic com esses valores. Sem
  isso o passo funciona só depois que o pacote ficar público. Também: a saída `--json` é salva como
  `resultados/e1-verificador.json`; se ela tiver o `logIndex`, ótimo para cruzar com `e1-rekor.json`.
- **cluster** (política Kyverno):
  - atestado `vuln`: aceitar a identidade do pipeline **ou** a do reescaneamento
    (`.../reescanear.yml@refs/heads/main`), porque o `--replace` troca o atestado do pipeline pelo do
    reescaneamento;
  - `metadata.scanFinishedOn` vem em RFC 3339 com fração de segundo e `Z` (ex.:
    `2026-11-21T15:59:35.543721300Z`); o `time.Parse` do Go com layout RFC 3339 aceita a fração, então
    `time_since('', '{{ metadata.scanFinishedOn }}', '')` deve funcionar, mas vale um teste;
  - proveniência: `predicateType` `https://slsa.dev/provenance/v0.2`, identidade do gerador na tag v2.1.0;
  - `resultados/ataques-digests.json` segue o formato da seção 2.3 (lista `cenarios`, campo `id` = E2.x,
    `referencia` = `IMG@digest`); para E2.2 a tag é `main`;
  - depois do E2.2 a tag `:main` fica adulterada até rodar o `pipeline.yml` de novo; deploy por digest
    (`e1-digest.txt`) evita surpresa.
- **coordenador**: o disco C: está praticamente cheio (~0,1–0,8 GB livres durante o trabalho); o Docker
  Desktop e o kind (cluster) gravam no C: e vão falhar assim. Também não adicionei nada ao `.gitignore`
  (`resultados/` deve ser versionado? hoje não é ignorado, o que me parece o certo).

## 9. Correções para o relatório

- **E2.6 / Seção 3.4** ("build interrompido antes da assinatura"): o Trivy varre a imagem **por digest
  no registry**, então o build e o push (tag `sha-<7>-vulneravel`) já aconteceram quando ele barra. O
  que é interrompido é a **assinatura, a proveniência e a promoção para `:main`**. Sugestão: "pipeline
  interrompido antes da assinatura; a imagem fica publicada sem assinatura e é recusada no deploy".
- **Seção 3.2**: "Semgrep falha se achado de alta severidade" foi implementado como severidade `ERROR`
  do Semgrep (o nível mais alto das regras públicas; `WARNING`/`INFO` só são reportados).
- **Seção 3.2 / 2.7**: os atestados do cosign 2.6.5 entram no Rekor como `dsse`; a proveniência do
  gerador SLSA (cosign 2.2.3 interno) entra como `intoto`; a assinatura é `hashedrekord`.
- **Seção 3.2**: a tag `:main` só é movida depois da assinatura, dos atestados e da proveniência; a
  imagem nasce só com a tag `sha-<7>` (detalhe que vale citar, porque é o que impede um deploy de
  `:main` não assinada pelo próprio pipeline).
- **E2.5**: o atestado renovado tem outra identidade (`reescanear.yml`), que precisa constar na política.
- **E4**: a distroless `python3-debian12` traz o Python **3.11** do Debian 12, não o 3.12; a comparação
  é entre bases "Python 3", não exatamente da mesma versão. As bases `python:3.12*` atuais são Debian 13 (trixie).
- **Introdução (sugestão)**: o incidente do Trivy em março de 2026 (GHSA-69fq-xp46-6x23 /
  CVE-2026-33634: binário v0.69.4 malicioso, 76 tags do `trivy-action` sobrescritas, imagens
  maliciosas no Docker Hub) é um exemplo atual e direto do problema, envolvendo uma ferramenta usada
  no próprio pipeline; a escolha da 0.69.3 (release imutável, assinada antes do ataque) pode ser citada
  como aplicação do que o trabalho defende.
