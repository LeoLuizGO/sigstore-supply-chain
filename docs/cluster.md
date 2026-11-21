# Área "cluster": kind + Kyverno + políticas de admissão

Responsável: agente **cluster**. Arquivos desta área: `k8s/`, `politicas/`, `scripts/cluster/`,
`scripts/instalar-ferramentas.sh` e este documento.

> **Resumo da validação (21/11/2026).** O cluster de teste **não pôde ser criado**: o disco C: do
> notebook estava praticamente cheio (70 MB livres) e o disco virtual do Docker Desktop entrou em modo
> somente-leitura no meio do pull do node do kind (detalhes em [Ambiente](#ambiente-o-que-aconteceu-com-o-docker-desktop)).
> A semântica das três políticas foi validada **de verdade** (com rede, ghcr.io e Rekor reais) com o
> **Kyverno CLI v1.19.2**, que usa o mesmo motor de verificação do admission controller, contra uma imagem
> pública que tem exatamente os artefatos que o nosso pipeline vai gerar: **14 de 14 casos** com o resultado
> esperado ([tabela](#validação-real-das-políticas-kyverno-cli-com-imagem-pública)). Ficam pendentes, para
> quando houver espaço em disco: criar o cluster, confirmar a admissão via webhook (inclusive o patch de
> digest e o dry-run) e medir a latência de admissão (E4).

## O que foi feito

| Arquivo | Função |
|---|---|
| `scripts/instalar-ferramentas.sh` | Baixa `kind`, `cosign` 2.x e `kubectl` para `./bin` (versão fixa, SHA-256 conferido; Windows/Git Bash e Linux amd64). `--kyverno-cli` baixa também o Kyverno CLI (só para a validação sem cluster). |
| `k8s/kind-config.yaml` | Cluster de 1 nó, imagem do node fixada por digest. |
| `k8s/namespace.yaml` | Namespace `loja`, com Pod Security Admission `restricted`. |
| `k8s/deployment.yaml.tmpl` | Deployment `loja` (imagem parametrizada, `securityContext` restritivo, `readinessProbe`/`livenessProbe` em `/saude:8080`, raiz só-leitura com `/tmp` em `emptyDir`). |
| `politicas/01-registry-permitido.yaml.tmpl` | Só imagens `ghcr.io/leoluizgo/sigstore-supply-chain:<tag>` ou `@<digest>` no namespace `loja`. |
| `politicas/02-assinatura.yaml.tmpl` | `verifyImages` keyless: subject = `IDENTIDADE_PIPELINE`, issuer = `EMISSOR_OIDC`, Rekor público, `mutateDigest`, `verifyDigest`, `required`, Enforce. |
| `politicas/03-atestados.yaml.tmpl` | SBOM CycloneDX (pipeline) + proveniência SLSA v0.2 (slsa-github-generator, amarrada a repositório/ref/workflow) + `vuln` (pipeline OU reescaneamento) com `time_since(scanFinishedOn) <= JANELA_VARREDURA`. |
| `scripts/cluster/comum.sh` | Lê `config.env`, põe `./bin` no PATH, renderiza templates **sem envsubst** (substituição literal em bash), função `admitir` (dry-run ou real, mede o tempo, extrai a mensagem do Kyverno). |
| `scripts/cluster/criar-cluster.sh` / `destruir-cluster.sh` | Cria o cluster `sigstore`, instala o Kyverno (manifesto do release com checksum, `apply --server-side`), espera ficar pronto, cria o namespace. Confere antes se há ≥ 5 GB livres. |
| `scripts/cluster/aplicar-politicas.sh` | Renderiza e aplica as políticas escolhidas (`01 02`, `01 02 03`...); o conjunto escolhido vira o conjunto ativo. Também `--imprimir`, `--validar` (dry-run no servidor) e `--remover`. |
| `scripts/cluster/deploy.sh IMAGEM_REF` | Deploy (ou `--dry-run`) e mostra ADMITIDO/RECUSADO, tempo da admissão em ms, imagem final (com digest) ou a mensagem do Kyverno. |
| `scripts/cluster/ataques.sh` | E2: roda os cenários contra o cluster → `resultados/e2-ataques.csv`. |
| `scripts/cluster/medir-latencia.sh` | E4: N admissões, cache frio e quente → `resultados/e4-latencia-admissao.csv` (+ amostras brutas). |
| `scripts/cluster/teste/config-lariat.env`, `validar-cli.sh` | Reprodução da validação com imagem pública (sem cluster). |

## Versões fixadas e por quê

| Componente | Versão | Por quê / como foi conferido |
|---|---|---|
| Kyverno | **v1.19.2** (`install.yaml` SHA-256 `4f785937…98037969`, conferido contra o `checksums.txt` do release) | É a última versão que ainda **cria** `ClusterPolicy` com `verifyImages`: o v1.20.0 (12/11/2026) passou a **recusar a criação e a alteração** de políticas legadas `kyverno.io` (PR kyverno#17535; só existe uma "válvula" temporária `--blockLegacyPolicyAPIs=false`, prevista para sair no 1.21). O 1.19.2 também corrige 24 advisories, entre eles uma falha de verificação de imagem que importa diretamente para o trabalho (PR kyverno#17994): até o 1.19.1, o webhook de validação confiava na anotação `kyverno.io/verify-images` que vinha **no próprio pedido**, e um pod criado com essa anotação já preenchida era admitido sem verificação. |
| Kubernetes (node) | **kindest/node:v1.35.8@sha256:07b2536e…09323c0** | Imagem pré-construída do kind v0.33.0 (fixada por digest, como o release recomenda). O Kyverno 1.19 suporta Kubernetes **v1.33–v1.36** (página "Releases" da documentação do Kyverno, versão da época do 1.19; conferida no histórico do repositório `kyverno/website`). 1.35 fica no meio da faixa e também dentro da faixa do 1.20 (1.34–1.37). |
| kind | **v0.33.0** (SHA-256 Windows `4b22adaa…15c9fc`, Linux `aee61515…8e0d`) | Último release; publica a imagem 1.35.8. |
| kubectl | **v1.35.8** (Windows `f675d702…16ba8`, Linux `874d5e72…0cbf`) | O `kubectl` do Docker Desktop instalado é o **1.28.2**, fora da política de compatibilidade (±1 versão menor do API server). O script usa o do host se ele for 1.34–1.36 e baixa o 1.35.8 caso contrário. |
| cosign | **v2.6.5** (Windows `19ec346d…825`, Linux `c3b4f541…644`) | Último 2.x (a ESPEC fixa o formato legado `.sig`/`.att`; o 3.x usa o formato novo de bundle por padrão). No cluster ele não é necessário (o Kyverno embute a biblioteca); serve para inspecionar assinaturas do host. |
| Kyverno CLI (opcional) | v1.19.2 (Windows `c787cd56…a1f6`, Linux `357eaf1d…f4a`) | Mesma versão do admission controller; usado só em `teste/validar-cli.sh`. |

Nada de Helm: o Kyverno é instalado pelo `install.yaml` oficial do release com `kubectl apply --server-side`
(os CRDs passam do limite da anotação do `apply` comum; `create` também funciona mas não é idempotente).

## Como rodar (ordem)

Pré-requisitos: Docker Desktop rodando, **≥ 5 GB livres no C:** (o disco do Docker Desktop fica em
`%LOCALAPPDATA%\Docker`), internet (o cluster baixa assinaturas do ghcr.io e consulta o Rekor/TUF).

```bash
scripts/instalar-ferramentas.sh            # kind, cosign, kubectl em ./bin
scripts/cluster/criar-cluster.sh           # cluster "sigstore" + Kyverno v1.19.2 + namespace loja
scripts/cluster/aplicar-politicas.sh       # 01 02 03 (configuração completa)

# E1: deploy da imagem legítima (de preferência por digest)
scripts/cluster/deploy.sh ghcr.io/leoluizgo/sigstore-supply-chain@sha256:<digest> --esperar

# E2: ataques (baixe o artifact "ataques-digests" do workflow ataques.yml)
scripts/cluster/ataques.sh --json ataques-digests.json --digest-antigo sha256:<digest antigo>

# E4: latência de admissão (padrão: 20 amostras, políticas 01 02 03, frio = cache desligado)
scripts/cluster/medir-latencia.sh ghcr.io/leoluizgo/sigstore-supply-chain@sha256:<digest>
scripts/cluster/medir-latencia.sh ghcr.io/leoluizgo/sigstore-supply-chain@sha256:<digest> \
    --politicas "01 02" --saida resultados/e4-latencia-admissao-so-assinatura.csv   # efeito do cache

scripts/cluster/destruir-cluster.sh
```

Experimento de rollback (E2.5) à mão: `aplicar-politicas.sh 01 02` → `deploy.sh <img>@<digest antigo> --dry-run`
(admitido) → `aplicar-politicas.sh 01 02 03` → mesmo comando (recusado com "varredura vencida"). O
`ataques.sh` faz exatamente isso (E2.5a/E2.5b). Para o E2.5b o atestado `vuln` do digest antigo precisa
ter mais de `JANELA_VARREDURA`; se ainda não tiver, rode com `JANELA_VARREDURA=1h scripts/cluster/ataques.sh ...`
(só esta variável pode ser sobrescrita pelo ambiente). E o E2.0 (controle positivo) exige que o digest
legítimo tenha sido varrido há menos de 24 h (rode o `reescanear.yml` antes, se preciso).

Validação sem cluster (reproduz a tabela abaixo; ~270 MB para o CLI):

```bash
scripts/instalar-ferramentas.sh --kyverno-cli
scripts/cluster/teste/validar-cli.sh          # ou com IDs: validar-cli.sh T9 T10
```

## Validação real das políticas (Kyverno CLI, com imagem pública)

**Imagem de teste:** `ghcr.io/chipzoller/lariat` (projeto de um mantenedor do Kyverno). A versão 0.0.37
(`sha256:31832bbb…330266a`) tem, no formato legado do cosign 2.2.4 e no mesmo repositório: assinatura
keyless do workflow `release.yaml`, atestados `cyclonedx` e `vuln` (Trivy) assinados pelo mesmo workflow e
proveniência SLSA v0.2 assinada pelo `generator_container_slsa3.yml` do slsa-github-generator — o mesmo
conjunto que o nosso pipeline vai produzir. Identidades descobertas no certificado com
`cosign verify`/`cosign verify-attestation` (cosign v2.6.5):

```
SIG  Subject = https://github.com/chipzoller/lariat/.github/workflows/release.yaml@refs/tags/0.0.37
     Issuer  = https://token.actions.githubusercontent.com
att cyclonedx / vuln : mesmo subject acima
att slsaprovenance   : https://github.com/slsa-framework/slsa-github-generator/.github/workflows/generator_container_slsa3.yml@refs/tags/v2.0.0
vuln: metadata.scanFinishedOn = 2024-05-20T19:46:48.371502005Z (Trivy 0.51.1)
```

As políticas usadas são **os mesmos templates do projeto**, renderizados com `scripts/cluster/teste/config-lariat.env`
(imagem, identidades e ref do lariat; como o lariat assina por tag, `IDENTIDADE_PIPELINE` usa
`…@refs/tags/*` para imitar o nosso caso de uma identidade só para todas as versões). O recurso é o
`k8s/deployment.yaml.tmpl` renderizado (Deployment no namespace `loja`). Saída real de
`scripts/cluster/teste/validar-cli.sh` (tempo = execução completa do CLI, inclui ~0,5 s de inicialização):

```
ID   POLIT  ESPERADO  OBTIDO        MS  DESCRICAO
T1   02     admitido  admitido    2585  assinatura keyless com a identidade certa
T2   02     recusado  recusado    3304  mesma imagem, subject esperado diferente
       assinatura-imagem: failed to verify image ghcr.io/chipzoller/lariat:0.0.37: .attestors[0].entries[0].keyless: subject mismatch: expected https://github.com/chip
       zoller/lariat/.github/workflows/release.yaml@refs/heads/main, received https://github.com/chipzoller/lariat/.github/workflows/release.yaml@refs/tags/0.0.37
T3   02     recusado  recusado    2555  imagem sem assinatura no mesmo repositório
       assinatura-imagem: failed to verify image ghcr.io/chipzoller/lariat:0.0.4: .attestors[0].entries[0].keyless: no signatures found
T4   02     recusado  recusado    2727  imagem com atestados mas sem assinatura (.sig)
       assinatura-imagem: failed to verify image ghcr.io/chipzoller/lariat:0.0.12: .attestors[0].entries[0].keyless: no signatures found
T5   01     recusado  recusado     468  registry fora da lista
       registry-permitido: validation error: imagem fora do registry permitido: no namespace loja só são aceitas imagens de ghcr.io/chipzoller/lariat (por tag ou dig
       est). rule autogen-so-imagens-do-projeto failed at path /spec/template/spec/containers/0/image/
T6   02     admitido  admitido     466  SEM a 01: imagem de outro registry nem é olhada pela 02
T7   01     recusado  recusado     497  repositório vizinho com o mesmo prefixo
       registry-permitido: validation error: imagem fora do registry permitido: ... (mesma mensagem do T5)
T8   01+02  admitido  admitido    2331  01+02 com a imagem referenciada por digest
T9   03     admitido  admitido    7171  SBOM + SLSA + vuln dentro da janela
T10  03     recusado  recusado    7888  vuln vencido (scanFinishedOn de 2024) com janela 24h
       atestados-imagem: image attestations verification failed, verifiedCount: 0, requiredCount: 1, error: .attestations[2].attestors[0].entries[2].keyless: attestati
       on checks failed for ghcr.io/chipzoller/lariat@sha256:31832bbb8d887342115cbe1d4ad2ee03d289ae6b9970e362e8982384c330266a and predicate https://cosign.sigstore.dev
       /attestation/vuln/v1: varredura vencida: scanFinishedOn=2024-05-20T19:46:48.371502005Z, janela=24h; subject mismatch: expected https://github.com/chipzoller/lar
       iat/.github/workflows/reescanear.yml@refs/heads/main, received https://github.com/chipzoller/lariat/.github/workflows/release.yaml@refs/tags/0.0.37
T11  03     recusado  recusado    4743  proveniência de outro ref
       atestados-imagem: image attestations verification failed, verifiedCount: 0, requiredCount: 1, error: .attestations[1].attestors[0].entries[1].keyless: attestati
       on checks failed for ghcr.io/chipzoller/lariat@sha256:31832bbb8d887342115cbe1d4ad2ee03d289ae6b9970e362e8982384c330266a and predicate https://slsa.dev/provenance
       /v0.2: proveniência de outro repositório/ref: git+https://github.com/chipzoller/lariat@refs/tags/0.0.37
T12  03     recusado  recusado    2478  SBOM/vuln assinados por outra identidade
       atestados-imagem: image attestations verification failed, verifiedCount: 0, requiredCount: 1, error: subject mismatch: expected https://github.com/chipzoller/la
       riat/.github/workflows/release.yaml@refs/heads/main, received https://github.com/chipzoller/lariat/.github/workflows/release.yaml@refs/tags/0.0.37
T13  02     admitido  admitido    2585  rollback: versão antiga assinada passa só com a 02
T14  02+03  recusado  recusado    9616  rollback com a 03: varredura vencida
       atestados-imagem: ... predicate https://cosign.sigstore.dev/attestation/vuln/v1: varredura vencida: scanFinishedOn=2024-05-10T13:22:22.790342378Z, janela=24h; ...

14 de 14 casos com o resultado esperado
```

O que isso mostra:

- **Assinatura (02):** identidade certa → admitida (T1, T8); subject diferente → recusada com
  `subject mismatch` (T2); sem `.sig` → `no signatures found` (T3), inclusive quando a imagem tem atestados
  mas não tem assinatura (T4).
- **Registry (01):** imagem de outro registry → recusada (T5); **sem a 01 a mesma imagem é admitida**,
  porque a 02 só olha imagens que casam com `imageReferences` (T6) — é o argumento para a política 01 no
  relatório; repositório vizinho `…/lariat-falso` também é recusado (T7).
- **Atestados (03):** os três tipos verificados juntos (T9); `time_since` funcionando com o campo real do
  Trivy (`metadata.scanFinishedOn`, RFC 3339 com nanossegundos): com janela de 100000 h passa, com 24 h é
  recusado com a nossa mensagem "varredura vencida" (T10); a condição sobre `invocation.configSource.uri`
  recusa proveniência de outro ref (T11); SBOM/vuln de outra identidade é recusado (T12).
- **Rollback (E2.5) em miniatura:** a versão antiga 0.0.18 assinada legitimamente passa com a 02 (T13) e é
  recusada quando a 03 entra (T14).
- O "OU" das identidades do `vuln` funciona como esperado: a mensagem do T10 traz as duas tentativas
  (pipeline: varredura vencida; reescaneamento: subject diferente) e só recusa porque nenhuma passou.
- Também carreguei as **políticas do projeto** (renderizadas com o `config.env` real) no CLI: as três são
  aceitas pelo validador do Kyverno (9 regras = 3 políticas × Pod + 2 autogen); um Deployment com nginx é
  recusado pela 01 e um com `ghcr.io/leoluizgo/sigstore-supply-chain@sha256:aaa…` (que ainda não existe) é
  recusado pela 02 e pela 03 (falha fechada).
- `kubectl apply --dry-run=server` das políticas **não** pôde ser feito (sem cluster); a sintaxe foi validada
  pelo CLI do Kyverno (mesma validação do webhook de políticas) e por parse YAML.

**Proveniência real do generator v2.1.0** (a versão do projeto), lida das imagens `ghcr.io/kyverno/kyverno:v1.19.2`
e `ghcr.io/fluxcd/source-controller:v1.7.0`, que usam o mesmo generator:

```
builder.id   = https://github.com/slsa-framework/slsa-github-generator/.github/workflows/generator_container_slsa3.yml@refs/tags/v2.1.0
buildType    = https://github.com/slsa-framework/slsa-github-generator/container@v1
invocation.configSource.uri        = git+https://github.com/fluxcd/source-controller@refs/tags/v1.7.0
invocation.configSource.entryPoint = .github/workflows/release.yml
```

Isso confere com o código do generator v2.1.0 (`github/workflow.go`: `"git+%s/%s%s"` com
`GITHUB_SERVER_URL`, `GITHUB_REPOSITORY` e `@GITHUB_REF`; `slsa/buildtype.go`: `entryPoint` é o caminho do
workflow obtido pela API do GitHub). Para o nosso projeto os valores esperados são
`git+https://github.com/LeoLuizGO/sigstore-supply-chain@refs/heads/main` e `.github/workflows/pipeline.yml`
(o exemplo do README do generator, com `.git` no fim, está desatualizado).

**Custo da verificação fora do cluster** (8 execuções do CLI, rede doméstica, 21/11/2026; não é a
latência de admissão do E4, só uma ordem de grandeza): sem verificação (T6) 485 ± 25 ms; com a 02 (T1)
2534 ± 133 ms; com a 03 (T9) 6130 ± 221 ms. Descontada a inicialização, ≈ 2,0 s para a 02 e ≈ 5,6 s para a
03 — e o CLI faz **duas** verificações por regra (estágios de mutação e de validação, ver abaixo), sem cache.
Por isso as políticas usam `webhookTimeoutSeconds: 30` (o padrão de 10 s seria arriscado com a 03 no cache frio).

## Comportamentos do Kyverno 1.19.2 que importam para o relatório

Conferidos no código da tag v1.19.2 (`pkg/engine/internal/imageverifier.go`,
`pkg/image/verifiers/cpol/cosign/`, `cmd/internal/flag.go`, `pkg/controllers/webhook/controller.go`) e,
quando indicado, na execução do CLI.

1. **Verificação em dois estágios.** Desde o 1.19.2 a imagem é verificada no webhook de **mutação** (onde
   também troca a tag pelo digest) e de novo no de **validação** (antes o segundo estágio só lia uma
   anotação — a falha corrigida pelo PR #17994). Visto no CLI: cada regra produz duas linhas ("verified image
   signatures for …:0.0.37" e "image verified" já com `@sha256:…`).
2. **Cache de verificação.** Flags do admission controller: `--imageVerifyCacheEnabled` (padrão `true`),
   `--imageVerifyCacheTTLDuration` (padrão 60 min), `--imageVerifyCacheMaxSize` (1000). A chave é ligada ao
   **digest** (se a referência vem por tag, o Kyverno faz um HEAD no registry para resolver a tag antes de
   consultar o cache, para que mover a tag não reaproveite um veredito antigo) e ao conteúdo da regra. Só
   resultados aprovados entram no cache. **Entradas com `conditions` (a política 03 inteira) nunca usam o
   cache**: são verificadas por completo em toda admissão — o que é correto para a janela de varredura (um
   "aprovado" em cache poderia sobreviver ao vencimento), mas significa que o cache só acelera a 02.
   `medir-latencia.sh` mede o frio com `--imageVerifyCacheEnabled=false` (ou reiniciando o pod).
3. **Vários atestados do mesmo tipo.** Para cada entrada de identidade, o Kyverno: (a) pega todos os
   atestados do `.att` que verificam criptograficamente; (b) se **algum** atestado do tipo pedido tiver outro
   subject, a entrada inteira falha; (c) **todos** os do tipo precisam satisfazer as `conditions`. Logo, sem
   `--replace`, um atestado `vuln` antigo vencido ao lado do novo faz a 03 recusar, e um `vuln` do pipeline ao
   lado de um do reescaneamento faz as duas entradas falharem. O `cosign attest --replace` (código do cosign
   v2.6.5, `pkg/cosign/remote/remote.go`) remove do `.att` todos os atestados com o mesmo `predicateType`,
   **de qualquer assinante**, e deixa só o novo — por isso o reescaneamento precisa dele.
4. **Dry-run passa pelos webhooks.** Os webhooks de recurso do Kyverno são registrados com
   `sideEffects: NoneOnDryRun`, então o API server os chama em `--dry-run=server`; o Kyverno só deixa de gerar
   relatórios/eventos. `ataques.sh` e `medir-latencia.sh` usam `kubectl create --dry-run=server` (sempre um
   CREATE com nome próprio, para o kubectl nunca responder "unchanged" sem falar com o servidor). Não foi
   possível observar isso num cluster nesta rodada.
5. **Autogen.** As regras são escritas para `Pod`; o Kyverno gera `autogen-<regra>` (Deployment, ReplicaSet,
   StatefulSet, DaemonSet, Job) e `autogen-cronjob-<regra>`. Por isso a recusa aparece já no
   `kubectl apply` do Deployment (mensagem com "rule autogen-…"), e não só depois, na criação do pod. O pod
   criado pelo ReplicaSet passa de novo pela regra de Pod.
6. **Mensagens de erro** (formato real, do CLI): `failed to verify image <ref>: .attestors[0].entries[0].keyless: subject mismatch: expected …, received …`;
   `… no signatures found`; `image attestations verification failed, verifiedCount: 0, requiredCount: 1, error: … attestation checks failed for <img@digest> and predicate <tipo>: <message da condição>`.
   No cluster o `kubectl` mostra isso depois de `admission webhook "mutate.kyverno.svc-fail" denied the request:`.
   Pequeno bug cosmético do Kyverno: o caminho `.attestations[2].attestors[0].entries[2]` usa o índice do
   atestado no lugar do índice da entrada.
7. **Política legada obsoleta.** O CLI avisa: "kyverno.io/v1 ClusterPolicy is deprecated … migrate to …
   ImageValidatingPolicy". É a última versão em que dá para usar esta sintaxe sem válvula de escape.
8. **Falha fechada.** `failurePolicy: Fail`: se o Kyverno, o ghcr.io ou o Rekor estiverem fora, o deploy é
   recusado (erro de infraestrutura é reportado como "error", que com Fail também bloqueia).

## Riscos e limitações

- **Disco do C:**: sem ≥ 5 GB livres o cluster não sobe (e pode danificar o disco do Docker, como aconteceu).
- **Atualidade só na admissão:** um pod já rodando não é removido quando o atestado `vuln` vence; mas
  qualquer recriação (reinício do nó, rollout, escala) passa de novo pela 03 e falha. O reescaneamento precisa
  rodar com folga dentro da janela (ex.: a cada 12 h para janela de 24 h).
- **`scanFinishedOn` é declarado pelo assinante** (pipeline/reescaneamento), não pelo Rekor. Um workflow de
  reescaneamento comprometido poderia declarar datas falsas; a garantia é "uma identidade confiável afirma que
  varreu em t".
- **Atestado injetado pelo atacante:** com acesso de escrita ao registry, o atacante pode acrescentar ao `.att`
  um `vuln` assinado por outra identidade; pela regra 3 acima isso faz a 03 **recusar** a imagem legítima
  (negação de serviço, não desvio — falha fechada). Idem para apagar atestados.
- **Dependência de rede:** a cada admissão no cache frio o Kyverno consulta o ghcr.io e o Rekor; o trust root
  vem do TUF do Sigstore na inicialização.
- **Curingas:** `subject`/`issuer` e o operador `Equals` do Kyverno aceitam `*` e `?`. Os valores do projeto
  não têm curingas, então a comparação é exata; não colocar curingas em `config.env`.
- **`JANELA_VARREDURA`** precisa ser uma duração do Go (`24h`, `90m`); `1d` não é aceito.
- **Política legada:** migrar para `ImageValidatingPolicy` (CEL) seria necessário para usar o Kyverno ≥ 1.20.

## Ambiente: o que aconteceu com o Docker Desktop

- O Docker Desktop (cliente 24.0.6, de 2023) estava parado; eu o iniciei e ele subiu (WSL 2, cgroup v2).
- No `kind create cluster --name teste-politicas`, o pull do `kindest/node` fez o disco virtual
  `C:\Users\Leo\AppData\Local\Docker\wsl\data\ext4.vhdx` crescer para 5,7 GB e o C: ficou com **70 MB
  livres**. O kernel do WSL registrou `EXT4-fs error … I/O error … Remounting filesystem read-only` e
  `Delayed block allocation failed … Data will be lost` no disco de dados do Docker; o `docker run` do node
  falhou com `read-only file system` e o daemon caiu logo depois.
- Não tentei de novo (não havia espaço). O container do node não chegou a ser criado e nenhum contexto foi
  gravado no `~/.kube/config`; a rede Docker `kind`, criada antes do node, pode ter ficado (é inofensiva;
  quando o Docker voltar, `bin/kind delete cluster --name teste-politicas` limpa qualquer resto). Fechei o
  Docker Desktop, que voltou ao estado em que estava (parado).
- **O que o usuário precisa fazer:** liberar espaço no C: (≥ 5 GB, idealmente 10 GB) ou mover o disco do
  Docker para o D: (Docker Desktop → Settings → Resources → Advanced → Disk image location). Ao reabrir, se
  o Docker reclamar do disco ou imagens antigas estiverem corrompidas, as opções são
  Troubleshoot → "Clean / Purge data" (apaga imagens e containers locais).
- Para não piorar o C:, os arquivos temporários da validação (Kyverno CLI, shellcheck, cópias) ficaram em
  `D:\claude-tmp-sigstore`; apaguei os meus no fim. A pasta em si continua lá porque o agente pipeline
  passou a usar `D:\claude-tmp-sigstore\pipeline` (~2,7 GB na hora em que olhei); pode ser apagada quando
  ele terminar. Em `./bin` ficam kind + cosign + kubectl (~265 MB, dos
  quais 193 MB são o cosign); dá para apagar e baixar de novo com o script.

## O que fica pendente (precisa de cluster e/ou da imagem do projeto)

1. Com espaço em disco: `criar-cluster.sh` (nunca rodou de ponta a ponta), `aplicar-politicas.sh --validar`
   e `aplicar-politicas.sh` (as políticas ficarem `Ready`).
2. Confirmar no cluster: recusa no `kubectl apply` do Deployment, patch tag → digest (`deploy.sh … :main`
   deve mostrar `imagem final: …:main@sha256:…`), `--dry-run=server` passando pelo webhook.
3. Quando o pipeline publicar a imagem: E1 (`deploy.sh … --esperar`, pod pronto em `/saude`), E2
   (`ataques.sh`, com o artifact do `ataques.yml` e um digest antigo) e E4 (`medir-latencia.sh`).
4. Os scripts de cluster foram exercitados só com um `kubectl` falso (teste de fumaça do fluxo, do parsing
   do `ataques-digests.json` e do CSV) e passam no `shellcheck` 0.11.0 sem avisos.

## Pedidos para outras áreas

**Pipeline**
1. **Usuário da imagem:** o Deployment roda com `runAsNonRoot`, `runAsUser/runAsGroup: 10001`,
   `readOnlyRootFilesystem: true` (só `/tmp` gravável) e sem capabilities; o namespace exige o perfil
   `restricted`. O Dockerfile deve ter `USER 10001` numérico (ou me digam o UID) e a app deve escutar na
   **8080** e responder **200 em `GET /saude`**.
2. **Reescaneamento com `--replace`:** `cosign attest --replace --type vuln …` (obrigatório, ver item 3 dos
   comportamentos). Agendar com folga dentro de `JANELA_VARREDURA` e reescanear só os digests em uso — **não**
   reescanear o digest antigo do E2.5, senão o rollback deixa de ser recusado.
3. **Tipos e identidades exatos:** SBOM com `--type cyclonedx` e `vuln` assinados pelo `pipeline.yml@refs/heads/main`;
   proveniência pelo `generator_container_slsa3.yml@refs/tags/v2.1.0` chamado a partir do `pipeline.yml` num push
   (ou dispatch) na `main` — a política espera `configSource.uri = git+https://github.com/LeoLuizGO/sigstore-supply-chain@refs/heads/main`
   e `entryPoint = .github/workflows/pipeline.yml`. Manter o formato legado do cosign 2.x (sem
   `--new-bundle-format`), que é o que a política legada do Kyverno lê.
4. **`ataques-digests.json`:** o `ataques.sh` lê `imagem`, `digest_legitimo` e `cenarios[].{cenario, referencia, referencia_tag}`
   (E2.2 pela `referencia_tag`, os outros pela `referencia` com digest). Se for possível, acrescentar um campo
   opcional `digest_antigo` (digest legítimo anterior, para o E2.5); hoje ele vem por `--digest-antigo`.
5. O E2.6 (Trivy barra a dependência vulnerável) não passa pelo cluster; se quiserem uma linha no
   `e2-ataques.csv`, acrescentem-na no mesmo formato (`cenario,imagem,esperado,obtido,mensagem`).

**Coordenador**
1. `JANELA_VARREDURA` em `config.env`: documentar que é duração do Go (`24h`), sem `d`.
2. Opcional: levar `URI_FONTE_ESPERADA` e `ENTRYPOINT_ESPERADO` para o `config.env` (hoje são derivados em
   `scripts/cluster/comum.sh` a partir de `OWNER`/`REPO`).
3. README: pré-requisito de ≥ 5 GB livres no disco do Docker Desktop.

## Correções para o relatório

1. **A política de assinatura sozinha não basta:** o relatório (3.2) diz que o Kyverno "só admite a imagem se a
   assinatura for válida…". Na prática, `verifyImages` só verifica as imagens que casam com `imageReferences`;
   uma imagem de outro registry passa direto (T6). O texto final deve citar a regra complementar de registry
   permitido (política 01).
2. **Versão do Kyverno e API:** registrar que foi usado o Kyverno 1.19.2 com `ClusterPolicy`/`verifyImages`,
   API marcada como obsoleta (o 1.20 já recusa criar políticas legadas; a substituta é `ImageValidatingPolicy`).
   Vale citar a falha corrigida no 1.19.2 (verificação confiando em anotação do próprio pedido) como exemplo de
   que o próprio verificador faz parte da base confiável.
3. **Mitigação do rollback (3.4):** é viável e foi demonstrada com imagem real (T10/T14), mas o texto deve dizer
   que (a) a data verificada é `metadata.scanFinishedOn`, declarada pelo assinante; (b) a janela só é checada na
   admissão — pods em execução continuam; (c) o reescaneamento precisa substituir (`--replace`) o atestado anterior.
4. **Latência (E4):** há duas verificações por admissão (webhooks de mutação e de validação) e o cache de
   verificação do Kyverno só vale para regras sem `conditions`; com a política de atestados, toda admissão
   verifica tudo de novo. As medidas do E4 são de ida e volta do `kubectl` (o arquivo de amostras traz uma
   linha de base sem políticas para descontar o custo do próprio `kubectl`/API server).
