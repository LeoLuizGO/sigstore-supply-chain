# Cadeia de suprimentos assinada com Sigstore

Trabalho da disciplina de Segurança em Computação (UFSC, Profs. Jean Martina e Thaís Bardini Idalino).
Grupo: Leonardo Luiz Gambalonga Alves de Oliveira e Pedro Philippi Araujo.

Um pipeline do GitHub Actions constrói uma imagem de container, varre vulnerabilidades, gera SBOM e
proveniência SLSA e assina tudo no modo keyless do Sigstore (Fulcio + Rekor). Um cluster kind com
Kyverno só admite a imagem se a assinatura e os atestados conferirem. Um verificador escrito pelo
grupo em Python refaz as checagens criptográficas (ECDSA, cadeia X.509 do Fulcio, checkpoint, SET e
prova de inclusão Merkle do Rekor) sem depender do cosign.

| Pasta | Conteúdo | Detalhes |
|---|---|---|
| `app/`, `Dockerfile` | aplicação de exemplo ("loja"), só biblioteca padrão | [docs/pipeline.md](docs/pipeline.md) |
| `.github/workflows/` | `pipeline.yml` (E1, E2.6), `ataques.yml` (E2.1–E2.4), `reescanear.yml` (E2.5), `varredura-bases.yml` (E4) | [docs/pipeline.md](docs/pipeline.md) |
| `politicas/`, `k8s/`, `scripts/cluster/` | políticas Kyverno, cluster kind, deploy, ataques, latência | [docs/cluster.md](docs/cluster.md) |
| `verificador/` | verificador próprio (E3) e testes | [docs/verificador.md](docs/verificador.md) |
| `resultados/` | CSVs e evidências dos experimentos | formatos em [docs/ESPEC.md](docs/ESPEC.md) |
| `config.env` | identidades, imagem, janela de varredura (fonte única) | |

## Pré-requisitos

- Windows com Git Bash (ou Linux), `gh` autenticado, Python 3.11+.
- Docker Desktop com **pelo menos 5 GB livres no disco onde fica a imagem do WSL** (por padrão o C:).
  Em 21/11 o C: estava com menos de 1 GB e o Docker corrompeu o disco do WSL ao baixar a imagem do kind.
  Libere espaço ou mova o disco em *Settings → Resources → Advanced → Disk image location*.
- Verificador: `python -m venv verificador/.venv && verificador/.venv/Scripts/pip install -r verificador/requirements.txt`
  (o Python global tem `cryptography` 39, antigo demais). Ative com `source verificador/.venv/Scripts/activate`.

## Roteiro de execução

```bash
# 0. Ferramentas locais (kind, cosign, kubectl em ./bin) e testes offline do verificador
scripts/instalar-ferramentas.sh
verificador/.venv/Scripts/python -m pytest -q verificador/testes

# 1. Publicar o repositório (dispara o pipeline.yml)
gh repo create LeoLuizGO/sigstore-supply-chain --public --source . --push
#    Depois do primeiro push: tornar o pacote do GHCR público
#    https://github.com/users/LeoLuizGO/packages/container/sigstore-supply-chain/settings
#    → Change visibility → Public. Se o passo do verificador falhou por causa disso:
gh run rerun <run-id> --failed

# 2. E1: pipeline completo (repita algumas vezes para as médias do E4)
gh workflow run pipeline.yml --ref main
scripts/ci/baixar-evidencias.sh            # resultados/e1-*

# 3. Cluster local + políticas + deploy da imagem legítima
scripts/cluster/criar-cluster.sh
scripts/cluster/aplicar-politicas.sh
scripts/cluster/deploy.sh ghcr.io/leoluizgo/sigstore-supply-chain@sha256:<digest> --esperar

# 4. E2: ataques (E2.6 falha no Trivy, como esperado)
gh workflow run pipeline.yml --ref main -f incluir_dependencia_vulneravel=true
gh workflow run ataques.yml --ref main -f cenario=todos -f digest_antigo=sha256:<digest de um dia antes>
scripts/ci/baixar-evidencias.sh --ataques
scripts/cluster/ataques.sh --json resultados/ataques-digests.json --digest-antigo sha256:<digest antigo>
#    E2.2 sobrescreve :main; rode o pipeline.yml de novo para restaurar.

# 5. E3: verificador próprio sobre a imagem do projeto e as imagens de ataque
python -m verificador imagem ghcr.io/leoluizgo/sigstore-supply-chain@sha256:<digest> \
  --identidade "https://github.com/LeoLuizGO/sigstore-supply-chain/.github/workflows/pipeline.yml@refs/heads/main" \
  --emissor https://token.actions.githubusercontent.com
#    (comparação com cosign e casos reais do E2: docs/verificador.md, seção 9)

# 6. E4: métricas
gh workflow run varredura-bases.yml --ref main
scripts/ci/baixar-evidencias.sh --bases
scripts/ci/metricas-pipeline.sh 5
scripts/cluster/medir-latencia.sh ghcr.io/leoluizgo/sigstore-supply-chain@sha256:<digest>
python -m verificador inspecionar ghcr.io/leoluizgo/sigstore-supply-chain@sha256:<digest> --csv resultados/e4-tamanhos.csv
```

O rollback (E2.5) precisa de um digest legítimo cujo atestado de varredura tenha mais de
`JANELA_VARREDURA` (24 h): rode o pipeline num dia e use esse digest como "antigo" no dia seguinte, ou
rode `JANELA_VARREDURA=1h scripts/cluster/ataques.sh ...` uma hora depois.

Cada execução do pipeline registra entradas novas no Rekor público, que é permanente e mostra o nome
do repositório e do workflow.

## Versões fixadas

Cosign v2.6.5 (formato legado `.sig`/`.att`), Trivy 0.69.3 (anterior ao incidente de março de 2026
com o trivy-action), Syft 1.57.2, crane 0.22.1, Semgrep 1.186.0, slsa-github-generator v2.1.0,
Kyverno v1.19.2, kind v0.33.0 com Kubernetes 1.35.8. Actions de terceiros fixadas por SHA do commit.
Detalhes e checksums nos arquivos de `docs/`.
