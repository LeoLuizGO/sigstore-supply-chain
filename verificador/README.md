# Verificador independente de assinaturas Sigstore (E3)

Refaz, passo a passo e sem usar o cosign, as checagens do `cosign verify` para imagens assinadas
no modo keyless pelo Cosign 2.x (formato legado `sha256-<hex>.sig`). Ele responde "válida" ou dá o
motivo exato da rejeição. Detalhes, resultados e limitações estão em [`docs/verificador.md`](../docs/verificador.md).

## Instalação

```bash
python -m venv verificador/.venv
verificador/.venv/Scripts/python -m pip install -r verificador/requirements.txt   # Linux: .venv/bin/python
```

## Uso (da raiz do repositório)

```bash
python -m verificador digest ghcr.io/org/img:tag                 # tag -> sha256:...
python -m verificador baixar IMG@sha256:... -o evidencia.json     # registry + Rekor -> JSON autocontido
python -m verificador verificar evidencia.json --digest sha256:... \
    --identidade "$IDENTIDADE_PIPELINE" --emissor "$EMISSOR_OIDC" [--json] [--ecdsa biblioteca|manual|ambos]
python -m verificador imagem IMG@sha256:... --identidade ... --emissor ...   # baixar + verificar
python -m verificador inspecionar IMG@sha256:... [--json] [--csv resultados/e4-tamanhos.csv]
python -m verificador exportar-bundle evidencia.json -o x.sigstore.json --payload payload.json  # p/ sigstore-python
```

Códigos de saída: 0 = válida, 1 = rejeitada, 2 = erro de uso ou de rede. O comando `verificar` roda
offline: usa só a evidência e o `trusted_root.json` fixado neste diretório.

## Experimentos e testes

```bash
python -m pytest verificador/testes                    # 173 testes, offline
python -m verificador.experimentos.e3 [--real EVID=SAN ...] [--cosign BIN] [--sigstore BIN]
python -m verificador.experimentos.benchmark           # microbenchmark das etapas (E4)
```

## Estrutura

| Arquivo | Conteúdo |
|---|---|
| `verifica.py` | função VERIFICA (Seção 3.3 do relatório): etapas, motivos de rejeição, relatório |
| `ecdsa_p256.py` | ECDSA P-256 didático em Python puro (curva, soma/dobra, multiplicação escalar, DER) |
| `merkle.py` | RFC 6962/9162: hashes de folha/nó, VERIFICA_INCLUSAO e árvore de referência |
| `checkpoint.py` | checkpoint do Rekor (signed note) |
| `certificado.py` | cadeia X.509 até o Fulcio, EKU, emissor OIDC, SAN, extensões 1.3.6.1.4.1.57264.1.* |
| `trusted_root.py`, `trusted_root.json` | raiz de confiança fixada (cópia do `sigstore/root-signing`) |
| `registry.py`, `rekor.py`, `evidencia.py` | rede (somente leitura) e formato da evidência |
| `bundle.py` | exportação para bundle Sigstore v0.3 e para o bundle legado do cosign |
| `inspecionar.py` | artefatos `.sig`/`.att`/`.sbom` e tamanhos (E4) |
| `sintetico.py` | infraestrutura Sigstore falsa (AC, log, árvore, checkpoint, SET) para testes |
| `experimentos/` | `casos.py` (casos do E3), `e3.py`, `benchmark.py` |
| `dados/` | evidências reais baixadas (fluxcd, external-secrets, podinfo), usadas nos testes offline |
