# Verificador próprio (E3): implementação, testes e resultados

Área: `verificador/` (agente verificador). Data dos testes: 21/11/2026, Windows 11, Python 3.11.1.
Resumo: o verificador está implementado e testado. Ele refaz todas as checagens do `cosign verify`
para o formato legado do Cosign 2.x e confere também a prova de inclusão e o checkpoint, que o
`cosign verify` desse formato não confere (ele usa só o SET). Rodamos 173 testes unitários e 31 casos
sintéticos (um por motivo de rejeição). Em três imagens públicas reais, com 37 casos legítimos e
adulterados, o nosso verificador, o `cosign` 2.6.5 e o `sigstore-python` 4.5.1 chegaram ao mesmo
resultado em todos os casos que os três conseguem avaliar. O mini-exemplo da Seção 2.8 do relatório
confere em todos os valores.

## 1. O que foi feito

Pacote `verificador/`, rodando com `python -m verificador ...` a partir da raiz do repositório. A CLI
segue o contrato da ESPEC: `digest`, `baixar`, `verificar`, `imagem`, `inspecionar`, com saída 0/1/2 e
`--json`. Há também `exportar-bundle`, para o cross-check. Dependências: `cryptography` e `requests`
(`pytest` nos testes), com versões fixadas em `verificador/requirements.txt`. Instalação, uso e a
lista de arquivos estão em `verificador/README.md`.

Fluxo:

1. **`baixar IMG@sha256:X`**: lê o manifesto da tag `sha256-X.sig` no registry e baixa cada camada
   (o payload simple signing). Pega o `logIndex` na anotação `dev.sigstore.cosign/bundle` e busca a
   entrada com `GET https://rekor.sigstore.dev/api/v1/log/entries?logIndex=N`, que traz body,
   integratedTime, logID, prova de inclusão, checkpoint e SET. Tudo é salvo cru num **JSON de
   evidência autocontido**. O acesso ao registry é anônimo, pelo fluxo genérico de token Bearer
   (401 + `WWW-Authenticate: Bearer realm,service,scope`). Testado em ghcr.io, Docker Hub e cgr.dev.
2. **`verificar evidencia.json`**: 100% offline, usa só a evidência e o `verificador/trusted_root.json`
   fixado. Cada camada do `.sig` é uma assinatura independente. A imagem é **válida se ao menos uma
   assinatura passar em todas as etapas**, e o relatório mostra o resultado de cada etapa de cada
   assinatura.

### Etapas e motivos de rejeição (`verifica.py`)

| # | Etapa | O que confere | Motivo de rejeição |
|---|---|---|---|
| 0 | formato | mediaType simple signing, assinatura base64, certificado PEM presente | `formato de assinatura não suportado` / `assinatura sem certificado Fulcio (chave própria, não keyless)` / `nenhuma assinatura encontrada` (sem `.sig`) |
| 1 | payload | `critical.type` e `critical.image.docker-manifest-digest == digest esperado` | `payload malformado` / `assinatura é de outra imagem` |
| 2 | cadeia X.509 | folha → intermediária → raiz do Fulcio **do trusted_root** (`verify_directly_issued_by` em cada elo, raiz autoassinada, elos superiores com `CA:TRUE`), validade das ACs e janela `validFor` no instante t = integratedTime | `AC desconhecida` / `cadeia da AC fora da validade` |
| 3 | EKU | ExtendedKeyUsage contém codeSigning | `certificado sem EKU codeSigning` |
| 4 | emissor OIDC | extensão 1.3.6.1.4.1.57264.1.8 (UTF8String DER), com fallback para a 1.1 (bytes crus) | `emissor errado` |
| 5 | identidade | SAN (URI/e-mail) == identidade esperada (comparação exata) | `identidade errada` |
| 6 | ECDSA P-256 | assinatura sobre os bytes exatos do payload, com a chave do certificado, pela `cryptography` **e** pela implementação manual (`--ecdsa ambos`, padrão; se as duas discordarem, a saída é 2) | `assinatura inválida` |
| 7 | entrada do Rekor | body = hashedrekord v0.0.1; `spec.data.hash` == SHA-256 do payload; `spec.signature.content` == assinatura; `publicKey` == o mesmo certificado (DER); logIndex da resposta == o pedido | `entrada do Rekor ausente` / `tipo de entrada do Rekor não suportado` / `entrada do Rekor não confere` |
| 8 | checkpoint | signed note: corpo até a linha em branco; linha `— <nome> base64(hint[4] ‖ DER)` com hint == logID[:4]; ECDSA da chave do log localizada pelo logID; nome == origem; tamanho/raiz == `treeSize`/`rootHash` da prova | `log de transparência desconhecido` / `checkpoint inválido` / `checkpoint não confere com a prova` |
| 9 | prova de inclusão | folha = SHA256(0x00 ‖ body); VERIFICA_INCLUSAO (RFC 9162 §2.1.3.2) com o **índice local** `inclusionProof.logIndex` e a raiz **do checkpoint assinado** | `prova de inclusão inválida` |
| 10 | SET (Rekor) | ECDSA do log sobre `{"body","integratedTime","logID","logIndex"}` em JSON canônico (chaves ordenadas, sem espaços) | `SET inválido` |
| 11 | bundle da anotação | `Payload` da anotação == entrada do Rekor, e SET da anotação válido | `bundle do registry não confere com o Rekor` / `SET inválido` |
| 12 | tempo | notBefore ≤ integratedTime ≤ notAfter do certificado folha | `assinatura fora da validade do certificado` |

As etapas independentes rodam mesmo depois de uma falha. O motivo informado é o da primeira etapa
que falhou, na ordem da tabela, que é a do pseudocódigo VERIFICA. O relatório também lista as
extensões do GitHub no certificado (1.3.6.1.4.1.57264.1.1 a 1.22: build signer URI, repositório,
commit, ref, trigger, run URL, visibilidade etc.). Se houver carimbo RFC 3161
(`dev.sigstore.cosign/rfc3161timestamp`), ele é **ignorado com aviso explícito**, porque essa
extensão não foi implementada. O tempo usado é sempre o integratedTime.

### ECDSA didático (`ecdsa_p256.py`)

Parâmetros da P-256 (p, a = p − 3, b, G, n), soma e dobra de pontos em coordenadas afins,
multiplicação escalar por "dobra e soma", decodificação DER estrita de (r, s) e verificação
exatamente como na Seção 2.3 (faixa de r e s, e, w, u1, u2, X = u1·G + u2·Q, x(X) mod n == r).
Também tem uma assinatura "de livro" (`assina_didatico`), usada só em teste. Os testes conferem a
implementação com o vetor oficial da RFC 6979 A.2.5 (P-256/SHA-256, "sample") e com 40 pares de
chaves aleatórias contra a `cryptography`. Também demonstram a recuperação da chave quando o nonce
é reutilizado (caso PS3 da Seção 2.3).

### `trusted_root.json` fixado

Cópia de `https://raw.githubusercontent.com/sigstore/root-signing/main/targets/trusted_root.json`
(último commit nesse arquivo: `c9bda74ad2221f938f7d2e0295ca3aad2da710a8`, de 22/09/2025), com
SHA-256 `6494e21ea73fa7ee769f85f57d5a3e6a08725eae1e38c755fc3517c9e6bc0b66`. Conteúdo:

- 2 ACs do Fulcio: a antiga (2021–2022, só a raiz) e a atual (intermediária `sigstore-intermediate`
  e raiz `sigstore`, ambas ECDSA P-384 com assinatura ecdsa-with-SHA384);
- 2 logs:
  - `rekor.sigstore.dev`: ECDSA P-256, logID `c0d23d6a…`;
  - `log2025-1.rekor.sigstore.dev`: Rekor v2, Ed25519. Não é usado pelo Cosign 2.x e não é suportado;
- 2 CT logs e 1 TSA, que não usamos.

A atualização via TUF fica fora do escopo.

## 2. Como rodar

```bash
python -m venv verificador/.venv
verificador/.venv/Scripts/python -m pip install -r verificador/requirements.txt
PY=verificador/.venv/Scripts/python      # no Linux: verificador/.venv/bin/python

$PY -m pytest verificador/testes                                   # testes (offline)
$PY -m verificador.experimentos.e3                                 # E3 sintético -> resultados/e3-verificador.csv
$PY -m verificador.experimentos.benchmark --n 500 --n-manual 50    # microbenchmark
```

E3 completo, com dados reais e cross-check. O comando abaixo é o que gerou o CSV atual.

```bash
# cosign 2.6.5 (último 2.x): baixado de github.com/sigstore/cosign/releases/download/v2.6.5/
#   cosign-windows-amd64.exe  sha256 19ec346d0050f59ffad9694da97ef9704be34ec60ddc41c5f1d16d8619385825
#   (igual ao cosign_checksums.txt do release)
$PY -m pip install sigstore==4.5.1          # só para o cross-check
$PY -m verificador.experimentos.e3 \
  --real verificador/dados/fluxcd-source-controller-v1.7.0.json=https://github.com/fluxcd/source-controller/.github/workflows/release.yml@refs/tags/v1.7.0 \
  --real verificador/dados/external-secrets-v0.20.0.json=https://github.com/external-secrets/external-secrets/.github/workflows/release.yml@refs/heads/main \
  --real verificador/dados/podinfo-6.9.0.json=https://github.com/stefanprodan/podinfo/.github/workflows/release.yml@refs/tags/6.9.0 \
  --cosign <pasta-temporária>/cosign-windows-amd64.exe --sigstore verificador/.venv/Scripts/sigstore.exe
```

## 3. Testes unitários (pytest)

```
$ verificador/.venv/Scripts/python -m pytest verificador/testes
============================= 173 passed in 8.68s =============================
  test_merkle.py       46 testes
  test_ecdsa.py        47 testes
  test_verificador.py  80 testes (31 casos sintéticos + 37 reais offline + formato/parsers)
```

- **Mini-exemplo da Seção 2.8**: todos os valores do relatório conferem. h0 = 475dca70c1ec1537,
  h1 = 75f91a0150c85497, h2 = 44fb37b9be8db9bd, h3 = 4f18cddc25d2c1c1, h01 = b2489a497d57cf8b,
  h23 = af7a3e6321199414, raiz = 5d5487109c0530dd (completa:
  `5d5487109c0530ddf8b89ffa01264bd00aaefa85b29f77907f1107155f071f10`). A prova [h3, h01] do índice 2
  reproduz os passos do "Processamento", e a adulteração "entrada-2X" dá fccd9c1003019f3e. **Nenhum
  erro encontrado nesses valores.**
- **Árvores de qualquer tamanho**: para N = 1…33, 63, 64, 65, 100, 127, 129 e 1000, testamos todos
  os índices (60 amostrados no caso de 1000). VERIFICA_INCLUSAO é comparada com uma implementação de
  referência que monta a árvore inteira (MTH/PATH da RFC 6962 §2.1). Em todos os casos, índice
  errado, folha errada, hash da prova alterado, prova curta e prova longa são rejeitados.
- **ECDSA manual × cryptography**: vetor RFC 6979; 40 chaves aleatórias com assinatura válida,
  mensagem com 1 bit trocado, (r+1, s), (r, s+1), 1 bit qualquer do DER e outra chave. As duas
  implementações sempre concordam. (r, n−s) também é aceita pelas duas, pela maleabilidade do ECDSA.
  Os testes cobrem ainda r ou s fora de [1, n−1], DER malformado ou não mínimo, ponto fora da curva e
  reutilização de nonce.

## 4. E3 sintético (offline)

`sintetico.py` monta uma "mini-infraestrutura Sigstore" falsa, com chaves novas a cada execução:

- AC raiz e intermediária P-384;
- certificado folha P-256 de 10 minutos, com SAN, EKU, KU e as extensões 1.1, 1.8, 1.9–1.14, 1.20 e
  1.21 do Fulcio;
- payload simple signing e assinatura;
- um "Rekor" de teste: chave P-256, árvore com várias entradas hashedrekord (a nossa e outras), prova,
  checkpoint signed note, SET e índice global = local + 100000, simulando shards;
- manifesto `.sig` com as anotações do cosign e `trusted_root` de teste.

O formato é idêntico ao da evidência real. Os 31 casos estão em `experimentos/casos.py`:

| Caso | Resultado | Motivo |
|---|---|---|
| legítima | válida | – |
| árvore de 1 entrada | válida | – |
| última entrada de árvore com 13 folhas (não potência de 2) | válida | – |
| duas assinaturas: outra identidade + legítima | válida | (a 1ª falha em identidade, a 2ª passa) |
| sem assinatura (E2.1) | rejeitada | nenhuma assinatura encontrada |
| payload de outra imagem (troca de assinatura, E2.4) | rejeitada | assinatura é de outra imagem |
| evidência de outra imagem para o digest esperado | rejeitada | assinatura é de outra imagem |
| assinatura trocada (mesma chave, outro payload) | rejeitada | assinatura inválida |
| 1 bit alterado na assinatura | rejeitada | assinatura inválida |
| 1 byte alterado no payload (fora do digest) | rejeitada | assinatura inválida |
| identidade errada (ataques.yml, E2.3a) | rejeitada | identidade errada |
| emissor errado (accounts.google.com) | rejeitada | emissor errado |
| AC desconhecida (mesmos nomes, outras chaves) | rejeitada | AC desconhecida |
| certificado sem EKU codeSigning | rejeitada | certificado sem EKU codeSigning |
| chave local sem certificado (E2.3b) | rejeitada | assinatura sem certificado Fulcio (chave própria, não keyless) |
| certificado expirado no integratedTime (+1 h) | rejeitada | assinatura fora da validade do certificado |
| integratedTime antes do notBefore | rejeitada | assinatura fora da validade do certificado |
| hash da prova alterado | rejeitada | prova de inclusão inválida |
| índice errado na prova | rejeitada | prova de inclusão inválida |
| prova truncada | rejeitada | prova de inclusão inválida |
| checkpoint com assinatura inválida | rejeitada | checkpoint inválido |
| checkpoint assinado por outra chave | rejeitada | checkpoint inválido |
| raiz falsa na prova e no checkpoint (sem a chave do log) | rejeitada | checkpoint inválido |
| raiz do checkpoint diferente (assinado pelo log) | rejeitada | checkpoint não confere com a prova |
| body do Rekor de outro artefato (prova e SET válidos) | rejeitada | entrada do Rekor não confere |
| body do Rekor alterado | rejeitada | entrada do Rekor não confere |
| entrada do Rekor ausente | rejeitada | entrada do Rekor ausente |
| SET do Rekor inválido | rejeitada | SET inválido |
| SET da anotação inválido | rejeitada | SET inválido |
| bundle da anotação com integratedTime alterado | rejeitada | bundle do registry não confere com o Rekor |
| chave do log fora do trusted_root | rejeitada | log de transparência desconhecido |

Conferimos que cada adulteração derruba só a etapa pretendida. As exceções são as dependências
naturais: por exemplo, trocar a assinatura também quebra a correspondência com a entrada do Rekor.

## 5. Dados reais

Três imagens públicas assinadas no modo keyless por workflows do GitHub Actions, no formato legado
`.sig`. As evidências estão em `verificador/dados/`.

| Imagem | Digest | Assinaturas | SAN | logIndex global (na árvore) | integratedTime |
|---|---|---|---|---|---|
| `ghcr.io/fluxcd/source-controller:v1.7.0` | `sha256:233e0a1e…31c1a4` | 1 | `…/source-controller/.github/workflows/release.yml@refs/tags/v1.7.0` | 518724339 (396820077) | 2025-09-15 14:54:01Z |
| `ghcr.io/external-secrets/external-secrets:v0.20.0` | `sha256:acfd4d75…7c9c12` | 2 | `…/external-secrets/.github/workflows/release.yml@refs/heads/main` | 545467866 (423563604), 545473195 (423568933) | 2025-09-22 10:27Z / 10:45Z |
| `ghcr.io/stefanprodan/podinfo:6.9.0` | `sha256:10af81c9…a33eac` | 1 | `…/podinfo/.github/workflows/release.yml@refs/tags/6.9.0` | 213358887 (91454625) | 2025-05-15 09:38Z |

O emissor das três é `https://token.actions.githubusercontent.com`. Antes de escolhê-las, testamos
outras candidatas:

- o Kyverno (`ghcr.io/kyverno/kyverno:v1.20.0`, v1.15, v1.14, v1.13) **não publica mais `.sig`**,
  só `.att`. Nosso verificador e o cosign 2.6.5 dizem "nenhuma assinatura encontrada" / "no
  signatures found";
- o próprio `ghcr.io/sigstore/cosign/cosign:v2.6.5` também não tem `.sig`.

Saída real (verificação offline da evidência do fluxcd; as 22 linhas de extensões estão abreviadas):

```
$ python -m verificador verificar verificador/dados/fluxcd-source-controller-v1.7.0.json \
    --digest sha256:233e0a1e842cab6ad7d2ed876d39c03d80ba727f78a8b6f159f8b471eb31c1a4 \
    --identidade https://github.com/fluxcd/source-controller/.github/workflows/release.yml@refs/tags/v1.7.0 \
    --emissor https://token.actions.githubusercontent.com
Assinatura 1/1 (camada sha256:41125b8403a7…): VÁLIDA
  [ok   ] formato              simple signing + assinatura + certificado PEM
  [ok   ] payload              docker-manifest-digest = sha256:233e0a1e842cab6ad7d2ed876d39c03d80ba727f78a8b6f159f8b471eb31c1a4
  [ok   ] cadeia X.509         folha -> CN=sigstore-intermediate,O=sigstore.dev -> CN=sigstore,O=sigstore.dev (AC do trusted_root https://fulcio.sigstore.dev, validFor [2022-04-13 20:06:15+00:00, aberta])
  [ok   ] EKU codeSigning      ExtendedKeyUsage contém codeSigning (1.3.6.1.5.5.7.3.3)
  [ok   ] emissor OIDC         'https://token.actions.githubusercontent.com' (extensão 1.3.6.1.4.1.57264.1.8); esperado 'https://token.actions.githubusercontent.com'
  [ok   ] identidade (SAN)     SAN = ['https://github.com/fluxcd/source-controller/.github/workflows/release.yml@refs/tags/v1.7.0']; esperado '...'
  [ok   ] ECDSA P-256          biblioteca=ok, manual=ok
  [ok   ] entrada do Rekor     hashedrekord v0.0.1: hash do payload, assinatura e certificado conferem
  [ok   ] checkpoint           assinado por rekor.sigstore.dev (hint c0d23d6a = logID[:4]); origem 'rekor.sigstore.dev - 1193050959916656506', tamanho 3911549985, raiz 8796ce57987fd75b…
  [ok   ] prova de inclusão    folha 4421bedde3b810ee…, índice 396820077 de 3911549985, 32 hashes -> raiz 8796ce57987fd75b…
  [ok   ] SET (Rekor)          ECDSA do log sobre {body, integratedTime, logID, logIndex}
  [ok   ] bundle da anotação   Payload igual ao do Rekor e SET da anotação válido (SET com bytes diferentes do atual: ECDSA é aleatorizado)
  [ok   ] tempo                integratedTime 2025-09-15T14:54:01+00:00 em [2025-09-15T14:54:00+00:00, 2025-09-15T15:04:00+00:00]
  certificado: serial 2707d8cfba9c6f8c…, válido [2025-09-15T14:54:00+00:00, 2025-09-15T15:04:00+00:00]
    1.3.6.1.4.1.57264.1.8    Issuer (V2)                              https://token.actions.githubusercontent.com
    1.3.6.1.4.1.57264.1.9    Build Signer URI                         https://github.com/fluxcd/source-controller/.github/workflows/release.yml@refs/tags/v1.7.0
    1.3.6.1.4.1.57264.1.12   Source Repository URI                    https://github.com/fluxcd/source-controller
    1.3.6.1.4.1.57264.1.13   Source Repository Digest                 39b9314d479ab0cc5aa554dab3525b9bfb80d099
    1.3.6.1.4.1.57264.1.14   Source Repository Ref                    refs/tags/v1.7.0
    1.3.6.1.4.1.57264.1.20   Build Trigger                            push
    1.3.6.1.4.1.57264.1.21   Run Invocation URI                       https://github.com/fluxcd/source-controller/actions/runs/17737048317/attempts/1
    (... 1.1–1.6, 1.10, 1.11, 1.15–1.19, 1.22)
  rekor: logIndex 518724339 (na árvore: 396820077 de 3911549985), integrado em 2025-09-15T14:54:01+00:00, uuid 108e9186e8c5677a4421bedd…

RESULTADO: VÁLIDA (1 de 1 assinatura(s) válida(s))          [exit 0]
```

A mesma evidência com 1 hash da prova alterado é rejeitada com `[FALHA] prova de inclusão …
-> raiz 0cbe8708a5761ecc…` e `RESULTADO: REJEITADA — prova de inclusão inválida` (exit 1). O SET
continua válido nesse caso (veja a Seção 7).

### Cross-check com cosign 2.6.5 e sigstore-python 4.5.1

Os casos foram avaliados assim:

- **casos com a evidência intacta** (legítima, identidade errada, emissor errado):
  `cosign verify IMG@digest` direto no registry, o caminho real;
- **casos adulterados**: a evidência adulterada é convertida em **bundle Sigstore v0.3**
  (`exportar-bundle`) e verificada com
  `cosign verify-blob --new-bundle-format --bundle … --trusted-root verificador/trusted_root.json` e
  com `sigstore verify identity --bundle …`. O artefato desses dois comandos é o payload.
  O bundle exportado da evidência intacta é aceito pelos dois.
  Também testamos o bundle legado do cosign: `exportar-bundle --formato cosign` +
  `cosign verify-blob --bundle` dá `Verified OK`.

Nenhum dos testes de cross-check assinou nada.

Resultado (`resultados/e3-verificador.csv`, 68 linhas = 31 sintéticas + 37 reais, **0 divergências**):

| Caso real (×3 imagens) | nosso | cosign | sigstore-python | mensagem do cosign / sigstore-python |
|---|---|---|---|---|
| legítima | válida | válida | válida | `cosign verify` no registry: "The cosign claims were validated…" / `OK: payload.json` |
| identidade esperada errada | identidade errada | rejeitada | rejeitada | `none of the expected identities matched…` / `Certificate's SANs do not match…` |
| emissor esperado errado | emissor errado | rejeitada | rejeitada | `none of the expected identities matched…` / `Certificate's OIDCIssuer does not match…` |
| 1 byte alterado no payload | assinatura inválida | rejeitada | rejeitada | `invalid signature when validating ASN.1 encoded signature` / `Signature is invalid for input` |
| 1 bit alterado na assinatura | assinatura inválida | rejeitada | rejeitada | `transparency log signature does not match` / `Signature is invalid for input` |
| 1 hash da prova alterado | prova de inclusão inválida | rejeitada | rejeitada | `failed to verify log inclusion: calculated root…` / `inclusion proof contains invalid root hash` |
| índice da prova errado | prova de inclusão inválida | rejeitada | rejeitada | idem |
| raiz falsa na prova e no checkpoint | checkpoint inválido | rejeitada | rejeitada | idem (eles comparam a raiz antes de verificar o checkpoint) |
| assinatura do checkpoint alterada | checkpoint inválido | rejeitada | rejeitada | `signature on checkpoint did not verify` / `checkpoint: invalid signature` |
| SET alterado | SET inválido | rejeitada | rejeitada | `not enough verified log entries … 0 < 1` / `SET: invalid inclusion promise` |
| digest esperado de outra imagem | assinatura é de outra imagem | n/a | n/a | o verify-blob não conhece o digest da imagem; no registry não podemos publicar o `.sig` copiado (E2.4 fica para o pipeline) |
| sem certificado | assinatura sem certificado Fulcio | n/a | n/a | não dá para montar um bundle keyless sem certificado |
| só a 1ª de 2 assinaturas adulterada (external-secrets) | válida | n/a | n/a | mostra a regra "ao menos uma válida" |

A saída completa do E3 (uma linha por caso, com a mensagem de cada ferramenta) é reproduzida pelo
comando da Seção 2.

## 6. Microbenchmark (E4)

`python -m verificador.experimentos.benchmark --n 500 --n-manual 50`, sobre a evidência real do
fluxcd (Python 3.11.1, cryptography 50.0.2, notebook Intel de 11ª geração, Family 6 Model 141,
Windows 11):

| Etapa | n | média (ms) | desvio (ms) | mín (ms) | máx (ms) |
|---|---:|---:|---:|---:|---:|
| ECDSA P-256 (biblioteca cryptography) | 500 | 0.062 | 0.005 | 0.058 | 0.112 |
| ECDSA P-256 (manual, Python puro) | 50 | 11.559 | 0.337 | 11.105 | 12.609 |
| certificado: parse PEM + extensões Fulcio | 500 | 0.064 | 0.006 | 0.060 | 0.131 |
| cadeia X.509 até a raiz do trusted_root | 500 | 2.067 | 0.129 | 1.888 | 3.046 |
| prova de inclusão (32 hashes) | 500 | 0.032 | 0.009 | 0.029 | 0.119 |
| checkpoint (parse + ECDSA do log) | 500 | 0.063 | 0.006 | 0.061 | 0.141 |
| SET (JSON canônico + ECDSA do log) | 500 | 0.061 | 0.007 | 0.058 | 0.165 |
| verificação completa (ECDSA biblioteca) | 500 | 3.230 | 0.950 | 2.565 | 11.477 |
| verificação completa (ECDSA ambos) | 50 | 17.691 | 2.437 | 15.142 | 25.657 |

Leitura:

- toda a criptografia da verificação offline custa **~3 ms**, dominados pela cadeia X.509: duas
  verificações ECDSA **P-384** (intermediária e raiz) e a tentativa com a AC antiga do trusted_root;
- o ECDSA manual em Python é ~190× mais lento que a `cryptography` (C/Rust), mas ainda leva só 12 ms;
- a prova de inclusão (32 SHA-256) é a etapa mais barata.

Para comparar, `cosign verify` online contra o ghcr.io levou 2,3 s e `sigstore verify identity`
(com atualização TUF) levou 2,0 s de relógio. Ou seja, o custo real está na rede e no início do
processo, não na criptografia.

### Tamanhos dos artefatos (exemplo real; E4)

`python -m verificador inspecionar ghcr.io/fluxcd/source-controller@sha256:233e0a1e… --csv …`:

```
manifesto da imagem: application/vnd.oci.image.index.v1+json, 2382 bytes
sha256-233e…c1a4.sig  (manifesto 9695 B, total 9943 B)
  [1] application/vnd.dev.cosign.simplesigning.v1+json 248 B assina sha256:233e0a1e842c…
      anotações: assinatura=96 B, bundle=5001 B, certificado=2423 B, cadeia=1530 B
sha256-233e…c1a4.att  (manifesto 10003 B, total 23295 B)
  [1] application/vnd.dsse.envelope.v1+json 13292 B predicateType=https://slsa.dev/provenance/v0.2 (statement 9824 B)
      anotações: assinatura=0 B, bundle=5277 B, certificado=2508 B, cadeia=1530 B, predicateType=32 B
```

Uma assinatura de 96 bytes custa ~10 KB no registry. Metade disso é o bundle do Rekor, porque o
body da entrada carrega o certificado em base64 do PEM, ou seja, codificado duas vezes. No
external-secrets, o `.att` com dois SBOMs SPDX duplicados soma 540 KB. **Pendente**: gerar
`resultados/e4-tamanhos.csv` para a nossa imagem depois que o pipeline rodar (ver Seção 9).

## 7. Observações técnicas que valem para o relatório final

1. **Índice global × local.** O `logIndex` do bundle e do cosign é global. A prova usa o índice da
   árvore ativa. A diferença nas três imagens é a mesma: 121.904.262 = 4.163.431 + 117.740.831,
   que são os tamanhos dos dois shards inativos (`GET /api/v1/log`, `inactiveShards`). Por exemplo,
   518724339 − 396820077 = 121904262.
2. **SET × prova de inclusão.** No formato legado, a anotação `dev.sigstore.cosign/bundle` só tem o
   SET (uma *promessa* assinada de inclusão), não a prova. O `cosign verify` desse formato confere só
   o SET, e a própria saída dele diz: "Existence of the claims in the transparency log was verified
   **offline**". Com a prova adulterada, o SET continua válido (Seção 5). Quem só confia no SET
   depende da honestidade do log; a prova contra um checkpoint assinado é a verificação que a
   Seção 2.6 descreve. O nosso verificador faz as duas.
3. **O tamanho da árvore precisa vir assinado.** VERIFICA_INCLUSAO sozinha não fixa N: a prova do
   índice 0 numa árvore de 5 folhas também é aceita, contra a mesma raiz, se o tamanho declarado for
   6. Em árvores de 1 a 39 folhas, isso acontece em 656 pares (índice, N+1). Por isso o tamanho é
   conferido contra o checkpoint assinado, e não só a raiz. Isso está registrado nos testes.
4. **SET não é determinístico.** O SET devolvido hoje pelo Rekor tem bytes diferentes do SET
   gravado na anotação em 2025. Os dois são válidos (ECDSA é aleatorizado), por isso comparamos o
   conteúdo assinado (body, integratedTime, logID, logIndex), não os bytes do SET.
5. **Provas recentes.** A árvore ativa do Rekor v1 tinha ~3,91 bilhões de folhas em 21/11/2026, e as
   provas têm 32 hashes (log2 3,9·10⁹ ≈ 31,9), o que bate com a estimativa da Seção 2.6.
6. **Certificados reais**: validade de exatamente 10 minutos, chave efêmera P-256. A cadeia do
   Fulcio é P-384/SHA-384 e a folha é assinada com ecdsa-with-SHA384. O integratedTime cai 1 s
   depois do notBefore.
7. **Maleabilidade**: (r, n − s) também é uma assinatura válida. Isso não afeta o modelo do Sigstore,
   porque a entrada do Rekor fixa os bytes da assinatura.
8. **Rekor v2** (`log2025-1`, Ed25519) já está no trusted_root oficial. Ele não emite SET nem
   integratedTime; o tempo confiável passa a vir de uma TSA RFC 3161. O Cosign 2.x no formato
   legado continua usando o Rekor v1, que é o que verificamos.

## 8. Limitações (escrever no relatório)

- **SCT do certificado não verificado**: o Fulcio embute um SCT do CT log dele. Não conferimos esse
  SCT. O cosign e o sigstore-python conferem.
- **Sem TUF**: o `trusted_root.json` é fixado e não é atualizado.
- **RFC 3161 não implementado**: o carimbo é ignorado com aviso; o tempo vem do integratedTime.
- **Sem prova de consistência / gossip**: verificamos a inclusão contra o checkpoint que o próprio
  log devolve. Um log malicioso que mostrasse visões diferentes a clientes diferentes (split view) só
  seria detectado comparando checkpoints entre observadores (witnesses). Também não guardamos
  checkpoints antigos.
- **Formatos suportados**: só o formato legado do Cosign 2.x (`.sig`, `hashedrekord` v0.0.1,
  Rekor v1). O formato novo (bundle via OCI referrers), o Rekor v2 e entradas `dsse`/`intoto` não
  são suportados. **Atestados (`.att`) são listados e decodificados pelo `inspecionar`, mas não são
  verificados criptograficamente** (quem os verifica é o Kyverno, área do cluster).
- `critical.identity.docker-reference` não é imposto, como no cosign: o vínculo é com o digest.
- A identidade é comparada por igualdade exata (sem regex, ao contrário do `--certificate-identity-regexp`).
- Cadeia: só aceitamos a ordem [intermediária…, raiz] do trusted_root; não montamos cadeias
  alternativas. A KeyUsage da folha não é conferida, só a EKU.

## 9. Pendente (precisa do pipeline/registry do projeto)

Quando o `pipeline.yml` tiver publicado e assinado a imagem, e o `ataques.yml` tiver produzido as
tags do E2, rodar da raiz:

```bash
source config.env
PY=verificador/.venv/Scripts/python
D=$($PY -m verificador digest "$IMAGEM:main")
$PY -m verificador baixar "$IMAGEM@$D" -o resultados/e3-evidencia-main.json
$PY -m verificador verificar resultados/e3-evidencia-main.json --digest "$D" \
    --identidade "$IDENTIDADE_PIPELINE" --emissor "$EMISSOR_OIDC"
$PY -m verificador inspecionar "$IMAGEM@$D" --csv resultados/e4-tamanhos.csv
for t in ataque-sem-assinatura ataque-outra-identidade ataque-chave-local ataque-troca-assinatura; do
  $PY -m verificador baixar "$IMAGEM@$($PY -m verificador digest $IMAGEM:$t)" -o resultados/e3-evidencia-$t.json
done
$PY -m verificador.experimentos.e3 --cosign bin/cosign --sigstore verificador/.venv/Scripts/sigstore.exe \
  --real resultados/e3-evidencia-main.json="$IDENTIDADE_PIPELINE" \
  --caso-real "E2.1 sem assinatura"     resultados/e3-evidencia-ataque-sem-assinatura.json   "$IDENTIDADE_PIPELINE" "nenhuma assinatura encontrada" \
  --caso-real "E2.3a outra identidade"  resultados/e3-evidencia-ataque-outra-identidade.json "$IDENTIDADE_PIPELINE" "identidade errada" \
  --caso-real "E2.3b chave local"       resultados/e3-evidencia-ataque-chave-local.json      "$IDENTIDADE_PIPELINE" "assinatura sem certificado Fulcio (chave própria, não keyless)" \
  --caso-real "E2.4 troca de assinatura" resultados/e3-evidencia-ataque-troca-assinatura.json "$IDENTIDADE_PIPELINE" "assinatura é de outra imagem"
```

Obs. sobre o E2.3b: a assinatura com chave local feita pelo cosign 2.x também vai para o Rekor
(`hashedrekord` com chave pública em vez de certificado), mas a camada não tem
`dev.sigstore.cosign/certificate`. O motivo esperado é o da tabela acima. O E2.2 (camada alterada)
aparece como "nenhuma assinatura encontrada" para o novo digest. O E2.5 (rollback) é aceito pelo
verificador, como esperado: a assinatura não garante atualidade.

## 10. Correções para o relatório

Nenhum valor numérico do relatório está errado (o mini-exemplo confere inteiro). Encontramos
imprecisões de texto:

1. **Seção 3.3** ("o formato armazenado no registry varia entre versões e, nas mais antigas, não
   inclui a prova de inclusão, que nesse caso será obtida pela API do Rekor"). No formato legado do
   Cosign 2.x, que é o que o projeto usa por decisão da ESPEC, a anotação `dev.sigstore.cosign/bundle`
   **nunca** inclui a prova de inclusão, em nenhuma versão. Ela tem só `SignedEntryTimestamp` e
   `Payload{body, integratedTime, logIndex, logID}`. A prova vem sempre da API do Rekor
   (`/api/v1/log/entries?logIndex=N`). Só o formato novo (bundle v0.3) traz a prova e o checkpoint
   embutidos. Evidência: as anotações das três imagens reais em `verificador/dados/*.json`.
2. **Seções 2.6 e 3.3**: falta o **SET** (signed entry timestamp, "inclusion promise"). O log devolve
   o integratedTime e a prova, e também uma promessa assinada de inclusão. No formato legado é o SET,
   e não a prova, que o `cosign verify` confere ("verified offline"). Sugestão: citar o SET na 2.6 e
   acrescentar ao pseudocódigo VERIFICA a linha
   `se não verifica_set(trusted_root.chave_do_log(entrada.log_id), entrada): rejeita("SET inválido")`,
   que nós implementamos.
3. **Seção 3.3, VERIFICA_INCLUSAO**: o pseudocódigo deveria dizer que `indice` é o índice **dentro
   da árvore** (`inclusionProof.logIndex`), e não o `logIndex` global que o cosign mostra. Hoje eles
   diferem em 121.904.262 por causa dos shards antigos do Rekor. Com o índice global, a prova falha.
   O "repita … até" (do-while) é equivalente ao "enquanto" da RFC 9162, porque nesse ponto fn é par e
   não nulo. Não é erro.
4. **Seção 2.5** ("o Fulcio … emite um certificado … que contém a identidade do workflow e o emissor
   OIDC em extensões próprias"). Mais preciso: a identidade (job_workflow_ref) vai no **Subject
   Alternative Name** (extensão padrão X.509, como URI). O emissor vai na extensão do Fulcio
   **1.3.6.1.4.1.57264.1.8**, um UTF8String DER que substitui a 1.1, obsoleta e com bytes crus. As
   demais claims (repositório, commit, ref, trigger, run) vão nas extensões 1.9 a 1.22.
5. **Seção 2.3/2.5**: só a chave efêmera é ECDSA P-256. As chaves da AC do Fulcio (raiz e
   intermediária) são **P-384**, e o certificado folha é assinado com ecdsa-with-SHA384. Vale uma
   frase, porque a cadeia não usa a mesma curva da Seção 2.3.
6. **Seção 2.6** ("As versões mais recentes do Sigstore também aceitam carimbos RFC 3161"): no
   Rekor v2, que já está no trusted_root oficial desde 23/09/2025, o log não devolve mais
   integratedTime/SET, e o carimbo RFC 3161 passa a ser a fonte de tempo obrigatória. Não afeta o
   nosso pipeline (Cosign 2.x usa Rekor v1), mas vale atualizar a frase.

## 11. Pedidos para outras áreas

- **pipeline**: manter o Cosign **2.x** no formato legado. O último 2.x é o **v2.6.5**; o binário
  Windows tem sha256 `19ec346d…19385825`, conferido com o `cosign_checksums.txt` do release.
  Sem `--new-bundle-format` e sem registry referrers; senão não há `.sig` e o verificador responde
  "nenhuma assinatura encontrada". Salvar em `resultados/e1-*` o digest e o `logIndex` (o global,
  que é o que o cosign imprime).
- **pipeline**: para o E2.4, o `.sig` copiado precisa ir para `sha256-<digest malicioso>.sig` sem
  alteração. O verificador acusa "assinatura é de outra imagem".
- **todos/coordenador**: o `python` global desta máquina tem `cryptography` 39.0.0, antiga demais
  (o verificador precisa de >= 42 e sai com código 2 e uma mensagem clara). Para o contrato
  `python -m verificador …` funcionar como está na ESPEC, ative antes o venv
  (`source verificador/.venv/Scripts/activate`) ou chame `verificador/.venv/Scripts/python`.
- **coordenador**: `verificador/dados/*.json` (evidências reais, ~77 KB no total) são fixtures dos
  testes offline e devem ser versionados. `verificador/.venv/` já é ignorado pelo `.gitignore`.
