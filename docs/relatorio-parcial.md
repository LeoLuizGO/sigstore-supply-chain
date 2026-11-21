# Relatório parcial (versão entregue em 15/11/2026)

**UNIVERSIDADE FEDERAL DE SANTA CATARINA\[image\]**
CENTRO TECNOLÓGICO
DEPARTAMENTO DE INFORMÁTICA E ESTATÍSTICA
Disciplina de Segurança em Computação
Profs. Jean Martina e Thaís Bardini Idalino
**Integridade da cadeia de suprimentos de software com assinaturas keyless e transparency logs**
Relatório parcial
Leonardo Luiz Gambalonga Alves de Oliveira
Pedro Philippi Araujo
Florianópolis
2026
## **Resumo**
Este relatório parcial apresenta a fundamentação teórica e o planejamento experimental de um pipeline de integração e entrega contínuas (CI/CD) em que toda imagem de container é assinada digitalmente e só pode ser implantada após verificação criptográfica. A solução estudada é o Sigstore, que combina assinaturas ECDSA com chaves efêmeras, certificados X.509 de curta duração vinculados a uma identidade OIDC e um log de transparência baseado em árvores de Merkle. São descritos o funcionamento e as garantias de cada mecanismo, um mini-exemplo de prova de inclusão em árvore de Merkle e o plano de quatro experimentos: o pipeline completo, cenários de ataque à cadeia de suprimentos, um verificador independente implementado pelo grupo e métricas de custo.
**Palavras-chave:** assinatura digital; ECDSA; infraestrutura de chaves públicas; árvore de Merkle; transparency log; Sigstore; cadeia de suprimentos de software.
# **1. Introdução**
*“Criptografia é normalmente evitada, não penetrada” - *Adi Shamir, co-inventor do algoritmo RSA.
Boa parte dos incidentes de segurança de maior impacto dos últimos anos não envolveu a quebra de nenhum algoritmo criptográfico. O atacante comprometeu o caminho entre o código-fonte e o artefato que vai para produção, conhecido como cadeia de suprimentos de software (software supply chain) \[6\]. Alguns casos ilustram o problema:
  - **SolarWinds (2020):** o servidor de build da empresa foi invadido e o código malicioso foi inserido durante a compilação. O binário distribuído aos clientes saiu assinado com o certificado legítimo da empresa \[14\].
  - **Codecov (2021):** um script de upload usado em pipelines de CI foi alterado para enviar variáveis de ambiente, incluindo credenciais, a um servidor do atacante \[15\].
  - **xz-utils (2024):** um backdoor foi inserido na biblioteca por um mantenedor que havia ganhado a confiança do projeto ao longo de anos \[16\].
  - **tj-actions/changed-files (2025):** uma GitHub Action usada por milhares de repositórios foi modificada e passou a expor segredos de CI nos logs de execução \[17\].
O caso SolarWinds mostra que assinar o artefato não basta quando a chave de assinatura fica no mesmo ambiente que foi comprometido. A pergunta que orienta este trabalho é: como o ambiente de execução pode ter uma garantia criptográfica de que a imagem que vai rodar é exatamente a que o CI legítimo construiu a partir do repositório legítimo?
A aplicação escolhida é o **Sigstore** \[1\], um conjunto de serviços abertos para assinatura de software mantido pela Open Source Security Foundation (OpenSSF). O Sigstore substitui a chave privada de longa duração por chaves efêmeras, emite certificados de poucos minutos vinculados à identidade do workflow de CI e registra cada assinatura em um log público e auditável. O tema se enquadra na linha "Engenharia Segura e DevSecOps" do enunciado (assinatura e verificação de artefatos), com ênfase nos esquemas criptográficos envolvidos: funções hash, assinatura ECDSA, certificados X.509 e árvores de Merkle.
A escolha foi motivada por três fatores: o tema é atual e tem aplicação direta no trabalho de desenvolvimento de software; ele reúne em um único sistema vários conceitos vistos na disciplina; e permite experimentos de ataque concretos, com resultados verificáveis em sala.
O objetivo do trabalho é implementar um pipeline em que imagens sem assinatura válida, adulteradas ou assinadas por outra identidade sejam recusadas no deploy, e escrever um verificador próprio que refaça as checagens criptográficas sem depender da ferramenta oficial. A Seção 2 apresenta a fundamentação teórica e um mini-exemplo, e a Seção 3 descreve a implementação planejada e os experimentos.
# **2. Desenvolvimento**
## **2.1 Modelo de ameaça**
O framework SLSA (Supply-chain Levels for Software Artifacts) \[9\] divide as ameaças à cadeia de suprimentos em quatro pontos: o código-fonte (commit malicioso ou repositório comprometido), o processo de build (alteração durante a compilação), as dependências (pacote de terceiros comprometido) e a distribuição (troca do artefato no registry ou no caminho até o servidor). Este trabalho trata principalmente das duas últimas fases: garantir que o artefato implantado é o mesmo que saiu do build legítimo e que nenhuma dependência com vulnerabilidade crítica conhecida foi incluída.
Assume-se que o atacante pode publicar imagens no registry, alterar tags e reaproveitar imagens antigas, mas não controla a conta do GitHub nem os serviços do Sigstore. As consequências de um comprometimento desses serviços são discutidas na Seção 2.6.
## **2.2 Funções hash e endereçamento por conteúdo**
Uma função hash criptográfica H mapeia mensagens de tamanho arbitrário em uma saída de tamanho fixo (256 bits no SHA-256) e deve ter três propriedades \[7\]: resistência à pré-imagem (dado y, é inviável achar m com H(m) = y), resistência à segunda pré-imagem (dado m, é inviável achar m' ≠ m com H(m') = H(m)) e resistência a colisões (é inviável achar qualquer par m ≠ m' com H(m) = H(m')).
Imagens de container seguem a especificação OCI, em que cada camada e o manifesto da imagem são identificados pelo seu digest SHA-256, por exemplo sha256:9f86d0…. Como o manifesto lista os digests de todas as camadas, o digest do manifesto identifica a imagem inteira: alterar um único byte de qualquer camada muda o digest dessa camada, que muda o manifesto e, portanto, o digest final. Por isso o que se assina é o digest. A tag (app:latest, app:v1.2) é apenas um nome mutável que pode ser apontado para outra imagem a qualquer momento, e assinar uma tag não garantiria nada sobre o conteúdo.
## **2.3 Assinatura digital ECDSA**
O Cosign, cliente de assinatura do Sigstore, usa por padrão o ECDSA sobre a curva NIST P-256 com SHA-256 \[7\]. Os parâmetros públicos são a curva E, um ponto gerador G de ordem prima n e a função hash H.
**Geração de chaves.** Escolhe-se a chave privada d aleatória em \[1, n−1\] e calcula-se a chave pública Q = d·G. Obter d a partir de Q exige resolver o problema do logaritmo discreto em curvas elípticas, considerado inviável para curvas de 256 bits.
**Assinatura** de uma mensagem m:
  - calcular e = H(m), interpretado como inteiro;
  - escolher um nonce k aleatório e secreto em \[1, n−1\];
  - calcular o ponto (x1, y1) = k·G e r = x1 mod n (se r = 0, escolher outro k);
  - calcular s = k−1(e + r·d) mod n (se s = 0, escolher outro k);
  - a assinatura é o par (r, s).
**Verificação** de (r, s) com a chave pública Q:
  - verificar que r e s estão em \[1, n−1\];
  - calcular e = H(m) e w = s−1 mod n;
  - calcular u1 = e·w mod n e u2 = r·w mod n;
  - calcular o ponto X = u1·G + u2·Q;
  - aceitar se e somente se a coordenada x de X, reduzida mod n, for igual a r.
**Por que funciona.** Substituindo Q = d·G, tem-se X = u1·G + u2·d·G = w(e + r·d)·G. Como s = k−1(e + r·d), vale w = s−1 = k(e + r·d)−1, logo w(e + r·d) = k e X = k·G, cuja coordenada x é exatamente a que gerou r. Sem conhecer d, não se consegue produzir um s que satisfaça essa igualdade para um e novo.
**Importância do nonce.** Se o mesmo k for usado em duas assinaturas (r, s1) e (r, s2) de mensagens com hashes e1 e e2, então s1 − s2 = k−1(e1 − e2), o que revela k = (e1 − e2)/(s1 − s2) mod n e, em seguida, a chave privada d = (s1·k − e1)/r mod n. Foi esse erro que permitiu a extração da chave de assinatura do console PlayStation 3 em 2010. Implementações atuais derivam k de forma determinística a partir de d e da mensagem (RFC 6979) ou usam um gerador seguro.
## **2.4 Certificados X.509 e o problema da chave de longa duração**
Uma assinatura prova que quem a gerou possuía a chave privada correspondente a Q, mas não diz a quem Q pertence. Esse vínculo é feito por um certificado X.509, no qual uma autoridade certificadora (AC) assina uma declaração do tipo "a chave pública Q pertence à identidade I, válida entre as datas t1 e t2". O verificador confia na AC raiz e valida a cadeia de certificados até ela.
No modelo tradicional de assinatura de software, a chave privada do projeto vale por anos e precisa ficar disponível no CI. Isso cria três problemas: a chave vira o principal alvo do atacante (caso SolarWinds); a revogação depende de listas (CRL/OCSP) que muitos verificadores não consultam; e a distribuição da chave pública aos consumidores é manual. O TUF (The Update Framework) \[5\] já tratava a sobrevivência a comprometimentos de chave em sistemas de atualização. O Sigstore segue outro caminho: elimina a chave de longa duração.
## **2.5 Assinatura keyless: OIDC e a AC Fulcio**
No modo keyless, a cada execução do pipeline o Cosign:
  - gera um par de chaves ECDSA efêmero (d, Q), mantido apenas em memória;
  - obtém do GitHub Actions um ID token OIDC, que é um JWT assinado pelo GitHub contendo, entre outras, as claims iss (emissor, https://token.actions.githubusercontent.com), repository e job\_workflow\_ref (o arquivo de workflow e o ref que o executou);
  - envia ao Fulcio, a AC do Sigstore, a chave pública Q, o token e uma prova de posse da chave (uma assinatura feita com d);
  - o Fulcio valida a assinatura do JWT com as chaves públicas publicadas pelo emissor, confere a prova de posse e emite um certificado X.509 válido por cerca de 10 minutos, que contém a identidade do workflow e o emissor OIDC em extensões próprias;
  - o Cosign assina o digest da imagem com d e descarta a chave privada.
A identidade que o verificador confere deixa de ser "quem possui a chave X" e passa a ser "o workflow W do repositório R, autenticado pelo emissor E". Uma chave efêmera vazada depois do uso não serve para nada, pois seu certificado já expirou. Resta um problema: como aceitar, horas ou anos depois, uma assinatura cujo certificado só valia por 10 minutos? A resposta é o log de transparência.
## **2.6 Logs de transparência e árvores de Merkle**
O Rekor é o log de transparência do Sigstore. Ele segue o modelo do Certificate Transparency, definido nas RFC 6962 e 9162 \[3\]\[4\] e exigido hoje pelos principais navegadores para certificados TLS. A ideia é manter um registro público, apenas de inserção (append-only), em que qualquer pessoa pode verificar que uma entrada está presente e que nada foi removido ou alterado depois.
O log é organizado como uma árvore de Merkle: as folhas são as entradas e cada nó interno é o hash dos seus dois filhos. Para impedir que um nó interno seja apresentado como folha (ataque de segunda pré-imagem), a RFC 6962 usa prefixos de domínio diferentes:
leaf(d) = SHA-256(0x00 ‖ d) node(l, r) = SHA-256(0x01 ‖ l ‖ r)
O hash da raiz resume todo o conteúdo do log. Periodicamente, o log assina um checkpoint (signed tree head) contendo o tamanho da árvore e o hash da raiz. A partir dele, o log fornece dois tipos de prova:
  - **Prova de inclusão:** para mostrar que a entrada de índice i está numa árvore de tamanho N, basta fornecer os hashes dos irmãos no caminho da folha até a raiz, cerca de log2N hashes. O verificador recalcula a raiz e compara com a do checkpoint assinado. Com 100 milhões de entradas, a prova tem cerca de 27 hashes.
  - **Prova de consistência:** mostra que a árvore de tamanho N2 é uma extensão da árvore de tamanho N1, ou seja, que nenhuma entrada antiga foi alterada ou removida.
No Sigstore, cada assinatura registrada no Rekor contém o hash do artefato, a assinatura e o certificado. O log devolve o momento de integração da entrada e uma prova de inclusão. Na verificação, aceita-se a assinatura se o momento em que ela entrou no log estiver dentro da janela de validade do certificado. Assim, a assinatura continua verificável depois que o certificado expira, sem que ninguém precise guardar uma chave. As versões mais recentes do Sigstore também aceitam carimbos de tempo de uma autoridade RFC 3161 como fonte de tempo confiável.
O log também permite detectar abusos: o mantenedor de um projeto pode monitorar o Rekor e ser alertado se aparecer uma assinatura em nome do seu repositório que ele não reconhece. Se o Fulcio fosse comprometido e emitisse certificados falsos, esses certificados precisariam aparecer no log para serem aceitos, o que torna o ataque visível. Essa é a mesma garantia que o Certificate Transparency oferece para certificados TLS.
## **2.7 Atestados: SBOM e proveniência**
Além da assinatura da imagem, o pipeline gera atestados no formato in-toto \[2\]: declarações assinadas que associam o digest da imagem (subject) a um predicado. Serão usados dois predicados: o SBOM (Software Bill of Materials), lista de todos os pacotes contidos na imagem, e a proveniência SLSA, que descreve qual workflow, commit e ambiente produziram o artefato. A proveniência será gerada pelo slsa-github-generator, um workflow reutilizável do projeto SLSA; como é ele quem assina, o certificado desse atestado traz a identidade do workflow do gerador, e não a do workflow do projeto, o que precisa ser refletido na política de verificação. Os atestados são assinados pelo mesmo processo keyless e também registrados no Rekor, o que permite escrever políticas sobre como a imagem foi construída, e não apenas sobre quem a assinou.
## **2.8 Mini-exemplo: prova de inclusão em uma árvore de Merkle**
Considere um log com quatro entradas, d0 = "entrada-0", d1 = "entrada-1", d2 = "entrada-2" e d3 = "entrada-3". Os valores abaixo foram calculados com SHA-256 e os prefixos da RFC 6962, e estão truncados nos primeiros 16 dígitos hexadecimais para facilitar a leitura.
|  |  |  |
| :- | :- | :- |
| **Nó** | **Definição** | **Valor (16 primeiros hex)** |
| h0 | leaf(d0) | 475dca70c1ec1537 |
| h1 | leaf(d1) | 75f91a0150c85497 |
| h2 | leaf(d2) | 44fb37b9be8db9bd |
| h3 | leaf(d3) | 4f18cddc25d2c1c1 |
| h01 | node(h0, h1) | b2489a497d57cf8b |
| h23 | node(h2, h3) | af7a3e6321199414 |
| raiz | node(h01, h23) | 5d5487109c0530dd |

**Entrada:** o verificador recebe a entrada d2, seu índice i = 2, o tamanho da árvore N = 4, a raiz assinada 5d5487109c0530dd e a prova de inclusão \[h3, h01\].
**Processamento:**
  - x = leaf(d2) = 44fb37b9be8db9bd;
  - Como d2 é filho da esquerda, x = node(x, h3) = af7a3e6321199414;
  - O nó obtido é filho da direita, então x = node(h01, x) = 5d5487109c0530dd.
**Saída:** o valor calculado é igual à raiz assinada, portanto a entrada está no log. Se o atacante alterar a entrada para "entrada-2X", o mesmo processo produz fccd9c1003019f3e, diferente da raiz, e a verificação falha. Para que uma entrada falsa fosse aceita, seria preciso encontrar uma segunda pré-imagem do SHA-256 ou forjar a assinatura do checkpoint.
# **3. Experimento**
## **3.1 Ambiente e ferramentas**
|  |  |  |
| :- | :- | :- |
| **Componente** | **Ferramenta** | **Função** |
| Repositório e CI | GitHub e GitHub Actions | Código da aplicação de exemplo e execução do pipeline |
| Análise estática | Semgrep | Detecção de padrões inseguros no código (SAST) |
| Varredura de vulnerabilidades | Trivy \[11\] | Busca de CVEs nas dependências e na imagem; interrompe o build em caso de CVE crítica |
| SBOM | Syft | Geração da lista de pacotes da imagem |
| Assinatura e atestados | Cosign, Fulcio e Rekor (Sigstore) \[10\] | Assinatura keyless, emissão de certificados e log de transparência |
| Registry | GitHub Container Registry (GHCR) | Armazenamento das imagens, assinaturas e atestados |
| Ambiente de execução | Kubernetes local (kind) com Kyverno | Política de admissão que recusa imagens sem assinatura válida |
| Verificador próprio | Python 3 com a biblioteca cryptography | Verificação independente da assinatura ECDSA, do certificado Fulcio e da prova de inclusão no Rekor (E3) |

## **3.2 Arquitetura do pipeline**
A cada push na branch principal, o pipeline executa as etapas abaixo. Uma falha em qualquer etapa interrompe o processo. A identidade assinada comprova a origem declarada pelo workflow, mas não prova que o código é benigno nem que o build não foi comprometido.
  - Semgrep analisa o código-fonte.
  - A imagem é construída e publicada no GHCR, e seu digest é registrado.
  - Trivy analisa a imagem (base python-slim) e interrompe o pipeline se houver CVE crítica com correção disponível; também gera o relatório de vulnerabilidades no formato cosign-vuln.
  - Syft gera o SBOM da imagem.
  - Cosign assina o digest no modo keyless (Fulcio emite o certificado e o Rekor registra a assinatura) e anexa os atestados de SBOM e de varredura de vulnerabilidades; a proveniência SLSA é gerada e assinada pelo slsa-github-generator.
  - No cluster kind local, o deploy é feito a partir do notebook, pois o runner do GitHub não tem acesso a esse cluster. O Kyverno intercepta o pedido de deploy e só admite a imagem se a assinatura for válida e o certificado identificar o workflow esperado do repositório esperado.
\[image\]
Pseudocódigo do workflow:
ao receber push em main:          \# permissões: id-token: write, packages: write  
    semgrep\_scan(codigo)                           \# falha se achado de alta severidade  
    digest = docker\_build\_e\_push(ghcr/app)         \# python-slim; digest do manifesto  
    trivy\_scan(digest, CRITICAL, ignore\_unfixed)   \# falha se CVE crítica corrigível  
    sbom = syft(digest, formato = "cyclonedx")  
    vuln = trivy\_scan(digest, formato = "cosign-vuln")  
    cosign\_sign(digest)                            \# OIDC + chave efêmera + Fulcio + Rekor  
    cosign\_attest(digest, sbom, tipo = "cyclonedx")  
    cosign\_attest(digest, vuln, tipo = "vuln")  
    proveniencia = slsa\_github\_generator(digest)   \# assinada pelo workflow do gerador  
  
no notebook, com o cluster kind local:  
    kubectl\_apply(deployment com imagem ghcr/app@digest)  \# Kyverno verifica
## **3.3 Verificador próprio (E3)**
O núcleo criptográfico do trabalho é um verificador escrito pelo grupo, que refaz as checagens do cosign verify passo a passo. A entrada é a referência da imagem por digest, a identidade esperada (repositório e workflow) e o emissor OIDC esperado. A saída é "válida" ou o motivo da rejeição.
função VERIFICA(digest\_esperado, identidade\_esperada, emissor\_esperado,  
                bundle, trusted\_root):  
    (assinatura, payload, certificado, prova\_log, timestamp) = ler\_bundle(bundle)  
    se payload.digest \!= digest\_esperado: rejeita("assinatura é de outra imagem")  
  
    \# 1. Certificado e identidade (cadeia do Fulcio no trusted\_root fixado)  
    se não valida\_cadeia(certificado, trusted\_root.fulcio):  
        rejeita("AC desconhecida")  
    se certificado.emissor\_oidc \!= emissor\_esperado: rejeita("emissor errado")  
    se certificado.san \!= identidade\_esperada: rejeita("identidade errada")  
  
    \# 2. Assinatura ECDSA sobre os bytes exatos do payload  
    Q = certificado.chave\_publica  
    se não ecdsa\_verifica(Q, assinatura, payload):  
        rejeita("assinatura inválida")  
  
    \# 3. Entrada no Rekor: correspondência, checkpoint e prova de inclusão  
    entrada = prova\_log.entrada\_canonica  
    se não entrada\_corresponde(entrada, assinatura, certificado, payload):  
        rejeita("entrada não confere")  
    folha = SHA256(0x00 || entrada)  
    cp = prova\_log.checkpoint  
    se não verifica\_checkpoint(trusted\_root.chave\_do\_log(cp.log\_id), cp):  
        rejeita("checkpoint inválido")  
    se não VERIFICA\_INCLUSAO(folha, prova\_log.indice, cp.tamanho,  
                             prova\_log.caminho, cp.raiz):  
        rejeita("prova de inclusão inválida")  
  
    \# 4. Tempo confiável: integratedTime do Rekor ou, se houver, carimbo RFC 3161  
    t = prova\_log.integrated\_time  
    se timestamp presente:                         \# extensão opcional  
        se não valida\_rfc3161(timestamp, assinatura, trusted\_root.tsas):  
            rejeita("timestamp inválido")  
        t = timestamp.tempo  
    se t fora de \[certificado.inicio, certificado.fim\]:  
        rejeita("assinatura fora da validade do certificado")  
    retorna válida
A verificação da prova de inclusão segue o algoritmo da RFC 9162, Seção 2.1.3.2 \[4\], que também trata árvores cujo tamanho não é potência de 2:
função VERIFICA\_INCLUSAO(folha, indice, tamanho, prova, raiz):  
    se indice \>= tamanho: retorna falso  
    fn = indice; sn = tamanho - 1; r = folha  
    para cada p em prova:  
        se sn == 0: retorna falso  
        se (fn é ímpar) ou (fn == sn):  
            r = SHA256(0x01 || p || r)  
            se fn é par:  
                repita fn = fn \>\> 1; sn = sn \>\> 1 até (fn ímpar) ou (fn == 0)  
        senão:  
            r = SHA256(0x01 || r || p)  
        fn = fn \>\> 1; sn = sn \>\> 1  
    retorna (sn == 0) e (r == raiz)
O verificador será validado com o mini-exemplo da Seção 2.8 e com bundles Sigstore reais, comparando o resultado com o cosign verify e com o sigstore-python \[18\] em imagens legítimas e adulteradas do experimento E2. A versão do Cosign será fixada e o bundle de cada assinatura será salvo explicitamente, pois o formato armazenado no registry varia entre versões e, nas mais antigas, não inclui a prova de inclusão, que nesse caso será obtida pela API do Rekor. O trusted\_root.json do Sigstore será baixado uma vez e fixado; sua atualização via TUF fica fora do escopo. A biblioteca cryptography cobre ECDSA e X.509; a validação de carimbos RFC 3161, que exige um parser ASN.1 adicional, é tratada como extensão opcional. Entradas de tipos ou versões não suportados serão rejeitadas.
## **3.4 Experimentos planejados**
**E1. Pipeline completo.** Execução do fluxo da Seção 3.2 de ponta a ponta, com registro da entrada gerada no Rekor e do deploy, feito a partir do notebook, aceito pelo Kyverno no cluster kind local. O pacote no GHCR será público, para que o cluster não precise de credenciais de pull, e o workflow terá as permissões id-token: write e packages: write.
**E2. Ataques à cadeia de suprimentos.** Cada cenário será executado contra o cluster protegido, com registro do resultado obtido.
|  |  |  |
| :- | :- | :- |
| **Cenário de ataque** | **Resultado esperado** | **Mecanismo responsável** |
| Publicar no registry uma imagem sem assinatura e tentar o deploy | Deploy recusado | Política de admissão do Kyverno |
| Alterar uma camada da imagem depois de assinada e republicar na mesma tag | Deploy recusado | O digest muda e não há assinatura para o novo digest |
| Assinar a imagem com outra identidade (fork do repositório ou chave local do atacante) | Deploy recusado | Identidade e emissor conferidos no certificado |
| Trocar a assinatura de uma imagem pela de outra imagem | Deploy recusado | O payload assinado contém o digest da imagem original |
| Implantar uma versão antiga, assinada legitimamente mas com vulnerabilidade conhecida (rollback) | Deploy aceito | Nenhum: a assinatura não garante que o artefato é atual |
| Incluir uma dependência com CVE crítica | Build interrompido antes da assinatura | Trivy |

O cenário de rollback será usado para discutir o limite das assinaturas digitais: elas garantem integridade e origem, mas não atualidade. Como mitigação, será gerado e assinado um atestado de varredura de vulnerabilidades associado ao digest. A política do Kyverno exigirá esse predicado e uma data de varredura dentro da janela definida pelo experimento. Para continuarem aceitas, as versões em uso precisam ser reescaneadas periodicamente, gerando novos atestados; uma versão que deixa de ser reescaneada passa a ser recusada quando o atestado sai da janela.
**E3. Verificador próprio.** Execução do verificador da Seção 3.3 sobre as imagens legítimas e sobre os casos adulterados do E2, comparando os resultados com os do cosign verify.
**E4. Métricas.** Serão medidos o tempo adicionado ao pipeline por cada etapa de segurança, a latência da verificação no momento do deploy, a quantidade de CVEs encontradas em três imagens base (python completa, python-slim e distroless), em uma varredura separada que não bloqueia o pipeline, e o tamanho do SBOM e dos artefatos de assinatura.
# **Referências**
\[1\] NEWMAN, Z.; MEYERS, J. S.; TORRES-ARIAS, S. Sigstore: Software Signing for Everybody. In: Proceedings of the 2022 ACM SIGSAC Conference on Computer and Communications Security (CCS). ACM, 2022.
\[2\] TORRES-ARIAS, S.; AFZALI, H.; KUPPUSAMY, T. K.; CURTMOLA, R.; CAPPOS, J. in-toto: Providing farm-to-table guarantees for bits and bytes. In: 28th USENIX Security Symposium, 2019.
\[3\] LAURIE, B.; LANGLEY, A.; KASPER, E. RFC 6962: Certificate Transparency. IETF, 2013.
\[4\] LAURIE, B.; MESSERI, E.; STRADLING, R. RFC 9162: Certificate Transparency Version 2.0. IETF, 2021.
\[5\] SAMUEL, J.; MATHEWSON, N.; CAPPOS, J.; DINGLEDINE, R. Survivable Key Compromise in Software Update Systems. In: Proceedings of the 17th ACM Conference on Computer and Communications Security (CCS), 2010.
\[6\] LADISA, P.; PLATE, H.; MARTINEZ, M.; BARAIS, O. SoK: Taxonomy of Attacks on Open-Source Software Supply Chains. In: IEEE Symposium on Security and Privacy (SP), 2023.
\[7\] STINSON, D. R.; PATERSON, M. B. Cryptography: Theory and Practice. 4. ed. CRC Press, 2018.
\[8\] NIST. SP 800-218: Secure Software Development Framework (SSDF) Version 1.1. National Institute of Standards and Technology, 2022.
\[9\] OPENSSF. SLSA: Supply-chain Levels for Software Artifacts. Disponível em: https://slsa.dev/.
\[10\] SIGSTORE. Sigstore Documentation. Disponível em: https://docs.sigstore.dev/.
\[11\] AQUA SECURITY. Trivy. Disponível em: https://aquasecurity.github.io/trivy/.
\[12\] OWASP. DevSecOps Guideline. Disponível em: https://owasp.org/www-project-devsecops-guideline/.
\[13\] PORNIN, T. RFC 6979: Deterministic Usage of the Digital Signature Algorithm (DSA) and Elliptic Curve Digital Signature Algorithm (ECDSA). IETF, 2013.
\[14\] CISA. Emergency Directive 21-01: Mitigate SolarWinds Orion Code Compromise. Washington: Cybersecurity and Infrastructure Security Agency, 2020. Disponível em: https://www.cisa.gov/news-events/directives/ed-21-01-mitigate-solarwinds-orion-code-compromise.
\[15\] CODECOV. Bash Uploader Security Update. 2021. Disponível em: https://about.codecov.io/security-update/.
\[16\] FREUND, A. Backdoor in upstream xz/liblzma leading to ssh server compromise. Lista oss-security, 29 mar. 2024. Disponível em: https://www.openwall.com/lists/oss-security/2024/03/29/4. Ver também CVE-2024-3094.
\[17\] NIST. CVE-2025-30066: tj-actions/changed-files. National Vulnerability Database, 2025. Disponível em: https://nvd.nist.gov/vuln/detail/CVE-2025-30066.
\[18\] SIGSTORE. sigstore-python: a Sigstore client written in Python. Disponível em: https://github.com/sigstore/sigstore-python.
**Uso de inteligência artificial.** Foram utilizados o Claude (Anthropic), por meio do Claude Code, para levantar opções de tema, estruturar o relatório, redigir uma primeira versão do texto, calcular os valores do mini-exemplo da Seção 2.8 e avaliar a viabilidade do plano experimental, e o ChatGPT (OpenAI), para revisar o texto e sugerir correções técnicas. O conteúdo foi revisado pelo grupo, e as referências foram conferidas nas fontes originais.
