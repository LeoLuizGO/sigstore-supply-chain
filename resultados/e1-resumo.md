## E1 - pipeline completo

- Imagem: `ghcr.io/leoluizgo/sigstore-supply-chain`
- Digest: `sha256:dc1e2591bcf6de5187d1e27ec4a943ef5774d4f66b0b2bdd56cad889e943eade`
- Tags: `sha-68f9bc9` e `main`
- Rekor (assinatura): logIndex 4048534373 - https://search.sigstore.dev/?logIndex=4048534373
- Identidade esperada: `https://github.com/LeoLuizGO/sigstore-supply-chain/.github/workflows/pipeline.yml@refs/heads/main`

| Verificação | Resultado |
|---|---|
| tag_main | OK |
| cosign_verify | OK |
| cosign_verify_attestation_cyclonedx | OK |
| cosign_verify_attestation_vuln | OK |
| cosign_verify_attestation_slsaprovenance | OK |
| verificador_do_grupo | OK |
