"""Evidência autocontida: tudo o que veio do registry e do Rekor para um digest.

Formato (JSON):
{
  "formato": "verificador-ufsc/evidencia-v1",
  "imagem": "ghcr.io/org/repo",            # sem tag/digest
  "digest": "sha256:...",                  # digest da imagem cujas assinaturas foram buscadas
  "baixado_em": "2026-11-21T12:00:00Z",
  "rekor_url": "https://rekor.sigstore.dev",
  "manifesto_sig": {"tag": "sha256-<hex>.sig", "digest": "sha256:...", "conteudo": {...}} | null,
  "payloads": {"<digest da camada>": "<base64 dos bytes exatos>"},
  "rekor": {"<logIndex global>": {"<uuid>": {...resposta crua do Rekor...}}},
  "erros": ["..."]                         # problemas de rede ao montar a evidência
}
O comando `verificar` lê só este arquivo (e o trusted_root), sem rede.
"""

from __future__ import annotations

import base64
import json
from datetime import datetime, timezone

from . import rekor as rekor_mod
from .registry import Registry, analisa_referencia, tag_cosign

FORMATO = "verificador-ufsc/evidencia-v1"


def baixar(imagem: str, rekor_url: str = rekor_mod.REKOR_PADRAO) -> dict:
    ref = analisa_referencia(imagem)
    reg = Registry(ref)
    erros: list[str] = []
    digest = ref.digest
    if digest is None:
        digest = reg.resolve_tag(ref.tag)
        erros.append(f"referência por tag ({ref.tag}) resolvida para {digest}; "
                     "prefira passar IMAGEM@sha256:...")
    ev = {
        "formato": FORMATO,
        "imagem": ref.nome,
        "digest": digest,
        "baixado_em": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "rekor_url": rekor_url,
        "manifesto_sig": None,
        "payloads": {},
        "rekor": {},
        "erros": erros,
    }
    tag = tag_cosign(digest, "sig")
    m = reg.manifesto(tag)
    if m is None:
        return ev
    corpo, tipo, dig = m
    conteudo = json.loads(corpo)
    ev["manifesto_sig"] = {"tag": tag, "digest": dig, "mediaType": tipo, "conteudo": conteudo}
    for camada in conteudo.get("layers", []):
        ev["payloads"][camada["digest"]] = base64.b64encode(reg.blob(camada["digest"])).decode()
        bundle = camada.get("annotations", {}).get("dev.sigstore.cosign/bundle")
        if not bundle:
            erros.append(f"camada {camada['digest']} sem anotação de bundle: logIndex desconhecido")
            continue
        try:
            idx = json.loads(bundle)["Payload"]["logIndex"]
            ev["rekor"][str(idx)] = rekor_mod.busca_por_indice(idx, rekor_url)
        except (rekor_mod.ErroRekor, KeyError, ValueError) as e:
            erros.append(f"camada {camada['digest']}: {e}")
    return ev


def salva(ev: dict, caminho: str) -> None:
    with open(caminho, "w", encoding="utf-8") as f:
        json.dump(ev, f, indent=2, ensure_ascii=False)
        f.write("\n")


def carrega(caminho: str) -> dict:
    with open(caminho, encoding="utf-8") as f:
        ev = json.load(f)
    if ev.get("formato") != FORMATO:
        raise ValueError(f"formato de evidência desconhecido: {ev.get('formato')}")
    return ev
