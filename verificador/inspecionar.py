"""Lista os artefatos ligados a um digest no esquema legado do Cosign e seus tamanhos (E4).

  sha256-<hex>.sig  -> assinaturas (camadas simple signing + anotações)
  sha256-<hex>.att  -> atestados (camadas = envelopes DSSE com um statement in-toto)
  sha256-<hex>.sbom -> SBOM anexado com `cosign attach sbom` (obsoleto, raramente usado)
"""

from __future__ import annotations

import base64
import csv
import json

from .registry import Registry, analisa_referencia, tag_cosign
from .verifica import ANOT_ASSINATURA, ANOT_BUNDLE, ANOT_CADEIA, ANOT_CERT

ANOTACOES = {ANOT_ASSINATURA: "assinatura", ANOT_CERT: "certificado", ANOT_CADEIA: "cadeia",
             ANOT_BUNDLE: "bundle"}


def inspeciona(imagem: str) -> dict:
    ref = analisa_referencia(imagem)
    reg = Registry(ref)
    digest = ref.digest or reg.resolve_tag(ref.tag)
    corpo, tipo, _ = reg.manifesto(digest)
    saida = {"imagem": ref.nome, "digest": digest,
             "manifesto": {"mediaType": tipo, "bytes": len(corpo)}, "artefatos": []}
    for sufixo in ("sig", "att", "sbom"):
        tag = tag_cosign(digest, sufixo)
        m = reg.manifesto(tag)
        if m is None:
            continue
        corpo_m, tipo_m, dig_m = m
        man = json.loads(corpo_m)
        art = {"tipo": sufixo, "tag": tag, "digest": dig_m, "bytes_manifesto": len(corpo_m),
               "camadas": []}
        for c in man.get("layers", []):
            blob = reg.blob(c["digest"])
            anot = c.get("annotations", {}) or {}
            item = {"digest": c["digest"], "mediaType": c.get("mediaType"), "bytes": len(blob),
                    "anotacoes_bytes": {ANOTACOES.get(k, k): len(v.encode()) for k, v in anot.items()}}
            if sufixo == "att":
                try:
                    env = json.loads(blob)
                    stmt = json.loads(base64.b64decode(env["payload"]))
                    item["dsse_payloadType"] = env.get("payloadType")
                    item["predicateType"] = stmt.get("predicateType")
                    item["subject"] = [s.get("digest") for s in stmt.get("subject", [])]
                    item["bytes_statement"] = len(base64.b64decode(env["payload"]))
                except (ValueError, KeyError, TypeError) as e:
                    item["erro"] = f"envelope DSSE ilegível: {e}"
            elif sufixo == "sig":
                try:
                    item["docker-manifest-digest"] = json.loads(blob)["critical"]["image"]["docker-manifest-digest"]
                except (ValueError, KeyError, TypeError):
                    pass
            art["camadas"].append(item)
        art["bytes_total"] = art["bytes_manifesto"] + sum(
            i["bytes"] for i in art["camadas"])
        saida["artefatos"].append(art)
    return saida


def linhas_csv(info: dict) -> list[tuple[str, int]]:
    """Linhas artefato,bytes para resultados/e4-tamanhos.csv."""
    L = [("manifesto da imagem", info["manifesto"]["bytes"])]
    for art in info["artefatos"]:
        L.append((f"{art['tipo']}: manifesto (com anotações)", art["bytes_manifesto"]))
        for i, c in enumerate(art["camadas"], 1):
            rotulo = c.get("predicateType") or c.get("mediaType")
            L.append((f"{art['tipo']}[{i}]: camada {rotulo}", c["bytes"]))
            for nome, n in c["anotacoes_bytes"].items():
                L.append((f"{art['tipo']}[{i}]: anotação {nome}", n))
        L.append((f"{art['tipo']}: total (manifesto + camadas)", art["bytes_total"]))
    return L


def escreve_csv(info: dict, caminho: str) -> None:
    with open(caminho, "w", newline="", encoding="utf-8") as f:
        w = csv.writer(f)
        w.writerow(["artefato", "bytes"])
        w.writerows(linhas_csv(info))


def formata(info: dict) -> str:
    L = [f"{info['imagem']}@{info['digest']}",
         f"  manifesto da imagem: {info['manifesto']['mediaType']}, {info['manifesto']['bytes']} bytes"]
    if not info["artefatos"]:
        L.append("  nenhum artefato .sig/.att/.sbom encontrado")
    for art in info["artefatos"]:
        L.append(f"  {art['tag']}  (manifesto {art['bytes_manifesto']} B, total {art['bytes_total']} B)")
        for i, c in enumerate(art["camadas"], 1):
            extra = ""
            if "predicateType" in c:
                extra = f" predicateType={c['predicateType']} (statement {c['bytes_statement']} B)"
            elif "docker-manifest-digest" in c:
                extra = f" assina {c['docker-manifest-digest'][:19]}…"
            L.append(f"    [{i}] {c['mediaType']} {c['bytes']} B{extra}")
            if c["anotacoes_bytes"]:
                L.append("        anotações: " + ", ".join(f"{k}={v} B" for k, v in c["anotacoes_bytes"].items()))
    return "\n".join(L)
