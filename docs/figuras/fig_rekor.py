import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
from matplotlib.patches import FancyBboxPatch, FancyArrowPatch
plt.rcParams["font.family"] = "Arial"

AZ = ("#dbe7f6", "#2f5d8a")
LA = ("#fbe3c4", "#b0661a")
VE = ("#eef5ea", "#4a7a3a")
CI = ("#f3f3f3", "#7a7a7a")

fig, ax = plt.subplots(figsize=(9.0, 5.7), dpi=220)
ax.set_xlim(0, 110); ax.set_ylim(0, 70); ax.axis("off")


def caixa(x, y, w, h, cor, titulo, linhas=(), lw=1.4, fs=7.4, mono=False):
    ax.add_patch(FancyBboxPatch((x, y), w, h, boxstyle="round,pad=0.3,rounding_size=1.2", fc=cor[0], ec=cor[1], lw=lw))
    ax.text(x + w / 2, y + h - 2.3, titulo, ha="center", va="center", fontsize=8.6, weight="bold", color=cor[1])
    for k, l in enumerate(linhas):
        ax.text(x + w / 2, y + h - 5.6 - k * 2.9, l, ha="center", va="center", fontsize=fs, color="#333",
                family="Consolas" if mono else "Arial")


def seta(p, q, cor="#555", lw=1.3, txt=None, tpos=0.5, dx=0, dy=1.6, ls="-", rad=0.0, fs=7):
    ax.add_patch(FancyArrowPatch(p, q, arrowstyle="-|>", mutation_scale=10, color=cor, lw=lw, ls=ls,
                                 connectionstyle=f"arc3,rad={rad}", shrinkA=2, shrinkB=2))
    if txt:
        x = p[0] + (q[0] - p[0]) * tpos + dx; y = p[1] + (q[1] - p[1]) * tpos + dy
        ax.text(x, y, txt, ha="center", va="center", fontsize=fs, color=cor, style="italic")


# 1. assinante
caixa(1, 40, 23, 20, AZ, "Pipeline (assinante)",
      ["certificado Fulcio", "(chave efêmera, ~10 min)", "assina o digest", "da imagem"])
# 2. Rekor
ax.add_patch(FancyBboxPatch((33, 24), 33, 36, boxstyle="round,pad=0.3,rounding_size=1.4", fc="#fafafa", ec="#444", lw=1.6))
ax.text(49.5, 57.5, "Rekor (log de transparência)", ha="center", fontsize=8.6, weight="bold", color="#333")
ax.text(49.5, 54.4, "árvore de Merkle append-only", ha="center", fontsize=7.2, color="#555")
# mini árvore
import itertools
fx = [37.5, 42.5, 47.5, 52.5, 57.5, 62.0]
ry, my, ly = 45.5, 38, 30.5
nos_m = [40, 50, 60]
ax.add_patch(FancyBboxPatch((47, ry - 1.4), 5, 2.8, boxstyle="round,pad=0.15,rounding_size=0.5", fc=VE[0], ec=VE[1], lw=1.3))
ax.text(49.5, ry, "raiz", ha="center", va="center", fontsize=6.4, color=VE[1], weight="bold")
for m in nos_m:
    ax.add_patch(FancyBboxPatch((m - 1.6, my - 1.2), 3.2, 2.4, boxstyle="round,pad=0.1,rounding_size=0.4", fc="#e8e8e8", ec="#888", lw=0.9))
    ax.plot([m, 49.5], [my + 1.3, ry - 1.5], color="#999", lw=0.8)
pares = [(fx[0], 40), (fx[1], 40), (fx[2], 50), (fx[3], 50), (fx[4], 60), (fx[5], 60)]
for k, (x, m) in enumerate(pares):
    nova = k == 5
    c = LA if nova else ("#e8e8e8", "#888")
    ax.add_patch(FancyBboxPatch((x - 1.6, ly - 1.2), 3.2, 2.4, boxstyle="round,pad=0.1,rounding_size=0.4", fc=c[0], ec=c[1], lw=1.4 if nova else 0.9))
    ax.plot([x, m], [ly + 1.3, my - 1.3], color="#999", lw=0.8)
ax.text(60.0, ly - 3.6, "nova entrada", ha="center", fontsize=6.6, color=LA[1], weight="bold")
ax.text(49.5, 51.4, "folha = hash do artefato, assinatura e certificado", ha="center", fontsize=6.4, color="#666")

seta((24.6, 50), (32.6, 50), AZ[1], 1.5, "entrada", dy=2.0)

# 3. saídas do log
caixa(75, 44, 33, 16, LA, "SET (signed entry timestamp)",
      ["assinatura do log sobre", "corpo, integratedTime,", "logIndex e logID"])
caixa(75, 24, 33, 16, VE, "Checkpoint (signed note)",
      ["origem, tamanho N e raiz", "+ assinatura ECDSA do log", "+ prova de inclusão (API)"])
seta((66.4, 52), (74.6, 52), LA[1], 1.4, "promessa", dy=1.8)
seta((66.4, 32), (74.6, 32), VE[1], 1.4, "a cada lote", dy=1.8)

# registry
caixa(1, 18, 23, 15, CI, "Registry (GHCR)", ["imagem + .sig", "(assinatura, cert", "e SET no legado)"])
seta((12.5, 39.6), (12.5, 33.4), "#555", 1.2, "push", dx=3.2, dy=0)
seta((91.5, 60.6), (12.5, 60.6), LA[1], 1.2, None, ls=(0, (3, 2)), rad=0.12)
ax.text(52, 66.6, "o SET volta ao assinante e é gravado no registry junto com a assinatura", ha="center", fontsize=6.8, color=LA[1], style="italic")

# verificador
ax.add_patch(FancyBboxPatch((30, 1), 78, 16, boxstyle="round,pad=0.3,rounding_size=1.4", fc=AZ[0], ec=AZ[1], lw=1.6))
ax.text(69, 14.3, "Verificador (Kyverno, cosign ou o nosso)  —  chaves do log e da AC vêm do trusted_root.json",
        ha="center", fontsize=7.8, weight="bold", color=AZ[1])
checks = ["1. SET válido com a chave do log", "2. prova de inclusão leva à raiz do checkpoint",
          "3. checkpoint assinado pelo log", "4. integratedTime dentro da validade do certificado"]
for k, t in enumerate(checks):
    ax.text(33 + (k % 2) * 38, 9.6 - (k // 2) * 4.4, t, fontsize=7.3, color="#223", va="center")
seta((12.5, 17.6), (29.6, 9), "#555", 1.2, "pull", tpos=0.45, dy=2.4)
seta((91.5, 23.6), (91.5, 17.6), VE[1], 1.2)
# monitor
ax.text(49.5, 21.0, "monitores leem o log e alertam sobre assinaturas inesperadas", ha="center", fontsize=6.6,
        color="#666", style="italic")

import os
fig.savefig(os.path.join(os.path.dirname(os.path.abspath(__file__)), "fig-rekor-2.6.png"), bbox_inches="tight", pad_inches=0.08, facecolor="white")
