import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
from matplotlib.patches import FancyBboxPatch, FancyArrowPatch
plt.rcParams["font.family"] = "Arial"

CAM = ("#dbe7f6", "#2f5d8a")   # caminho recalculado
PRO = ("#fbe3c4", "#b0661a")   # hashes da prova
OUT = ("#f0f0f0", "#8a8a8a")   # não usados
DAD = ("#ffffff", "#555555")

fig, ax = plt.subplots(figsize=(8.2, 5.0), dpi=220)
ax.set_xlim(0, 100); ax.set_ylim(0, 62); ax.axis("off")

W, H = 17, 7.6


def no(x, y, nome, valor, cor, lw=1.3, w=W, h=H):
    ax.add_patch(FancyBboxPatch((x - w / 2, y - h / 2), w, h, boxstyle="round,pad=0.25,rounding_size=1.2",
                                fc=cor[0], ec=cor[1], lw=lw))
    ax.text(x, y + 1.5, nome, ha="center", va="center", fontsize=9.5, weight="bold", color="#222")
    ax.text(x, y - 1.6, valor, ha="center", va="center", fontsize=7.6, family="Consolas", color="#333")


def seta(x1, y1, x2, y2, cor="#9a9a9a", lw=1.1):
    ax.add_patch(FancyArrowPatch((x1, y1), (x2, y2), arrowstyle="-|>", mutation_scale=9, color=cor, lw=lw,
                                 shrinkA=0, shrinkB=0))


xs = [14, 38, 62, 86]
yL, yM, yR, yD = 22, 37, 52, 7
# dados
for i, x in enumerate(xs):
    w = 15
    ax.add_patch(FancyBboxPatch((x - w / 2, yD - 2.6), w, 5.2, boxstyle="round,pad=0.2,rounding_size=0.8",
                                fc=DAD[0], ec=DAD[1], lw=0.9, ls=(0, (3, 2))))
    ax.text(x, yD, f'd{i} = "entrada-{i}"', ha="center", va="center", fontsize=7.8, color="#333")
    c = CAM[1] if i == 2 else "#9a9a9a"
    seta(x, yD + 2.9, x, yL - H / 2 - 0.4, c, 1.6 if i == 2 else 1.0)
    if i != 2:
        ax.text(x + 1.2, (yD + yL) / 2 - 1.2, "leaf", fontsize=7, color="#777", style="italic")

folhas = [("h0", "475dca70c1ec1537", OUT), ("h1", "75f91a0150c85497", OUT),
          ("h2", "44fb37b9be8db9bd", CAM), ("h3", "4f18cddc25d2c1c1", PRO)]
for x, (n, v, c) in zip(xs, folhas):
    no(x, yL, n, v, c, lw=2.0 if c != OUT else 1.1)

mx = [26, 74]
no(mx[0], yM, "h01", "b2489a497d57cf8b", PRO, lw=2.0)
no(mx[1], yM, "h23", "af7a3e6321199414", CAM, lw=2.0)
no(50, yR, "raiz", "5d5487109c0530dd", CAM, lw=2.4, w=19)

# arestas
for x, m, cam in [(xs[0], mx[0], False), (xs[1], mx[0], False), (xs[2], mx[1], True), (xs[3], mx[1], True)]:
    seta(x, yL + H / 2 + 0.4, m + (x - m) * 0.35, yM - H / 2 - 0.4, CAM[1] if cam else "#9a9a9a", 1.6 if cam else 1.0)
for m, cam in [(mx[0], True), (mx[1], True)]:
    seta(m, yM + H / 2 + 0.4, 50 + (m - 50) * 0.3, yR - H / 2 - 0.4, CAM[1], 1.6)

# passos
def passo(x, y, k, txt, ha="left"):
    ax.text(x, y, k, ha="center", va="center", fontsize=8, weight="bold", color="white",
            bbox=dict(boxstyle="circle,pad=0.25", fc=CAM[1], ec="none"))
    ax.text(x + (2.2 if ha == "left" else -2.2), y, txt, ha=ha, va="center", fontsize=7.6, color=CAM[1])

passo(64.5, 14.5, "1", "x = leaf(d2)")
passo(84, 29.5, "2", "x = node(x, h3)")
passo(68, 45.8, "3", "x = node(h01, x)")

# checkpoint
ax.add_patch(FancyBboxPatch((66, 49), 32, 9, boxstyle="round,pad=0.3,rounding_size=1",
                            fc="#eef5ea", ec="#4a7a3a", lw=1.3))
ax.text(82, 55.6, "checkpoint assinado pelo log", ha="center", fontsize=8.2, weight="bold", color="#2f5a24")
ax.text(82, 52.6, "N = 4   raiz = 5d5487109c0530dd", ha="center", fontsize=7.4, family="Consolas", color="#333")
ax.text(82, 50.2, "+ assinatura ECDSA do Rekor", ha="center", fontsize=7.2, color="#555")
ax.text(62.9, yR + 0.3, "=?", fontsize=11, color="#4a7a3a", ha="center", va="center", weight="bold")

# legenda
lg = [(CAM, "caminho recalculado pelo verificador"), (PRO, "hashes enviados na prova [h3, h01]"),
      (OUT, "nós que o verificador não precisa")]
for k, (c, t) in enumerate(lg):
    y = 58.5 - k * 4.2
    ax.add_patch(FancyBboxPatch((2, y - 1.3), 3.6, 2.6, boxstyle="round,pad=0.1,rounding_size=0.5",
                                fc=c[0], ec=c[1], lw=1.4))
    ax.text(7, y, t, va="center", fontsize=7.6, color="#333")

import os
fig.savefig(os.path.join(os.path.dirname(os.path.abspath(__file__)), "fig-merkle-2.8.png"), bbox_inches="tight", pad_inches=0.08, facecolor="white")
