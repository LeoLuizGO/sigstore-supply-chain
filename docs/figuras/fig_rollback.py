"""Figura do cenário de rollback (Seção 3.5, E2.5): assinatura não vence, atestado de varredura vence."""
import os
import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
from matplotlib.patches import FancyBboxPatch, Rectangle, Polygon
plt.rcParams["font.family"] = "Arial"

AZ = "#2f5d8a"; AZc = "#dbe7f6"
VE = "#4a7a3a"; VEc = "#cfe5c6"
VM = "#b03a2e"; VMc = "#f4d3cf"
LA = "#b0661a"; LAc = "#fbe3c4"
CI = "#666"

fig, ax = plt.subplots(figsize=(9.0, 5.0), dpi=220)
ax.set_xlim(-20, 104); ax.set_ylim(0, 62); ax.axis("off")

# eixo do tempo
ax.annotate("", xy=(101, 18.5), xytext=(0, 18.5), arrowprops=dict(arrowstyle="-|>", color="#444", lw=1.2))
ax.text(101, 15.6, "tempo", ha="right", fontsize=7.5, color="#444", style="italic")
for x, t in [(5, "dia 0"), (25, "dia 1"), (45, "dia 2"), (65, "dia 3"), (85, "dia 4")]:
    ax.plot([x, x], [17.8, 19.2], color="#444", lw=1)
    ax.text(x, 15.6, t, ha="center", fontsize=7, color="#555")


def barra(x0, x1, y, fc, ec, txt=None, tx=None, h=3.8, tc="#222", ha="center"):
    ax.add_patch(Rectangle((x0, y - h / 2), x1 - x0, h, fc=fc, ec=ec, lw=1.0))
    if txt:
        ax.text(tx if tx is not None else (x0 + x1) / 2, y, txt, ha=ha, va="center", fontsize=6.9, color=tc)


def losango(x, y, c, s=1.5):
    ax.add_patch(Polygon([(x, y + s), (x + s, y), (x, y - s), (x - s, y)], closed=True, fc=c, ec="white", lw=0.6, zorder=5))


def rotulo(y, nome, digest, nota, cor):
    ax.text(-19, y + 2.6, nome, fontsize=8.6, weight="bold", color="#222", va="center")
    ax.text(-19, y - 0.4, digest, fontsize=7, family="Consolas", color="#555", va="center")
    ax.text(-19, y - 3.2, nota, fontsize=6.8, color=cor, va="center")


xa = 75  # momento do ataque

# --- v1 (antiga) ---
yv1s, yv1a = 50, 44.5
rotulo((yv1s + yv1a) / 2, "v1 (antiga)", "sha256:dc1e…", "tem CVE crítica", VM)
barra(5, 100, yv1s, AZc, AZ, "assinatura válida para sempre (integratedTime dentro da validade do certificado)", tx=6.5, ha="left")
barra(5, 25, yv1a, VEc, VE, "varredura em dia", tx=7.5, ha="left")
barra(25, 100, yv1a, VMc, VM, "atestado vencido: ninguém mais reescaneia a v1", tx=27, ha="left", tc=VM)
losango(5, yv1a, VE)
ax.annotate("", xy=(25, 39.6), xytext=(5, 39.6), arrowprops=dict(arrowstyle="<->", color=VE, lw=1))
ax.text(26.5, 39.6, "janela: 24 h (10 min no E2)", va="center", fontsize=6.7, color=VE)

# --- v2 (atual) ---
yv2s, yv2a = 32, 26.5
rotulo((yv2s + yv2a) / 2, "v2 (atual, main)", "sha256:c6d2…", "CVE corrigida", VE)
barra(15, 100, yv2s, AZc, AZ, "assinatura válida para sempre", tx=16.5, ha="left")
barra(15, 100, yv2a, VEc, VE)
for x in [15, 25, 45, 65, 85]:
    losango(x, yv2a, VE)
losango(16, 22.0, VE, 1.1)
ax.text(18, 22.0, "varredura assinada; o reescanear.yml renova o atestado da main todo dia (cosign attest --replace)",
        fontsize=6.6, color=VE, va="center")
ax.text(15, 35.6, "v2 publicada", fontsize=6.6, color=CI, va="center")

# ataque
ax.plot([xa, xa], [24.4, 55.5], color=VM, lw=1.5, ls=(0, (4, 2)))
ax.text(xa, 57.6, "atacante faz deploy da v1 (rollback)", ha="center", fontsize=7.8, color=VM, weight="bold")
ax.plot([xa], [yv1a], marker="o", ms=6.5, mfc="white", mec=VM, mew=1.7, zorder=6)
ax.plot([xa], [yv1s], marker="o", ms=6.5, mfc="white", mec=AZ, mew=1.7, zorder=6)


def caixa(x, y, w, h, fc, ec, titulo, linhas, tc):
    ax.add_patch(FancyBboxPatch((x, y), w, h, boxstyle="round,pad=0.3,rounding_size=1", fc=fc, ec=ec, lw=1.3))
    ax.text(x + w / 2, y + h - 2.1, titulo, ha="center", va="center", fontsize=7.8, weight="bold", color=tc)
    for k, l in enumerate(linhas):
        ax.text(x + w / 2, y + h - 5.0 - k * 2.6, l, ha="center", va="center", fontsize=6.9, color="#333")


caixa(2, 1, 44, 10.5, LAc, LA, "Só as políticas 01 e 02: v1 ADMITIDA",
      ["a assinatura é legítima e não vence;", "a versão vulnerável volta a rodar"], LA)
caixa(50, 1, 50, 10.5, AZc, AZ, "Com a política 03: v1 RECUSADA",
      ["\"varredura vencida\": scanFinishedOn fora da janela;", "a v2, reescaneada todo dia, continua sendo admitida"], AZ)

fig.savefig(os.path.join(os.path.dirname(os.path.abspath(__file__)), "fig-rollback-3.5.png"),
            bbox_inches="tight", pad_inches=0.08, facecolor="white")
