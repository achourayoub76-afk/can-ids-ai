"""Graphique : score d'anomalie dans le temps, avec les attaques réelles en surbrillance."""
from __future__ import annotations

from pathlib import Path

import matplotlib

matplotlib.use("Agg")
import matplotlib.pyplot as plt  # noqa: E402
import numpy as np  # noqa: E402


def plot_timeline(df, res, threshold: float, path: str | Path) -> None:
    Path(path).parent.mkdir(parents=True, exist_ok=True)
    fig, ax = plt.subplots(figsize=(12, 4))
    colors = np.where(res["anomaly"].to_numpy(), "tab:red", "tab:blue")
    ax.scatter(df["ts"], res["score"], s=1, alpha=0.4, c=colors)
    ax.axhline(threshold, ls="--", color="k", lw=1, label="seuil")
    ymax = float(res["score"].max())
    for name, g in df[df["label"] == 1].groupby("attack_type"):
        ax.axvspan(g["ts"].min(), g["ts"].max(), color="orange", alpha=0.15)
        ax.text(g["ts"].min(), ymax, name, va="bottom", fontsize=9)
    ax.set_xlabel("temps (s)")
    ax.set_ylabel("score d'anomalie")
    ax.set_title("Score d'anomalie par trame (rouge = alerte, zone orange = attaque réelle)")
    ax.legend(loc="upper right")
    fig.tight_layout()
    fig.savefig(path, dpi=130)
    plt.close(fig)
