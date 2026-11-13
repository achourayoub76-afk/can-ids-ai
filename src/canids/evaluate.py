"""Métriques : global et par type d'attaque.

Les faux positifs sont séparés en deux :
- hors attaque : trames normales loin de toute attaque (le « vrai » taux de fausses alarmes) ;
- pendant attaque : trames légitimes entourant des trames injectées. Leur timing est réellement
  perturbé (la trame précédente du même ID est une trame injectée) : à l'échelle de la trame,
  elles sont indiscernables d'une anomalie, c'est une limite inhérente à l'évaluation par trame.
"""
from __future__ import annotations

import numpy as np
import pandas as pd
from sklearn.metrics import precision_recall_fscore_support


def evaluate(df: pd.DataFrame, res: pd.DataFrame) -> tuple[pd.DataFrame, pd.DataFrame]:
    mask = df["label"].notna().to_numpy()
    if not mask.any():
        raise ValueError("Pas de labels dans cette session : évaluation impossible.")

    atk = df[df["label"] == 1]
    in_window = np.zeros(len(df), bool)
    for _, g in atk.groupby("attack_type"):
        in_window |= ((df["ts"] >= g["ts"].min()) & (df["ts"] <= g["ts"].max())).to_numpy()

    y = df.loc[mask, "label"].astype(int).to_numpy()
    win = in_window[mask]
    preds = {"ML seul": res["ml_flag"], "Règles seules": res["rule_flag"], "Hybride": res["anomaly"]}

    rows = []
    for name, p in preds.items():
        pv = p.to_numpy()[mask].astype(int)
        pr, rc, f1, _ = precision_recall_fscore_support(y, pv, average="binary", zero_division=0)
        out_n = (y == 0) & ~win
        in_n = (y == 0) & win
        rows.append({
            "détecteur": name, "précision": pr, "rappel": rc, "f1": f1,
            "fpr_hors_attaque": (pv[out_n] == 1).mean() if out_n.any() else 0.0,
            "fpr_pendant_attaque": (pv[in_n] == 1).mean() if in_n.any() else 0.0,
        })
    overall = pd.DataFrame(rows).set_index("détecteur")

    per_type = {}
    for t, idx in atk.groupby("attack_type").groups.items():
        row = {"trames": len(idx)}
        row.update({f"rappel {n}": float(p.loc[idx].mean()) for n, p in preds.items()})
        per_type[t] = row
    return overall, pd.DataFrame(per_type).T
