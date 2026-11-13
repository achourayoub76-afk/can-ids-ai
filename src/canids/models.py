"""Détecteur hybride : règles (ID/DLC inconnus) + modèle ML.

- iforest : Isolation Forest, NON supervisé, entraîné uniquement sur du trafic normal.
- rf      : Random Forest, supervisé, nécessite des trames étiquetées (normal/attaque).
"""
from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

import joblib
import numpy as np
import pandas as pd
from sklearn.ensemble import IsolationForest, RandomForestClassifier

from .features import Profile, compute_features

KINDS = ("iforest", "rf")


@dataclass
class Detector:
    kind: str
    profile: Profile
    model: object
    threshold: float

    @classmethod
    def fit(cls, df: pd.DataFrame, kind: str = "iforest", quantile: float = 0.995, seed: int = 0) -> "Detector":
        if kind not in KINDS:
            raise ValueError(f"Modèle inconnu : {kind} (choix : {KINDS})")
        normal = df[df["label"].isna() | (df["label"] == 0)]
        if normal.empty:
            raise ValueError("Aucune trame normale pour entraîner le profil.")
        profile = Profile.fit(normal)

        if kind == "iforest":
            X = compute_features(normal, profile).to_numpy()
            model = IsolationForest(n_estimators=200, random_state=seed, n_jobs=-1).fit(X)
            threshold = float(np.quantile(-model.score_samples(X), quantile))
        else:
            labeled = df[df["label"].notna()]
            if labeled["label"].nunique() < 2:
                raise ValueError("Le modèle rf exige des trames normales ET des attaques étiquetées.")
            X = compute_features(labeled, profile).to_numpy()
            model = RandomForestClassifier(
                n_estimators=150, min_samples_leaf=2, class_weight="balanced",
                n_jobs=-1, random_state=seed,
            ).fit(X, labeled["label"].astype(int).to_numpy())
            threshold = 0.5
        return cls(kind, profile, model, threshold)

    def predict(self, df: pd.DataFrame) -> pd.DataFrame:
        X = compute_features(df, self.profile).to_numpy()
        if self.kind == "iforest":
            score = -self.model.score_samples(X)
        else:
            score = self.model.predict_proba(X)[:, 1]
        ml = score > self.threshold

        ids = df["can_id"].to_numpy(int)
        dlc = df["dlc"].to_numpy(int)
        unknown = ~np.isin(ids, np.fromiter(self.profile.dlcs.keys(), dtype=int))
        bad_dlc = np.array(
            [(c in self.profile.dlcs) and (d not in self.profile.dlcs[c]) for c, d in zip(ids, dlc)],
            dtype=bool,
        )
        rule = unknown | bad_dlc
        reason = ["+".join(n for n, f in zip(("id_inconnu", "dlc_inattendu", "ml"), flags) if f)
                  for flags in zip(unknown, bad_dlc, ml)]
        return pd.DataFrame(
            {"score": score, "ml_flag": ml, "rule_flag": rule, "anomaly": ml | rule, "reason": reason},
            index=df.index,
        )

    def save(self, path: str | Path) -> None:
        Path(path).parent.mkdir(parents=True, exist_ok=True)
        joblib.dump(self, path)

    @staticmethod
    def load(path: str | Path) -> "Detector":
        return joblib.load(path)
