"""Extraction de caractéristiques par trame (timing, charge du bus, payload)."""
from __future__ import annotations

from dataclasses import dataclass, field

import numpy as np
import pandas as pd

FEATURES = [
    "dt_any_log",   # log10 du temps depuis la trame précédente (tous ID)
    "dt_dev",       # écart de cadence du même ID : |dt - période| / dispersion normale
    "rate_50ms",    # trames/s sur les 50 dernières ms (charge du bus)
    "win_entropy",  # entropie des ID sur une fenêtre de 64 trames
    "ham_prev",     # distance de Hamming avec le payload précédent du même ID
    "max_byte_z",   # écart maximal (z-score) d'un octet par rapport au profil normal
]
WINDOW_FRAMES = 64
RATE_WINDOW_S = 0.05
Z_CLIP = 10.0
DT_DEV_CLIP = 50.0
POPCOUNT = np.array([bin(i).count("1") for i in range(256)], dtype=np.uint8)


def payload_matrix(data) -> np.ndarray:
    """Convertit une série de payloads (bytes) en matrice (n, 8) uint8, complétée par des 0."""
    raw = b"".join(bytes(d).ljust(8, b"\x00")[:8] for d in data)
    if not raw:
        return np.zeros((0, 8), dtype=np.uint8)
    return np.frombuffer(raw, dtype=np.uint8).reshape(-1, 8)


def _per_id_deltas(ts, ids, pay):
    """Delta de temps et distance de Hamming avec la trame précédente de même ID."""
    n = len(ts)
    order = np.argsort(ids, kind="stable")  # stable : conserve l'ordre temporel par ID
    ids_s, ts_s, pay_s = ids[order], ts[order], pay[order]
    same = np.zeros(n, bool)
    same[1:] = ids_s[1:] == ids_s[:-1]
    dt_s = np.full(n, np.nan)
    dt_s[1:] = np.diff(ts_s)
    dt_s[~same] = np.nan
    ham_s = np.zeros(n)
    ham_s[1:] = POPCOUNT[pay_s[1:] ^ pay_s[:-1]].sum(axis=1)
    ham_s[~same] = 0.0
    dt, ham = np.empty(n), np.empty(n)
    dt[order], ham[order] = dt_s, ham_s
    return dt, ham


def _entropy(s: pd.Series) -> float:
    p = s.value_counts(normalize=True).to_numpy()
    return float(-(p * np.log2(p)).sum())


@dataclass
class Profile:
    """Profil du trafic normal appris à l'entraînement."""

    period: dict = field(default_factory=dict)  # ID -> période médiane (s)
    dt_scale: dict = field(default_factory=dict)  # ID -> dispersion robuste de la période (s)
    dlcs: dict = field(default_factory=dict)    # ID -> {DLC observés}
    mean: dict = field(default_factory=dict)    # ID -> moyenne par octet
    std: dict = field(default_factory=dict)     # ID -> écart-type par octet

    @classmethod
    def fit(cls, df: pd.DataFrame) -> "Profile":
        prof = cls()
        all_ids, all_dt = [], []
        for _, g in df.groupby("session", sort=False):
            g = g.sort_values("ts", kind="stable")
            ids = g["can_id"].to_numpy(int)
            dt, _ = _per_id_deltas(g["ts"].to_numpy(float), ids, payload_matrix(g["data"]))
            all_ids.append(ids)
            all_dt.append(dt)
        ids_cat, dt_cat = np.concatenate(all_ids), np.concatenate(all_dt)
        s_dt = pd.Series(dt_cat)
        periods = s_dt.groupby(ids_cat).median()
        dev = (s_dt - pd.Series(ids_cat).map(periods).to_numpy(float)).abs()
        mad = dev.groupby(ids_cat).median() * 1.4826  # écart-type robuste
        for cid, v in periods.items():
            if np.isfinite(v) and v > 0:
                prof.period[int(cid)] = float(v)
                prof.dt_scale[int(cid)] = float(max(mad.get(cid, 0.0), 0.005 * v, 1e-5))

        pay = payload_matrix(df["data"]).astype(float)
        ids = df["can_id"].to_numpy(int)
        dlc = df["dlc"].to_numpy(int)
        for cid in np.unique(ids):
            m = ids == cid
            prof.mean[int(cid)] = pay[m].mean(axis=0)
            prof.std[int(cid)] = np.maximum(pay[m].std(axis=0), 0.5)
            prof.dlcs[int(cid)] = {int(x) for x in np.unique(dlc[m])}
        return prof


def _session_features(g: pd.DataFrame, prof: Profile) -> pd.DataFrame:
    n = len(g)
    ts = g["ts"].to_numpy(float)
    ids = g["can_id"].to_numpy(int)
    pay = payload_matrix(g["data"])

    dt_any = np.zeros(n)
    if n > 1:
        dt_any[1:] = np.diff(ts)
        dt_any[0] = dt_any[1]
    dt_any_log = np.log10(np.clip(dt_any, 1e-6, None))

    dt_id, ham = _per_id_deltas(ts, ids, pay)
    per = pd.Series(ids).map(prof.period).to_numpy(float)
    scale = pd.Series(ids).map(prof.dt_scale).to_numpy(float)
    dt_dev = np.clip(np.nan_to_num(np.abs(dt_id - per) / scale, nan=0.0), 0.0, DT_DEV_CLIP)

    start = np.searchsorted(ts, ts - RATE_WINDOW_S, side="left")
    rate = (np.arange(n) - start + 1) / RATE_WINDOW_S

    win = np.arange(n) // WINDOW_FRAMES
    ent = pd.Series(ids).groupby(win).transform(_entropy).to_numpy(float)

    z = np.full(n, Z_CLIP)  # ID inconnu -> z maximal
    payf = pay.astype(float)
    for cid in np.unique(ids):
        if int(cid) in prof.mean:
            m = ids == cid
            zz = np.abs(payf[m] - prof.mean[int(cid)]) / prof.std[int(cid)]
            z[m] = np.minimum(zz.max(axis=1), Z_CLIP)

    return pd.DataFrame(
        {
            "dt_any_log": dt_any_log,
            "dt_dev": dt_dev,
            "rate_50ms": rate,
            "win_entropy": ent,
            "ham_prev": ham,
            "max_byte_z": z,
        },
        index=g.index,
    )[FEATURES]


def compute_features(df: pd.DataFrame, prof: Profile) -> pd.DataFrame:
    """Calcule les caractéristiques session par session ; l'index de `df` est conservé."""
    parts = []
    for _, g in df.groupby("session", sort=False):
        parts.append(_session_features(g.sort_values("ts", kind="stable"), prof))
    return pd.concat(parts).loc[df.index]
