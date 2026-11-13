"""Stockage des trames CAN et des alertes dans SQLite."""
from __future__ import annotations

import sqlite3
from pathlib import Path
from typing import Iterable, Sequence

import pandas as pd

SCHEMA = """
CREATE TABLE IF NOT EXISTS frames (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    session     TEXT    NOT NULL,   -- jeu de données / capture (ex. train, test)
    ts          REAL    NOT NULL,   -- horodatage en secondes
    can_id      INTEGER NOT NULL,   -- identifiant d'arbitrage (11 bits)
    dlc         INTEGER NOT NULL,   -- nombre d'octets de données
    data        BLOB    NOT NULL,   -- payload brut (0 à 8 octets)
    label       INTEGER,            -- 0 = normal, 1 = attaque, NULL = inconnu
    attack_type TEXT                -- dos, fuzzing, replay, spoofing...
);
CREATE INDEX IF NOT EXISTS idx_frames_session_ts ON frames(session, ts);
CREATE INDEX IF NOT EXISTS idx_frames_can_id     ON frames(can_id);

CREATE TABLE IF NOT EXISTS alerts (
    id         INTEGER PRIMARY KEY AUTOINCREMENT,
    frame_id   INTEGER NOT NULL REFERENCES frames(id),
    model      TEXT    NOT NULL,
    score      REAL    NOT NULL,
    reason     TEXT,
    created_at TEXT DEFAULT CURRENT_TIMESTAMP
);
CREATE INDEX IF NOT EXISTS idx_alerts_frame ON alerts(frame_id);
"""

# (ts, can_id, dlc, data, label, attack_type)
FrameRow = tuple


class FrameDB:
    def __init__(self, path: str | Path):
        self.path = str(path)
        if self.path != ":memory:":
            Path(self.path).parent.mkdir(parents=True, exist_ok=True)
        self.conn = sqlite3.connect(self.path)
        self.conn.executescript(SCHEMA)

    def close(self) -> None:
        self.conn.close()

    def __enter__(self) -> "FrameDB":
        return self

    def __exit__(self, *exc) -> None:
        self.close()

    # --- trames -----------------------------------------------------------
    def clear_session(self, session: str) -> None:
        self.conn.execute(
            "DELETE FROM alerts WHERE frame_id IN (SELECT id FROM frames WHERE session = ?)",
            (session,),
        )
        self.conn.execute("DELETE FROM frames WHERE session = ?", (session,))
        self.conn.commit()

    def insert_frames(self, session: str, frames: Iterable[FrameRow]) -> int:
        rows = [
            (session, float(ts), int(cid), int(dlc), bytes(data),
             None if label is None else int(label), atype)
            for ts, cid, dlc, data, label, atype in frames
        ]
        self.conn.executemany(
            "INSERT INTO frames(session, ts, can_id, dlc, data, label, attack_type) "
            "VALUES (?,?,?,?,?,?,?)",
            rows,
        )
        self.conn.commit()
        return len(rows)

    def load_frames(self, sessions: Sequence[str] | None = None) -> pd.DataFrame:
        query = "SELECT id, session, ts, can_id, dlc, data, label, attack_type FROM frames"
        params: list = []
        if sessions:
            query += " WHERE session IN (%s)" % ",".join("?" * len(sessions))
            params = list(sessions)
        query += " ORDER BY session, ts, id"
        df = pd.read_sql_query(query, self.conn, params=params)
        df["label"] = pd.to_numeric(df["label"])
        return df

    def stats(self) -> pd.DataFrame:
        return pd.read_sql_query(
            "SELECT session, COUNT(*) AS trames, "
            "SUM(CASE WHEN label = 1 THEN 1 ELSE 0 END) AS trames_attaque, "
            "COUNT(DISTINCT can_id) AS ids, "
            "ROUND(MAX(ts) - MIN(ts), 1) AS duree_s "
            "FROM frames GROUP BY session",
            self.conn,
        )

    # --- alertes ----------------------------------------------------------
    def clear_alerts(self, session: str, model: str) -> None:
        self.conn.execute(
            "DELETE FROM alerts WHERE model = ? AND frame_id IN "
            "(SELECT id FROM frames WHERE session = ?)",
            (model, session),
        )
        self.conn.commit()

    def insert_alerts(self, frame_ids, model: str, scores, reasons) -> int:
        rows = [(int(f), model, float(s), r) for f, s, r in zip(frame_ids, scores, reasons)]
        self.conn.executemany(
            "INSERT INTO alerts(frame_id, model, score, reason) VALUES (?,?,?,?)", rows
        )
        self.conn.commit()
        return len(rows)
