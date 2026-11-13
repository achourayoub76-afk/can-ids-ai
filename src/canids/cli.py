"""Interface en ligne de commande : python -m canids <commande> ou `canids <commande>`."""
from __future__ import annotations

import argparse

import pandas as pd

from .db import FrameDB
from .evaluate import evaluate
from .importers import PARSERS
from .models import KINDS, Detector
from .simulator import ATTACKS, simulate_session

pd.set_option("display.width", 140)


def cmd_simulate(a) -> None:
    attacks = tuple(a.attacks)
    plan = [("train", (), a.seed), ("labeled", attacks, a.seed + 1), ("test", attacks, a.seed + 2)]
    with FrameDB(a.db) as db:
        for session, atk, seed in plan:
            frames = simulate_session(a.duration, atk, seed, a.attack_len)
            db.clear_session(session)
            n = db.insert_frames(session, frames)
            print(f"[{session}] {n} trames insérées (attaques : {', '.join(atk) or 'aucune'})")


def cmd_import(a) -> None:
    kwargs = {"attack_type": a.attack_type} if a.format == "hcrl" else {}
    with FrameDB(a.db) as db:
        db.clear_session(a.session)
        n = db.insert_frames(a.session, PARSERS[a.format](a.file, **kwargs))
        print(f"[{a.session}] {n} trames importées depuis {a.file}")


def cmd_stats(a) -> None:
    with FrameDB(a.db) as db:
        print(db.stats().to_string(index=False))


def cmd_train(a) -> None:
    sessions = a.sessions.split(",") if a.sessions else (["train"] if a.model == "iforest" else ["train", "labeled"])
    with FrameDB(a.db) as db:
        df = db.load_frames(sessions)
    print(f"Entraînement {a.model} sur {sessions} ({len(df)} trames)...")
    det = Detector.fit(df, a.model, quantile=a.quantile, seed=a.seed)
    det.save(a.out)
    print(f"Modèle enregistré : {a.out} (seuil = {det.threshold:.4f})")


def cmd_evaluate(a) -> None:
    det = Detector.load(a.model)
    with FrameDB(a.db) as db:
        df = db.load_frames([a.session])
    res = det.predict(df)
    overall, per_type = evaluate(df, res)
    print("\n== Résultats globaux ==")
    print(overall.round(4).to_string())
    print("\n== Rappel par type d'attaque ==")
    print(per_type.round(3).to_string())
    if a.plot:
        from .report import plot_timeline

        plot_timeline(df, res, det.threshold, a.plot)
        print(f"\nGraphique : {a.plot}")


def cmd_detect(a) -> None:
    det = Detector.load(a.model)
    with FrameDB(a.db) as db:
        df = db.load_frames([a.session])
        res = det.predict(df)
        flagged = res[res["anomaly"]]
        db.clear_alerts(a.session, det.kind)
        db.insert_alerts(df.loc[flagged.index, "id"], det.kind, flagged["score"], flagged["reason"])
    print(f"{len(flagged)} alertes sur {len(df)} trames ({100 * len(flagged) / max(len(df), 1):.2f} %)")
    print(flagged["reason"].value_counts().head(8).to_string())
    print("\nRequête SQL : SELECT f.ts, f.can_id, a.score, a.reason FROM alerts a JOIN frames f ON f.id=a.frame_id;")


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="canids", description="Détection d'anomalies sur le bus CAN par IA")
    sub = p.add_subparsers(dest="cmd", required=True)

    def add(name, fn, help_):
        sp = sub.add_parser(name, help=help_)
        sp.add_argument("--db", default="data/can.db", help="fichier SQLite (défaut : data/can.db)")
        sp.set_defaults(func=fn)
        return sp

    s = add("simulate", cmd_simulate, "génère des sessions train/labeled/test synthétiques")
    s.add_argument("--duration", type=float, default=120.0)
    s.add_argument("--attack-len", type=float, default=5.0)
    s.add_argument("--attacks", nargs="*", default=list(ATTACKS), choices=ATTACKS)
    s.add_argument("--seed", type=int, default=42)

    s = add("import", cmd_import, "importe une capture réelle (candump / hcrl)")
    s.add_argument("--file", required=True)
    s.add_argument("--format", choices=list(PARSERS), required=True)
    s.add_argument("--session", required=True)
    s.add_argument("--attack-type", default="attack")

    add("stats", cmd_stats, "résumé de la base")

    s = add("train", cmd_train, "entraîne un détecteur")
    s.add_argument("--model", choices=KINDS, default="iforest")
    s.add_argument("--sessions", help="sessions séparées par des virgules")
    s.add_argument("--quantile", type=float, default=0.995, help="quantile du seuil (iforest)")
    s.add_argument("--seed", type=int, default=0)
    s.add_argument("--out", default="models/detector.joblib")

    s = add("evaluate", cmd_evaluate, "évalue un modèle sur une session étiquetée")
    s.add_argument("--model", default="models/detector.joblib")
    s.add_argument("--session", default="test")
    s.add_argument("--plot", help="chemin du graphique PNG")

    s = add("detect", cmd_detect, "détecte et enregistre les alertes dans la base")
    s.add_argument("--model", default="models/detector.joblib")
    s.add_argument("--session", default="test")
    return p


def main(argv=None) -> None:
    args = build_parser().parse_args(argv)
    args.func(args)


if __name__ == "__main__":
    main()
