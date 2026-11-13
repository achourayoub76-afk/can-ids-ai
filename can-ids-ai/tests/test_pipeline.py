import pytest

from canids.db import FrameDB
from canids.evaluate import evaluate
from canids.models import Detector
from canids.simulator import ATTACKS, simulate_session


@pytest.fixture(scope="module")
def db_path(tmp_path_factory):
    path = tmp_path_factory.mktemp("db") / "can.db"
    with FrameDB(path) as db:
        db.insert_frames("train", simulate_session(30, (), seed=1, attack_len=2))
        db.insert_frames("labeled", simulate_session(30, ATTACKS, seed=2, attack_len=2))
        db.insert_frames("test", simulate_session(30, ATTACKS, seed=3, attack_len=2))
    return path


def _run(db_path, kind, sessions):
    with FrameDB(db_path) as db:
        det = Detector.fit(db.load_frames(sessions), kind)
        test = db.load_frames(["test"])
    overall, per_type = evaluate(test, det.predict(test))
    return overall, per_type


def test_iforest_detects_attacks_with_few_false_positives(db_path):
    overall, per_type = _run(db_path, "iforest", ["train"])
    hybrid = overall.loc["Hybride"]
    assert hybrid["rappel"] > 0.9
    assert hybrid["fpr_hors_attaque"] < 0.02
    assert set(per_type.index) == set(ATTACKS)


def test_random_forest_supervised(db_path):
    overall, _ = _run(db_path, "rf", ["train", "labeled"])
    assert overall.loc["Hybride", "f1"] > 0.9


def test_rf_requires_labels(db_path):
    with FrameDB(db_path) as db:
        with pytest.raises(ValueError):
            Detector.fit(db.load_frames(["train"]), "rf")
