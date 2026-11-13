from canids.db import FrameDB
from canids.importers import parse_candump, parse_hcrl_csv


def test_db_roundtrip():
    with FrameDB(":memory:") as db:
        db.insert_frames("s", [(0.1, 0x123, 3, b"\x01\x02\x03", 0, "normal"), (0.2, 0x7FF, 1, b"\xff", None, None)])
        df = db.load_frames(["s"])
        assert list(df["can_id"]) == [0x123, 0x7FF]
        assert df["data"].iloc[0] == b"\x01\x02\x03"
        assert db.stats()["trames"].iloc[0] == 2


def test_parse_candump(tmp_path):
    f = tmp_path / "a.log"
    f.write_text("(1436509052.249713) can0 044#2A366C2BBA\n(1436509052.250000) can0 7DF#\nbruit\n")
    frames = list(parse_candump(f))
    assert len(frames) == 2
    assert frames[0][1] == 0x044 and frames[0][3] == bytes.fromhex("2A366C2BBA")
    assert frames[1][2] == 0


def test_parse_hcrl(tmp_path):
    f = tmp_path / "a.csv"
    f.write_text("Timestamp,ID,DLC,D0,D1,Flag\n1478198376.389427,0316,2,05,21,R\n1478198376.390000,0000,2,00,00,T\n")
    frames = list(parse_hcrl_csv(f, attack_type="dos"))
    assert [fr[4] for fr in frames] == [0, 1]
    assert frames[1][5] == "dos"
