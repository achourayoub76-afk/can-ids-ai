"""Import de captures CAN réelles (candump, dataset Car-Hacking HCRL)."""
from __future__ import annotations

import re
from pathlib import Path
from typing import Iterator

# (ts, can_id, dlc, data, label, attack_type)
Frame = tuple

_CANDUMP = re.compile(
    r"^\((?P<ts>\d+\.\d+)\)\s+\S+\s+(?P<id>[0-9A-Fa-f]+)#(?P<data>[0-9A-Fa-f]*)\s*$"
)


def parse_candump(path: str | Path) -> Iterator[Frame]:
    """Format `candump -L` : (1436509052.249713) can0 044#2A366C2BBA.

    Les trames sans label (label=None) sont traitées comme « supposées normales »
    pour l'entraînement non supervisé.
    """
    with open(path, encoding="utf-8", errors="ignore") as fh:
        for line in fh:
            m = _CANDUMP.match(line.strip())
            if not m or len(m["data"]) % 2:
                continue
            data = bytes.fromhex(m["data"])
            yield float(m["ts"]), int(m["id"], 16), len(data), data, None, None


def parse_hcrl_csv(path: str | Path, attack_type: str = "attack") -> Iterator[Frame]:
    """CSV du dataset Car-Hacking (HCRL) : Timestamp,ID,DLC,DATA[0..7],Flag (R/T).

    R = trame normale, T = trame injectée. Adaptez si votre version diffère.
    """
    with open(path, encoding="utf-8", errors="ignore") as fh:
        for line in fh:
            parts = [p.strip() for p in line.strip().split(",")]
            if len(parts) < 4:
                continue
            try:
                ts = float(parts[0])
                cid = int(parts[1], 16)
                dlc = int(parts[2])
                data = bytes(int(x, 16) for x in parts[3 : 3 + dlc])
            except ValueError:
                continue  # en-tête ou ligne corrompue
            flag = parts[-1].upper()
            if flag == "T":
                yield ts, cid, len(data), data, 1, attack_type
            else:
                yield ts, cid, len(data), data, 0, "normal"


PARSERS = {"candump": parse_candump, "hcrl": parse_hcrl_csv}
