"""Simulateur de trafic CAN (ECU fictifs) avec injection d'attaques étiquetées.

Les données sont synthétiques : elles servent à tester la chaîne de bout en bout.
Pour des résultats réalistes, utilisez des captures réelles (voir data/README.md).
"""
from __future__ import annotations

import math
from dataclasses import dataclass
from typing import Callable

import numpy as np

ATTACKS = ("dos", "fuzzing", "replay", "spoofing")

# (ts, can_id, dlc, data, label, attack_type)
Frame = tuple


def _u16(v: float) -> int:
    return int(min(max(v, 0), 65535))


def _rpm(t, k, rng):
    v = _u16(2000 + 1200 * math.sin(2 * math.pi * t / 30) + rng.normal(0, 15))
    return bytes([v >> 8, v & 0xFF, 0x00, 0x1F, k % 16, 0, 0, 0])


def _speed(t, k, rng):
    v = _u16(900 + 500 * math.sin(2 * math.pi * t / 45 + 1) + rng.normal(0, 5))
    return bytes([v >> 8, v & 0xFF, (k * 3) % 256, 0, 0, 0, 0, k % 256])


def _steering(t, k, rng):
    v = _u16(32768 + 9000 * math.sin(2 * math.pi * t / 12) + rng.normal(0, 40))
    return bytes([v >> 8, v & 0xFF, 0, 0, 0, 0, 0, k % 16])


def _brake(t, k, rng):
    pressed = 1 if math.sin(2 * math.pi * t / 20) > 0.85 else 0
    return bytes([pressed, 0x40 if pressed else 0x00, k % 16, 0, 0, 0, 0, 0])


def _throttle(t, k, rng):
    v = int(min(max(40 + 35 * math.sin(2 * math.pi * t / 25 + 2) + rng.normal(0, 1), 0), 100))
    return bytes([v, 0x00, 0x00, k % 16, 0, 0, 0, 0])


def _status(t, k, rng):
    return bytes([0x02, 0x10, 0x00, 0x00, 0x00, 0x00, 0x00, k % 256])


def _temp(t, k, rng):
    v = int(min(max(85 + 4 * math.sin(2 * math.pi * t / 90) + rng.normal(0, 0.3), 0), 255))
    return bytes([v, 0x55, 0, 0, 0, 0, 0, 0])


def _lights(t, k, rng):
    return bytes([0x01 if (int(t) // 20) % 2 == 0 else 0x03, 0, 0, 0, 0, 0, 0, 0])


def _doors(t, k, rng):
    return bytes([0x00, 0x00, 0, 0, 0, 0, 0, 0])


@dataclass(frozen=True)
class ECU:
    can_id: int
    period: float
    dlc: int
    gen: Callable


ECUS = [
    ECU(0x0C0, 0.010, 8, _rpm),
    ECU(0x1A0, 0.020, 8, _speed),
    ECU(0x2B0, 0.010, 8, _steering),
    ECU(0x3C0, 0.020, 4, _brake),
    ECU(0x244, 0.020, 6, _throttle),
    ECU(0x316, 0.050, 8, _status),
    ECU(0x440, 0.100, 8, _temp),
    ECU(0x5E0, 0.100, 3, _lights),
    ECU(0x6F0, 0.200, 2, _doors),
]


def generate_normal(duration: float, rng: np.random.Generator) -> list[Frame]:
    frames: list[Frame] = []
    for ecu in ECUS:
        phase = rng.uniform(0, ecu.period)
        for k in range(int(duration / ecu.period)):
            t = max(phase + k * ecu.period + rng.normal(0, 0.02 * ecu.period), 0.0)
            data = ecu.gen(t, k, rng)[: ecu.dlc]
            frames.append((t, ecu.can_id, ecu.dlc, data, 0, "normal"))
    return frames


# --- attaques ---------------------------------------------------------------
def attack_dos(start: float, length: float, rng) -> list[Frame]:
    """Déni de service : flot de trames à l'ID 0x000 (priorité maximale)."""
    n = int(length / 0.0005)
    return [(start + i * 0.0005, 0x000, 8, bytes(8), 1, "dos") for i in range(n)]


def attack_fuzzing(start: float, length: float, rng) -> list[Frame]:
    """Fuzzing : ID et payload aléatoires."""
    n = int(length / 0.002)
    ids = rng.integers(0, 0x800, n)
    return [
        (start + i * 0.002, int(ids[i]), 8, bytes(rng.integers(0, 256, 8, dtype=np.uint8)), 1, "fuzzing")
        for i in range(n)
    ]


def attack_replay(normal: list[Frame], start: float, length: float, src_start: float) -> list[Frame]:
    """Rejeu : ré-émission de trames légitimes capturées plus tôt."""
    shift = start - src_start
    return [
        (ts + shift, cid, dlc, data, 1, "replay")
        for ts, cid, dlc, data, *_ in normal
        if src_start <= ts < src_start + length
    ]


def attack_spoofing(start: float, length: float, rng, target: int = 0x0C0, period: float = 0.010) -> list[Frame]:
    """Usurpation : ID légitime (régime moteur) avec une valeur forcée à 7000 tr/min."""
    n = int(length / period)
    return [
        (start + 0.005 + i * period + rng.normal(0, 0.0002), target, 8,
         bytes([0x1B, 0x58, 0x00, 0x1F, i % 16, 0, 0, 0]), 1, "spoofing")
        for i in range(n)
    ]


def simulate_session(
    duration: float = 120.0,
    attacks: tuple[str, ...] = (),
    seed: int = 0,
    attack_len: float = 5.0,
) -> list[Frame]:
    """Génère une session de trafic trié par horodatage."""
    rng = np.random.default_rng(seed)
    normal = generate_normal(duration, rng)
    frames = list(normal)
    src_start = 1.0
    slot = duration / (len(attacks) + 1)
    for i, name in enumerate(attacks):
        start = slot * (i + 1) - attack_len / 2
        if name == "dos":
            frames += attack_dos(start, attack_len, rng)
        elif name == "fuzzing":
            frames += attack_fuzzing(start, attack_len, rng)
        elif name == "replay":
            start = max(start, src_start + attack_len + 0.5)
            frames += attack_replay(normal, start, attack_len, src_start)
        elif name == "spoofing":
            frames += attack_spoofing(start, attack_len, rng)
        else:
            raise ValueError(f"Attaque inconnue : {name} (choix : {ATTACKS})")
    frames.sort(key=lambda f: f[0])
    return frames
