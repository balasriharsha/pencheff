"""CVSS v3.1 score calculator."""

from __future__ import annotations

import math

# CVSS v3.1 metric values
METRIC_VALUES = {
    "AV": {"N": 0.85, "A": 0.62, "L": 0.55, "P": 0.20},
    "AC": {"L": 0.77, "H": 0.44},
    "PR": {
        "unchanged": {"N": 0.85, "L": 0.62, "H": 0.27},
        "changed": {"N": 0.85, "L": 0.68, "H": 0.50},
    },
    "UI": {"N": 0.85, "R": 0.62},
    "S": {"U": False, "C": True},
    "C": {"H": 0.56, "L": 0.22, "N": 0.0},
    "I": {"H": 0.56, "L": 0.22, "N": 0.0},
    "A": {"H": 0.56, "L": 0.22, "N": 0.0},
}


def calculate_cvss(vector: str) -> float:
    """Calculate CVSS v3.1 base score from a vector string."""
    if not vector or not vector.startswith("CVSS:3.1/"):
        return 0.0

    metrics = {}
    parts = vector.replace("CVSS:3.1/", "").split("/")
    for part in parts:
        key, val = part.split(":")
        metrics[key] = val

    try:
        scope_changed = METRIC_VALUES["S"][metrics["S"]]

        # Impact sub-score
        isc_base = 1 - (
            (1 - METRIC_VALUES["C"][metrics["C"]]) *
            (1 - METRIC_VALUES["I"][metrics["I"]]) *
            (1 - METRIC_VALUES["A"][metrics["A"]])
        )

        if scope_changed:
            impact = 7.52 * (isc_base - 0.029) - 3.25 * (isc_base - 0.02) ** 15
        else:
            impact = 6.42 * isc_base

        if impact <= 0:
            return 0.0

        # Exploitability sub-score
        pr_scope = "changed" if scope_changed else "unchanged"
        exploitability = (
            8.22 *
            METRIC_VALUES["AV"][metrics["AV"]] *
            METRIC_VALUES["AC"][metrics["AC"]] *
            METRIC_VALUES["PR"][pr_scope][metrics["PR"]] *
            METRIC_VALUES["UI"][metrics["UI"]]
        )

        if scope_changed:
            score = min(1.08 * (impact + exploitability), 10.0)
        else:
            score = min(impact + exploitability, 10.0)

        return math.ceil(score * 10) / 10
    except (KeyError, ValueError):
        return 0.0
