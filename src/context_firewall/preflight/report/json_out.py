"""JSON reporter — emits the stable Preflight scorecard schema.

The top-level shape (`schema_version`, `assessment`, `dimensions`, `gate`,
`evidence_boundary`, `limitations`) is a public contract. Downstream CI
integrations should read from `gate.status` — NOT from `dimensions.*.grade` —
to determine release decisions.
"""

from __future__ import annotations

import json
import sys
from typing import IO

from ..models import ScoreCard


def render(scorecard: ScoreCard, stream: IO = sys.stdout) -> None:
    stream.write(json.dumps(scorecard.model_dump(mode="json"), indent=2))
    stream.write("\n")
