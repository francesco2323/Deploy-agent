"""Append-only, hash-chained JSONL audit log. Ship to S3 Object Lock / CloudWatch in real use."""
from __future__ import annotations

import hashlib
import json
import time
from pathlib import Path

from . import __version__

_GENESIS = "0" * 64


def _h(rec: dict) -> str:
    return hashlib.sha256(json.dumps(rec, sort_keys=True).encode()).hexdigest()


class Audit:
    def __init__(self, path: str | Path):
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self.prev = _GENESIS
        if self.path.exists():
            lines = self.path.read_text().strip().splitlines()
            if lines:
                self.prev = json.loads(lines[-1])["hash"]

    def log(self, event: str, **data) -> None:
        rec = {"ts": round(time.time(), 3), "version": __version__, "event": event, "data": data, "prev": self.prev}
        rec["hash"] = _h(rec)
        with self.path.open("a") as f:
            f.write(json.dumps(rec) + "\n")
        self.prev = rec["hash"]

    @staticmethod
    def verify(path: str | Path) -> bool:
        prev = _GENESIS
        for line in Path(path).read_text().splitlines():
            rec = json.loads(line)
            h = rec.pop("hash")
            if rec["prev"] != prev or _h(rec) != h:
                return False
            prev = h
        return True
