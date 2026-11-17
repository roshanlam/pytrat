"""pytest wiring for pytrat-fastapi tests; helpers live in ``_fastapi_testkit``."""

from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))

from _fastapi_testkit import kit

__all__ = ["kit"]
