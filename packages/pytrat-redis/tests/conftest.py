"""pytest wiring for pytrat-redis tests; helpers live in ``_redis_testkit``."""

from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))
