"""Pytest configuration for PRIVGUARD SDK tests."""

import sys
from pathlib import Path

sdk_path = Path(__file__).parent.parent
src_path = sdk_path / "src"
tests_path = sdk_path / "tests"

for p in (str(src_path), str(sdk_path), str(tests_path)):
    if p not in sys.path:
        sys.path.insert(0, p)
