"""``python -m examples.trader --config trader.toml``."""

from __future__ import annotations

import sys

from examples.trader.trader import main

if __name__ == "__main__":
    sys.exit(main())
