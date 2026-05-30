"""`python -m canon_megatank` entrypoint — dispatches to main.run()."""

from __future__ import annotations

import sys

from .main import run

if __name__ == "__main__":
    sys.exit(run())
