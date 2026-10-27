"""Allow ``python -m netwatch.gui``."""

from .app import main

if __name__ == "__main__":
    raise SystemExit(main())
