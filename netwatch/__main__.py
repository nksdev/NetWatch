"""Allow ``python -m netwatch``.

With no arguments this starts the GUI, because that is what most people
want when they run the package directly. Pass ``--cli`` for the terminal
interface instead.
"""

from __future__ import annotations

import sys


def main() -> int:
    if "--cli" in sys.argv:
        sys.argv.remove("--cli")
        from .cli import main as cli_main

        return cli_main()
    from .gui.app import main as gui_main

    return gui_main()


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
