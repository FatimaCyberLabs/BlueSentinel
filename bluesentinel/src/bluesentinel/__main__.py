"""Punto de entrada: `python -m bluesentinel` o el comando `bluesentinel`."""

from __future__ import annotations

import sys


def main() -> int:
    from PySide6.QtWidgets import QApplication

    from bluesentinel.bootstrap import bootstrap
    from bluesentinel.presentation.main_window import MainWindow

    context = bootstrap()

    app = QApplication(sys.argv)
    app.setApplicationName("BlueSentinel")
    app.setOrganizationName("BlueSentinel Project")

    window = MainWindow(context)
    window.show()

    return app.exec()


if __name__ == "__main__":
    sys.exit(main())
