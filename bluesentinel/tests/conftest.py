"""Configuración compartida de pytest para todo el proyecto."""

from __future__ import annotations

import sys
from pathlib import Path

# Permite importar `bluesentinel` desde `src/` sin instalar el paquete.
SRC_PATH = Path(__file__).resolve().parent.parent / "src"
if str(SRC_PATH) not in sys.path:
    sys.path.insert(0, str(SRC_PATH))
