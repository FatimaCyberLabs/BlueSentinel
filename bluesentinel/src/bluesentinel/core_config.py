"""Configuración central de BlueSentinel (rutas, entorno, versión).

Centralizada aquí para que ningún módulo hardcodee rutas de la base de
datos o de logs por su cuenta.
"""

from __future__ import annotations

import os
from dataclasses import dataclass
from pathlib import Path

APP_NAME = "BlueSentinel"
APP_VERSION = "0.1.0"


def _default_data_dir() -> Path:
    if os.name == "nt":
        base = Path(os.environ.get("APPDATA", Path.home() / "AppData" / "Roaming"))
    else:
        base = Path(os.environ.get("XDG_DATA_HOME", Path.home() / ".local" / "share"))
    return base / "BlueSentinel"


@dataclass(frozen=True, slots=True)
class AppConfig:
    """Configuración inmutable de la aplicación, resuelta una vez al arrancar."""

    data_dir: Path
    db_path: Path
    log_dir: Path
    log_level: str
    sql_echo: bool

    @classmethod
    def load(cls) -> AppConfig:
        data_dir = Path(os.environ.get("BLUESENTINEL_DATA_DIR", _default_data_dir()))
        return cls(
            data_dir=data_dir,
            db_path=data_dir / "bluesentinel.db",
            log_dir=data_dir / "logs",
            log_level=os.environ.get("BLUESENTINEL_LOG_LEVEL", "INFO"),
            sql_echo=os.environ.get("BLUESENTINEL_SQL_ECHO", "0") == "1",
        )
