"""Configuración del engine y de la sesión de SQLAlchemy para BlueSentinel.

Usa SQLite con `foreign_keys=ON` forzado vía evento (SQLite lo desactiva por
defecto) y `WAL` para permitir lecturas concurrentes mientras la UI escribe
en segundo plano (ej. ingesta de eventos mientras el analista navega el
Dashboard).
"""

from __future__ import annotations

from contextlib import contextmanager
from pathlib import Path
from typing import Iterator

from sqlalchemy import Engine, create_engine, event
from sqlalchemy.orm import DeclarativeBase, Session, sessionmaker


class Base(DeclarativeBase):
    """Clase base declarativa para todos los modelos ORM de BlueSentinel."""


def _enable_sqlite_pragmas(dbapi_connection: object, _connection_record: object) -> None:
    cursor = dbapi_connection.cursor()  # type: ignore[attr-defined]
    cursor.execute("PRAGMA foreign_keys=ON")
    cursor.execute("PRAGMA journal_mode=WAL")
    cursor.close()


def build_engine(db_path: Path, *, echo: bool = False) -> Engine:
    """Crea el engine de SQLAlchemy apuntando a un archivo SQLite en `db_path`."""
    db_path.parent.mkdir(parents=True, exist_ok=True)
    engine = create_engine(f"sqlite:///{db_path}", echo=echo, future=True)
    event.listen(engine, "connect", _enable_sqlite_pragmas)
    return engine


def build_session_factory(engine: Engine) -> sessionmaker[Session]:
    return sessionmaker(bind=engine, autoflush=False, expire_on_commit=False, future=True)


@contextmanager
def session_scope(session_factory: sessionmaker[Session]) -> Iterator[Session]:
    """Context manager transaccional: commit al salir, rollback si hay excepción."""
    session = session_factory()
    try:
        yield session
        session.commit()
    except Exception:
        session.rollback()
        raise
    finally:
        session.close()
