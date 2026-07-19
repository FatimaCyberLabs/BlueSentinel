"""Composition root de BlueSentinel.

Aquí, y solo aquí, se conectan las implementaciones concretas de
`infrastructure` con los casos de uso de `application`. Es el único lugar
del proyecto que conoce tanto SQLAlchemy como los servicios de negocio —
todo lo demás recibe sus dependencias inyectadas desde aquí.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass

from sqlalchemy.orm import Session, sessionmaker

from bluesentinel.application.detection.investigation_service import InvestigationService
from bluesentinel.application.ioc.ioc_service import IOCService
from bluesentinel.core_config import AppConfig
from bluesentinel.infrastructure.db.base import Base, build_engine, build_session_factory
from bluesentinel.infrastructure.db.repositories.ioc_repository_impl import (
    SQLAlchemyIOCRepository,
)
from bluesentinel.infrastructure.logging.setup import configure_logging

logger = logging.getLogger(__name__)


@dataclass
class AppContext:
    """Contenedor con todo lo que la capa de presentación necesita para arrancar."""

    config: AppConfig
    session_factory: sessionmaker[Session]

    def new_ioc_service(self, session: Session) -> IOCService:
        """Crea un IOCService atado a una sesión de BD dada (una por unidad de trabajo)."""
        return IOCService(SQLAlchemyIOCRepository(session))

    def new_investigation_service(self, session: Session) -> InvestigationService:
        """Crea un InvestigationService atado a una sesión de BD dada."""
        return InvestigationService(session)


def bootstrap() -> AppContext:
    """Inicializa configuración, logging, base de datos y devuelve el contexto de la app."""
    config = AppConfig.load()
    configure_logging(config.log_dir, config.log_level)
    logger.info("Iniciando BlueSentinel. data_dir=%s", config.data_dir)

    engine = build_engine(config.db_path, echo=config.sql_echo)
    Base.metadata.create_all(engine)
    session_factory = build_session_factory(engine)

    logger.info("Base de datos lista en %s", config.db_path)
    return AppContext(config=config, session_factory=session_factory)
