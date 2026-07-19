"""Casos de uso del módulo IOC Manager.

`IOCService` orquesta el dominio (`IOC`) y el puerto `IOCRepository`, sin
saber nada de SQLAlchemy ni de PySide6. Es la capa que la UI (ViewModels)
y otros módulos (Sigma Engine, Threat Feed Importer) invocan.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass
from datetime import datetime
from uuid import UUID

from bluesentinel.domain.entities.ioc import IOC
from bluesentinel.domain.exceptions import DuplicateEntityError, EntityNotFoundError
from bluesentinel.domain.repositories.ioc_repository import IOCRepository
from bluesentinel.domain.value_objects.enums import ConfidenceLevel, IOCType, Severity

logger = logging.getLogger(__name__)


@dataclass(slots=True, frozen=True)
class IOCSummary:
    """DTO de salida usado por la UI (evita filtrar la entidad de dominio directamente)."""

    id: UUID
    ioc_type: str
    value: str
    severity: str
    confidence: str
    source: str
    tags: tuple[str, ...]
    first_seen: datetime
    last_seen: datetime
    is_active: bool

    @classmethod
    def from_entity(cls, ioc: IOC) -> IOCSummary:
        return cls(
            id=ioc.id,
            ioc_type=ioc.ioc_type.value,
            value=ioc.value,
            severity=ioc.severity.value,
            confidence=ioc.confidence.value,
            source=ioc.source,
            tags=tuple(sorted(ioc.tags)),
            first_seen=ioc.first_seen,
            last_seen=ioc.last_seen,
            is_active=ioc.is_active,
        )


class IOCService:
    """Caso de uso central del IOC Manager: alta, deduplicación, búsqueda y triage."""

    def __init__(self, repository: IOCRepository) -> None:
        self._repository = repository

    def ingest_ioc(
        self,
        ioc_type: IOCType,
        value: str,
        severity: Severity = Severity.MEDIUM,
        confidence: ConfidenceLevel = ConfidenceLevel.UNKNOWN,
        source: str = "manual",
        tags: set[str] | None = None,
        notes: str = "",
        observed_at: datetime | None = None,
    ) -> IOCSummary:
        """Ingiere un IOC. Si ya existe (mismo tipo+valor), lo fusiona en vez de duplicar.

        Esta es la operación crítica del módulo: SOC analysts y el Threat Feed
        Importer llaman este mismo método, garantizando reglas de dedupe
        consistentes en todo el sistema.
        """
        existing = self._repository.get_by_value(ioc_type, IOC.normalize(ioc_type, value))
        if existing is not None:
            existing.mark_seen(observed_at)
            existing.escalate(severity)
            for tag in tags or set():
                existing.add_tag(tag)
            self._repository.update(existing)
            logger.info(
                "IOC fusionado: type=%s value=%s severity=%s",
                existing.ioc_type.value,
                existing.value,
                existing.severity.value,
            )
            return IOCSummary.from_entity(existing)

        ioc = IOC.create(
            ioc_type=ioc_type,
            value=value,
            severity=severity,
            confidence=confidence,
            source=source,
            tags=tags,
            notes=notes,
        )
        try:
            self._repository.add(ioc)
        except DuplicateEntityError:
            # Condición de carrera: otro hilo/proceso lo insertó entre el get y el add.
            existing = self._repository.get_by_value(ioc_type, ioc.value)
            if existing is None:
                raise
            existing.mark_seen(observed_at)
            self._repository.update(existing)
            return IOCSummary.from_entity(existing)

        logger.info("IOC creado: type=%s value=%s source=%s", ioc_type.value, ioc.value, source)
        return IOCSummary.from_entity(ioc)

    def deactivate_ioc(self, ioc_id: UUID) -> None:
        ioc = self._repository.get_by_id(ioc_id)
        if ioc is None:
            raise EntityNotFoundError("IOC", ioc_id)
        ioc.deactivate()
        self._repository.update(ioc)
        logger.info("IOC desactivado: id=%s value=%s", ioc_id, ioc.value)

    def list_active(
        self,
        ioc_type: IOCType | None = None,
        min_severity: Severity | None = None,
        limit: int = 100,
        offset: int = 0,
    ) -> list[IOCSummary]:
        min_weight = min_severity.weight if min_severity else None
        entities = self._repository.find_active(ioc_type, min_weight, limit, offset)
        return [IOCSummary.from_entity(e) for e in entities]

    def search(self, query: str, limit: int = 100) -> list[IOCSummary]:
        entities = self._repository.search(query, limit)
        return [IOCSummary.from_entity(e) for e in entities]

    def get_active_count(self) -> int:
        return self._repository.count_active()
