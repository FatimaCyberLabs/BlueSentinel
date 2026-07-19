"""ViewModel del módulo IOC Manager.

Puente entre `IOCService` (application) y `IOCManagerView` (presentation).
Expone señales Qt para que la vista se actualice reactivamente, pero no
contiene ningún widget — es testeable con `pytest-qt` sin renderizar nada.
"""

from __future__ import annotations

import logging

from PySide6.QtCore import QObject, Signal, Slot
from sqlalchemy.orm import sessionmaker

from bluesentinel.application.ioc.ioc_service import IOCService, IOCSummary
from bluesentinel.domain.exceptions import BlueSentinelError
from bluesentinel.domain.value_objects.enums import ConfidenceLevel, IOCType, Severity
from bluesentinel.infrastructure.db.repositories.ioc_repository_impl import (
    SQLAlchemyIOCRepository,
)

logger = logging.getLogger(__name__)


class IOCManagerViewModel(QObject):
    """Expone el estado y las operaciones del IOC Manager a la vista Qt."""

    iocs_changed = Signal(list)  # list[IOCSummary]
    error_occurred = Signal(str)
    operation_succeeded = Signal(str)

    def __init__(self, session_factory: sessionmaker) -> None:
        super().__init__()
        self._session_factory = session_factory

    def _with_service(self):
        """Context manager helper: abre sesión, construye el service, hace commit."""
        session = self._session_factory()
        service = IOCService(SQLAlchemyIOCRepository(session))
        return session, service

    @Slot()
    def refresh(self) -> None:
        session, service = self._with_service()
        try:
            summaries = service.list_active(limit=500)
            self.iocs_changed.emit(summaries)
        except BlueSentinelError as exc:
            logger.exception("Error al refrescar IOCs")
            self.error_occurred.emit(str(exc))
        finally:
            session.close()

    @Slot(str)
    def search(self, query: str) -> None:
        session, service = self._with_service()
        try:
            if not query.strip():
                self.refresh()
                return
            results = service.search(query)
            self.iocs_changed.emit(results)
        except BlueSentinelError as exc:
            self.error_occurred.emit(str(exc))
        finally:
            session.close()

    @Slot(str, str, str, str, str)
    def add_ioc(
        self,
        ioc_type_value: str,
        value: str,
        severity_value: str,
        confidence_value: str,
        source: str,
    ) -> None:
        session, service = self._with_service()
        try:
            summary: IOCSummary = service.ingest_ioc(
                ioc_type=IOCType(ioc_type_value),
                value=value,
                severity=Severity(severity_value),
                confidence=ConfidenceLevel(confidence_value),
                source=source or "manual",
            )
            session.commit()
            self.operation_succeeded.emit(f"IOC guardado: {summary.value}")
            self.refresh()
        except BlueSentinelError as exc:
            session.rollback()
            self.error_occurred.emit(str(exc))
        finally:
            session.close()

    @Slot(str)
    def deactivate_ioc(self, ioc_id: str) -> None:
        from uuid import UUID

        session, service = self._with_service()
        try:
            service.deactivate_ioc(UUID(ioc_id))
            session.commit()
            self.operation_succeeded.emit("IOC desactivado")
            self.refresh()
        except BlueSentinelError as exc:
            session.rollback()
            self.error_occurred.emit(str(exc))
        finally:
            session.close()
