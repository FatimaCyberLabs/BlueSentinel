"""ViewModel de investigación: conecta `InvestigationService` con todas las
vistas del Investigation Workbench (árbol de procesos, detecciones,
timeline, MITRE, caso) y el Dashboard. Un único ViewModel para todo el
flujo porque todas esas vistas comparten el mismo ciclo de vida de datos
(cargar escenario -> detectar -> abrir caso) y necesitan refrescarse juntas.
"""

from __future__ import annotations

import logging
from uuid import UUID

from PySide6.QtCore import QObject, Signal, Slot
from sqlalchemy.orm import sessionmaker

from bluesentinel.application.detection.investigation_service import InvestigationService
from bluesentinel.domain.entities.case import Case
from bluesentinel.domain.exceptions import BlueSentinelError
from bluesentinel.domain.value_objects.enums import CaseStatus

logger = logging.getLogger(__name__)


class InvestigationViewModel(QObject):
    pipeline_started = Signal()
    pipeline_finished = Signal(int, int)  # (nº eventos, nº detecciones)
    process_tree_ready = Signal(list)  # list[ProcessNode]
    detections_ready = Signal(list)  # list[dict]
    case_ready = Signal(object)  # Case | None
    mitre_coverage_ready = Signal(object)  # CoverageReport
    dashboard_ready = Signal(object)  # DashboardStats
    error_occurred = Signal(str)
    status_message = Signal(str)

    def __init__(self, session_factory: sessionmaker) -> None:
        super().__init__()
        self._session_factory = session_factory
        self._current_case: Case | None = None

    @property
    def current_case(self) -> Case | None:
        return self._current_case

    @Slot()
    def load_and_analyze(self) -> None:
        """El botón principal: carga el escenario de demo, corre detección, abre caso."""
        self.pipeline_started.emit()
        session = self._session_factory()
        try:
            service = InvestigationService(session)
            self.status_message.emit("Cargando escenario de intrusión sintético...")
            event_count = service.load_demo_scenario()

            self.status_message.emit("Ejecutando motor de detección Sigma...")
            matches = service.run_detection()

            case = None
            if matches:
                self.status_message.emit("Abriendo caso de investigación...")
                case = service.open_investigation_case(matches)
                self._current_case = case

            self.pipeline_finished.emit(event_count, len(matches))
            self._refresh_all(service)
        except BlueSentinelError as exc:
            logger.exception("Error en el pipeline de investigación")
            self.error_occurred.emit(str(exc))
        finally:
            session.close()

    @Slot()
    def refresh(self) -> None:
        session = self._session_factory()
        try:
            service = InvestigationService(session)
            self._refresh_all(service)
        except BlueSentinelError as exc:
            self.error_occurred.emit(str(exc))
        finally:
            session.close()

    def _refresh_all(self, service: InvestigationService) -> None:
        rows = service.get_detection_rows()
        self.detections_ready.emit(rows)

        roots = service.build_process_tree()
        self.process_tree_ready.emit(roots)

        case = service.get_latest_case()
        self._current_case = case
        self.case_ready.emit(case)

        coverage = service.calculate_mitre_coverage()
        self.mitre_coverage_ready.emit(coverage)

        stats = service.get_dashboard_stats()
        self.dashboard_ready.emit(stats)

    @Slot(str)
    def transition_case(self, new_status_value: str) -> None:
        if self._current_case is None:
            return
        session = self._session_factory()
        try:
            service = InvestigationService(session)
            case = service.transition_case(self._current_case.id, CaseStatus(new_status_value))
            self._current_case = case
            self.case_ready.emit(case)
            self.status_message.emit(f"Caso actualizado a: {case.status.value}")
        except BlueSentinelError as exc:
            self.error_occurred.emit(str(exc))
        finally:
            session.close()

    @Slot(str)
    def add_case_note(self, content: str) -> None:
        if self._current_case is None or not content.strip():
            return
        session = self._session_factory()
        try:
            service = InvestigationService(session)
            service.add_case_note(self._current_case.id, author="analyst", content=content.strip())
            self.status_message.emit("Nota añadida al caso")
        except BlueSentinelError as exc:
            self.error_occurred.emit(str(exc))
        finally:
            session.close()

    def get_case_notes(self) -> list[dict]:
        if self._current_case is None:
            return []
        session = self._session_factory()
        try:
            service = InvestigationService(session)
            return service.get_case_notes(self._current_case.id)
        finally:
            session.close()

    def get_detected_technique_ids(self) -> set[str]:
        session = self._session_factory()
        try:
            service = InvestigationService(session)
            return service.detected_technique_ids()
        finally:
            session.close()

    def get_affected_hosts(self, case_id: UUID) -> list[str]:
        session = self._session_factory()
        try:
            service = InvestigationService(session)
            return service.get_affected_hosts(case_id)
        finally:
            session.close()
