"""`InvestigationService`: el caso de uso que ata todo el flujo de investigación.

Este es el corazón del "workflow end-to-end" pedido: cargar datos ->
ejecutar detección -> abrir caso -> reconstruir árbol de procesos ->
mapear a MITRE -> construir timeline. Cada paso delega en el dominio
(`SigmaEvaluator`, `ProcessTreeBuilder`, `CoverageCalculator`, `Case`)
y usa los repositorios de infraestructura solo para leer/escribir —
ninguna regla de negocio vive aquí, solo orquestación.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass
from datetime import datetime
from uuid import UUID

from sqlalchemy.orm import Session

from bluesentinel.domain.detection.mitre_coverage import (
    CoverageCalculator,
    CoverageReport,
    MitreTechnique,
)
from bluesentinel.domain.detection.sigma_evaluator import SigmaEvaluator, SigmaMatch
from bluesentinel.domain.entities.case import Case
from bluesentinel.domain.entities.windows_event import WindowsEvent
from bluesentinel.domain.forensics.process_tree import ProcessNode, ProcessTreeBuilder
from bluesentinel.domain.value_objects.enums import CaseStatus, EvidenceType, Severity
from bluesentinel.infrastructure.db.repositories.case_repository_impl import (
    SQLAlchemyCaseRepository,
)
from bluesentinel.infrastructure.db.repositories.event_repository_impl import (
    SQLAlchemyEventRepository,
)
from bluesentinel.infrastructure.db.repositories.sigma_repository_impl import (
    SQLAlchemySigmaMatchRepository,
    SQLAlchemySigmaRuleRepository,
)
from bluesentinel.infrastructure.demo_data.attack_scenario import generate_intrusion_scenario
from bluesentinel.infrastructure.rules.rule_pack_loader import load_builtin_rule_pack
from bluesentinel.infrastructure.mitre.technique_catalog import BUILTIN_MITRE_CATALOG

logger = logging.getLogger(__name__)

_SEVERITY_BY_SIGMA_LEVEL = {
    "critical": Severity.CRITICAL,
    "high": Severity.HIGH,
    "medium": Severity.MEDIUM,
    "low": Severity.LOW,
    "informational": Severity.INFORMATIONAL,
}


@dataclass(slots=True, frozen=True)
class DashboardStats:
    """DTO agregando las cifras que pinta el Dashboard — todas calculadas de datos reales."""

    total_events: int
    total_detections: int
    critical_detections: int
    high_detections: int
    active_iocs: int
    open_cases: int
    distinct_hosts: int
    distinct_mitre_techniques: int
    top_rules: list[tuple[str, int]]  # (título de regla, nº de disparos)
    events_by_hour: list[tuple[str, int]]  # (etiqueta hora, nº eventos)


class InvestigationService:
    """Orquesta el flujo completo: ingesta -> detección -> caso -> forense -> MITRE."""

    def __init__(self, session: Session) -> None:
        self._session = session
        self._events = SQLAlchemyEventRepository(session)
        self._rules = SQLAlchemySigmaRuleRepository(session)
        self._matches = SQLAlchemySigmaMatchRepository(session)
        self._cases = SQLAlchemyCaseRepository(session)
        self._evaluator = SigmaEvaluator()
        self._tree_builder = ProcessTreeBuilder()

    # -- Paso 1: carga del dataset + reglas ------------------------------------------

    def load_demo_scenario(self) -> int:
        """Limpia el estado anterior y carga el escenario sintético + rule pack.

        Devuelve el número de eventos cargados. Es idempotente: se puede
        volver a ejecutar en cualquier momento para reiniciar la demo.
        """
        logger.info("Cargando escenario de demo...")
        self._matches.clear_all()
        self._cases.clear_all()
        self._events.clear_all()
        self._rules.clear_all()

        rules = load_builtin_rule_pack()
        for rule in rules:
            self._rules.add(rule)

        events = generate_intrusion_scenario()
        self._events.bulk_add(events)
        self._session.commit()
        logger.info("Escenario cargado: %d eventos, %d reglas", len(events), len(rules))
        return len(events)

    # -- Paso 2: ejecutar el motor de detección --------------------------------------

    def run_detection(self) -> list[SigmaMatch]:
        """Evalúa todas las reglas activas contra todos los eventos y persiste los matches."""
        rules = self._rules.get_all_enabled()
        events = self._events.get_all()
        matches = self._evaluator.evaluate_batch(rules, events)

        rule_id_map = {r.rule_id: str(r.id) for r in rules}
        self._matches.bulk_add(matches, rule_id_map)
        self._session.commit()
        logger.info("Detección ejecutada: %d matches sobre %d eventos", len(matches), len(events))
        return matches

    # -- Paso 3: abrir caso de investigación a partir de las detecciones ------------

    def open_investigation_case(self, matches: list[SigmaMatch]) -> Case:
        """Crea un `Case`, adjunta cada detección como evidencia, construye el
        timeline cronológico y calcula la severidad del caso a partir de la
        detección más severa — así es como un SOC real prioriza un caso.
        """
        if not matches:
            raise ValueError("No hay detecciones para abrir un caso de investigación")

        max_severity = max(
            (_SEVERITY_BY_SIGMA_LEVEL[m.rule.level.value] for m in matches), key=lambda s: s.weight
        )
        hosts = {m.event.computer for m in matches}
        case = Case.open_new(
            title=f"Intrusión sospechosa en {', '.join(sorted(hosts))}",
            severity=max_severity,
            summary=(
                f"{len(matches)} detecciones Sigma disparadas a través de "
                f"{len({m.rule.title for m in matches})} reglas distintas."
            ),
        )
        case.transition_to(CaseStatus.TRIAGE)
        case.transition_to(CaseStatus.INVESTIGATING)

        for match in matches:
            case.add_evidence(
                EvidenceType.SIGMA_MATCH,
                ref_id=str(match.event.id),
                notes=f"{match.rule.title} ({match.rule.level.value})",
            )
            case.add_timeline_entry(
                timestamp=match.event.time_created,
                description=f"[{match.rule.level.value.upper()}] {match.rule.title} — {match.event.image or match.event.target_object or match.event.destination_ip}",
                source_module="Sigma Detection Engine",
            )

        self._cases.add(case, affected_hosts=hosts)
        for entry in case.timeline:
            self._cases.add_timeline_entry(case.id, entry, source_module="Sigma Detection Engine")
        for ref in case.evidence:
            self._cases.add_evidence(case.id, ref)
        self._session.commit()
        logger.info("Caso abierto: %s (severidad=%s)", case.title, case.severity.value)
        return case

    def run_full_investigation_pipeline(self) -> tuple[int, list[SigmaMatch], Case | None]:
        """Ejecuta los 3 pasos anteriores en secuencia — el botón "Cargar y analizar"."""
        event_count = self.load_demo_scenario()
        matches = self.run_detection()
        case = self.open_investigation_case(matches) if matches else None
        return event_count, matches, case

    # -- Paso 4: forense — árbol de procesos -----------------------------------------

    def build_process_tree(self) -> list[ProcessNode]:
        events = self._events.get_all()
        return self._tree_builder.build(events)

    # -- Paso 5: cobertura MITRE ATT&CK ----------------------------------------------

    def calculate_mitre_coverage(self) -> CoverageReport:
        rules = self._rules.get_all()
        rule_technique_map = {r.title: list(r.mitre_technique_ids) for r in rules}
        return CoverageCalculator().calculate(BUILTIN_MITRE_CATALOG, rule_technique_map)

    def detected_technique_ids(self) -> set[str]:
        """Técnicas MITRE que tienen al menos un match real (no solo cobertura teórica)."""
        rows = self._matches.summary_rows()
        ids: set[str] = set()
        for row in rows:
            ids.update(row["mitre_technique_ids"])
        return ids

    # -- Paso 6: timeline e investigación ---------------------------------------------

    def get_detection_rows(self) -> list[dict]:
        """Filas planas de detección para pintar en la vista de Detecciones/Timeline."""
        return self._matches.summary_rows()

    def get_case_notes(self, case_id: UUID) -> list[dict]:
        return self._cases.get_notes(case_id)

    def get_affected_hosts(self, case_id: UUID) -> list[str]:
        return self._cases.get_affected_hosts(case_id)

    def add_case_note(self, case_id: UUID, author: str, content: str) -> None:
        self._cases.add_note(case_id, author, content)
        self._session.commit()

    def transition_case(self, case_id: UUID, new_status: CaseStatus) -> Case:
        case = self._cases.get_by_id(case_id)
        if case is None:
            raise ValueError(f"Caso {case_id} no encontrado")
        case.transition_to(new_status)
        self._cases.update_status(case_id, case.status, case.closed_at)
        self._session.commit()
        return case

    def get_latest_case(self) -> Case | None:
        return self._cases.get_latest()

    def get_all_cases(self) -> list[Case]:
        return self._cases.get_all()

    # -- Dashboard ---------------------------------------------------------------------

    def get_dashboard_stats(self) -> DashboardStats:
        events = self._events.get_all()
        rows = self._matches.summary_rows()
        critical = sum(1 for r in rows if r["level"] == "critical")
        high = sum(1 for r in rows if r["level"] == "high")

        rule_counts: dict[str, int] = {}
        for r in rows:
            rule_counts[r["rule_title"]] = rule_counts.get(r["rule_title"], 0) + 1
        top_rules = sorted(rule_counts.items(), key=lambda kv: kv[1], reverse=True)[:5]

        hourly: dict[str, int] = {}
        for e in events:
            label = e.time_created.strftime("%H:%M")
            hourly[label] = hourly.get(label, 0) + 1
        events_by_hour = sorted(hourly.items())

        technique_ids = {tid for r in rows for tid in r["mitre_technique_ids"]}
        cases = self._cases.get_all()

        return DashboardStats(
            total_events=len(events),
            total_detections=len(rows),
            critical_detections=critical,
            high_detections=high,
            active_iocs=0,  # se combina con IOCService desde el ViewModel
            open_cases=sum(1 for c in cases if not c.status.is_closed),
            distinct_hosts=len({e.computer for e in events}),
            distinct_mitre_techniques=len(technique_ids),
            top_rules=top_rules,
            events_by_hour=events_by_hour,
        )
