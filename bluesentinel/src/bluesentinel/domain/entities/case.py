"""Entidad de dominio: Case (caso de investigación / respuesta a incidentes)."""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
from uuid import UUID, uuid4

from bluesentinel.domain.exceptions import InvalidEntityStateError
from bluesentinel.domain.value_objects.enums import CaseStatus, EvidenceType, Severity

# Transiciones válidas del ciclo de vida de un caso (máquina de estados explícita).
_VALID_TRANSITIONS: dict[CaseStatus, set[CaseStatus]] = {
    CaseStatus.NEW: {CaseStatus.TRIAGE, CaseStatus.CLOSED_FALSE_POSITIVE},
    CaseStatus.TRIAGE: {
        CaseStatus.INVESTIGATING,
        CaseStatus.CLOSED_FALSE_POSITIVE,
        CaseStatus.CLOSED_BENIGN,
    },
    CaseStatus.INVESTIGATING: {
        CaseStatus.CONTAINMENT,
        CaseStatus.CLOSED_FALSE_POSITIVE,
        CaseStatus.CLOSED_BENIGN,
    },
    CaseStatus.CONTAINMENT: {CaseStatus.ERADICATION},
    CaseStatus.ERADICATION: {CaseStatus.RECOVERY},
    CaseStatus.RECOVERY: {CaseStatus.CLOSED_TRUE_POSITIVE},
    CaseStatus.CLOSED_TRUE_POSITIVE: set(),
    CaseStatus.CLOSED_FALSE_POSITIVE: set(),
    CaseStatus.CLOSED_BENIGN: set(),
}


@dataclass(slots=True)
class CaseEvidenceRef:
    """Referencia a una pieza de evidencia vinculada a un caso."""

    id: UUID
    evidence_type: EvidenceType
    ref_id: UUID | int | str
    notes: str
    added_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))


@dataclass(slots=True)
class TimelineEntry:
    """Un evento en la línea temporal reconstruida del caso."""

    id: UUID
    timestamp: datetime
    description: str
    source_module: str


@dataclass(slots=True)
class Case:
    """Caso de investigación gestionado por Case Management.

    La máquina de estados (`_VALID_TRANSITIONS`) impide, por diseño, saltos
    imposibles como pasar de `NEW` directo a `CLOSED_TRUE_POSITIVE` sin pasar
    por investigación y contención — reflejando el proceso real de IR
    (NIST SP 800-61).
    """

    id: UUID
    title: str
    status: CaseStatus
    severity: Severity
    assignee: str | None
    created_at: datetime
    summary: str = ""
    closed_at: datetime | None = None
    evidence: list[CaseEvidenceRef] = field(default_factory=list)
    timeline: list[TimelineEntry] = field(default_factory=list)

    @classmethod
    def open_new(
        cls,
        title: str,
        severity: Severity = Severity.MEDIUM,
        assignee: str | None = None,
        summary: str = "",
    ) -> Case:
        return cls(
            id=uuid4(),
            title=title,
            status=CaseStatus.NEW,
            severity=severity,
            assignee=assignee,
            created_at=datetime.now(timezone.utc),
            summary=summary,
        )

    def transition_to(self, new_status: CaseStatus) -> None:
        """Cambia el estado del caso, validando la transición contra la máquina de estados."""
        allowed = _VALID_TRANSITIONS[self.status]
        if new_status not in allowed:
            raise InvalidEntityStateError(
                f"Transición inválida: {self.status.value} -> {new_status.value}. "
                f"Transiciones permitidas desde {self.status.value}: "
                f"{sorted(s.value for s in allowed)}"
            )
        self.status = new_status
        if new_status.is_closed:
            self.closed_at = datetime.now(timezone.utc)

    def add_evidence(
        self, evidence_type: EvidenceType, ref_id: UUID | int | str, notes: str = ""
    ) -> CaseEvidenceRef:
        ref = CaseEvidenceRef(id=uuid4(), evidence_type=evidence_type, ref_id=ref_id, notes=notes)
        self.evidence.append(ref)
        return ref

    def add_timeline_entry(
        self, timestamp: datetime, description: str, source_module: str
    ) -> TimelineEntry:
        entry = TimelineEntry(
            id=uuid4(), timestamp=timestamp, description=description, source_module=source_module
        )
        self.timeline.append(entry)
        self.timeline.sort(key=lambda e: e.timestamp)
        return entry

    def reassign(self, new_assignee: str) -> None:
        if self.status.is_closed:
            raise InvalidEntityStateError("No se puede reasignar un caso cerrado")
        self.assignee = new_assignee
