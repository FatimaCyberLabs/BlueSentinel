"""Repositorio SQLAlchemy para `Case`, incluyendo evidencia, timeline y notas."""

from __future__ import annotations

from datetime import datetime
from uuid import UUID, uuid4

from sqlalchemy import select
from sqlalchemy.orm import Session

from bluesentinel.domain.entities.case import Case, CaseEvidenceRef, TimelineEntry
from bluesentinel.domain.exceptions import EntityNotFoundError
from bluesentinel.domain.value_objects.enums import CaseStatus, EvidenceType, Severity
from bluesentinel.infrastructure.db.models import (
    CaseEvidenceModel,
    CaseModel,
    CaseNoteModel,
    CaseTimelineModel,
)


class SQLAlchemyCaseRepository:
    def __init__(self, session: Session) -> None:
        self._session = session

    def add(self, case: Case, affected_hosts: set[str] | None = None) -> None:
        model = CaseModel(
            id=str(case.id),
            title=case.title,
            status=case.status.value,
            severity=case.severity.value,
            assignee=case.assignee,
            created_at=case.created_at,
            closed_at=case.closed_at,
            summary=case.summary,
            affected_hosts=",".join(sorted(affected_hosts or set())),
        )
        self._session.add(model)
        self._session.flush()

    def get_by_id(self, case_id: UUID) -> Case | None:
        model = self._session.get(CaseModel, str(case_id))
        return self._to_entity(model) if model else None

    def get_latest(self) -> Case | None:
        stmt = select(CaseModel).order_by(CaseModel.created_at.desc()).limit(1)
        model = self._session.execute(stmt).scalar_one_or_none()
        return self._to_entity(model) if model else None

    def get_all(self) -> list[Case]:
        stmt = select(CaseModel).order_by(CaseModel.created_at.desc())
        return [self._to_entity(m) for m in self._session.execute(stmt).scalars().all()]

    def update_status(self, case_id: UUID, new_status: CaseStatus, closed_at: datetime | None) -> None:
        model = self._session.get(CaseModel, str(case_id))
        if model is None:
            raise EntityNotFoundError("Case", case_id)
        model.status = new_status.value
        model.closed_at = closed_at
        self._session.flush()

    def add_timeline_entry(self, case_id: UUID, entry: TimelineEntry, source_module: str) -> None:
        model = CaseTimelineModel(
            id=str(entry.id),
            case_id=str(case_id),
            timestamp=entry.timestamp,
            description=entry.description,
            source_module=source_module,
        )
        self._session.add(model)
        self._session.flush()

    def add_evidence(self, case_id: UUID, ref: CaseEvidenceRef) -> None:
        model = CaseEvidenceModel(
            id=str(ref.id),
            case_id=str(case_id),
            evidence_type=ref.evidence_type.value,
            ref_id=str(ref.ref_id),
            notes=ref.notes,
            added_at=ref.added_at,
        )
        self._session.add(model)
        self._session.flush()

    def add_note(self, case_id: UUID, author: str, content: str) -> None:
        model = CaseNoteModel(
            id=str(uuid4()), case_id=str(case_id), author=author, content=content,
            created_at=datetime.utcnow(),
        )
        self._session.add(model)
        self._session.flush()

    def get_notes(self, case_id: UUID) -> list[dict]:
        stmt = (
            select(CaseNoteModel)
            .where(CaseNoteModel.case_id == str(case_id))
            .order_by(CaseNoteModel.created_at)
        )
        return [
            {"author": n.author, "content": n.content, "created_at": n.created_at}
            for n in self._session.execute(stmt).scalars().all()
        ]

    def clear_all(self) -> None:
        self._session.query(CaseTimelineModel).delete()
        self._session.query(CaseEvidenceModel).delete()
        self._session.query(CaseNoteModel).delete()
        self._session.query(CaseModel).delete()
        self._session.flush()

    def get_affected_hosts(self, case_id: UUID) -> list[str]:
        model = self._session.get(CaseModel, str(case_id))
        if model is None or not model.affected_hosts:
            return []
        return model.affected_hosts.split(",")

    @staticmethod
    def _to_entity(model: CaseModel) -> Case:
        case = Case(
            id=UUID(model.id),
            title=model.title,
            status=CaseStatus(model.status),
            severity=Severity(model.severity),
            assignee=model.assignee,
            created_at=model.created_at,
            summary=model.summary,
            closed_at=model.closed_at,
        )
        case.evidence = [
            CaseEvidenceRef(
                id=UUID(e.id),
                evidence_type=EvidenceType(e.evidence_type),
                ref_id=e.ref_id,
                notes=e.notes,
                added_at=e.added_at,
            )
            for e in model.evidence
        ]
        case.timeline = [
            TimelineEntry(
                id=UUID(t.id), timestamp=t.timestamp, description=t.description,
                source_module=t.source_module,
            )
            for t in model.timeline
        ]
        return case
