"""Implementación SQLAlchemy de `IOCRepository`.

Traduce entre `domain.entities.ioc.IOC` (rico en comportamiento) y
`infrastructure.db.models.IOCModel` (fila de tabla plana). Esta es la
única clase del proyecto que sabe simultáneamente de SQLAlchemy y del
dominio de IOC — mantiene el resto del sistema desacoplado.
"""

from __future__ import annotations

from uuid import UUID

from sqlalchemy import func, or_, select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from bluesentinel.domain.entities.ioc import IOC
from bluesentinel.domain.exceptions import DuplicateEntityError, EntityNotFoundError
from bluesentinel.domain.value_objects.enums import ConfidenceLevel, IOCType, Severity
from bluesentinel.infrastructure.db.models import IOCModel


class SQLAlchemyIOCRepository:
    """Repositorio de IOCs respaldado por SQLite vía SQLAlchemy.

    Implementa estructuralmente `domain.repositories.ioc_repository.IOCRepository`
    (no hay herencia explícita: Python usa duck typing / Protocol).
    """

    def __init__(self, session: Session) -> None:
        self._session = session

    def add(self, ioc: IOC) -> None:
        model = self._to_model(ioc)
        self._session.add(model)
        try:
            self._session.flush()
        except IntegrityError as exc:
            self._session.rollback()
            raise DuplicateEntityError("IOC", f"{ioc.ioc_type.value}:{ioc.value}") from exc

    def get_by_id(self, ioc_id: UUID) -> IOC | None:
        model = self._session.get(IOCModel, str(ioc_id))
        return self._to_entity(model) if model else None

    def get_by_value(self, ioc_type: IOCType, value: str) -> IOC | None:
        stmt = select(IOCModel).where(
            IOCModel.ioc_type == ioc_type.value, IOCModel.value == value
        )
        model = self._session.execute(stmt).scalar_one_or_none()
        return self._to_entity(model) if model else None

    def find_active(
        self,
        ioc_type: IOCType | None = None,
        min_severity_weight: int | None = None,
        limit: int = 100,
        offset: int = 0,
    ) -> list[IOC]:
        stmt = select(IOCModel).where(IOCModel.is_active.is_(True))
        if ioc_type is not None:
            stmt = stmt.where(IOCModel.ioc_type == ioc_type.value)
        stmt = stmt.order_by(IOCModel.last_seen.desc()).limit(limit).offset(offset)
        models = self._session.execute(stmt).scalars().all()
        entities = [self._to_entity(m) for m in models]
        if min_severity_weight is not None:
            entities = [e for e in entities if e.severity.weight >= min_severity_weight]
        return entities

    def search(self, query: str, limit: int = 100) -> list[IOC]:
        like_pattern = f"%{query}%"
        stmt = (
            select(IOCModel)
            .where(
                or_(
                    IOCModel.value.ilike(like_pattern),
                    IOCModel.source.ilike(like_pattern),
                    IOCModel.tags.ilike(like_pattern),
                    IOCModel.notes.ilike(like_pattern),
                )
            )
            .limit(limit)
        )
        models = self._session.execute(stmt).scalars().all()
        return [self._to_entity(m) for m in models]

    def update(self, ioc: IOC) -> None:
        model = self._session.get(IOCModel, str(ioc.id))
        if model is None:
            raise EntityNotFoundError("IOC", ioc.id)
        self._apply_entity_to_model(ioc, model)
        self._session.flush()

    def delete(self, ioc_id: UUID) -> None:
        model = self._session.get(IOCModel, str(ioc_id))
        if model is None:
            raise EntityNotFoundError("IOC", ioc_id)
        self._session.delete(model)
        self._session.flush()

    def count_active(self) -> int:
        stmt = select(func.count()).select_from(IOCModel).where(IOCModel.is_active.is_(True))
        return int(self._session.execute(stmt).scalar_one())

    # -- Mapeo entidad <-> modelo -------------------------------------------------

    @staticmethod
    def _to_model(ioc: IOC) -> IOCModel:
        return IOCModel(
            id=str(ioc.id),
            ioc_type=ioc.ioc_type.value,
            value=ioc.value,
            severity=ioc.severity.value,
            confidence=ioc.confidence.value,
            source=ioc.source,
            tags=",".join(sorted(ioc.tags)),
            notes=ioc.notes,
            first_seen=ioc.first_seen,
            last_seen=ioc.last_seen,
            is_active=ioc.is_active,
        )

    @staticmethod
    def _apply_entity_to_model(ioc: IOC, model: IOCModel) -> None:
        model.severity = ioc.severity.value
        model.confidence = ioc.confidence.value
        model.source = ioc.source
        model.tags = ",".join(sorted(ioc.tags))
        model.notes = ioc.notes
        model.first_seen = ioc.first_seen
        model.last_seen = ioc.last_seen
        model.is_active = ioc.is_active

    @staticmethod
    def _to_entity(model: IOCModel) -> IOC:
        return IOC(
            id=UUID(model.id),
            ioc_type=IOCType(model.ioc_type),
            value=model.value,
            severity=Severity(model.severity),
            confidence=ConfidenceLevel(model.confidence),
            source=model.source,
            tags=set(filter(None, model.tags.split(","))),
            first_seen=model.first_seen,
            last_seen=model.last_seen,
            is_active=model.is_active,
            notes=model.notes,
        )
