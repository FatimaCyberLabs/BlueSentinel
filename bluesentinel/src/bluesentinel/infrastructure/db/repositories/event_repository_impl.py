"""Repositorio SQLAlchemy para `WindowsEvent`.

Serializa `event_data` (dict libre de campos forenses) a JSON en la
columna `event_data_json` -- ver docstring de `WindowsEventModel` para
la justificación de no tener un esquema de columnas fijo por Event ID.
"""

from __future__ import annotations

import json
from datetime import datetime
from uuid import UUID

from sqlalchemy import select
from sqlalchemy.orm import Session

from bluesentinel.domain.entities.windows_event import WindowsEvent
from bluesentinel.infrastructure.db.models import WindowsEventModel


class SQLAlchemyEventRepository:
    """Persistencia de eventos de Windows, con soporte de ingesta masiva."""

    def __init__(self, session: Session) -> None:
        self._session = session

    def bulk_add(self, events: list[WindowsEvent]) -> None:
        models = [self._to_model(e) for e in events]
        self._session.add_all(models)
        self._session.flush()

    def get_all(self, limit: int = 5000) -> list[WindowsEvent]:
        stmt = select(WindowsEventModel).order_by(WindowsEventModel.time_created).limit(limit)
        return [self._to_entity(m) for m in self._session.execute(stmt).scalars().all()]

    def get_by_id(self, event_id: UUID) -> WindowsEvent | None:
        model = self._session.get(WindowsEventModel, str(event_id))
        return self._to_entity(model) if model else None

    def find_between(self, start: datetime, end: datetime) -> list[WindowsEvent]:
        stmt = (
            select(WindowsEventModel)
            .where(WindowsEventModel.time_created >= start, WindowsEventModel.time_created <= end)
            .order_by(WindowsEventModel.time_created)
        )
        return [self._to_entity(m) for m in self._session.execute(stmt).scalars().all()]

    def count(self) -> int:
        from sqlalchemy import func

        stmt = select(func.count()).select_from(WindowsEventModel)
        return int(self._session.execute(stmt).scalar_one())

    def clear_all(self) -> None:
        """Limpia todos los eventos -- usado al recargar el escenario de demo."""
        self._session.query(WindowsEventModel).delete()
        self._session.flush()

    @classmethod
    def event_from_model(cls, model: WindowsEventModel) -> WindowsEvent:
        """API pública de mapeo, usada por otros repositorios (ej. SigmaMatch summary_rows)
        que necesitan reconstruir el `WindowsEvent` de dominio a partir de una fila ya
        obtenida en un JOIN, sin volver a golpear la BD."""
        return cls._to_entity(model)

    @staticmethod
    def _to_model(event: WindowsEvent) -> WindowsEventModel:
        return WindowsEventModel(
            id=str(event.id),
            event_id=event.event_id,
            channel=event.channel,
            computer=event.computer,
            provider=event.provider,
            time_created=event.time_created,
            level=event.level,
            task_category=event.task_category,
            event_data_json=json.dumps(event.event_data),
            raw_xml=event.raw_xml,
        )

    @staticmethod
    def _to_entity(model: WindowsEventModel) -> WindowsEvent:
        return WindowsEvent(
            id=UUID(model.id),
            event_id=model.event_id,
            channel=model.channel,
            computer=model.computer,
            provider=model.provider,
            time_created=model.time_created,
            level=model.level,
            task_category=model.task_category,
            event_data=json.loads(model.event_data_json or "{}"),
            raw_xml=model.raw_xml,
        )
