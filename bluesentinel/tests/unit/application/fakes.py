"""Test double de `IOCRepository`: implementación en memoria.

Al depender `IOCService` de un `Protocol` (no de una clase concreta),
podemos testear toda la lógica de negocio sin tocar SQLAlchemy ni SQLite.
Esto es la prueba práctica de que la Dependency Inversion funciona.
"""

from __future__ import annotations

from uuid import UUID

from bluesentinel.domain.entities.ioc import IOC
from bluesentinel.domain.exceptions import DuplicateEntityError, EntityNotFoundError
from bluesentinel.domain.value_objects.enums import IOCType


class InMemoryIOCRepository:
    def __init__(self) -> None:
        self._store: dict[UUID, IOC] = {}

    def add(self, ioc: IOC) -> None:
        if self.get_by_value(ioc.ioc_type, ioc.value) is not None:
            raise DuplicateEntityError("IOC", f"{ioc.ioc_type.value}:{ioc.value}")
        self._store[ioc.id] = ioc

    def get_by_id(self, ioc_id: UUID) -> IOC | None:
        return self._store.get(ioc_id)

    def get_by_value(self, ioc_type: IOCType, value: str) -> IOC | None:
        for ioc in self._store.values():
            if ioc.ioc_type == ioc_type and ioc.value == value:
                return ioc
        return None

    def find_active(
        self,
        ioc_type: IOCType | None = None,
        min_severity_weight: int | None = None,
        limit: int = 100,
        offset: int = 0,
    ) -> list[IOC]:
        results = [i for i in self._store.values() if i.is_active]
        if ioc_type is not None:
            results = [i for i in results if i.ioc_type == ioc_type]
        if min_severity_weight is not None:
            results = [i for i in results if i.severity.weight >= min_severity_weight]
        results.sort(key=lambda i: i.last_seen, reverse=True)
        return results[offset : offset + limit]

    def search(self, query: str, limit: int = 100) -> list[IOC]:
        q = query.lower()
        results = [
            i
            for i in self._store.values()
            if q in i.value.lower() or q in i.source.lower() or q in i.notes.lower()
        ]
        return results[:limit]

    def update(self, ioc: IOC) -> None:
        if ioc.id not in self._store:
            raise EntityNotFoundError("IOC", ioc.id)
        self._store[ioc.id] = ioc

    def delete(self, ioc_id: UUID) -> None:
        if ioc_id not in self._store:
            raise EntityNotFoundError("IOC", ioc_id)
        del self._store[ioc_id]

    def count_active(self) -> int:
        return sum(1 for i in self._store.values() if i.is_active)
