"""Puerto (interfaz) del repositorio de IOCs.

Definido como `Protocol` estructural: la capa de aplicación depende de esta
interfaz, nunca de una implementación concreta (Dependency Inversion). La
implementación real vive en `infrastructure.db.repositories.ioc_repository_impl`.
"""

from __future__ import annotations

from typing import Protocol
from uuid import UUID

from bluesentinel.domain.entities.ioc import IOC
from bluesentinel.domain.value_objects.enums import IOCType


class IOCRepository(Protocol):
    """Contrato de persistencia para la entidad IOC."""

    def add(self, ioc: IOC) -> None:
        """Persiste un nuevo IOC. Lanza `DuplicateEntityError` si (type, value) ya existe."""
        ...

    def get_by_id(self, ioc_id: UUID) -> IOC | None:
        """Devuelve el IOC con ese id, o None si no existe."""
        ...

    def get_by_value(self, ioc_type: IOCType, value: str) -> IOC | None:
        """Búsqueda exacta por tipo + valor (usada para deduplicación)."""
        ...

    def find_active(
        self,
        ioc_type: IOCType | None = None,
        min_severity_weight: int | None = None,
        limit: int = 100,
        offset: int = 0,
    ) -> list[IOC]:
        """Lista IOCs activos, con filtros opcionales, paginado."""
        ...

    def search(self, query: str, limit: int = 100) -> list[IOC]:
        """Búsqueda de texto libre sobre valor, source, tags y notas."""
        ...

    def update(self, ioc: IOC) -> None:
        """Persiste cambios sobre un IOC existente."""
        ...

    def delete(self, ioc_id: UUID) -> None:
        """Elimina un IOC. Usado raramente; preferir `deactivate()` en el dominio."""
        ...

    def count_active(self) -> int:
        """Total de IOCs activos, usado en el Dashboard."""
        ...
