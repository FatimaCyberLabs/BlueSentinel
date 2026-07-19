"""Jerarquía de excepciones de dominio de BlueSentinel.

La capa de aplicación e infraestructura deben traducir errores de bajo nivel
(SQLAlchemy, IO, parsing) a estas excepciones antes de que crucen hacia
`presentation`. Así la UI nunca necesita saber qué motor de BD se está usando.
"""

from __future__ import annotations


class BlueSentinelError(Exception):
    """Excepción base de todo el dominio de la aplicación."""


class EntityNotFoundError(BlueSentinelError):
    """Se solicitó una entidad (IOC, Case, Rule...) que no existe."""

    def __init__(self, entity_name: str, identifier: object) -> None:
        self.entity_name = entity_name
        self.identifier = identifier
        super().__init__(f"{entity_name} con id={identifier!r} no encontrado")


class DuplicateEntityError(BlueSentinelError):
    """Se intentó crear una entidad que ya existe (ej. un IOC con el mismo valor)."""

    def __init__(self, entity_name: str, identifier: object) -> None:
        self.entity_name = entity_name
        self.identifier = identifier
        super().__init__(f"{entity_name} con id={identifier!r} ya existe")


class InvalidEntityStateError(BlueSentinelError):
    """La entidad no puede realizar la transición de estado solicitada."""


class ValidationError(BlueSentinelError):
    """Los datos proporcionados no cumplen las invariantes del dominio."""


class RuleParsingError(BlueSentinelError):
    """Error al parsear una regla Sigma o YARA."""


class EventParsingError(BlueSentinelError):
    """Error al parsear un evento de Windows / Sysmon (EVTX o XML)."""
