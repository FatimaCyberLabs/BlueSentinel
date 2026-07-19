"""Representación de dominio de una regla Sigma (post-parseo).

Cubre el subconjunto de la especificación oficial de Sigma
(https://github.com/SigmaHQ/sigma-specification) que aparece en la
inmensa mayoría de reglas publicadas en SigmaHQ: selecciones con
modificadores de campo (`contains`, `startswith`, `endswith`, `re`, `all`),
listas de valores (OR implícito), múltiples campos (AND implícito), y
expresiones de condición con `and`/`or`/`not`/paréntesis/`1 of`/`all of`/`them`.

No implementa (documentado y deliberado, no un descuido):
  - agregaciones temporales (`count() by ... > N`) — requieren estado de
    ventana deslizante, se deja para una iteración de "correlation engine"
    separada, ver docs/ARCHITECTURE.md.
  - `near` / regla-a-regla.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import StrEnum
from uuid import UUID, uuid4

from bluesentinel.domain.value_objects.enums import SigmaLevel, SigmaStatus


class FieldModifier(StrEnum):
    EQUALS = "equals"
    CONTAINS = "contains"
    STARTSWITH = "startswith"
    ENDSWITH = "endswith"
    REGEX = "re"
    ALL = "all"  # todos los valores de la lista deben matchear (en vez de OR)


@dataclass(slots=True, frozen=True)
class FieldCondition:
    """Una condición atómica: `campo|modificador: valor(es)`."""

    field_name: str
    modifier: FieldModifier
    values: tuple[str, ...]
    case_sensitive: bool = False


@dataclass(slots=True, frozen=True)
class Selection:
    """Un bloque `selection`/`filter` de la sección `detection`.

    Internamente es una lista de "AND-groups": cada dict del YAML original
    se convierte en un grupo donde todos sus `FieldCondition` deben
    cumplirse (AND), y los distintos grupos de la lista se combinan con OR
    — esto replica exactamente la semántica de Sigma cuando una selección
    es una lista de mapas.
    """

    name: str
    and_groups: tuple[tuple[FieldCondition, ...], ...]


@dataclass(slots=True)
class SigmaRule:
    """Regla Sigma parseada, lista para ser evaluada por `SigmaEvaluator`."""

    id: UUID
    rule_id: str  # el `id` YAML de Sigma (UUID de SigmaHQ), no el UUID interno
    title: str
    status: SigmaStatus
    level: SigmaLevel
    description: str
    logsource_product: str
    logsource_category: str
    logsource_service: str
    selections: dict[str, Selection]
    condition: str
    mitre_technique_ids: tuple[str, ...]
    false_positives: tuple[str, ...]
    raw_yaml: str
    enabled: bool = True

    @classmethod
    def new_id(cls) -> UUID:
        return uuid4()
