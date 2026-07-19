"""Parser de YAML Sigma -> `SigmaRule` de dominio.

Implementa el subconjunto real de la especificación Sigma usado por la
gran mayoría de reglas publicadas en el repositorio oficial SigmaHQ.
Deliberadamente vive en `domain/` (no en `infrastructure/`): parsear una
regla Sigma es una regla de negocio del dominio de detección, no un detalle
de framework — igual que `re` se usa dentro de `domain/entities/ioc.py`,
`yaml` se usa aquí. Ninguno de los dos toca SQL ni Qt.
"""

from __future__ import annotations

import yaml

from bluesentinel.domain.detection.sigma_rule import (
    FieldCondition,
    FieldModifier,
    Selection,
    SigmaRule,
)
from bluesentinel.domain.exceptions import RuleParsingError
from bluesentinel.domain.value_objects.enums import SigmaLevel, SigmaStatus

_RESERVED_KEYS = {"condition", "timeframe"}


def parse_sigma_rule(yaml_text: str) -> SigmaRule:
    """Parsea el YAML de una regla Sigma individual en un `SigmaRule` de dominio.

    Lanza `RuleParsingError` con un mensaje accionable si el YAML es
    inválido o usa una construcción Sigma no soportada (ver docstring del
    módulo `sigma_rule.py` para la lista de exclusiones documentadas).
    """
    try:
        raw = yaml.safe_load(yaml_text)
    except yaml.YAMLError as exc:
        raise RuleParsingError(f"YAML inválido: {exc}") from exc

    if not isinstance(raw, dict):
        raise RuleParsingError("La regla Sigma debe ser un mapeo YAML de nivel superior")

    detection = raw.get("detection")
    if not isinstance(detection, dict) or "condition" not in detection:
        raise RuleParsingError("La regla Sigma no tiene bloque 'detection.condition'")

    selections: dict[str, Selection] = {}
    for key, value in detection.items():
        if key in _RESERVED_KEYS:
            continue
        selections[key] = _parse_selection(key, value)

    logsource = raw.get("logsource", {}) or {}
    tags = raw.get("tags", []) or []
    mitre_ids = tuple(
        sorted(
            {
                tag.split(".", 1)[1].upper()
                for tag in tags
                if isinstance(tag, str) and tag.lower().startswith("attack.t")
            }
        )
    )

    try:
        level = SigmaLevel(str(raw.get("level", "medium")).lower())
    except ValueError as exc:
        raise RuleParsingError(f"Nivel de severidad Sigma no soportado: {raw.get('level')!r}") from exc

    try:
        status = SigmaStatus(str(raw.get("status", "experimental")).lower())
    except ValueError as exc:
        raise RuleParsingError(f"Status Sigma no soportado: {raw.get('status')!r}") from exc

    return SigmaRule(
        id=SigmaRule.new_id(),
        rule_id=str(raw.get("id", "")),
        title=str(raw.get("title", "Untitled Rule")),
        status=status,
        level=level,
        description=str(raw.get("description", "")),
        logsource_product=str(logsource.get("product", "")),
        logsource_category=str(logsource.get("category", "")),
        logsource_service=str(logsource.get("service", "")),
        selections=selections,
        condition=str(detection["condition"]),
        mitre_technique_ids=mitre_ids,
        false_positives=tuple(raw.get("falsepositives", []) or []),
        raw_yaml=yaml_text,
    )


def _parse_selection(name: str, value: object) -> Selection:
    if isinstance(value, dict):
        return Selection(name=name, and_groups=(_parse_and_group(value),))
    if isinstance(value, list):
        groups = tuple(_parse_and_group(item) for item in value if isinstance(item, dict))
        if not groups:
            raise RuleParsingError(f"Selección '{name}' es una lista vacía o inválida")
        return Selection(name=name, and_groups=groups)
    raise RuleParsingError(
        f"Selección '{name}' tiene un tipo no soportado: {type(value).__name__}"
    )


def _parse_and_group(mapping: dict) -> tuple[FieldCondition, ...]:
    conditions: list[FieldCondition] = []
    for raw_field, raw_values in mapping.items():
        field_name, modifier = _split_field_modifier(str(raw_field))
        values = _normalize_values(raw_values)
        conditions.append(
            FieldCondition(field_name=field_name, modifier=modifier, values=values)
        )
    return tuple(conditions)


def _split_field_modifier(raw_field: str) -> tuple[str, FieldModifier]:
    if "|" not in raw_field:
        return raw_field, FieldModifier.EQUALS
    field_name, _, modifier_str = raw_field.partition("|")
    modifier_map = {
        "contains": FieldModifier.CONTAINS,
        "startswith": FieldModifier.STARTSWITH,
        "endswith": FieldModifier.ENDSWITH,
        "re": FieldModifier.REGEX,
        "all": FieldModifier.ALL,
    }
    modifier = modifier_map.get(modifier_str)
    if modifier is None:
        raise RuleParsingError(
            f"Modificador de campo Sigma no soportado: '|{modifier_str}' en campo '{field_name}'"
        )
    return field_name, modifier


def _normalize_values(raw_values: object) -> tuple[str, ...]:
    if isinstance(raw_values, list):
        return tuple(str(v) for v in raw_values)
    return (str(raw_values),)
