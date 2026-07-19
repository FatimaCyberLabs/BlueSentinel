"""Carga paquetes de reglas Sigma (archivos YAML multi-documento, separados por `---`,
tal como se distribuyen los rule packs reales de SigmaHQ) desde el filesystem.

Vive en `infrastructure` (no en `domain`) porque *sí* toca el sistema de
archivos — a diferencia de `sigma_parser.parse_sigma_rule`, que solo
transforma texto ya en memoria y por eso vive en `domain/detection`.
"""

from __future__ import annotations

from pathlib import Path

import yaml

from bluesentinel.domain.detection.sigma_parser import parse_sigma_rule
from bluesentinel.domain.detection.sigma_rule import SigmaRule
from bluesentinel.domain.exceptions import RuleParsingError

BUILTIN_PACK_PATH = Path(__file__).parent / "packs" / "blueteam_core_pack.yml"


def load_rule_pack(path: Path) -> list[SigmaRule]:
    """Parsea un archivo YAML multi-documento en una lista de `SigmaRule`.

    Cada documento (separado por `---`) se re-serializa a YAML individual
    antes de pasarlo a `parse_sigma_rule`, para que el parser de dominio siga
    operando exclusivamente sobre texto de una sola regla — mantiene la
    frontera limpia entre "leer del disco" (infraestructura) y "entender una
    regla Sigma" (dominio).
    """
    text = path.read_text(encoding="utf-8")
    rules: list[SigmaRule] = []
    for index, document in enumerate(yaml.safe_load_all(text)):
        if document is None:
            continue
        try:
            single_yaml = yaml.safe_dump(document, sort_keys=False, allow_unicode=True)
            rules.append(parse_sigma_rule(single_yaml))
        except RuleParsingError as exc:
            raise RuleParsingError(
                f"Error en el documento #{index + 1} de {path.name}: {exc}"
            ) from exc
    return rules


def load_builtin_rule_pack() -> list[SigmaRule]:
    """Carga el paquete de reglas incluido con BlueSentinel (blueteam_core_pack.yml)."""
    return load_rule_pack(BUILTIN_PACK_PATH)
