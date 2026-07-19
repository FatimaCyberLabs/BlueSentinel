"""Motor de evaluación de reglas Sigma contra `WindowsEvent`.

Dos responsabilidades separadas deliberadamente:
  1. `_evaluate_selection`: ¿matchea esta selección contra este evento?
  2. `_ConditionEvaluator`: parsea y evalúa la expresión booleana de
     `detection.condition` (ej. `selection1 and not filter`, `1 of sel_*`),
     resolviendo cada nombre de selección llamando a (1).

Separar el "qué campo matchea" del "cómo se combinan las selecciones" es
exactamente cómo lo hace `pySigma` (el motor de referencia mantenido por
SigmaHQ) — y es lo que permite testear cada parte de forma aislada.
"""

from __future__ import annotations

import fnmatch
import re
from dataclasses import dataclass

from bluesentinel.domain.detection.sigma_rule import FieldCondition, FieldModifier, Selection, SigmaRule
from bluesentinel.domain.entities.windows_event import WindowsEvent
from bluesentinel.domain.exceptions import RuleParsingError


@dataclass(slots=True, frozen=True)
class SigmaMatch:
    """Resultado de una evaluación positiva: qué regla, qué evento, qué selecciones."""

    rule: SigmaRule
    event: WindowsEvent
    matched_selections: tuple[str, ...]


class SigmaEvaluator:
    """Evalúa un conjunto de `SigmaRule` contra un `WindowsEvent`."""

    def matches(self, rule: SigmaRule, event: WindowsEvent) -> SigmaMatch | None:
        if not rule.enabled:
            return None
        selection_results = {
            name: self._evaluate_selection(sel, event) for name, sel in rule.selections.items()
        }
        condition_evaluator = _ConditionEvaluator(selection_results)
        if condition_evaluator.evaluate(rule.condition):
            matched = tuple(name for name, result in selection_results.items() if result)
            return SigmaMatch(rule=rule, event=event, matched_selections=matched)
        return None

    def evaluate_batch(self, rules: list[SigmaRule], events: list[WindowsEvent]) -> list[SigmaMatch]:
        """Evalúa todas las reglas contra todos los eventos. O(rules * events) — para
        volúmenes grandes de eventos, `infrastructure` puede pre-indexar por
        `logsource`/`event_id` antes de llamar aquí; ese pre-filtro es una
        optimización de infraestructura, no cambia la semántica del dominio.
        """
        results: list[SigmaMatch] = []
        for event in events:
            for rule in rules:
                match = self.matches(rule, event)
                if match is not None:
                    results.append(match)
        return results

    # -- Evaluación de selecciones -------------------------------------------------

    def _evaluate_selection(self, selection: Selection, event: WindowsEvent) -> bool:
        # OR entre grupos; AND dentro de cada grupo — ver docstring de `Selection`.
        return any(
            all(self._evaluate_condition(cond, event) for cond in group)
            for group in selection.and_groups
        )

    def _evaluate_condition(self, condition: FieldCondition, event: WindowsEvent) -> bool:
        actual = event.field_value(condition.field_name)
        if actual is None:
            return False
        if not condition.case_sensitive:
            actual_cmp = actual.lower()
            values_cmp = tuple(v.lower() for v in condition.values)
        else:
            actual_cmp = actual
            values_cmp = condition.values

        if condition.modifier == FieldModifier.EQUALS:
            return any(self._glob_match(actual_cmp, v) for v in values_cmp)
        if condition.modifier == FieldModifier.CONTAINS:
            return any(v in actual_cmp for v in values_cmp)
        if condition.modifier == FieldModifier.STARTSWITH:
            return any(actual_cmp.startswith(v) for v in values_cmp)
        if condition.modifier == FieldModifier.ENDSWITH:
            return any(actual_cmp.endswith(v) for v in values_cmp)
        if condition.modifier == FieldModifier.REGEX:
            flags = 0 if condition.case_sensitive else re.IGNORECASE
            return any(re.search(v, actual, flags) for v in condition.values)
        if condition.modifier == FieldModifier.ALL:
            return all(v in actual_cmp for v in values_cmp)
        return False

    @staticmethod
    def _glob_match(actual: str, pattern: str) -> bool:
        """Sigma usa `*`/`?` como wildcards en coincidencia exacta, igual que fnmatch."""
        if "*" in pattern or "?" in pattern:
            return fnmatch.fnmatchcase(actual, pattern)
        return actual == pattern


class _ConditionEvaluator:
    """Parser + evaluador recursivo-descendente de la expresión booleana de Sigma.

    Gramática soportada (subconjunto real de Sigma, cubre la gran mayoría
    de reglas de SigmaHQ)::

        expr        := or_expr
        or_expr     := and_expr ("or" and_expr)*
        and_expr    := not_expr ("and" not_expr)*
        not_expr    := "not" not_expr | atom
        atom        := "(" expr ")" | quantifier | IDENTIFIER
        quantifier  := ("1" | "all") "of" (IDENTIFIER | IDENTIFIER"*" | "them")
    """

    def __init__(self, selection_results: dict[str, bool]) -> None:
        self._results = selection_results
        self._tokens: list[str] = []
        self._pos = 0

    def evaluate(self, condition: str) -> bool:
        self._tokens = self._tokenize(condition)
        self._pos = 0
        result = self._parse_or()
        if self._pos != len(self._tokens):
            raise RuleParsingError(f"Expresión de condición Sigma mal formada: {condition!r}")
        return result

    @staticmethod
    def _tokenize(condition: str) -> list[str]:
        spaced = condition.replace("(", " ( ").replace(")", " ) ")
        return [tok for tok in spaced.split() if tok]

    def _peek(self) -> str | None:
        return self._tokens[self._pos] if self._pos < len(self._tokens) else None

    def _advance(self) -> str:
        tok = self._tokens[self._pos]
        self._pos += 1
        return tok

    def _parse_or(self) -> bool:
        result = self._parse_and()
        while self._peek() == "or":
            self._advance()
            rhs = self._parse_and()
            result = result or rhs
        return result

    def _parse_and(self) -> bool:
        result = self._parse_not()
        while self._peek() == "and":
            self._advance()
            rhs = self._parse_not()
            result = result and rhs
        return result

    def _parse_not(self) -> bool:
        if self._peek() == "not":
            self._advance()
            return not self._parse_not()
        return self._parse_atom()

    def _parse_atom(self) -> bool:
        tok = self._peek()
        if tok is None:
            raise RuleParsingError("Expresión de condición Sigma incompleta")
        if tok == "(":
            self._advance()
            result = self._parse_or()
            if self._peek() != ")":
                raise RuleParsingError("Paréntesis sin cerrar en condición Sigma")
            self._advance()
            return result
        if (
            tok in ("1", "all")
            and self._pos + 1 < len(self._tokens)
            and self._tokens[self._pos + 1] == "of"
        ):
            return self._parse_quantifier()
        self._advance()
        return self._resolve_identifier(tok)

    def _parse_quantifier(self) -> bool:
        quantifier = self._advance()  # "1" o "all"
        self._advance()  # "of"
        target = self._advance()  # identificador, "identificador*" o "them"

        if target == "them":
            matched = list(self._results.values())
        elif target.endswith("*"):
            prefix = target[:-1]
            matched = [v for k, v in self._results.items() if k.startswith(prefix)]
        else:
            matched = [self._resolve_identifier(target)]

        if not matched:
            return False
        return any(matched) if quantifier == "1" else all(matched)

    def _resolve_identifier(self, name: str) -> bool:
        if name not in self._results:
            raise RuleParsingError(
                f"La condición referencia la selección '{name}', que no existe en 'detection'"
            )
        return self._results[name]
