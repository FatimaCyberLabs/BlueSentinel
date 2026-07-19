"""Tests del `_ConditionEvaluator`: la gramática booleana de `detection.condition`.

Se prueba a través de `SigmaEvaluator.matches` (no se importa el `_ConditionEvaluator`
privado directamente) para verificar el comportamiento observable, no la
implementación interna.
"""

from __future__ import annotations

from datetime import datetime, timezone

import pytest

from bluesentinel.domain.detection.sigma_evaluator import SigmaEvaluator
from bluesentinel.domain.detection.sigma_parser import parse_sigma_rule
from bluesentinel.domain.exceptions import RuleParsingError
from bluesentinel.domain.entities.windows_event import SYSMON_PROCESS_CREATE, WindowsEvent


def _event(**fields: str) -> WindowsEvent:
    return WindowsEvent.create(
        event_id=SYSMON_PROCESS_CREATE,
        channel="Microsoft-Windows-Sysmon/Operational",
        computer="WKS-01",
        provider="Microsoft-Windows-Sysmon",
        time_created=datetime.now(timezone.utc),
        event_data=fields,
    )


def _rule_with_condition(condition: str, selections_yaml: str) -> str:
    return f"""
title: Test Rule
id: 11111111-1111-1111-1111-111111111111
level: medium
logsource:
  product: windows
  category: process_creation
detection:
{selections_yaml}
  condition: {condition}
"""


SELECTIONS = """  sel_a:
    Image|endswith: '\\a.exe'
  sel_b:
    Image|endswith: '\\b.exe'
  sel_c:
    Image|endswith: '\\c.exe'
"""


class TestBooleanOperators:
    def test_and(self) -> None:
        rule = parse_sigma_rule(_rule_with_condition("sel_a and sel_b", SELECTIONS))
        # Ninguna selección referencia CommandLine, así que dos condiciones sobre el
        # mismo Image nunca son simultáneamente true -> el AND siempre es False aquí,
        # lo cual es exactamente lo que se espera semánticamente.
        event = _event(Image=r"C:\a.exe")
        assert SigmaEvaluator().matches(rule, event) is None

    def test_or(self) -> None:
        rule = parse_sigma_rule(_rule_with_condition("sel_a or sel_c", SELECTIONS))
        assert SigmaEvaluator().matches(rule, _event(Image=r"C:\a.exe")) is not None
        assert SigmaEvaluator().matches(rule, _event(Image=r"C:\c.exe")) is not None
        assert SigmaEvaluator().matches(rule, _event(Image=r"C:\b.exe")) is None

    def test_not(self) -> None:
        rule = parse_sigma_rule(_rule_with_condition("sel_a and not sel_b", SELECTIONS))
        assert SigmaEvaluator().matches(rule, _event(Image=r"C:\a.exe")) is not None

    def test_parentheses_change_precedence(self) -> None:
        rule = parse_sigma_rule(
            _rule_with_condition("(sel_a or sel_b) and not sel_c", SELECTIONS)
        )
        assert SigmaEvaluator().matches(rule, _event(Image=r"C:\a.exe")) is not None
        assert SigmaEvaluator().matches(rule, _event(Image=r"C:\c.exe")) is None


class TestQuantifiers:
    def test_one_of_them(self) -> None:
        rule = parse_sigma_rule(_rule_with_condition("1 of them", SELECTIONS))
        assert SigmaEvaluator().matches(rule, _event(Image=r"C:\b.exe")) is not None

    def test_all_of_them_requires_every_selection(self) -> None:
        rule = parse_sigma_rule(_rule_with_condition("all of them", SELECTIONS))
        # Un solo evento no puede matchear las 3 selecciones mutuamente excluyentes.
        assert SigmaEvaluator().matches(rule, _event(Image=r"C:\a.exe")) is None

    def test_one_of_prefix_wildcard(self) -> None:
        rule = parse_sigma_rule(_rule_with_condition("1 of sel_*", SELECTIONS))
        assert SigmaEvaluator().matches(rule, _event(Image=r"C:\c.exe")) is not None

    def test_unknown_selection_raises(self) -> None:
        rule = parse_sigma_rule(_rule_with_condition("sel_a and sel_nonexistent", SELECTIONS))
        with pytest.raises(RuleParsingError):
            SigmaEvaluator().matches(rule, _event(Image=r"C:\a.exe"))

    def test_unclosed_parenthesis_raises(self) -> None:
        rule = parse_sigma_rule(_rule_with_condition("(sel_a and sel_b", SELECTIONS))
        with pytest.raises(RuleParsingError):
            SigmaEvaluator().matches(rule, _event(Image=r"C:\a.exe"))
