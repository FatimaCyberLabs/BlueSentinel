"""Tests de la entidad Case, en particular su máquina de estados de IR."""

from __future__ import annotations

import pytest

from bluesentinel.domain.entities.case import Case
from bluesentinel.domain.exceptions import InvalidEntityStateError
from bluesentinel.domain.value_objects.enums import CaseStatus, EvidenceType, Severity


def test_open_new_case_starts_in_new_status() -> None:
    case = Case.open_new("Sospecha de exfiltración de datos")
    assert case.status == CaseStatus.NEW
    assert case.closed_at is None


def test_valid_transition_sequence_full_ir_lifecycle() -> None:
    case = Case.open_new("Ransomware detectado en HOST-01", severity=Severity.CRITICAL)
    case.transition_to(CaseStatus.TRIAGE)
    case.transition_to(CaseStatus.INVESTIGATING)
    case.transition_to(CaseStatus.CONTAINMENT)
    case.transition_to(CaseStatus.ERADICATION)
    case.transition_to(CaseStatus.RECOVERY)
    case.transition_to(CaseStatus.CLOSED_TRUE_POSITIVE)
    assert case.status == CaseStatus.CLOSED_TRUE_POSITIVE
    assert case.closed_at is not None


def test_invalid_transition_raises() -> None:
    case = Case.open_new("Alerta de phishing")
    with pytest.raises(InvalidEntityStateError):
        case.transition_to(CaseStatus.CLOSED_TRUE_POSITIVE)


def test_cannot_transition_out_of_closed_state() -> None:
    case = Case.open_new("Falso positivo de AV")
    case.transition_to(CaseStatus.TRIAGE)
    case.transition_to(CaseStatus.CLOSED_FALSE_POSITIVE)
    with pytest.raises(InvalidEntityStateError):
        case.transition_to(CaseStatus.INVESTIGATING)


def test_add_evidence_appends_reference() -> None:
    case = Case.open_new("Actividad sospechosa en endpoint")
    ref = case.add_evidence(EvidenceType.SIGMA_MATCH, ref_id="match-123", notes="Regla T1059")
    assert ref in case.evidence
    assert ref.evidence_type == EvidenceType.SIGMA_MATCH


def test_add_timeline_entry_keeps_chronological_order() -> None:
    from datetime import datetime, timedelta, timezone

    case = Case.open_new("Movimiento lateral")
    t0 = datetime.now(timezone.utc)
    case.add_timeline_entry(t0 + timedelta(minutes=10), "Segundo evento", "sysmon")
    case.add_timeline_entry(t0, "Primer evento", "event_log")
    assert case.timeline[0].description == "Primer evento"
    assert case.timeline[1].description == "Segundo evento"


def test_reassign_closed_case_raises() -> None:
    case = Case.open_new("Caso cerrado")
    case.transition_to(CaseStatus.TRIAGE)
    case.transition_to(CaseStatus.CLOSED_BENIGN)
    with pytest.raises(InvalidEntityStateError):
        case.reassign("analyst2")


def test_reassign_open_case_succeeds() -> None:
    case = Case.open_new("Caso abierto", assignee="analyst1")
    case.reassign("analyst2")
    assert case.assignee == "analyst2"
