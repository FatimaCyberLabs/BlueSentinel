"""Tests de la entidad de dominio IOC — sin BD, sin Qt, pura lógica de negocio."""

from __future__ import annotations

from datetime import datetime, timedelta, timezone

import pytest

from bluesentinel.domain.entities.ioc import IOC
from bluesentinel.domain.exceptions import ValidationError
from bluesentinel.domain.value_objects.enums import ConfidenceLevel, IOCType, Severity


class TestIOCCreation:
    def test_create_valid_sha256(self) -> None:
        ioc = IOC.create(IOCType.SHA256, "a" * 64, source="test")
        assert ioc.value == "a" * 64
        assert ioc.is_active is True
        assert ioc.severity == Severity.MEDIUM

    def test_create_normalizes_hash_to_lowercase(self) -> None:
        ioc = IOC.create(IOCType.MD5, "A" * 32, source="test")
        assert ioc.value == "a" * 32

    def test_create_normalizes_domain_trailing_dot(self) -> None:
        ioc = IOC.create(IOCType.DOMAIN, "evil.example.com.", source="test")
        assert ioc.value == "evil.example.com"

    @pytest.mark.parametrize(
        ("ioc_type", "value"),
        [
            (IOCType.SHA256, "not-a-hash"),
            (IOCType.SHA256, "a" * 63),  # longitud incorrecta
            (IOCType.MD5, "z" * 32),  # caracteres no hex
            (IOCType.IPV4, "999.999.999.999"),
            (IOCType.IPV4, "not-an-ip"),
            (IOCType.DOMAIN, "-invalid-.com"),
            (IOCType.EMAIL, "not-an-email"),
            (IOCType.URL, "ftp://missing-http-scheme.com"),
        ],
    )
    def test_create_rejects_invalid_values(self, ioc_type: IOCType, value: str) -> None:
        with pytest.raises(ValidationError):
            IOC.create(ioc_type, value, source="test")

    def test_create_rejects_empty_value(self) -> None:
        with pytest.raises(ValidationError):
            IOC.create(IOCType.DOMAIN, "   ", source="test")


class TestIOCLifecycle:
    def test_mark_seen_extends_last_seen(self) -> None:
        ioc = IOC.create(IOCType.IPV4, "1.2.3.4", source="test")
        later = ioc.last_seen + timedelta(days=1)
        ioc.mark_seen(later)
        assert ioc.last_seen == later

    def test_mark_seen_extends_first_seen_backwards(self) -> None:
        ioc = IOC.create(IOCType.IPV4, "1.2.3.4", source="test")
        earlier = ioc.first_seen - timedelta(days=5)
        ioc.mark_seen(earlier)
        assert ioc.first_seen == earlier

    def test_mark_seen_reactivates_inactive_ioc(self) -> None:
        ioc = IOC.create(IOCType.IPV4, "1.2.3.4", source="test")
        ioc.deactivate()
        assert ioc.is_active is False
        ioc.mark_seen(datetime.now(timezone.utc))
        assert ioc.is_active is True

    def test_deactivate(self) -> None:
        ioc = IOC.create(IOCType.IPV4, "1.2.3.4", source="test")
        ioc.deactivate()
        assert ioc.is_active is False

    def test_escalate_raises_severity(self) -> None:
        ioc = IOC.create(IOCType.IPV4, "1.2.3.4", severity=Severity.LOW, source="test")
        ioc.escalate(Severity.CRITICAL)
        assert ioc.severity == Severity.CRITICAL

    def test_escalate_never_lowers_severity(self) -> None:
        ioc = IOC.create(IOCType.IPV4, "1.2.3.4", severity=Severity.HIGH, source="test")
        ioc.escalate(Severity.LOW)
        assert ioc.severity == Severity.HIGH

    def test_add_tag_normalizes_case_and_whitespace(self) -> None:
        ioc = IOC.create(IOCType.IPV4, "1.2.3.4", source="test")
        ioc.add_tag("  APT29  ")
        assert "apt29" in ioc.tags


class TestSeverityWeight:
    def test_severity_ordering(self) -> None:
        assert Severity.CRITICAL.weight > Severity.HIGH.weight
        assert Severity.HIGH.weight > Severity.MEDIUM.weight
        assert Severity.MEDIUM.weight > Severity.LOW.weight
        assert Severity.LOW.weight > Severity.INFORMATIONAL.weight


class TestConfidenceLevel:
    def test_default_confidence_is_unknown(self) -> None:
        ioc = IOC.create(IOCType.IPV4, "1.2.3.4", source="test")
        assert ioc.confidence == ConfidenceLevel.UNKNOWN
