"""Tests de `IOCService` usando un repositorio en memoria (test double)."""

from __future__ import annotations

from uuid import uuid4

import pytest

from bluesentinel.application.ioc.ioc_service import IOCService
from bluesentinel.domain.exceptions import EntityNotFoundError
from bluesentinel.domain.value_objects.enums import ConfidenceLevel, IOCType, Severity
from tests.unit.application.fakes import InMemoryIOCRepository


@pytest.fixture
def service() -> IOCService:
    return IOCService(InMemoryIOCRepository())


class TestIngestIOC:
    def test_ingest_creates_new_ioc(self, service: IOCService) -> None:
        summary = service.ingest_ioc(IOCType.IPV4, "8.8.8.8", source="test")
        assert summary.value == "8.8.8.8"
        assert service.get_active_count() == 1

    def test_ingest_duplicate_merges_instead_of_creating_second(
        self, service: IOCService
    ) -> None:
        service.ingest_ioc(IOCType.IPV4, "8.8.8.8", severity=Severity.LOW, source="feed-a")
        service.ingest_ioc(IOCType.IPV4, "8.8.8.8", severity=Severity.CRITICAL, source="feed-b")
        assert service.get_active_count() == 1
        results = service.list_active()
        assert results[0].severity == "critical"  # escaló, nunca bajó

    def test_ingest_reactivates_deactivated_ioc(self, service: IOCService) -> None:
        summary = service.ingest_ioc(IOCType.DOMAIN, "evil.com", source="test")
        service.deactivate_ioc(summary.id)
        assert service.get_active_count() == 0
        service.ingest_ioc(IOCType.DOMAIN, "evil.com", source="test-again")
        assert service.get_active_count() == 1

    def test_ingest_merges_tags(self, service: IOCService) -> None:
        service.ingest_ioc(IOCType.DOMAIN, "evil.com", source="a", tags={"apt29"})
        summary = service.ingest_ioc(IOCType.DOMAIN, "evil.com", source="b", tags={"ransomware"})
        assert "apt29" in summary.tags
        assert "ransomware" in summary.tags


class TestDeactivateIOC:
    def test_deactivate_existing(self, service: IOCService) -> None:
        summary = service.ingest_ioc(IOCType.SHA256, "a" * 64, source="test")
        service.deactivate_ioc(summary.id)
        assert service.get_active_count() == 0

    def test_deactivate_missing_raises(self, service: IOCService) -> None:
        with pytest.raises(EntityNotFoundError):
            service.deactivate_ioc(uuid4())


class TestListAndSearch:
    def test_list_active_filters_by_type(self, service: IOCService) -> None:
        service.ingest_ioc(IOCType.IPV4, "1.1.1.1", source="test")
        service.ingest_ioc(IOCType.DOMAIN, "evil.com", source="test")
        results = service.list_active(ioc_type=IOCType.DOMAIN)
        assert len(results) == 1
        assert results[0].ioc_type == "domain"

    def test_list_active_filters_by_min_severity(self, service: IOCService) -> None:
        service.ingest_ioc(IOCType.IPV4, "1.1.1.1", severity=Severity.LOW, source="test")
        service.ingest_ioc(IOCType.IPV4, "2.2.2.2", severity=Severity.CRITICAL, source="test")
        results = service.list_active(min_severity=Severity.HIGH)
        assert len(results) == 1
        assert results[0].value == "2.2.2.2"

    def test_search_matches_source(self, service: IOCService) -> None:
        service.ingest_ioc(
            IOCType.IPV4, "3.3.3.3", source="MISP-ThreatFeed", confidence=ConfidenceLevel.HIGH
        )
        results = service.search("MISP")
        assert len(results) == 1
