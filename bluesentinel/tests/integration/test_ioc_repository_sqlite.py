"""Test de integración: `SQLAlchemyIOCRepository` contra SQLite real en memoria.

A diferencia de los tests unitarios (que usan el fake en memoria), estos
verifican que el mapeo Data Mapper y las constraints de la BD (unicidad,
persistencia real) funcionan de punta a punta.
"""

from __future__ import annotations

import pytest
from sqlalchemy import create_engine
from sqlalchemy.orm import Session

from bluesentinel.domain.entities.ioc import IOC
from bluesentinel.domain.exceptions import DuplicateEntityError, EntityNotFoundError
from bluesentinel.domain.value_objects.enums import ConfidenceLevel, IOCType, Severity
from bluesentinel.infrastructure.db.base import Base
from bluesentinel.infrastructure.db.repositories.ioc_repository_impl import (
    SQLAlchemyIOCRepository,
)


@pytest.fixture
def session() -> Session:
    engine = create_engine("sqlite:///:memory:", future=True)
    Base.metadata.create_all(engine)
    with Session(engine) as sess:
        yield sess


def test_add_and_get_by_id_roundtrip(session: Session) -> None:
    repo = SQLAlchemyIOCRepository(session)
    ioc = IOC.create(IOCType.IPV4, "203.0.113.5", severity=Severity.HIGH, source="test")
    repo.add(ioc)
    session.commit()

    fetched = repo.get_by_id(ioc.id)
    assert fetched is not None
    assert fetched.value == "203.0.113.5"
    assert fetched.severity == Severity.HIGH


def test_unique_constraint_raises_duplicate_error(session: Session) -> None:
    repo = SQLAlchemyIOCRepository(session)
    ioc1 = IOC.create(IOCType.DOMAIN, "malicious.example.com", source="test")
    repo.add(ioc1)
    session.commit()

    ioc2 = IOC.create(IOCType.DOMAIN, "malicious.example.com", source="test2")
    with pytest.raises(DuplicateEntityError):
        repo.add(ioc2)


def test_get_by_value(session: Session) -> None:
    repo = SQLAlchemyIOCRepository(session)
    ioc = IOC.create(IOCType.SHA256, "b" * 64, source="test")
    repo.add(ioc)
    session.commit()

    found = repo.get_by_value(IOCType.SHA256, "b" * 64)
    assert found is not None
    assert found.id == ioc.id


def test_find_active_excludes_inactive(session: Session) -> None:
    repo = SQLAlchemyIOCRepository(session)
    active = IOC.create(IOCType.IPV4, "1.1.1.1", source="test")
    inactive = IOC.create(IOCType.IPV4, "2.2.2.2", source="test")
    inactive.deactivate()
    repo.add(active)
    repo.add(inactive)
    session.commit()

    results = repo.find_active()
    values = {i.value for i in results}
    assert "1.1.1.1" in values
    assert "2.2.2.2" not in values


def test_update_persists_changes(session: Session) -> None:
    repo = SQLAlchemyIOCRepository(session)
    ioc = IOC.create(IOCType.IPV4, "9.9.9.9", severity=Severity.LOW, source="test")
    repo.add(ioc)
    session.commit()

    ioc.escalate(Severity.CRITICAL)
    ioc.add_tag("botnet")
    repo.update(ioc)
    session.commit()

    fetched = repo.get_by_id(ioc.id)
    assert fetched is not None
    assert fetched.severity == Severity.CRITICAL
    assert "botnet" in fetched.tags


def test_update_missing_raises_not_found(session: Session) -> None:
    repo = SQLAlchemyIOCRepository(session)
    ghost = IOC.create(IOCType.IPV4, "5.5.5.5", source="test")
    with pytest.raises(EntityNotFoundError):
        repo.update(ghost)


def test_delete_removes_entity(session: Session) -> None:
    repo = SQLAlchemyIOCRepository(session)
    ioc = IOC.create(IOCType.IPV4, "6.6.6.6", source="test")
    repo.add(ioc)
    session.commit()

    repo.delete(ioc.id)
    session.commit()
    assert repo.get_by_id(ioc.id) is None


def test_count_active(session: Session) -> None:
    repo = SQLAlchemyIOCRepository(session)
    for i in range(3):
        repo.add(IOC.create(IOCType.IPV4, f"10.0.0.{i}", source="test"))
    inactive = IOC.create(IOCType.IPV4, "10.0.0.99", source="test")
    inactive.deactivate()
    repo.add(inactive)
    session.commit()

    assert repo.count_active() == 3


def test_search_matches_tags(session: Session) -> None:
    repo = SQLAlchemyIOCRepository(session)
    ioc = IOC.create(
        IOCType.DOMAIN,
        "c2.example.com",
        source="test",
        tags={"cobaltstrike"},
        confidence=ConfidenceLevel.HIGH,
    )
    repo.add(ioc)
    session.commit()

    results = repo.search("cobaltstrike")
    assert len(results) == 1
    assert results[0].value == "c2.example.com"
