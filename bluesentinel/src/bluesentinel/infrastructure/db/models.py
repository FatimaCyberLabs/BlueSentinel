"""Modelos ORM de SQLAlchemy: mapeo fisico de las tablas de BlueSentinel.

Alineado con el redesign a 7 modulos (ver docs/ARCHITECTURE.md): se
eliminaron las tablas de YARA Scanner y Threat Feed Importer (modulos
cortados) y se unifico `windows_events` + `sysmon_events` en una unica
tabla `windows_events` con `event_data` serializado en JSON, reflejando
la entidad de dominio unica `domain.entities.windows_event.WindowsEvent`.

Nota de diseno: estos modelos son deliberadamente "tontos" (sin logica de
negocio) -- son DTOs de persistencia. La logica vive en las entidades de
`domain`. Los repositorios de `infrastructure.db.repositories` traducen
entre unos y otros (patron Data Mapper).
"""

from __future__ import annotations

import uuid
from datetime import datetime

from sqlalchemy import (
    Boolean,
    DateTime,
    ForeignKey,
    Index,
    Integer,
    String,
    Text,
    UniqueConstraint,
)
from sqlalchemy.orm import Mapped, mapped_column, relationship

from bluesentinel.infrastructure.db.base import Base


def _uuid_str() -> str:
    return str(uuid.uuid4())


class IOCModel(Base):
    __tablename__ = "iocs"
    __table_args__ = (
        UniqueConstraint("ioc_type", "value", name="uq_ioc_type_value"),
        Index("ix_ioc_value", "value"),
    )

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=_uuid_str)
    ioc_type: Mapped[str] = mapped_column(String(32), nullable=False)
    value: Mapped[str] = mapped_column(String(512), nullable=False)
    severity: Mapped[str] = mapped_column(String(16), nullable=False)
    confidence: Mapped[str] = mapped_column(String(16), nullable=False)
    source: Mapped[str] = mapped_column(String(128), nullable=False)
    tags: Mapped[str] = mapped_column(Text, default="")
    notes: Mapped[str] = mapped_column(Text, default="")
    first_seen: Mapped[datetime] = mapped_column(DateTime, nullable=False)
    last_seen: Mapped[datetime] = mapped_column(DateTime, nullable=False)
    is_active: Mapped[bool] = mapped_column(Boolean, default=True)


class WindowsEventModel(Base):
    """Un evento de Windows normalizado (Security, Sysmon, PowerShell...).

    `event_data` almacena el diccionario completo de campos crudos del
    evento como JSON -- el mismo dato que `WindowsEvent.event_data` en el
    dominio, sin perdida de fidelidad y sin forzar un esquema de columnas
    fijo que tendria que cambiar por cada nuevo Event ID soportado.
    """

    __tablename__ = "windows_events"
    __table_args__ = (
        Index("ix_winevent_time", "time_created"),
        Index("ix_winevent_event_id", "event_id"),
    )

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=_uuid_str)
    event_id: Mapped[int] = mapped_column(Integer, nullable=False)
    channel: Mapped[str] = mapped_column(String(128), nullable=False)
    computer: Mapped[str] = mapped_column(String(256), nullable=False)
    provider: Mapped[str] = mapped_column(String(256), nullable=False)
    time_created: Mapped[datetime] = mapped_column(DateTime, nullable=False)
    level: Mapped[int] = mapped_column(Integer, default=0)
    task_category: Mapped[str] = mapped_column(String(256), default="")
    event_data_json: Mapped[str] = mapped_column(Text, nullable=False, default="{}")
    raw_xml: Mapped[str] = mapped_column(Text, default="")
    case_id: Mapped[str | None] = mapped_column(String(36), ForeignKey("cases.id"), nullable=True)


class SigmaRuleModel(Base):
    __tablename__ = "sigma_rules"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=_uuid_str)
    rule_id: Mapped[str] = mapped_column(String(64), unique=True, nullable=False)
    title: Mapped[str] = mapped_column(String(256), nullable=False)
    status: Mapped[str] = mapped_column(String(32), nullable=False)
    level: Mapped[str] = mapped_column(String(16), nullable=False)
    logsource_product: Mapped[str] = mapped_column(String(64), default="")
    logsource_category: Mapped[str] = mapped_column(String(64), default="")
    logsource_service: Mapped[str] = mapped_column(String(64), default="")
    yaml_source: Mapped[str] = mapped_column(Text, nullable=False)
    enabled: Mapped[bool] = mapped_column(Boolean, default=True)
    mitre_technique_ids: Mapped[str] = mapped_column(Text, default="")  # CSV: T1059,T1055...


class SigmaMatchModel(Base):
    __tablename__ = "sigma_matches"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=_uuid_str)
    rule_id: Mapped[str] = mapped_column(String(36), ForeignKey("sigma_rules.id"), nullable=False)
    event_id: Mapped[str] = mapped_column(
        String(36), ForeignKey("windows_events.id"), nullable=False
    )
    matched_selections: Mapped[str] = mapped_column(Text, default="")  # CSV
    matched_at: Mapped[datetime] = mapped_column(DateTime, nullable=False)
    case_id: Mapped[str | None] = mapped_column(String(36), ForeignKey("cases.id"), nullable=True)


class MitreTechniqueModel(Base):
    __tablename__ = "mitre_techniques"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=_uuid_str)
    technique_id: Mapped[str] = mapped_column(String(16), unique=True, nullable=False)
    name: Mapped[str] = mapped_column(String(256), nullable=False)
    tactic: Mapped[str] = mapped_column(String(64), nullable=False)
    sub_technique_of: Mapped[str | None] = mapped_column(String(16), nullable=True)


class CaseModel(Base):
    __tablename__ = "cases"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=_uuid_str)
    title: Mapped[str] = mapped_column(String(256), nullable=False)
    status: Mapped[str] = mapped_column(String(32), nullable=False)
    severity: Mapped[str] = mapped_column(String(16), nullable=False)
    assignee: Mapped[str | None] = mapped_column(String(128), nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime, nullable=False)
    closed_at: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)
    summary: Mapped[str] = mapped_column(Text, default="")
    affected_hosts: Mapped[str] = mapped_column(Text, default="")  # CSV

    evidence: Mapped[list["CaseEvidenceModel"]] = relationship(
        back_populates="case", cascade="all, delete-orphan"
    )
    timeline: Mapped[list["CaseTimelineModel"]] = relationship(
        back_populates="case",
        cascade="all, delete-orphan",
        order_by="CaseTimelineModel.timestamp",
    )
    notes: Mapped[list["CaseNoteModel"]] = relationship(
        back_populates="case", cascade="all, delete-orphan", order_by="CaseNoteModel.created_at"
    )


class CaseEvidenceModel(Base):
    __tablename__ = "case_evidence"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=_uuid_str)
    case_id: Mapped[str] = mapped_column(String(36), ForeignKey("cases.id"), nullable=False)
    evidence_type: Mapped[str] = mapped_column(String(32), nullable=False)
    ref_id: Mapped[str] = mapped_column(String(64), nullable=False)
    notes: Mapped[str] = mapped_column(Text, default="")
    added_at: Mapped[datetime] = mapped_column(DateTime, nullable=False)

    case: Mapped[CaseModel] = relationship(back_populates="evidence")


class CaseTimelineModel(Base):
    __tablename__ = "case_timeline"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=_uuid_str)
    case_id: Mapped[str] = mapped_column(String(36), ForeignKey("cases.id"), nullable=False)
    timestamp: Mapped[datetime] = mapped_column(DateTime, nullable=False)
    description: Mapped[str] = mapped_column(Text, nullable=False)
    source_module: Mapped[str] = mapped_column(String(64), nullable=False)

    case: Mapped[CaseModel] = relationship(back_populates="timeline")


class CaseNoteModel(Base):
    """Nota de analista adjunta a un caso -- texto libre, editable, con autoria."""

    __tablename__ = "case_notes"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=_uuid_str)
    case_id: Mapped[str] = mapped_column(String(36), ForeignKey("cases.id"), nullable=False)
    author: Mapped[str] = mapped_column(String(128), nullable=False)
    content: Mapped[str] = mapped_column(Text, nullable=False)
    created_at: Mapped[datetime] = mapped_column(DateTime, nullable=False)

    case: Mapped[CaseModel] = relationship(back_populates="notes")


class AuditLogModel(Base):
    __tablename__ = "audit_log"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    actor: Mapped[str] = mapped_column(String(128), nullable=False)
    action: Mapped[str] = mapped_column(String(64), nullable=False)
    entity_type: Mapped[str] = mapped_column(String(64), nullable=False)
    entity_id: Mapped[str] = mapped_column(String(64), nullable=False)
    timestamp: Mapped[datetime] = mapped_column(DateTime, nullable=False)
    details: Mapped[str] = mapped_column(Text, default="")
