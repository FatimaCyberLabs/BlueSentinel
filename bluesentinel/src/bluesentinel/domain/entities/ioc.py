"""Entidad de dominio: Indicator of Compromise (IOC).

Esta clase es intencionalmente ajena a SQLAlchemy y a PySide6: encapsula
las reglas de negocio de un IOC (validación de formato por tipo, ciclo de
vida activo/inactivo, fusión de duplicados) para que sean testeables sin
levantar base de datos ni GUI.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from datetime import datetime, timezone
from uuid import UUID, uuid4

from bluesentinel.domain.exceptions import ValidationError
from bluesentinel.domain.value_objects.enums import ConfidenceLevel, IOCType, Severity

_HASH_LENGTHS: dict[IOCType, int] = {
    IOCType.MD5: 32,
    IOCType.SHA1: 40,
    IOCType.SHA256: 64,
}

_IPV4_RE = re.compile(
    r"^(25[0-5]|2[0-4]\d|1\d{2}|[1-9]?\d)(\.(25[0-5]|2[0-4]\d|1\d{2}|[1-9]?\d)){3}$"
)
_DOMAIN_RE = re.compile(
    r"^(?=.{1,253}$)(?!-)[A-Za-z0-9-]{1,63}(?<!-)"
    r"(\.(?!-)[A-Za-z0-9-]{1,63}(?<!-))+$"
)
_EMAIL_RE = re.compile(r"^[^@\s]+@[^@\s]+\.[^@\s]+$")


@dataclass(slots=True)
class IOC:
    """Un Indicator of Compromise gestionado por el módulo IOC Manager.

    Invariantes garantizadas por el constructor / `create`:
      - `value` es válido para su `ioc_type` (formato de hash, IP, dominio...).
      - `first_seen` <= `last_seen`.
      - Un IOC inactivo no puede volver a marcarse como visto sin reactivarse
        explícitamente (`reactivate`).
    """

    id: UUID
    ioc_type: IOCType
    value: str
    severity: Severity
    confidence: ConfidenceLevel
    source: str
    tags: set[str] = field(default_factory=set)
    first_seen: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    last_seen: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    is_active: bool = True
    notes: str = ""

    @classmethod
    def create(
        cls,
        ioc_type: IOCType,
        value: str,
        severity: Severity = Severity.MEDIUM,
        confidence: ConfidenceLevel = ConfidenceLevel.UNKNOWN,
        source: str = "manual",
        tags: set[str] | None = None,
        notes: str = "",
    ) -> IOC:
        """Factory que normaliza y valida antes de instanciar el IOC."""
        normalized_value = cls._normalize(ioc_type, value)
        cls._validate_format(ioc_type, normalized_value)
        now = datetime.now(timezone.utc)
        return cls(
            id=uuid4(),
            ioc_type=ioc_type,
            value=normalized_value,
            severity=severity,
            confidence=confidence,
            source=source,
            tags=tags or set(),
            first_seen=now,
            last_seen=now,
            is_active=True,
            notes=notes,
        )

    @staticmethod
    def normalize(ioc_type: IOCType, value: str) -> str:
        """Normaliza un valor crudo al formato canónico de su tipo (API pública)."""
        return IOC._normalize(ioc_type, value)

    @staticmethod
    def _normalize(ioc_type: IOCType, value: str) -> str:
        value = value.strip()
        if ioc_type in _HASH_LENGTHS:
            return value.lower()
        if ioc_type == IOCType.DOMAIN:
            return value.lower().rstrip(".")
        if ioc_type == IOCType.EMAIL:
            return value.lower()
        return value

    @staticmethod
    def _validate_format(ioc_type: IOCType, value: str) -> None:
        if not value:
            raise ValidationError("El valor del IOC no puede estar vacío")

        if ioc_type in _HASH_LENGTHS:
            expected_len = _HASH_LENGTHS[ioc_type]
            if len(value) != expected_len or not re.fullmatch(r"[a-f0-9]+", value):
                raise ValidationError(
                    f"Hash inválido para {ioc_type.value}: se esperaban "
                    f"{expected_len} caracteres hexadecimales, se recibió {value!r}"
                )
        elif ioc_type == IOCType.IPV4:
            if not _IPV4_RE.match(value):
                raise ValidationError(f"Dirección IPv4 inválida: {value!r}")
        elif ioc_type == IOCType.DOMAIN:
            if not _DOMAIN_RE.match(value):
                raise ValidationError(f"Dominio inválido: {value!r}")
        elif ioc_type == IOCType.EMAIL:
            if not _EMAIL_RE.match(value):
                raise ValidationError(f"Email inválido: {value!r}")
        elif ioc_type == IOCType.URL:
            if not (value.startswith("http://") or value.startswith("https://")):
                raise ValidationError(f"URL inválida (falta esquema http/https): {value!r}")

    def mark_seen(self, timestamp: datetime | None = None) -> None:
        """Registra una nueva observación de este IOC, reactivándolo si estaba inactivo."""
        observed_at = timestamp or datetime.now(timezone.utc)
        if observed_at < self.first_seen:
            self.first_seen = observed_at
        if observed_at > self.last_seen:
            self.last_seen = observed_at
        self.is_active = True

    def deactivate(self) -> None:
        """Retira el IOC de las evaluaciones activas (falso positivo / expirado)."""
        self.is_active = False

    def escalate(self, new_severity: Severity) -> None:
        """Sube la severidad del IOC; nunca la baja (eso requiere revisión manual explícita)."""
        if new_severity.weight > self.severity.weight:
            self.severity = new_severity

    def add_tag(self, tag: str) -> None:
        self.tags.add(tag.strip().lower())
