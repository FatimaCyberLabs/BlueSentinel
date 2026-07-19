"""Value objects compartidos por todo el dominio de BlueSentinel.

Estos Enums son la fuente única de verdad para clasificaciones usadas en
IOC Manager, Case Management, Sigma Engine y el resto de módulos. Vivir en
`domain` significa que ni la base de datos ni la UI pueden imponer valores
inconsistentes: todo pasa por aquí.
"""

from __future__ import annotations

from enum import StrEnum


class IOCType(StrEnum):
    """Tipos de indicador de compromiso soportados por IOC Manager."""

    IPV4 = "ipv4"
    IPV6 = "ipv6"
    DOMAIN = "domain"
    URL = "url"
    MD5 = "md5"
    SHA1 = "sha1"
    SHA256 = "sha256"
    EMAIL = "email"
    FILENAME = "filename"
    REGISTRY_KEY = "registry_key"
    MUTEX = "mutex"


class Severity(StrEnum):
    """Escala de severidad unificada, usada en IOCs, Cases, Sigma matches y eventos."""

    INFORMATIONAL = "informational"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"

    @property
    def weight(self) -> int:
        """Peso numérico para ordenar/priorizar en dashboards y colas de trabajo."""
        return {
            Severity.INFORMATIONAL: 0,
            Severity.LOW: 1,
            Severity.MEDIUM: 2,
            Severity.HIGH: 3,
            Severity.CRITICAL: 4,
        }[self]


class ConfidenceLevel(StrEnum):
    """Nivel de confianza de un IOC o de un veredicto de detección."""

    UNKNOWN = "unknown"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CONFIRMED = "confirmed"


class CaseStatus(StrEnum):
    """Ciclo de vida de un caso de investigación en Case Management."""

    NEW = "new"
    TRIAGE = "triage"
    INVESTIGATING = "investigating"
    CONTAINMENT = "containment"
    ERADICATION = "eradication"
    RECOVERY = "recovery"
    CLOSED_TRUE_POSITIVE = "closed_true_positive"
    CLOSED_FALSE_POSITIVE = "closed_false_positive"
    CLOSED_BENIGN = "closed_benign"

    @property
    def is_closed(self) -> bool:
        return self in {
            CaseStatus.CLOSED_TRUE_POSITIVE,
            CaseStatus.CLOSED_FALSE_POSITIVE,
            CaseStatus.CLOSED_BENIGN,
        }


class SigmaLevel(StrEnum):
    """Nivel de severidad definido por la especificación oficial de Sigma."""

    INFORMATIONAL = "informational"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class SigmaStatus(StrEnum):
    """Estado de madurez de una regla Sigma (según spec oficial)."""

    STABLE = "stable"
    TEST = "test"
    EXPERIMENTAL = "experimental"
    DEPRECATED = "deprecated"
    UNSUPPORTED = "unsupported"


class EvidenceType(StrEnum):
    """Tipo de evidencia adjuntable a un caso en Case Management."""

    WINDOWS_EVENT = "windows_event"
    SYSMON_EVENT = "sysmon_event"
    IOC = "ioc"
    SIGMA_MATCH = "sigma_match"
    YARA_MATCH = "yara_match"
    FILE_ARTIFACT = "file_artifact"
    NOTE = "note"
