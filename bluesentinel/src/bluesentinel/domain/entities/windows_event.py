"""Entidad de dominio: evento de Windows (Security / Sysmon / PowerShell / etc.).

Diseño deliberado: en vez de una entidad separada "SysmonEvent", un único
`WindowsEvent` con un diccionario `event_data` normalizado (los pares
Name/Value del bloque `<EventData>` de cualquier canal EVTX) más accesores
tipados para los campos que un analista consulta constantemente en
investigaciones reales: imagen del proceso, línea de comandos, proceso
padre, hashes, usuario. Esto refleja cómo se ve un evento EVTX real y evita
la duplicación de modelo que tenía la versión anterior (WindowsEventModel +
SysmonEventModel por separado, con el mismo dato repartido en dos tablas).
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime
from uuid import UUID, uuid4

# Event IDs de Sysmon más relevantes para investigación (Microsoft Sysmon 15.x).
SYSMON_PROCESS_CREATE = 1
SYSMON_NETWORK_CONNECT = 3
SYSMON_PROCESS_TERMINATE = 5
SYSMON_DRIVER_LOAD = 6
SYSMON_IMAGE_LOAD = 7
SYSMON_CREATE_REMOTE_THREAD = 8
SYSMON_RAW_ACCESS_READ = 9
SYSMON_PROCESS_ACCESS = 10
SYSMON_FILE_CREATE = 11
SYSMON_REGISTRY_EVENT_SET = 13
SYSMON_REGISTRY_EVENT_RENAME = 14
SYSMON_FILE_STREAM_CREATE = 15
SYSMON_PIPE_CREATE = 17
SYSMON_WMI_EVENT = 19
SYSMON_DNS_QUERY = 22

# Windows Security Log — autenticación, la otra fuente forense crítica.
SECURITY_LOGON = 4624
SECURITY_LOGON_FAILED = 4625
SECURITY_SPECIAL_PRIVILEGES = 4672
SECURITY_PROCESS_CREATE = 4688


@dataclass(slots=True)
class WindowsEvent:
    """Un evento de Windows normalizado, canal-agnóstico.

    `event_data` contiene TODOS los campos crudos del evento (lo que
    aparece en `<EventData>` en el XML original), permitiendo que el Sigma
    Engine evalúe contra cualquier campo sin que el dominio necesite conocer
    de antemano el esquema exacto de cada Event ID. Las `@property` de abajo
    son azúcar sintáctico para los ~10 campos que un analista usa siempre.
    """

    id: UUID
    event_id: int
    channel: str
    computer: str
    provider: str
    time_created: datetime
    level: int
    task_category: str
    event_data: dict[str, str] = field(default_factory=dict)
    raw_xml: str = ""

    @classmethod
    def create(
        cls,
        event_id: int,
        channel: str,
        computer: str,
        provider: str,
        time_created: datetime,
        event_data: dict[str, str],
        level: int = 4,
        task_category: str = "",
        raw_xml: str = "",
    ) -> WindowsEvent:
        return cls(
            id=uuid4(),
            event_id=event_id,
            channel=channel,
            computer=computer,
            provider=provider,
            time_created=time_created,
            level=level,
            task_category=task_category,
            event_data=dict(event_data),
            raw_xml=raw_xml,
        )

    def field_value(self, name: str) -> str | None:
        """Búsqueda case-insensitive de un campo — el Sigma Engine la usa intensivamente."""
        if name in self.event_data:
            return self.event_data[name]
        lowered = name.lower()
        for key, value in self.event_data.items():
            if key.lower() == lowered:
                return value
        return None

    # -- Accesores de conveniencia para los campos forenses más consultados ------

    @property
    def image(self) -> str:
        """Ruta del ejecutable del proceso (Sysmon EID 1) o vacío si no aplica."""
        return self.field_value("Image") or ""

    @property
    def command_line(self) -> str:
        return self.field_value("CommandLine") or ""

    @property
    def parent_image(self) -> str:
        return self.field_value("ParentImage") or ""

    @property
    def parent_command_line(self) -> str:
        return self.field_value("ParentCommandLine") or ""

    @property
    def user(self) -> str:
        return self.field_value("User") or self.field_value("SubjectUserName") or ""

    @property
    def hashes(self) -> str:
        return self.field_value("Hashes") or ""

    @property
    def target_filename(self) -> str:
        return self.field_value("TargetFilename") or ""

    @property
    def target_object(self) -> str:
        """Clave/valor de registro afectado (Sysmon EID 13/14)."""
        return self.field_value("TargetObject") or ""

    @property
    def destination_ip(self) -> str:
        return self.field_value("DestinationIp") or ""

    @property
    def query_name(self) -> str:
        """Dominio consultado (Sysmon EID 22, DNS query)."""
        return self.field_value("QueryName") or ""

    @property
    def is_process_creation(self) -> bool:
        return self.event_id in (SYSMON_PROCESS_CREATE, SECURITY_PROCESS_CREATE)

    @property
    def process_guid(self) -> str:
        return self.field_value("ProcessGuid") or ""

    @property
    def parent_process_guid(self) -> str:
        return self.field_value("ParentProcessGuid") or ""
