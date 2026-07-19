"""Reconstrucción de árbol de procesos (process lineage) a partir de eventos Sysmon.

Esta es la técnica de investigación más usada en DFIR real: dado un
conjunto de eventos "Process Create" (Sysmon EID 1), cada uno trae
`ProcessGuid` y `ParentProcessGuid` — identificadores estables que
sobreviven a la reutilización de PID (a diferencia del PID crudo, que
Windows recicla y que por sí solo es una fuente clásica de correlación
incorrecta en herramientas mal hechas).

`ProcessTreeBuilder` construye el árbol y además adjunta a cada proceso
los eventos *no* de creación (conexiones de red, accesos a otros procesos,
cambios de registro, creación de archivos) que comparten su `ProcessGuid`
como `SourceProcessGUID` — permitiendo responder la pregunta que todo
analista hace primero: "¿qué hizo exactamente este proceso, y quién lo
lanzó?"
"""

from __future__ import annotations

from dataclasses import dataclass, field

from bluesentinel.domain.entities.windows_event import (
    SYSMON_CREATE_REMOTE_THREAD,
    SYSMON_DNS_QUERY,
    SYSMON_FILE_CREATE,
    SYSMON_NETWORK_CONNECT,
    SYSMON_PROCESS_ACCESS,
    SYSMON_PROCESS_CREATE,
    SYSMON_REGISTRY_EVENT_SET,
    WindowsEvent,
)

# Event IDs cuyo campo de correlación con el proceso de origen es distinto de
# ProcessGuid (Sysmon los llama SourceProcessGUID en accesos entre procesos).
_SOURCE_GUID_EVENT_IDS = {SYSMON_PROCESS_ACCESS, SYSMON_CREATE_REMOTE_THREAD}
_OWN_GUID_EVENT_IDS = {
    SYSMON_NETWORK_CONNECT,
    SYSMON_FILE_CREATE,
    SYSMON_REGISTRY_EVENT_SET,
    SYSMON_DNS_QUERY,
}


@dataclass(slots=True)
class ProcessNode:
    """Un proceso en el árbol de lineage, con sus hijos y eventos asociados."""

    process_guid: str
    creation_event: WindowsEvent
    children: list["ProcessNode"] = field(default_factory=list)
    related_events: list[WindowsEvent] = field(default_factory=list)
    is_root: bool = False  # True si su padre no aparece en el dataset (borde de captura)

    @property
    def image(self) -> str:
        return self.creation_event.image

    @property
    def command_line(self) -> str:
        return self.creation_event.command_line

    @property
    def depth_first(self) -> list["ProcessNode"]:
        """Aplana el subárbol en preorden — útil para renderizar en la UI."""
        nodes = [self]
        for child in self.children:
            nodes.extend(child.depth_first)
        return nodes

    def network_events(self) -> list[WindowsEvent]:
        return [e for e in self.related_events if e.event_id == SYSMON_NETWORK_CONNECT]

    def registry_events(self) -> list[WindowsEvent]:
        return [e for e in self.related_events if e.event_id == SYSMON_REGISTRY_EVENT_SET]

    def accessed_by(self) -> list[WindowsEvent]:
        """Eventos donde OTRO proceso accedió a este (ej. dumping de credenciales)."""
        return [e for e in self.related_events if e.event_id == SYSMON_PROCESS_ACCESS]


class ProcessTreeBuilder:
    """Construye uno o más árboles de proceso a partir de una lista plana de eventos."""

    def build(self, events: list[WindowsEvent]) -> list[ProcessNode]:
        creation_events = [e for e in events if e.event_id == SYSMON_PROCESS_CREATE]
        other_events = [e for e in events if e.event_id != SYSMON_PROCESS_CREATE]

        nodes: dict[str, ProcessNode] = {
            e.process_guid: ProcessNode(process_guid=e.process_guid, creation_event=e)
            for e in creation_events
            if e.process_guid
        }

        roots: list[ProcessNode] = []
        for node in nodes.values():
            parent_guid = node.creation_event.parent_process_guid
            parent = nodes.get(parent_guid)
            if parent is not None:
                parent.children.append(node)
            else:
                node.is_root = True
                roots.append(node)

        for event in other_events:
            owner_guid = self._resolve_owner_guid(event)
            owner = nodes.get(owner_guid)
            if owner is not None:
                owner.related_events.append(event)

        for node in nodes.values():
            node.children.sort(key=lambda n: n.creation_event.time_created)

        roots.sort(key=lambda n: n.creation_event.time_created)
        return roots

    @staticmethod
    def _resolve_owner_guid(event: WindowsEvent) -> str:
        if event.event_id in _SOURCE_GUID_EVENT_IDS:
            return event.field_value("SourceProcessGUID") or ""
        return event.field_value("ProcessGuid") or ""

    def find_node(self, roots: list[ProcessNode], process_guid: str) -> ProcessNode | None:
        for root in roots:
            for node in root.depth_first:
                if node.process_guid == process_guid:
                    return node
        return None
