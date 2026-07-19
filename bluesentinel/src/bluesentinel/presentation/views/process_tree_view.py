"""Vista forense: árbol de procesos interactivo.

QTreeWidget nativo (expand/collapse gratis), con una fila de detalle que
muestra TODOS los campos forenses del proceso seleccionado — Image,
CommandLine, ParentImage, ProcessGuid, ParentProcessGuid, User, hashes — y
resalta en rojo los procesos que aparecen en al menos una detección Sigma.
"""

from __future__ import annotations

from PySide6.QtCore import Qt
from PySide6.QtGui import QColor, QFont
from PySide6.QtWidgets import (
    QGroupBox,
    QHBoxLayout,
    QLabel,
    QPlainTextEdit,
    QSplitter,
    QTreeWidget,
    QTreeWidgetItem,
    QVBoxLayout,
    QWidget,
)

from bluesentinel.domain.forensics.process_tree import ProcessNode

_SUSPICIOUS_BG = QColor("#5c1f1f")
_ROOT_ICON = "\U0001F5A5"  # 🖥
_PROC_ICON = "\u2699"  # ⚙


class ProcessTreeView(QWidget):
    def __init__(self, parent: QWidget | None = None) -> None:
        super().__init__(parent)
        self._flagged_images: set[str] = set()
        self._node_by_item: dict[int, ProcessNode] = {}
        self._build_ui()

    def _build_ui(self) -> None:
        title = QLabel("Árbol de Procesos")
        title.setStyleSheet("font-size: 16px; font-weight: 600;")

        self.tree = QTreeWidget()
        self.tree.setHeaderLabels(["Proceso", "Usuario", "Hora"])
        self.tree.setColumnWidth(0, 420)
        self.tree.itemSelectionChanged.connect(self._on_selection_changed)

        self.detail_panel = QGroupBox("Detalle forense")
        detail_layout = QVBoxLayout(self.detail_panel)
        self.detail_text = QPlainTextEdit()
        self.detail_text.setReadOnly(True)
        self.detail_text.setFont(QFont("Consolas", 10))
        detail_layout.addWidget(self.detail_text)

        splitter = QSplitter(Qt.Vertical)
        splitter.addWidget(self.tree)
        splitter.addWidget(self.detail_panel)
        splitter.setStretchFactor(0, 3)
        splitter.setStretchFactor(1, 2)

        layout = QVBoxLayout(self)
        layout.addWidget(title)
        layout.addWidget(splitter)

    def set_flagged_images(self, images: set[str]) -> None:
        """Imágenes de proceso que tienen al menos una detección Sigma asociada."""
        self._flagged_images = images

    def load_tree(self, roots: list[ProcessNode]) -> None:
        self.tree.clear()
        self._node_by_item.clear()
        for root in roots:
            item = self._build_item(root)
            self.tree.addTopLevelItem(item)
        self.tree.expandAll()

    def _build_item(self, node: ProcessNode) -> QTreeWidgetItem:
        image_name = node.image.split("\\")[-1] if node.image else "(desconocido)"
        icon = _ROOT_ICON if node.is_root else _PROC_ICON
        item = QTreeWidgetItem(
            [
                f"{icon}  {image_name}",
                node.creation_event.user,
                node.creation_event.time_created.strftime("%H:%M:%S"),
            ]
        )
        is_suspicious = image_name.lower() in {i.lower() for i in self._flagged_images} or bool(
            node.accessed_by()
        )
        if is_suspicious:
            for col in range(3):
                item.setBackground(col, _SUSPICIOUS_BG)
                item.setForeground(col, QColor("#ffffff"))
        self._node_by_item[id(item)] = node
        for child in node.children:
            item.addChild(self._build_item(child))
        return item

    def _on_selection_changed(self) -> None:
        items = self.tree.selectedItems()
        if not items:
            self.detail_text.setPlainText("")
            return
        node = self._node_by_item.get(id(items[0]))
        if node is None:
            return
        self.detail_text.setPlainText(self._format_detail(node))

    @staticmethod
    def _format_detail(node: ProcessNode) -> str:
        ev = node.creation_event
        lines = [
            f"Image:              {ev.image}",
            f"CommandLine:        {ev.command_line}",
            f"ParentImage:        {ev.parent_image}",
            f"ParentCommandLine:  {ev.parent_command_line}",
            f"User:               {ev.user}",
            f"ProcessGuid:        {ev.process_guid}",
            f"ParentProcessGuid:  {ev.parent_process_guid}",
            f"Hashes:             {ev.hashes or '(no capturado en este dataset)'}",
            f"Host:               {ev.computer}",
            f"Hora de creación:   {ev.time_created.isoformat()}",
            "",
            f"Eventos de red asociados:     {len(node.network_events())}",
            f"Claves de registro tocadas:   {len(node.registry_events())}",
            f"Accesos de otros procesos:    {len(node.accessed_by())}",
        ]
        for access in node.accessed_by():
            lines.append(
                f"  -> Acceso sospechoso: target={access.field_value('TargetImage')} "
                f"granted_access={access.field_value('GrantedAccess')}"
            )
        for net in node.network_events():
            lines.append(
                f"  -> Conexión: {net.destination_ip}:{net.field_value('DestinationPort')} "
                f"({net.field_value('DestinationHostname') or 'sin resolución DNS'})"
            )
        return "\n".join(lines)
