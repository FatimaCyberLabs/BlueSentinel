"""Vista del módulo IOC Manager.

Widget PySide6 puro: no toca SQLAlchemy ni `application` directamente,
solo habla con `IOCManagerViewModel` a través de señales/slots.
"""

from __future__ import annotations

from PySide6.QtCore import Qt
from PySide6.QtWidgets import (
    QComboBox,
    QDialog,
    QDialogButtonBox,
    QFormLayout,
    QHBoxLayout,
    QHeaderView,
    QLabel,
    QLineEdit,
    QMessageBox,
    QPushButton,
    QTableWidget,
    QTableWidgetItem,
    QVBoxLayout,
    QWidget,
)

from bluesentinel.application.ioc.ioc_service import IOCSummary
from bluesentinel.domain.value_objects.enums import ConfidenceLevel, IOCType, Severity
from bluesentinel.presentation.viewmodels.ioc_viewmodel import IOCManagerViewModel

_SEVERITY_COLORS = {
    "critical": "#c0392b",
    "high": "#e67e22",
    "medium": "#f1c40f",
    "low": "#2ecc71",
    "informational": "#7f8c8d",
}

_COLUMNS = ["Tipo", "Valor", "Severidad", "Confianza", "Fuente", "Tags", "Visto por última vez"]


class AddIOCDialog(QDialog):
    """Diálogo modal para dar de alta un IOC manualmente."""

    def __init__(self, parent: QWidget | None = None) -> None:
        super().__init__(parent)
        self.setWindowTitle("Nuevo IOC")
        self.setMinimumWidth(420)

        self.type_combo = QComboBox()
        self.type_combo.addItems([t.value for t in IOCType])

        self.value_input = QLineEdit()
        self.value_input.setPlaceholderText("ej. 185.220.101.42 / evil.com / hash SHA256...")

        self.severity_combo = QComboBox()
        self.severity_combo.addItems([s.value for s in Severity])
        self.severity_combo.setCurrentText(Severity.MEDIUM.value)

        self.confidence_combo = QComboBox()
        self.confidence_combo.addItems([c.value for c in ConfidenceLevel])

        self.source_input = QLineEdit()
        self.source_input.setPlaceholderText("ej. Threat Intel Team, MISP feed, análisis manual")

        form = QFormLayout()
        form.addRow("Tipo:", self.type_combo)
        form.addRow("Valor:", self.value_input)
        form.addRow("Severidad:", self.severity_combo)
        form.addRow("Confianza:", self.confidence_combo)
        form.addRow("Fuente:", self.source_input)

        buttons = QDialogButtonBox(QDialogButtonBox.Ok | QDialogButtonBox.Cancel)
        buttons.accepted.connect(self.accept)
        buttons.rejected.connect(self.reject)

        layout = QVBoxLayout(self)
        layout.addLayout(form)
        layout.addWidget(buttons)

    def values(self) -> tuple[str, str, str, str, str]:
        return (
            self.type_combo.currentText(),
            self.value_input.text().strip(),
            self.severity_combo.currentText(),
            self.confidence_combo.currentText(),
            self.source_input.text().strip(),
        )


class IOCManagerView(QWidget):
    """Vista principal del IOC Manager: tabla filtrable + acciones de alta/baja."""

    def __init__(self, view_model: IOCManagerViewModel, parent: QWidget | None = None) -> None:
        super().__init__(parent)
        self._vm = view_model
        self._current_rows: list[IOCSummary] = []
        self._build_ui()
        self._connect_signals()
        self._vm.refresh()

    def _build_ui(self) -> None:
        title = QLabel("IOC Manager")
        title.setStyleSheet("font-size: 20px; font-weight: 600;")

        self.search_input = QLineEdit()
        self.search_input.setPlaceholderText("Buscar por valor, fuente, tag o nota...")

        self.add_button = QPushButton("+ Nuevo IOC")
        self.deactivate_button = QPushButton("Desactivar seleccionado")
        self.deactivate_button.setEnabled(False)
        self.refresh_button = QPushButton("Actualizar")

        toolbar = QHBoxLayout()
        toolbar.addWidget(self.search_input, stretch=1)
        toolbar.addWidget(self.add_button)
        toolbar.addWidget(self.deactivate_button)
        toolbar.addWidget(self.refresh_button)

        self.table = QTableWidget(0, len(_COLUMNS))
        self.table.setHorizontalHeaderLabels(_COLUMNS)
        self.table.horizontalHeader().setSectionResizeMode(1, QHeaderView.Stretch)
        self.table.setSelectionBehavior(QTableWidget.SelectRows)
        self.table.setEditTriggers(QTableWidget.NoEditTriggers)

        self.status_label = QLabel("")
        self.status_label.setStyleSheet("color: #888;")

        layout = QVBoxLayout(self)
        layout.addWidget(title)
        layout.addLayout(toolbar)
        layout.addWidget(self.table)
        layout.addWidget(self.status_label)

    def _connect_signals(self) -> None:
        self._vm.iocs_changed.connect(self._on_iocs_changed)
        self._vm.error_occurred.connect(self._on_error)
        self._vm.operation_succeeded.connect(self._on_success)

        self.search_input.textChanged.connect(self._vm.search)
        self.add_button.clicked.connect(self._open_add_dialog)
        self.refresh_button.clicked.connect(self._vm.refresh)
        self.deactivate_button.clicked.connect(self._deactivate_selected)
        self.table.itemSelectionChanged.connect(
            lambda: self.deactivate_button.setEnabled(bool(self.table.selectedItems()))
        )

    def _on_iocs_changed(self, summaries: list[IOCSummary]) -> None:
        self._current_rows = summaries
        self.table.setRowCount(len(summaries))
        for row, ioc in enumerate(summaries):
            values = [
                ioc.ioc_type,
                ioc.value,
                ioc.severity,
                ioc.confidence,
                ioc.source,
                ", ".join(ioc.tags),
                ioc.last_seen.strftime("%Y-%m-%d %H:%M UTC"),
            ]
            for col, text in enumerate(values):
                item = QTableWidgetItem(text)
                if col == 2:
                    color = _SEVERITY_COLORS.get(ioc.severity, "#888")
                    item.setForeground(Qt.GlobalColor.white)
                    item.setBackground(_qcolor(color))
                self.table.setItem(row, col, item)
        self.status_label.setText(f"{len(summaries)} IOC(s) activos")

    def _on_error(self, message: str) -> None:
        QMessageBox.critical(self, "Error en IOC Manager", message)

    def _on_success(self, message: str) -> None:
        self.status_label.setText(message)

    def _open_add_dialog(self) -> None:
        dialog = AddIOCDialog(self)
        if dialog.exec() == QDialog.Accepted:
            ioc_type, value, severity, confidence, source = dialog.values()
            if not value:
                QMessageBox.warning(self, "Dato incompleto", "El valor del IOC es obligatorio.")
                return
            self._vm.add_ioc(ioc_type, value, severity, confidence, source)

    def _deactivate_selected(self) -> None:
        row = self.table.currentRow()
        if row < 0 or row >= len(self._current_rows):
            return
        ioc = self._current_rows[row]
        confirm = QMessageBox.question(
            self, "Confirmar", f"¿Desactivar el IOC {ioc.value!r}?"
        )
        if confirm == QMessageBox.Yes:
            self._vm.deactivate_ioc(str(ioc.id))


def _qcolor(hex_color: str):
    from PySide6.QtGui import QColor

    return QColor(hex_color)
