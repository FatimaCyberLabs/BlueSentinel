"""Vista de Timeline: reconstrucción cronológica de la investigación completa.

Fusiona las entradas del timeline del caso (`Case.timeline`, ya en orden
cronológico por diseño de dominio) con los detalles de evidencia — cada fila
es un punto de la narrativa de la intrusión, no solo un evento crudo.
"""

from __future__ import annotations

from PySide6.QtWidgets import (
    QHeaderView,
    QLabel,
    QTableWidget,
    QTableWidgetItem,
    QVBoxLayout,
    QWidget,
)

from bluesentinel.domain.entities.case import Case

_COLUMNS = ["Hora", "Módulo origen", "Descripción"]


class TimelineView(QWidget):
    def __init__(self, parent: QWidget | None = None) -> None:
        super().__init__(parent)
        self._build_ui()

    def _build_ui(self) -> None:
        title = QLabel("Línea Temporal de la Investigación")
        title.setStyleSheet("font-size: 16px; font-weight: 600;")

        self.table = QTableWidget(0, len(_COLUMNS))
        self.table.setHorizontalHeaderLabels(_COLUMNS)
        self.table.horizontalHeader().setSectionResizeMode(2, QHeaderView.Stretch)
        self.table.setEditTriggers(QTableWidget.NoEditTriggers)
        self.table.setSelectionBehavior(QTableWidget.SelectRows)

        self.empty_label = QLabel(
            "Sin caso activo — ejecuta 'Cargar y analizar escenario' para generar la línea temporal."
        )
        self.empty_label.setStyleSheet("color: #888;")

        layout = QVBoxLayout(self)
        layout.addWidget(title)
        layout.addWidget(self.empty_label)
        layout.addWidget(self.table)

    def load_case(self, case: Case | None) -> None:
        if case is None or not case.timeline:
            self.table.setRowCount(0)
            self.empty_label.show()
            return
        self.empty_label.hide()
        self.table.setRowCount(len(case.timeline))
        for row_idx, entry in enumerate(case.timeline):
            values = [
                entry.timestamp.strftime("%Y-%m-%d %H:%M:%S"),
                entry.source_module,
                entry.description,
            ]
            for col, text in enumerate(values):
                self.table.setItem(row_idx, col, QTableWidgetItem(text))
