"""Vista de Detecciones: tabla filtrable de todos los matches Sigma disparados."""

from __future__ import annotations

from PySide6.QtGui import QColor
from PySide6.QtWidgets import (
    QComboBox,
    QHBoxLayout,
    QHeaderView,
    QLabel,
    QLineEdit,
    QTableWidget,
    QTableWidgetItem,
    QVBoxLayout,
    QWidget,
)

_LEVEL_COLORS = {
    "critical": "#c0392b",
    "high": "#e67e22",
    "medium": "#f1c40f",
    "low": "#2ecc71",
    "informational": "#7f8c8d",
}
_COLUMNS = ["Severidad", "Regla", "Host", "Proceso / Objetivo", "Técnica MITRE", "Hora"]


class DetectionsView(QWidget):
    def __init__(self, parent: QWidget | None = None) -> None:
        super().__init__(parent)
        self._all_rows: list[dict] = []
        self._build_ui()

    def _build_ui(self) -> None:
        title = QLabel("Detecciones")
        title.setStyleSheet("font-size: 16px; font-weight: 600;")

        self.severity_filter = QComboBox()
        self.severity_filter.addItems(["Todas las severidades", "critical", "high", "medium", "low"])
        self.severity_filter.currentTextChanged.connect(self._apply_filters)

        self.search_input = QLineEdit()
        self.search_input.setPlaceholderText("Filtrar por regla, host, proceso o técnica...")
        self.search_input.textChanged.connect(self._apply_filters)

        toolbar = QHBoxLayout()
        toolbar.addWidget(self.severity_filter)
        toolbar.addWidget(self.search_input, stretch=1)

        self.table = QTableWidget(0, len(_COLUMNS))
        self.table.setHorizontalHeaderLabels(_COLUMNS)
        self.table.horizontalHeader().setSectionResizeMode(3, QHeaderView.Stretch)
        self.table.setEditTriggers(QTableWidget.NoEditTriggers)
        self.table.setSelectionBehavior(QTableWidget.SelectRows)

        self.count_label = QLabel("0 detecciones")
        self.count_label.setStyleSheet("color: #888;")

        layout = QVBoxLayout(self)
        layout.addWidget(title)
        layout.addLayout(toolbar)
        layout.addWidget(self.table)
        layout.addWidget(self.count_label)

    def load_rows(self, rows: list[dict]) -> None:
        self._all_rows = rows
        self._render(rows)

    def all_rows(self) -> list[dict]:
        """API pública de solo lectura, usada por otras vistas del workbench
        (ej. ProcessTreeView para resaltar procesos con detección asociada)."""
        return self._all_rows

    def _apply_filters(self) -> None:
        severity = self.severity_filter.currentText()
        query = self.search_input.text().strip().lower()
        filtered = self._all_rows
        if severity != "Todas las severidades":
            filtered = [r for r in filtered if r["level"] == severity]
        if query:
            filtered = [
                r
                for r in filtered
                if query in r["rule_title"].lower()
                or query in r["event"].computer.lower()
                or query in (r["event"].image or "").lower()
                or any(query in tid.lower() for tid in r["mitre_technique_ids"])
            ]
        self._render(filtered)

    def _render(self, rows: list[dict]) -> None:
        self.table.setRowCount(len(rows))
        for row_idx, row in enumerate(rows):
            event = row["event"]
            target = event.image or event.target_object or event.destination_ip or "(n/a)"
            values = [
                row["level"],
                row["rule_title"],
                event.computer,
                target,
                ", ".join(row["mitre_technique_ids"]) or "—",
                event.time_created.strftime("%Y-%m-%d %H:%M:%S"),
            ]
            for col, text in enumerate(values):
                item = QTableWidgetItem(text)
                if col == 0:
                    color = _LEVEL_COLORS.get(row["level"], "#888")
                    item.setBackground(QColor(color))
                    item.setForeground(QColor("#ffffff"))
                self.table.setItem(row_idx, col, item)
        self.count_label.setText(f"{len(rows)} detección(es)")
