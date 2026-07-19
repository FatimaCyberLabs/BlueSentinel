"""Vista MITRE ATT&CK Explorer: heatmap de cobertura por táctica.

Cada celda es una técnica. Color = estado real, no decorativo:
  - Gris: sin regla que la cubra (punto ciego de detección).
  - Ámbar: cubierta por una regla, pero sin detección disparada en esta investigación.
  - Rojo: cubierta Y con al menos una detección real en el caso actual.
"""

from __future__ import annotations

from PySide6.QtCore import Qt
from PySide6.QtWidgets import (
    QGridLayout,
    QLabel,
    QScrollArea,
    QVBoxLayout,
    QWidget,
)

from bluesentinel.domain.detection.mitre_coverage import CoverageReport

_NOT_COVERED = "#3a3f4b"
_COVERED_NOT_DETECTED = "#8a6d1f"
_DETECTED = "#c0392b"

_TACTIC_ORDER = [
    "initial-access",
    "execution",
    "persistence",
    "privilege-escalation",
    "defense-evasion",
    "credential-access",
    "discovery",
    "lateral-movement",
    "collection",
    "command-and-control",
    "exfiltration",
]
_TACTIC_LABELS = {
    "initial-access": "Acceso Inicial",
    "execution": "Ejecución",
    "persistence": "Persistencia",
    "privilege-escalation": "Escalada de Privilegios",
    "defense-evasion": "Evasión de Defensa",
    "credential-access": "Acceso a Credenciales",
    "discovery": "Descubrimiento",
    "lateral-movement": "Movimiento Lateral",
    "collection": "Recolección",
    "command-and-control": "Comando y Control",
    "exfiltration": "Exfiltración",
}


class MitreCoverageView(QWidget):
    def __init__(self, parent: QWidget | None = None) -> None:
        super().__init__(parent)
        self._build_ui()

    def _build_ui(self) -> None:
        title = QLabel("MITRE ATT&CK — Cobertura de Detección")
        title.setStyleSheet("font-size: 16px; font-weight: 600;")

        self.summary_label = QLabel("")
        self.summary_label.setStyleSheet("color: #aaa;")

        legend = QLabel(
            "\u25A0 Sin cobertura     \u25A0 Cubierta (sin disparo en este caso)     \u25A0 Detectada en este caso"
        )
        legend.setStyleSheet(
            f"color: {_NOT_COVERED};"
        )  # placeholder de estilo; el texto real usa colores por rich text abajo
        legend.setTextFormat(Qt.RichText)
        legend.setText(
            f'<span style="color:{_NOT_COVERED}">■</span> Sin cobertura&nbsp;&nbsp;&nbsp;'
            f'<span style="color:{_COVERED_NOT_DETECTED}">■</span> Cubierta&nbsp;&nbsp;&nbsp;'
            f'<span style="color:{_DETECTED}">■</span> Detectada en este caso'
        )

        self.grid_container = QWidget()
        self.grid_layout = QGridLayout(self.grid_container)
        self.grid_layout.setSpacing(6)

        scroll = QScrollArea()
        scroll.setWidgetResizable(True)
        scroll.setWidget(self.grid_container)

        layout = QVBoxLayout(self)
        layout.addWidget(title)
        layout.addWidget(self.summary_label)
        layout.addWidget(legend)
        layout.addWidget(scroll)

    def load_coverage(self, report: CoverageReport, detected_technique_ids: set[str]) -> None:
        while self.grid_layout.count():
            child = self.grid_layout.takeAt(0)
            if child.widget():
                child.widget().deleteLater()

        row = 0
        for tactic in _TACTIC_ORDER:
            techniques = report.by_tactic.get(tactic, [])
            if not techniques:
                continue
            label = QLabel(_TACTIC_LABELS.get(tactic, tactic))
            label.setStyleSheet("font-weight: 600; color: #d0d0d0;")
            self.grid_layout.addWidget(label, row, 0)

            col = 1
            for coverage in sorted(techniques, key=lambda c: c.technique.technique_id):
                cell = self._build_cell(coverage, detected_technique_ids)
                self.grid_layout.addWidget(cell, row, col)
                col += 1
            row += 1

        covered = report.covered_techniques
        total = report.total_techniques
        detected = len(detected_technique_ids)
        self.summary_label.setText(
            f"{covered}/{total} técnicas del catálogo cubiertas por al menos una regla "
            f"({report.coverage_ratio:.0%})  ·  {detected} técnicas con detección real en el caso actual"
        )

    def _build_cell(self, coverage, detected_technique_ids: set[str]) -> QLabel:
        technique = coverage.technique
        if technique.technique_id in detected_technique_ids:
            color = _DETECTED
        elif coverage.is_covered:
            color = _COVERED_NOT_DETECTED
        else:
            color = _NOT_COVERED

        cell = QLabel(technique.technique_id)
        cell.setAlignment(Qt.AlignCenter)
        cell.setFixedSize(90, 40)
        cell.setStyleSheet(
            f"background-color: {color}; color: white; border-radius: 4px; font-size: 11px;"
        )
        tooltip = f"{technique.technique_id} — {technique.name}"
        if coverage.covering_rule_titles:
            tooltip += "\nReglas: " + ", ".join(coverage.covering_rule_titles)
        else:
            tooltip += "\nSin regla de detección (punto ciego)"
        cell.setToolTip(tooltip)
        return cell
