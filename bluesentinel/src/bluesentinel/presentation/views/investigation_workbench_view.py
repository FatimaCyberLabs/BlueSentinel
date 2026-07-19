"""Investigation Workbench: la pantalla central de BlueSentinel.

Combina el árbol de procesos (izquierda) con detecciones, timeline, MITRE
y el caso (pestañas a la derecha) — el analista investiga sin salir de esta
vista, que es exactamente el flujo pedido: cargar -> detectar -> investigar
árbol de procesos -> mapear MITRE -> reconstruir timeline -> gestionar caso.
"""

from __future__ import annotations

from PySide6.QtWidgets import (
    QHBoxLayout,
    QLabel,
    QProgressBar,
    QPushButton,
    QSplitter,
    QTabWidget,
    QVBoxLayout,
    QWidget,
)

from bluesentinel.presentation.viewmodels.investigation_viewmodel import InvestigationViewModel
from bluesentinel.presentation.views.case_view import CaseView
from bluesentinel.presentation.views.detections_view import DetectionsView
from bluesentinel.presentation.views.mitre_view import MitreCoverageView
from bluesentinel.presentation.views.process_tree_view import ProcessTreeView
from bluesentinel.presentation.views.timeline_view import TimelineView


class InvestigationWorkbenchView(QWidget):
    def __init__(self, view_model: InvestigationViewModel, parent: QWidget | None = None) -> None:
        super().__init__(parent)
        self._vm = view_model
        self._build_ui()
        self._connect_signals()

    def _build_ui(self) -> None:
        self.load_button = QPushButton("\u25B6  Cargar y analizar escenario")
        self.load_button.setStyleSheet(
            "QPushButton { background-color: #2b6cb0; color: white; padding: 8px 16px; "
            "border-radius: 4px; font-weight: 600; } QPushButton:hover { background-color: #3a7bd5; }"
        )
        self.load_button.clicked.connect(self._vm.load_and_analyze)

        self.progress = QProgressBar()
        self.progress.setRange(0, 0)
        self.progress.hide()

        self.status_label = QLabel(
            "Sin datos cargados — esta demo genera un escenario de intrusión sintético completo "
            "(phishing -> PowerShell -> persistencia -> dump de LSASS -> movimiento lateral -> C2)."
        )
        self.status_label.setStyleSheet("color: #999;")

        toolbar = QHBoxLayout()
        toolbar.addWidget(self.load_button)
        toolbar.addWidget(self.progress)
        toolbar.addWidget(self.status_label, stretch=1)

        self.process_tree_view = ProcessTreeView()
        self.detections_view = DetectionsView()
        self.timeline_view = TimelineView()
        self.mitre_view = MitreCoverageView()
        self.case_view = CaseView()

        self.tabs = QTabWidget()
        self.tabs.addTab(self.detections_view, "Detecciones")
        self.tabs.addTab(self.timeline_view, "Linea Temporal")
        self.tabs.addTab(self.mitre_view, "MITRE ATT&CK")
        self.tabs.addTab(self.case_view, "Caso")

        splitter = QSplitter()
        splitter.addWidget(self.process_tree_view)
        splitter.addWidget(self.tabs)
        splitter.setStretchFactor(0, 1)
        splitter.setStretchFactor(1, 2)

        layout = QVBoxLayout(self)
        layout.addLayout(toolbar)
        layout.addWidget(splitter)

    def _connect_signals(self) -> None:
        self._vm.pipeline_started.connect(self._on_pipeline_started)
        self._vm.pipeline_finished.connect(self._on_pipeline_finished)
        self._vm.status_message.connect(self.status_label.setText)
        self._vm.error_occurred.connect(self._on_error)

        self._vm.process_tree_ready.connect(self._on_process_tree_ready)
        self._vm.detections_ready.connect(self.detections_view.load_rows)
        self._vm.case_ready.connect(self._on_case_ready)
        self._vm.mitre_coverage_ready.connect(self._on_mitre_ready)

        self.case_view.status_change_requested.connect(self._vm.transition_case)
        self.case_view.note_submitted.connect(self._on_note_submitted)

    def _on_pipeline_started(self) -> None:
        self.load_button.setEnabled(False)
        self.progress.show()

    def _on_pipeline_finished(self, event_count: int, detection_count: int) -> None:
        self.load_button.setEnabled(True)
        self.progress.hide()
        self.status_label.setText(
            f"{event_count} eventos ingeridos - {detection_count} detecciones disparadas"
        )

    def _on_error(self, message: str) -> None:
        self.progress.hide()
        self.load_button.setEnabled(True)
        self.status_label.setText(f"Error: {message}")

    def _on_process_tree_ready(self, roots: list) -> None:
        rows = self.detections_view.all_rows()
        flagged = {row["event"].image.split("\\")[-1] for row in rows if row["event"].image}
        self.process_tree_view.set_flagged_images(flagged)
        self.process_tree_view.load_tree(roots)

    def _on_case_ready(self, case) -> None:
        self.timeline_view.load_case(case)
        hosts = self._vm.get_affected_hosts(case.id) if case else []
        self.case_view.load_case(case, affected_hosts=hosts)
        if case is not None:
            self.case_view.load_notes(self._vm.get_case_notes())

    def _on_mitre_ready(self, report) -> None:
        detected = self._vm.get_detected_technique_ids()
        self.mitre_view.load_coverage(report, detected)

    def _on_note_submitted(self, content: str) -> None:
        self._vm.add_case_note(content)
        self.case_view.load_notes(self._vm.get_case_notes())
