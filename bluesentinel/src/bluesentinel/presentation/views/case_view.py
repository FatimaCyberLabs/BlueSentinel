"""Vista de Case Management: resumen del caso, transición de estado y notas de analista."""

from __future__ import annotations

from PySide6.QtCore import Qt, Signal
from PySide6.QtWidgets import (
    QComboBox,
    QGroupBox,
    QHBoxLayout,
    QLabel,
    QLineEdit,
    QListWidget,
    QListWidgetItem,
    QPushButton,
    QVBoxLayout,
    QWidget,
)

from bluesentinel.domain.entities.case import Case
from bluesentinel.domain.value_objects.enums import CaseStatus

_NEXT_STATUS_OPTIONS = {
    CaseStatus.NEW: [CaseStatus.TRIAGE, CaseStatus.CLOSED_FALSE_POSITIVE],
    CaseStatus.TRIAGE: [CaseStatus.INVESTIGATING, CaseStatus.CLOSED_FALSE_POSITIVE, CaseStatus.CLOSED_BENIGN],
    CaseStatus.INVESTIGATING: [CaseStatus.CONTAINMENT, CaseStatus.CLOSED_FALSE_POSITIVE, CaseStatus.CLOSED_BENIGN],
    CaseStatus.CONTAINMENT: [CaseStatus.ERADICATION],
    CaseStatus.ERADICATION: [CaseStatus.RECOVERY],
    CaseStatus.RECOVERY: [CaseStatus.CLOSED_TRUE_POSITIVE],
}

_SEVERITY_COLORS = {
    "critical": "#c0392b", "high": "#e67e22", "medium": "#f1c40f",
    "low": "#2ecc71", "informational": "#7f8c8d",
}


class CaseView(QWidget):
    """Vista pasiva: emite señales, el ViewModel decide qué hacer con ellas."""

    status_change_requested = Signal(str)
    note_submitted = Signal(str)

    def __init__(self, parent: QWidget | None = None) -> None:
        super().__init__(parent)
        self._current_case: Case | None = None
        self._build_ui()

    def _build_ui(self) -> None:
        title = QLabel("Caso de Investigación")
        title.setStyleSheet("font-size: 16px; font-weight: 600;")

        self.empty_label = QLabel(
            "Sin caso activo — ejecuta 'Cargar y analizar escenario' para abrir uno automáticamente."
        )
        self.empty_label.setStyleSheet("color: #888;")

        self.summary_box = QGroupBox("Resumen")
        summary_layout = QVBoxLayout(self.summary_box)
        self.case_title_label = QLabel("")
        self.case_title_label.setStyleSheet("font-size: 14px; font-weight: 600;")
        self.case_meta_label = QLabel("")
        self.case_meta_label.setTextFormat(Qt.RichText)
        self.case_meta_label.setStyleSheet("color: #aaa;")
        self.case_summary_label = QLabel("")
        self.case_summary_label.setWordWrap(True)
        summary_layout.addWidget(self.case_title_label)
        summary_layout.addWidget(self.case_meta_label)
        summary_layout.addWidget(self.case_summary_label)

        status_row = QHBoxLayout()
        status_row.addWidget(QLabel("Transicionar a:"))
        self.status_combo = QComboBox()
        self.transition_button = QPushButton("Aplicar")
        self.transition_button.clicked.connect(self._on_transition_clicked)
        status_row.addWidget(self.status_combo)
        status_row.addWidget(self.transition_button)
        status_row.addStretch()

        self.affected_hosts_box = QGroupBox("Hosts afectados")
        hosts_layout = QVBoxLayout(self.affected_hosts_box)
        self.hosts_list = QListWidget()
        hosts_layout.addWidget(self.hosts_list)

        self.evidence_box = QGroupBox("Evidencia vinculada")
        evidence_layout = QVBoxLayout(self.evidence_box)
        self.evidence_list = QListWidget()
        evidence_layout.addWidget(self.evidence_list)

        self.notes_box = QGroupBox("Notas del analista")
        notes_layout = QVBoxLayout(self.notes_box)
        self.notes_list = QListWidget()
        self.note_input = QLineEdit()
        self.note_input.setPlaceholderText("Añadir nota de investigación...")
        self.note_input.returnPressed.connect(self._on_note_submitted)
        notes_layout.addWidget(self.notes_list)
        notes_layout.addWidget(self.note_input)

        layout = QVBoxLayout(self)
        layout.addWidget(title)
        layout.addWidget(self.empty_label)
        layout.addWidget(self.summary_box)
        layout.addLayout(status_row)
        layout.addWidget(self.affected_hosts_box)
        layout.addWidget(self.evidence_box)
        layout.addWidget(self.notes_box)

        self._set_case_widgets_visible(False)

    def _set_case_widgets_visible(self, visible: bool) -> None:
        for widget in (
            self.summary_box, self.status_combo, self.transition_button,
            self.affected_hosts_box, self.evidence_box, self.notes_box,
        ):
            widget.setVisible(visible)
        self.empty_label.setVisible(not visible)

    def load_case(self, case: Case | None, affected_hosts: list[str] | None = None) -> None:
        self._current_case = case
        if case is None:
            self._set_case_widgets_visible(False)
            return
        self._set_case_widgets_visible(True)

        self.case_title_label.setText(case.title)
        color = _SEVERITY_COLORS.get(case.severity.value, "#888")
        self.case_meta_label.setText(
            f'Severidad: <span style="color:{color}">{case.severity.value.upper()}</span>  ·  '
            f"Estado: {case.status.value}  ·  Creado: {case.created_at.strftime('%Y-%m-%d %H:%M UTC')}"
        )
        self.case_summary_label.setText(case.summary)

        self.status_combo.clear()
        next_options = _NEXT_STATUS_OPTIONS.get(case.status, [])
        self.status_combo.addItems([s.value for s in next_options])
        self.transition_button.setEnabled(bool(next_options))

        self.hosts_list.clear()
        for host in affected_hosts or []:
            self.hosts_list.addItem(QListWidgetItem(host))

        self.evidence_list.clear()
        for ref in case.evidence:
            self.evidence_list.addItem(QListWidgetItem(f"[{ref.evidence_type.value}] {ref.notes}"))

    def load_notes(self, notes: list[dict]) -> None:
        self.notes_list.clear()
        for note in notes:
            ts = note["created_at"].strftime("%Y-%m-%d %H:%M")
            self.notes_list.addItem(QListWidgetItem(f"[{ts}] {note['author']}: {note['content']}"))

    def _on_transition_clicked(self) -> None:
        if self.status_combo.currentText():
            self.status_change_requested.emit(self.status_combo.currentText())

    def _on_note_submitted(self) -> None:
        text = self.note_input.text().strip()
        if not text:
            return
        self.note_submitted.emit(text)
        self.note_input.clear()
