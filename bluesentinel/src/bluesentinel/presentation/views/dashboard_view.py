"""Dashboard: panel de estado del SOC con datos calculados en tiempo real
por `InvestigationService.get_dashboard_stats()` — nada hardcodeado.
"""

from __future__ import annotations

from PySide6.QtCore import Qt
from PySide6.QtGui import QPainter, QColor, QFont
from PySide6.QtWidgets import QGridLayout, QGroupBox, QHBoxLayout, QLabel, QVBoxLayout, QWidget

from bluesentinel.application.detection.investigation_service import DashboardStats


class _StatCard(QGroupBox):
    def __init__(self, label: str, color: str = "#3a7bd5") -> None:
        super().__init__()
        self.setStyleSheet("QGroupBox { border: 1px solid #333; border-radius: 6px; }")
        layout = QVBoxLayout(self)
        self.value_label = QLabel("0")
        self.value_label.setStyleSheet(f"font-size: 28px; font-weight: 700; color: {color};")
        caption = QLabel(label)
        caption.setStyleSheet("color: #999; font-size: 12px;")
        layout.addWidget(self.value_label)
        layout.addWidget(caption)

    def set_value(self, value: object) -> None:
        self.value_label.setText(str(value))


class _BarChart(QWidget):
    """Gráfico de barras simple dibujado con QPainter — evita depender de
    QtCharts, que no siempre está disponible en todas las distribuciones
    de PySide6, y demuestra manejo directo del framework de pintura de Qt."""

    def __init__(self, title: str) -> None:
        super().__init__()
        self._title = title
        self._data: list[tuple[str, int]] = []
        self.setMinimumHeight(180)

    def set_data(self, data: list[tuple[str, int]]) -> None:
        self._data = data
        self.update()

    def paintEvent(self, event) -> None:  # noqa: N802 (nombre impuesto por Qt)
        painter = QPainter(self)
        painter.setRenderHint(QPainter.Antialiasing)
        painter.fillRect(self.rect(), QColor("#20242c"))

        painter.setPen(QColor("#ddd"))
        painter.setFont(QFont("Segoe UI", 10, QFont.Bold))
        painter.drawText(10, 20, self._title)

        if not self._data:
            painter.setPen(QColor("#666"))
            painter.drawText(self.rect(), Qt.AlignCenter, "Sin datos — carga el escenario primero")
            return

        max_value = max(v for _, v in self._data) or 1
        chart_top = 35
        chart_bottom = self.height() - 25
        chart_height = chart_bottom - chart_top
        bar_width = max(8, (self.width() - 20) // max(len(self._data), 1) - 4)

        x = 12
        painter.setFont(QFont("Segoe UI", 7))
        for label, value in self._data:
            bar_height = int((value / max_value) * chart_height)
            painter.fillRect(x, chart_bottom - bar_height, bar_width, bar_height, QColor("#3a7bd5"))
            painter.setPen(QColor("#999"))
            painter.drawText(x - 2, chart_bottom + 12, label)
            painter.setPen(QColor("#ddd"))
            painter.drawText(x, chart_bottom - bar_height - 4, str(value))
            x += bar_width + 4


class DashboardView(QWidget):
    def __init__(self, parent: QWidget | None = None) -> None:
        super().__init__(parent)
        self._build_ui()

    def _build_ui(self) -> None:
        title = QLabel("Dashboard de Operaciones SOC")
        title.setStyleSheet("font-size: 20px; font-weight: 600;")

        self.cards = {
            "events": _StatCard("Eventos ingeridos", "#3a7bd5"),
            "detections": _StatCard("Detecciones totales", "#f1c40f"),
            "critical": _StatCard("Alertas críticas", "#c0392b"),
            "high": _StatCard("Alertas altas", "#e67e22"),
            "hosts": _StatCard("Hosts afectados", "#8e44ad"),
            "techniques": _StatCard("Técnicas MITRE detectadas", "#16a085"),
            "cases": _StatCard("Casos abiertos", "#2980b9"),
            "iocs": _StatCard("IOCs activos", "#27ae60"),
        }
        grid = QGridLayout()
        for i, card in enumerate(self.cards.values()):
            grid.addWidget(card, i // 4, i % 4)

        self.top_rules_chart = _BarChart("Reglas Sigma más disparadas")
        self.events_chart = _BarChart("Volumen de eventos por hora")

        charts_row = QHBoxLayout()
        charts_row.addWidget(self.top_rules_chart)
        charts_row.addWidget(self.events_chart)

        self.status_label = QLabel(
            "Sin datos cargados. Ve a 'Investigación' y pulsa 'Cargar y analizar escenario'."
        )
        self.status_label.setStyleSheet("color: #888;")

        layout = QVBoxLayout(self)
        layout.addWidget(title)
        layout.addWidget(self.status_label)
        layout.addLayout(grid)
        layout.addLayout(charts_row)
        layout.addStretch()

    def load_stats(self, stats: DashboardStats, active_iocs: int, open_cases: int) -> None:
        self.cards["events"].set_value(stats.total_events)
        self.cards["detections"].set_value(stats.total_detections)
        self.cards["critical"].set_value(stats.critical_detections)
        self.cards["high"].set_value(stats.high_detections)
        self.cards["hosts"].set_value(stats.distinct_hosts)
        self.cards["techniques"].set_value(stats.distinct_mitre_techniques)
        self.cards["cases"].set_value(open_cases)
        self.cards["iocs"].set_value(active_iocs)

        self.top_rules_chart.set_data(stats.top_rules)
        self.events_chart.set_data(stats.events_by_hour[-12:])

        if stats.total_events > 0:
            self.status_label.setText(
                f"Última carga: {stats.total_events} eventos analizados · "
                f"{stats.total_detections} detecciones · {stats.distinct_mitre_techniques} técnicas MITRE"
            )
