"""Ventana principal de BlueSentinel: shell de navegación de la plataforma.

Tres modulos, los tres completos y conectados de extremo a extremo:
  1. Dashboard          -- estado del SOC con datos reales
  2. Investigacion       -- workbench completo (arbol de procesos, detecciones,
                            timeline, MITRE ATT&CK, gestion de caso)
  3. IOC Manager          -- gestion de indicadores de compromiso

Sin "proximamente": todo lo que aparece en el sidebar funciona de punta a punta.
"""

from __future__ import annotations

from PySide6.QtCore import Qt
from PySide6.QtGui import QKeySequence, QShortcut
from PySide6.QtWidgets import (
    QLabel,
    QListWidget,
    QListWidgetItem,
    QMainWindow,
    QMessageBox,
    QSplitter,
    QStackedWidget,
    QStatusBar,
)

from bluesentinel.application.ioc.ioc_service import IOCService
from bluesentinel.bootstrap import AppContext
from bluesentinel.core_config import APP_NAME, APP_VERSION
from bluesentinel.infrastructure.db.repositories.ioc_repository_impl import (
    SQLAlchemyIOCRepository,
)
from bluesentinel.presentation.viewmodels.investigation_viewmodel import InvestigationViewModel
from bluesentinel.presentation.viewmodels.ioc_viewmodel import IOCManagerViewModel
from bluesentinel.presentation.views.dashboard_view import DashboardView
from bluesentinel.presentation.views.investigation_workbench_view import (
    InvestigationWorkbenchView,
)
from bluesentinel.presentation.views.ioc_manager_view import IOCManagerView

_DARK_STYLESHEET = """
QMainWindow, QWidget { background-color: #14161c; color: #e2e4e9; font-family: 'Segoe UI', sans-serif; }
QGroupBox { border: 1px solid #2a2e38; border-radius: 6px; margin-top: 8px; padding-top: 10px; font-weight: 600; }
QGroupBox::title { subcontrol-origin: margin; left: 8px; padding: 0 4px; color: #aab; }
QTableWidget, QTreeWidget, QListWidget { background-color: #1b1f27; alternate-background-color: #20242e;
    border: 1px solid #2a2e38; gridline-color: #2a2e38; }
QHeaderView::section { background-color: #20242e; color: #ccd; padding: 6px; border: none; border-bottom: 1px solid #333; }
QTabWidget::pane { border: 1px solid #2a2e38; }
QTabBar::tab { background: #1b1f27; color: #aab; padding: 8px 16px; }
QTabBar::tab:selected { background: #2b6cb0; color: white; }
QLineEdit, QComboBox, QPlainTextEdit { background-color: #1b1f27; border: 1px solid #333;
    border-radius: 4px; padding: 5px; color: #e2e4e9; }
QPushButton { background-color: #2a2e38; color: #e2e4e9; border-radius: 4px; padding: 6px 12px; }
QPushButton:hover { background-color: #383e4a; }
QScrollBar:vertical { background: #14161c; width: 10px; }
QScrollBar::handle:vertical { background: #333; border-radius: 5px; }
"""


class MainWindow(QMainWindow):
    def __init__(self, context: AppContext) -> None:
        super().__init__()
        self._context = context
        self.setWindowTitle(f"{APP_NAME} v{APP_VERSION} -- Blue Team Investigation Platform")
        self.resize(1600, 960)
        self.setStyleSheet(_DARK_STYLESHEET)

        self._investigation_vm = InvestigationViewModel(context.session_factory)
        self._ioc_vm = IOCManagerViewModel(context.session_factory)

        self._sidebar = QListWidget()
        self._sidebar.setFixedWidth(220)
        self._sidebar.setStyleSheet(
            "QListWidget { background-color: #10121a; border: none; font-size: 14px; }"
            "QListWidget::item { padding: 14px 18px; }"
            "QListWidget::item:selected { background-color: #2b6cb0; color: white; }"
        )

        self._stack = QStackedWidget()

        self.dashboard_view = DashboardView()
        self.workbench_view = InvestigationWorkbenchView(self._investigation_vm)
        self.ioc_view = IOCManagerView(self._ioc_vm)

        for label, widget in [
            ("\U0001F4CA  Dashboard", self.dashboard_view),
            ("\U0001F50D  Investigacion", self.workbench_view),
            ("\U0001F3AF  IOC Manager", self.ioc_view),
        ]:
            self._sidebar.addItem(QListWidgetItem(label))
            self._stack.addWidget(widget)

        self._sidebar.currentRowChanged.connect(self._stack.setCurrentIndex)
        self._sidebar.setCurrentRow(1)  # Arranca en Investigacion: es la demo.

        splitter = QSplitter()
        splitter.addWidget(self._sidebar)
        splitter.addWidget(self._stack)
        splitter.setStretchFactor(1, 1)
        self.setCentralWidget(splitter)

        self._status_bar = QStatusBar()
        self._status_bar.showMessage(f"Base de datos local: {context.config.db_path}")
        self.setStatusBar(self._status_bar)

        self._investigation_vm.dashboard_ready.connect(self._on_dashboard_ready)
        self._investigation_vm.pipeline_finished.connect(
            lambda *_: self._sidebar.setCurrentRow(1)
        )
        self._investigation_vm.error_occurred.connect(self._on_error)

        search_shortcut = QShortcut(QKeySequence("Ctrl+K"), self)
        search_shortcut.activated.connect(self._focus_search)

        self._ioc_vm.iocs_changed.connect(lambda _rows: self._refresh_dashboard_iocs())

    def _focus_search(self) -> None:
        self._sidebar.setCurrentRow(1)
        self.workbench_view.tabs.setCurrentIndex(0)
        self.workbench_view.detections_view.search_input.setFocus()

    def _on_dashboard_ready(self, stats) -> None:
        session = self._context.session_factory()
        try:
            active_iocs = IOCService(SQLAlchemyIOCRepository(session)).get_active_count()
        finally:
            session.close()
        open_cases = 1 if self._investigation_vm.current_case else 0
        self.dashboard_view.load_stats(stats, active_iocs=active_iocs, open_cases=open_cases)

    def _refresh_dashboard_iocs(self) -> None:
        self._investigation_vm.refresh()

    def _on_error(self, message: str) -> None:
        QMessageBox.critical(self, "Error", message)
