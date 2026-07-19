"""Tests end-to-end: YAML Sigma -> parse -> evaluate contra WindowsEvent.

Estos son los tests que realmente importan para un rol de Detection
Engineer: prueban que el motor detecta técnicas de ataque reales y, tan
importante como eso, que NO dispara falsos positivos contra actividad
benigna con forma similar (test negativo explícito por cada regla).
"""

from __future__ import annotations

from datetime import datetime, timezone

from bluesentinel.domain.detection.sigma_evaluator import SigmaEvaluator
from bluesentinel.domain.detection.sigma_parser import parse_sigma_rule
from bluesentinel.domain.entities.windows_event import (
    SYSMON_PROCESS_ACCESS,
    SYSMON_PROCESS_CREATE,
    SYSMON_REGISTRY_EVENT_SET,
    WindowsEvent,
)

from tests.unit.domain.test_sigma_parser import (
    ENCODED_POWERSHELL_RULE,
    LSASS_DUMP_RULE,
    RUN_KEY_PERSISTENCE_RULE,
)


def _process_event(image: str, command_line: str, parent_image: str = "") -> WindowsEvent:
    return WindowsEvent.create(
        event_id=SYSMON_PROCESS_CREATE,
        channel="Microsoft-Windows-Sysmon/Operational",
        computer="WKS-FINANCE-07",
        provider="Microsoft-Windows-Sysmon",
        time_created=datetime.now(timezone.utc),
        event_data={
            "Image": image,
            "CommandLine": command_line,
            "ParentImage": parent_image,
        },
    )


class TestEncodedPowerShellDetection:
    def setup_method(self) -> None:
        self.rule = parse_sigma_rule(ENCODED_POWERSHELL_RULE)
        self.evaluator = SigmaEvaluator()

    def test_detects_encoded_command(self) -> None:
        event = _process_event(
            image=r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe",
            command_line="powershell.exe -nop -w hidden -enc SQBFAFgAIAAoAE4AZQB3AC0A...",
        )
        match = self.evaluator.matches(self.rule, event)
        assert match is not None
        assert "selection_img" in match.matched_selections
        assert "selection_cli" in match.matched_selections

    def test_does_not_detect_plain_powershell(self) -> None:
        """Negativo explícito: powershell.exe sin -enc no debe disparar la regla."""
        event = _process_event(
            image=r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe",
            command_line="powershell.exe -Command Get-Process",
        )
        assert self.evaluator.matches(self.rule, event) is None

    def test_filter_excludes_legitimate_updater(self) -> None:
        """El bloque `filter_legit` debe suprimir el match aunque selection matchee."""
        event = _process_event(
            image=r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe",
            command_line="powershell.exe -enc SQBFAFgA...",
            parent_image=r"C:\Program Files\Vendor\ProductivitySuiteUpdater.exe",
        )
        assert self.evaluator.matches(self.rule, event) is None

    def test_does_not_detect_unrelated_process(self) -> None:
        event = _process_event(image=r"C:\Windows\System32\notepad.exe", command_line="notepad.exe")
        assert self.evaluator.matches(self.rule, event) is None


class TestLSASSDumpDetection:
    def setup_method(self) -> None:
        self.rule = parse_sigma_rule(LSASS_DUMP_RULE)
        self.evaluator = SigmaEvaluator()

    def test_detects_credential_dumping_access(self) -> None:
        event = WindowsEvent.create(
            event_id=SYSMON_PROCESS_ACCESS,
            channel="Microsoft-Windows-Sysmon/Operational",
            computer="WKS-FINANCE-07",
            provider="Microsoft-Windows-Sysmon",
            time_created=datetime.now(timezone.utc),
            event_data={
                "TargetImage": r"C:\Windows\System32\lsass.exe",
                "GrantedAccess": "0x1410",
                "SourceImage": r"C:\Users\Public\rundll32.exe",
            },
        )
        match = self.evaluator.matches(self.rule, event)
        assert match is not None

    def test_does_not_detect_benign_lsass_access(self) -> None:
        """Acceso con permisos mínimos (0x1000, query limited) no es indicativo de dumping."""
        event = WindowsEvent.create(
            event_id=SYSMON_PROCESS_ACCESS,
            channel="Microsoft-Windows-Sysmon/Operational",
            computer="WKS-FINANCE-07",
            provider="Microsoft-Windows-Sysmon",
            time_created=datetime.now(timezone.utc),
            event_data={
                "TargetImage": r"C:\Windows\System32\lsass.exe",
                "GrantedAccess": "0x1000",
            },
        )
        assert self.evaluator.matches(self.rule, event) is None


class TestRunKeyPersistenceDetection:
    def setup_method(self) -> None:
        self.rule = parse_sigma_rule(RUN_KEY_PERSISTENCE_RULE)
        self.evaluator = SigmaEvaluator()

    def test_detects_run_key_write(self) -> None:
        event = WindowsEvent.create(
            event_id=SYSMON_REGISTRY_EVENT_SET,
            channel="Microsoft-Windows-Sysmon/Operational",
            computer="WKS-FINANCE-07",
            provider="Microsoft-Windows-Sysmon",
            time_created=datetime.now(timezone.utc),
            event_data={
                "TargetObject": r"HKU\S-1-5-21-...\Software\Microsoft\Windows\CurrentVersion\Run\Updater",
                "Details": r"C:\Users\Public\update.exe",
            },
        )
        assert self.evaluator.matches(self.rule, event) is not None

    def test_does_not_detect_unrelated_registry_key(self) -> None:
        event = WindowsEvent.create(
            event_id=SYSMON_REGISTRY_EVENT_SET,
            channel="Microsoft-Windows-Sysmon/Operational",
            computer="WKS-FINANCE-07",
            provider="Microsoft-Windows-Sysmon",
            time_created=datetime.now(timezone.utc),
            event_data={"TargetObject": r"HKLM\Software\Microsoft\Windows\Explorer\Advanced"},
        )
        assert self.evaluator.matches(self.rule, event) is None


class TestEvaluateBatch:
    def test_batch_evaluation_across_multiple_rules_and_events(self) -> None:
        rules = [
            parse_sigma_rule(ENCODED_POWERSHELL_RULE),
            parse_sigma_rule(LSASS_DUMP_RULE),
            parse_sigma_rule(RUN_KEY_PERSISTENCE_RULE),
        ]
        events = [
            _process_event(
                r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe",
                "powershell -enc AAAA",
            ),
            _process_event(r"C:\Windows\System32\calc.exe", "calc.exe"),
        ]
        matches = SigmaEvaluator().evaluate_batch(rules, events)
        assert len(matches) == 1
        assert matches[0].rule.title == "Suspicious Encoded PowerShell Command Line"
