"""Tests de `ProcessTreeBuilder` usando una cadena de ataque LOLBin realista:

WINWORD.EXE (documento malicioso con macro)
  -> powershell.exe (dropper vía macro)
       -> rundll32.exe (inyecta y accede a lsass.exe para dumping)
     [conexión de red saliente hacia C2]

Esto es deliberadamente el patrón de ataque más común en informes de
Mandiant/CrowdStrike para intrusiones iniciales vía phishing con macro.
"""

from __future__ import annotations

from datetime import datetime, timedelta, timezone

from bluesentinel.domain.entities.windows_event import (
    SYSMON_NETWORK_CONNECT,
    SYSMON_PROCESS_ACCESS,
    SYSMON_PROCESS_CREATE,
    WindowsEvent,
)
from bluesentinel.domain.forensics.process_tree import ProcessTreeBuilder

T0 = datetime(2026, 3, 14, 9, 0, 0, tzinfo=timezone.utc)


def _proc(guid: str, parent_guid: str, image: str, cmdline: str, offset_sec: int) -> WindowsEvent:
    return WindowsEvent.create(
        event_id=SYSMON_PROCESS_CREATE,
        channel="Microsoft-Windows-Sysmon/Operational",
        computer="WKS-FINANCE-07",
        provider="Microsoft-Windows-Sysmon",
        time_created=T0 + timedelta(seconds=offset_sec),
        event_data={
            "ProcessGuid": guid,
            "ParentProcessGuid": parent_guid,
            "Image": image,
            "CommandLine": cmdline,
        },
    )


def _attack_chain_events() -> list[WindowsEvent]:
    winword = _proc("{guid-winword}", "{guid-explorer}", r"C:\...\WINWORD.EXE", "WINWORD.EXE invoice.docm", 0)
    powershell = _proc(
        "{guid-ps}",
        "{guid-winword}",
        r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe",
        "powershell -nop -w hidden -enc SQBFAFgA...",
        5,
    )
    rundll32 = _proc(
        "{guid-rundll}", "{guid-ps}", r"C:\Windows\System32\rundll32.exe", "rundll32.exe comsvcs.dll, MiniDump", 20
    )
    lsass_access = WindowsEvent.create(
        event_id=SYSMON_PROCESS_ACCESS,
        channel="Microsoft-Windows-Sysmon/Operational",
        computer="WKS-FINANCE-07",
        provider="Microsoft-Windows-Sysmon",
        time_created=T0 + timedelta(seconds=21),
        event_data={
            "SourceProcessGUID": "{guid-rundll}",
            "TargetImage": r"C:\Windows\System32\lsass.exe",
            "GrantedAccess": "0x1410",
        },
    )
    c2_connection = WindowsEvent.create(
        event_id=SYSMON_NETWORK_CONNECT,
        channel="Microsoft-Windows-Sysmon/Operational",
        computer="WKS-FINANCE-07",
        provider="Microsoft-Windows-Sysmon",
        time_created=T0 + timedelta(seconds=6),
        event_data={
            "ProcessGuid": "{guid-ps}",
            "DestinationIp": "185.220.101.42",
            "DestinationPort": "443",
        },
    )
    return [winword, powershell, rundll32, lsass_access, c2_connection]


def test_builds_correct_process_hierarchy() -> None:
    roots = ProcessTreeBuilder().build(_attack_chain_events())
    assert len(roots) == 1
    winword_node = roots[0]
    assert winword_node.image.endswith("WINWORD.EXE")
    assert winword_node.is_root is True

    powershell_node = winword_node.children[0]
    assert powershell_node.image.endswith("powershell.exe")

    rundll_node = powershell_node.children[0]
    assert rundll_node.image.endswith("rundll32.exe")


def test_network_event_attached_to_correct_process() -> None:
    roots = ProcessTreeBuilder().build(_attack_chain_events())
    powershell_node = roots[0].children[0]
    net_events = powershell_node.network_events()
    assert len(net_events) == 1
    assert net_events[0].destination_ip == "185.220.101.42"


def test_process_access_attached_to_source_process_not_target() -> None:
    """El evento de acceso a LSASS debe colgar de rundll32 (quien accede), no de lsass."""
    roots = ProcessTreeBuilder().build(_attack_chain_events())
    rundll_node = roots[0].children[0].children[0]
    access_events = rundll_node.accessed_by()
    assert len(access_events) == 1
    assert access_events[0].field_value("TargetImage") == r"C:\Windows\System32\lsass.exe"


def test_depth_first_flattening_preserves_full_chain() -> None:
    roots = ProcessTreeBuilder().build(_attack_chain_events())
    flat = roots[0].depth_first
    images = [n.image.split("\\")[-1] for n in flat]
    assert images == ["WINWORD.EXE", "powershell.exe", "rundll32.exe"]


def test_find_node_by_guid() -> None:
    roots = ProcessTreeBuilder().build(_attack_chain_events())
    found = ProcessTreeBuilder().find_node(roots, "{guid-rundll}")
    assert found is not None
    assert found.image.endswith("rundll32.exe")


def test_orphan_process_becomes_its_own_root() -> None:
    """Si el padre no aparece en el dataset capturado, el hijo se marca is_root."""
    orphan = _proc("{guid-orphan}", "{guid-unknown-parent}", r"C:\svc.exe", "svc.exe", 100)
    roots = ProcessTreeBuilder().build([orphan])
    assert len(roots) == 1
    assert roots[0].is_root is True
