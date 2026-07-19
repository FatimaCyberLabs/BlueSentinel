"""Catálogo MITRE ATT&CK embebido: subconjunto curado de Enterprise ATT&CK.

BlueSentinel no descarga el bundle STIX completo de MITRE en runtime (esa
es la aproximación de un scraper, no de un producto): en cambio embebe el
subconjunto de técnicas más relevante para detección basada en host/Sysmon
-- exactamente las tácticas y técnicas que el rule pack incluido referencia,
más un margen de técnicas hermanas para que el heatmap muestre huecos de
cobertura reales, no solo lo que ya está cubierto (que sería trivial y
poco honesto).

IDs y nombres verificados contra la matriz pública de MITRE ATT&CK
(Enterprise, v15/v16). Ampliar este catálogo es tan simple como añadir
entradas -- no requiere tocar `domain` ni `application`.
"""

from __future__ import annotations

from bluesentinel.domain.detection.mitre_coverage import MitreTechnique

BUILTIN_MITRE_CATALOG: list[MitreTechnique] = [
    # --- Initial Access ---------------------------------------------------------
    MitreTechnique("T1566", "Phishing", "initial-access"),
    MitreTechnique("T1566.001", "Spearphishing Attachment", "initial-access", sub_technique_of="T1566"),
    MitreTechnique("T1204", "User Execution", "initial-access"),
    MitreTechnique("T1204.002", "Malicious File", "initial-access", sub_technique_of="T1204"),
    MitreTechnique("T1078", "Valid Accounts", "initial-access"),
    # --- Execution ----------------------------------------------------------------
    MitreTechnique("T1059", "Command and Scripting Interpreter", "execution"),
    MitreTechnique("T1059.001", "PowerShell", "execution", sub_technique_of="T1059"),
    MitreTechnique("T1059.003", "Windows Command Shell", "execution", sub_technique_of="T1059"),
    MitreTechnique("T1047", "Windows Management Instrumentation", "execution"),
    MitreTechnique("T1053", "Scheduled Task/Job", "execution"),
    # --- Persistence ----------------------------------------------------------------
    MitreTechnique("T1547", "Boot or Logon Autostart Execution", "persistence"),
    MitreTechnique("T1547.001", "Registry Run Keys / Startup Folder", "persistence", sub_technique_of="T1547"),
    MitreTechnique("T1053.005", "Scheduled Task", "persistence", sub_technique_of="T1053"),
    MitreTechnique("T1136", "Create Account", "persistence"),
    # --- Privilege Escalation --------------------------------------------------------
    MitreTechnique("T1055", "Process Injection", "privilege-escalation"),
    MitreTechnique("T1548", "Abuse Elevation Control Mechanism", "privilege-escalation"),
    # --- Defense Evasion ---------------------------------------------------------------
    MitreTechnique("T1027", "Obfuscated Files or Information", "defense-evasion"),
    MitreTechnique("T1562", "Impair Defenses", "defense-evasion"),
    MitreTechnique("T1562.001", "Disable or Modify Tools", "defense-evasion", sub_technique_of="T1562"),
    MitreTechnique("T1070", "Indicator Removal", "defense-evasion"),
    MitreTechnique("T1036", "Masquerading", "defense-evasion"),
    # --- Credential Access ------------------------------------------------------------
    MitreTechnique("T1003", "OS Credential Dumping", "credential-access"),
    MitreTechnique("T1003.001", "LSASS Memory", "credential-access", sub_technique_of="T1003"),
    MitreTechnique("T1110", "Brute Force", "credential-access"),
    MitreTechnique("T1552", "Unsecured Credentials", "credential-access"),
    # --- Discovery -----------------------------------------------------------------------
    MitreTechnique("T1082", "System Information Discovery", "discovery"),
    MitreTechnique("T1087", "Account Discovery", "discovery"),
    MitreTechnique("T1069", "Permission Groups Discovery", "discovery"),
    # --- Lateral Movement ------------------------------------------------------------------
    # Nota: T1047 (WMI) es oficialmente táctica "Execution" en MITRE, pero se usa
    # constantemente para movimiento lateral remoto (wmic /node:...) -- se deja
    # clasificado en Execution para no inventar un ID que no existe en el framework.
    MitreTechnique("T1021", "Remote Services", "lateral-movement"),
    MitreTechnique("T1021.002", "SMB/Windows Admin Shares", "lateral-movement", sub_technique_of="T1021"),
    # --- Collection ----------------------------------------------------------------------------
    MitreTechnique("T1005", "Data from Local System", "collection"),
    # --- Command and Control -----------------------------------------------------------------
    MitreTechnique("T1071", "Application Layer Protocol", "command-and-control"),
    MitreTechnique("T1071.001", "Web Protocols", "command-and-control", sub_technique_of="T1071"),
    MitreTechnique("T1105", "Ingress Tool Transfer", "command-and-control"),
    # --- Exfiltration --------------------------------------------------------------------------
    MitreTechnique("T1041", "Exfiltration Over C2 Channel", "exfiltration"),
]
