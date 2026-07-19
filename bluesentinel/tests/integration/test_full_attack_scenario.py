"""Test de integración de extremo a extremo: el escenario de intrusión sintético
completo, evaluado contra el rule pack real que se distribuye con BlueSentinel.

Este es el test que demuestra que el proyecto funciona como un sistema, no
solo como unidades aisladas: carga reglas Sigma reales desde YAML, genera
un dataset de eventos con forma de EVTX real, corre la evaluación completa,
y verifica tanto las detecciones esperadas (recall) como la ausencia de
falsos positivos sobre actividad benigna con forma similar (precision).
"""

from __future__ import annotations

from bluesentinel.domain.detection.sigma_evaluator import SigmaEvaluator
from bluesentinel.domain.forensics.process_tree import ProcessTreeBuilder
from bluesentinel.infrastructure.demo_data.attack_scenario import generate_intrusion_scenario
from bluesentinel.infrastructure.rules.rule_pack_loader import load_builtin_rule_pack


def test_rule_pack_loads_all_seven_rules() -> None:
    rules = load_builtin_rule_pack()
    assert len(rules) == 7
    titles = {r.title for r in rules}
    assert "LSASS Memory Dump via Process Access (comsvcs.dll / rundll32)" in titles


def test_scenario_generates_full_kill_chain_events() -> None:
    events = generate_intrusion_scenario()
    assert len(events) > 15
    # Debe incluir tanto actividad maliciosa como ruido benigno.
    images = {e.image for e in events if e.image}
    assert any("WINWORD.EXE" in img for img in images)
    assert any("Teams.exe" in img for img in images)  # ruido benigno


def test_full_scenario_triggers_expected_detections() -> None:
    rules = load_builtin_rule_pack()
    events = generate_intrusion_scenario()
    matches = SigmaEvaluator().evaluate_batch(rules, events)

    matched_titles = {m.rule.title for m in matches}
    expected_detections = {
        "Office Application Spawning Windows Shell or Script Interpreter",
        "Suspicious Encoded PowerShell Command Line",
        "Persistence via Registry Run Key",
        "AMSI Provider Tampering via Registry",
        "LSASS Memory Dump via Process Access (comsvcs.dll / rundll32)",
        "WMI Process Creation on Remote Host",
        "Outbound Connection to Known C2 Beacon Pattern",
    }
    assert expected_detections.issubset(matched_titles), (
        f"Faltan detecciones: {expected_detections - matched_titles}"
    )


def test_full_scenario_does_not_flag_benign_updater_powershell() -> None:
    """El PowerShell legítimo lanzado por ProductivitySuiteUpdater.exe (ruido
    benigno con -enc, igual que el ataque) NO debe aparecer como el origen de
    un match de la regla de PowerShell codificado — el `filter_legit` de la
    regla debe suprimirlo específicamente.
    """
    rules = load_builtin_rule_pack()
    events = generate_intrusion_scenario()
    matches = SigmaEvaluator().evaluate_batch(rules, events)

    encoded_ps_matches = [
        m for m in matches if m.rule.title == "Suspicious Encoded PowerShell Command Line"
    ]
    for match in encoded_ps_matches:
        assert match.event.parent_image != r"C:\Program Files\Vendor\ProductivitySuiteUpdater.exe"


def test_full_scenario_process_tree_reconstructs_attack_lineage() -> None:
    events = generate_intrusion_scenario()
    roots = ProcessTreeBuilder().build(events)
    assert len(roots) == 1

    flat = roots[0].depth_first
    image_names = [n.image.split("\\")[-1] for n in flat]

    # La cadena de ataque completa debe aparecer en el orden correcto de lineage.
    attack_chain = ["WINWORD.EXE", "powershell.exe", "rundll32.exe"]
    positions = [image_names.index(name) for name in attack_chain]
    assert positions == sorted(positions), "El lineage del ataque debe preservar el orden padre->hijo"


def test_full_scenario_mitre_coverage() -> None:
    """Verifica que las técnicas MITRE cubiertas por el rule pack abarcan
    múltiples tácticas de la kill chain (no solo una fase aislada)."""
    rules = load_builtin_rule_pack()
    all_technique_ids = {tid for r in rules for tid in r.mitre_technique_ids}
    expected_tactics_covered = {
        "T1059.001",  # Execution
        "T1547.001",  # Persistence
        "T1562.001",  # Defense Evasion
        "T1003.001",  # Credential Access
        "T1047",  # Lateral Movement
        "T1071.001",  # Command and Control
    }
    assert expected_tactics_covered.issubset(all_technique_ids)
