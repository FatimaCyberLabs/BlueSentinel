"""Tests del parser Sigma usando reglas con la forma real de SigmaHQ."""

from __future__ import annotations

import pytest

from bluesentinel.domain.detection.sigma_parser import parse_sigma_rule
from bluesentinel.domain.detection.sigma_rule import FieldModifier
from bluesentinel.domain.exceptions import RuleParsingError
from bluesentinel.domain.value_objects.enums import SigmaLevel, SigmaStatus

ENCODED_POWERSHELL_RULE = """
title: Suspicious Encoded PowerShell Command Line
id: 65531a81-a694-4b76-9d90-2f4e0a1a1111
status: stable
description: Detects PowerShell invoked with an obfuscated/encoded command, common in droppers.
level: high
logsource:
  product: windows
  category: process_creation
tags:
  - attack.execution
  - attack.t1059.001
  - attack.defense_evasion
  - attack.t1027
detection:
  selection_img:
    Image|endswith:
      - '\\powershell.exe'
      - '\\pwsh.exe'
  selection_cli:
    CommandLine|contains:
      - '-enc '
      - '-EncodedCommand'
      - '-e '
  filter_legit:
    ParentImage|endswith: '\\ProductivitySuiteUpdater.exe'
  condition: selection_img and selection_cli and not filter_legit
falsepositives:
  - Legitimate administration scripts
"""

LSASS_DUMP_RULE = """
title: LSASS Memory Dump via ProcessAccess
id: 0f4c1b3a-2222-4b76-9d90-2f4e0a1a2222
status: stable
level: critical
logsource:
  product: windows
  category: process_access
tags:
  - attack.credential_access
  - attack.t1003.001
detection:
  selection:
    TargetImage|endswith: '\\lsass.exe'
    GrantedAccess:
      - '0x1010'
      - '0x1410'
      - '0x1438'
  condition: selection
"""

RUN_KEY_PERSISTENCE_RULE = """
title: Persistence via Registry Run Key
id: 9a8b7c6d-3333-4b76-9d90-2f4e0a1a3333
status: test
level: medium
logsource:
  product: windows
  category: registry_event
tags:
  - attack.persistence
  - attack.t1547.001
detection:
  selection:
    TargetObject|contains: '\\CurrentVersion\\Run\\'
  condition: selection
"""


def test_parse_basic_fields() -> None:
    rule = parse_sigma_rule(ENCODED_POWERSHELL_RULE)
    assert rule.title == "Suspicious Encoded PowerShell Command Line"
    assert rule.level == SigmaLevel.HIGH
    assert rule.status == SigmaStatus.STABLE
    assert rule.logsource_category == "process_creation"


def test_parse_extracts_mitre_technique_ids() -> None:
    rule = parse_sigma_rule(ENCODED_POWERSHELL_RULE)
    assert "T1059.001" in rule.mitre_technique_ids
    assert "T1027" in rule.mitre_technique_ids


def test_parse_selections_and_modifiers() -> None:
    rule = parse_sigma_rule(ENCODED_POWERSHELL_RULE)
    assert set(rule.selections.keys()) == {"selection_img", "selection_cli", "filter_legit"}

    img_condition = rule.selections["selection_img"].and_groups[0][0]
    assert img_condition.field_name == "Image"
    assert img_condition.modifier == FieldModifier.ENDSWITH
    assert "\\powershell.exe" in img_condition.values


def test_parse_and_within_group_or_across_fields() -> None:
    rule = parse_sigma_rule(LSASS_DUMP_RULE)
    group = rule.selections["selection"].and_groups[0]
    assert len(group) == 2  # TargetImage AND GrantedAccess


def test_parse_rejects_missing_detection_block() -> None:
    with pytest.raises(RuleParsingError):
        parse_sigma_rule("title: Broken Rule\nlogsource:\n  product: windows\n")


def test_parse_rejects_missing_condition() -> None:
    broken = "title: X\ndetection:\n  selection:\n    Image: foo.exe\n"
    with pytest.raises(RuleParsingError):
        parse_sigma_rule(broken)


def test_parse_rejects_unsupported_modifier() -> None:
    broken = (
        "title: X\ndetection:\n  selection:\n    Image|unsupported: foo\n"
        "  condition: selection\n"
    )
    with pytest.raises(RuleParsingError):
        parse_sigma_rule(broken)


def test_parse_rejects_invalid_yaml() -> None:
    with pytest.raises(RuleParsingError):
        parse_sigma_rule("title: [unclosed")


def test_parse_run_key_rule() -> None:
    rule = parse_sigma_rule(RUN_KEY_PERSISTENCE_RULE)
    assert rule.mitre_technique_ids == ("T1547.001",)
    condition = rule.selections["selection"].and_groups[0][0]
    assert condition.modifier == FieldModifier.CONTAINS
