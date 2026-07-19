"""Catálogo MITRE ATT&CK y cálculo de cobertura de detección.

`MitreTechnique` es deliberadamente mínimo (id, nombre, táctica, sub-técnica
de) — BlueSentinel no reimplementa el framework completo de MITRE, importa
el subconjunto de técnicas referenciadas por las reglas Sigma cargadas.
`DetectionCoverage` es el cálculo que un Detection Engineer real hace
constantemente: de las técnicas relevantes para mi entorno, ¿cuáles tengo
cubiertas con al menos una regla activa, y cuáles son puntos ciegos?
"""

from __future__ import annotations

from dataclasses import dataclass, field


@dataclass(slots=True, frozen=True)
class MitreTechnique:
    technique_id: str  # ej. "T1059.001"
    name: str
    tactic: str  # ej. "execution"
    sub_technique_of: str | None = None

    @property
    def is_sub_technique(self) -> bool:
        return self.sub_technique_of is not None

    @property
    def parent_id(self) -> str:
        return self.sub_technique_of or self.technique_id.split(".")[0]


@dataclass(slots=True, frozen=True)
class TechniqueCoverage:
    technique: MitreTechnique
    covering_rule_titles: tuple[str, ...]

    @property
    def is_covered(self) -> bool:
        return len(self.covering_rule_titles) > 0


@dataclass(slots=True)
class CoverageReport:
    """Reporte de cobertura de detección: qué técnicas del catálogo tienen
    al menos una regla Sigma habilitada que las referencia, agrupadas por
    táctica — la vista que alimenta el heatmap del MITRE ATT&CK Explorer.
    """

    by_tactic: dict[str, list[TechniqueCoverage]] = field(default_factory=dict)

    @property
    def total_techniques(self) -> int:
        return sum(len(v) for v in self.by_tactic.values())

    @property
    def covered_techniques(self) -> int:
        return sum(1 for techs in self.by_tactic.values() for t in techs if t.is_covered)

    @property
    def coverage_ratio(self) -> float:
        if self.total_techniques == 0:
            return 0.0
        return self.covered_techniques / self.total_techniques


class CoverageCalculator:
    """Calcula `CoverageReport` a partir del catálogo de técnicas y las reglas Sigma activas."""

    def calculate(
        self,
        catalog: list[MitreTechnique],
        rule_technique_map: dict[str, list[str]],  # rule_title -> [technique_ids]
    ) -> CoverageReport:
        technique_to_rules: dict[str, list[str]] = {}
        for rule_title, technique_ids in rule_technique_map.items():
            for tid in technique_ids:
                technique_to_rules.setdefault(tid, []).append(rule_title)

        report = CoverageReport()
        for technique in catalog:
            coverage = TechniqueCoverage(
                technique=technique,
                covering_rule_titles=tuple(technique_to_rules.get(technique.technique_id, [])),
            )
            report.by_tactic.setdefault(technique.tactic, []).append(coverage)
        return report
