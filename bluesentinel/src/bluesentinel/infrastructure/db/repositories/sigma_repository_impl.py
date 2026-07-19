"""Repositorio SQLAlchemy para `SigmaRule` y `SigmaMatch`.

Nota: `SigmaRuleModel` guarda el YAML original (`yaml_source`) en vez de
serializar la estructura parseada -- reconstruir el `SigmaRule` de dominio
al leer significa volver a llamar a `parse_sigma_rule`, que es barato y
garantiza que el modelo de dominio y lo persistido nunca puedan divergir
(single source of truth = el YAML, igual que en un repo real de reglas).
"""

from __future__ import annotations

from datetime import datetime
from uuid import UUID

from sqlalchemy import select
from sqlalchemy.orm import Session

from bluesentinel.domain.detection.sigma_evaluator import SigmaMatch
from bluesentinel.domain.detection.sigma_parser import parse_sigma_rule
from bluesentinel.domain.detection.sigma_rule import SigmaRule
from bluesentinel.infrastructure.db.models import SigmaMatchModel, SigmaRuleModel, WindowsEventModel
from bluesentinel.infrastructure.db.repositories.event_repository_impl import (
    SQLAlchemyEventRepository,
)


class SQLAlchemySigmaRuleRepository:
    def __init__(self, session: Session) -> None:
        self._session = session

    def add(self, rule: SigmaRule) -> None:
        model = SigmaRuleModel(
            id=str(rule.id),
            rule_id=rule.rule_id or str(rule.id),
            title=rule.title,
            status=rule.status.value,
            level=rule.level.value,
            logsource_product=rule.logsource_product,
            logsource_category=rule.logsource_category,
            logsource_service=rule.logsource_service,
            yaml_source=rule.raw_yaml,
            enabled=rule.enabled,
            mitre_technique_ids=",".join(rule.mitre_technique_ids),
        )
        self._session.add(model)
        self._session.flush()

    def get_all_enabled(self) -> list[SigmaRule]:
        stmt = select(SigmaRuleModel).where(SigmaRuleModel.enabled.is_(True))
        models = self._session.execute(stmt).scalars().all()
        return [self._to_entity(m) for m in models]

    def get_all(self) -> list[SigmaRule]:
        models = self._session.execute(select(SigmaRuleModel)).scalars().all()
        return [self._to_entity(m) for m in models]

    def count(self) -> int:
        from sqlalchemy import func

        stmt = select(func.count()).select_from(SigmaRuleModel)
        return int(self._session.execute(stmt).scalar_one())

    def clear_all(self) -> None:
        self._session.query(SigmaRuleModel).delete()
        self._session.flush()

    @staticmethod
    def _to_entity(model: SigmaRuleModel) -> SigmaRule:
        # Re-parsear desde el YAML fuente garantiza que domain y BD nunca diverjan.
        rule = parse_sigma_rule(model.yaml_source)
        rule.id = UUID(model.id)
        rule.enabled = model.enabled
        return rule


class SQLAlchemySigmaMatchRepository:
    def __init__(self, session: Session) -> None:
        self._session = session

    def bulk_add(self, matches: list[SigmaMatch], rule_id_map: dict[str, str]) -> None:
        """Persiste una tanda de matches. `rule_id_map` traduce
        `rule.rule_id` (id YAML de Sigma) -> id de fila `SigmaRuleModel`."""
        now = datetime.utcnow()
        models = []
        for match in matches:
            db_rule_id = rule_id_map.get(match.rule.rule_id)
            if db_rule_id is None:
                continue
            models.append(
                SigmaMatchModel(
                    rule_id=db_rule_id,
                    event_id=str(match.event.id),
                    matched_selections=",".join(match.matched_selections),
                    matched_at=now,
                )
            )
        self._session.add_all(models)
        self._session.flush()

    def count(self) -> int:
        from sqlalchemy import func

        stmt = select(func.count()).select_from(SigmaMatchModel)
        return int(self._session.execute(stmt).scalar_one())

    def clear_all(self) -> None:
        self._session.query(SigmaMatchModel).delete()
        self._session.flush()

    def summary_rows(self) -> list[dict]:
        """Devuelve filas planas (regla + evento) listas para pintar en la UI,
        sin exponer los modelos ORM fuera de infrastructure."""
        stmt = (
            select(SigmaMatchModel, SigmaRuleModel, WindowsEventModel)
            .join(SigmaRuleModel, SigmaMatchModel.rule_id == SigmaRuleModel.id)
            .join(WindowsEventModel, SigmaMatchModel.event_id == WindowsEventModel.id)
            .order_by(WindowsEventModel.time_created)
        )
        rows = []
        for match_model, rule_model, event_model in self._session.execute(stmt).all():
            event = SQLAlchemyEventRepository.event_from_model(event_model)
            rows.append(
                {
                    "rule_title": rule_model.title,
                    "level": rule_model.level,
                    "mitre_technique_ids": rule_model.mitre_technique_ids.split(",")
                    if rule_model.mitre_technique_ids
                    else [],
                    "event": event,
                    "matched_selections": match_model.matched_selections.split(","),
                    "matched_at": match_model.matched_at,
                }
            )
        return rows
