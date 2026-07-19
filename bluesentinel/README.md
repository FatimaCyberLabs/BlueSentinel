# BlueSentinel

**Plataforma de investigacion de Blue Team para SOC Analysts, Detection
Engineers e Incident Responders.** Motor de deteccion Sigma real, forense
de arbol de procesos, mapeo MITRE ATT&CK y gestion de casos -- construida
con Clean Architecture, SQLAlchemy y PySide6.

## Que hace, en una frase

Carga un escenario de intrusion sintetico (phishing -> PowerShell ofuscado
-> persistencia -> evasion de AMSI -> dump de LSASS -> movimiento lateral
-> C2), lo evalua contra un rule pack Sigma real, reconstruye el arbol de
procesos del ataque, mapea las tecnicas MITRE ATT&CK involucradas, y abre
automaticamente un caso de investigacion con timeline, evidencia y notas
de analista -- todo dentro de una unica pantalla de trabajo (Investigation
Workbench), sin salir de la aplicacion.

## Flujo de investigacion end-to-end

1. **Cargar y analizar escenario** (un boton) -> ingesta ~25 eventos de
   Windows/Sysmon con forma real (Image, CommandLine, ProcessGuid,
   ParentProcessGuid, GrantedAccess, TargetObject...).
2. El **motor Sigma** (parser + evaluador de gramatica booleana propio,
   sin dependencias externas de deteccion) evalua 7 reglas reales contra
   cada evento.
3. Las detecciones abren automaticamente un **caso de investigacion** con
   severidad calculada, evidencia vinculada y timeline cronologico.
4. El **arbol de procesos** reconstruye el lineage completo via
   ProcessGuid/ParentProcessGuid y resalta los procesos con detecciones.
5. El **MITRE ATT&CK Explorer** muestra un heatmap de cobertura real
   (que tecnicas estan cubiertas por regla vs. cuales tuvieron un match
   real en este caso vs. puntos ciegos).
6. El analista gestiona el **caso**: transiciona su estado (maquina de
   estados de IR: New -> Triage -> Investigating -> Containment ->
   Eradication -> Recovery -> Closed), añade notas.

## Stack

- Python 3.13, type hints estrictos (`mypy --strict`)
- PySide6 (UI, patron MVVM, tema oscuro custom)
- SQLAlchemy 2.0 + SQLite (WAL, foreign keys forzadas)
- `structlog` (logging JSON estructurado + rotacion diaria)
- `pytest` / `pytest-qt` / `pytest-cov`
- CI en GitHub Actions (lint, type-check, tests en Linux + Windows, build)

## Arquitectura

Clean Architecture en 4 capas. Documentacion completa en
[`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md), incluyendo por que se
cortaron 6 de los 13 modulos originalmente considerados y se invirtio ese
tiempo en profundidad sobre los 7 restantes.

```
src/bluesentinel/
├── domain/
│   ├── entities/         # IOC, Case, WindowsEvent
│   ├── detection/         # SigmaRule, sigma_parser, sigma_evaluator, mitre_coverage
│   └── forensics/          # ProcessTreeBuilder (lineage via ProcessGuid)
├── application/
│   ├── ioc/                # IOCService
│   ├── cases/               # (integrado en InvestigationService)
│   └── detection/            # InvestigationService -- orquesta el pipeline completo
├── infrastructure/
│   ├── db/                    # modelos SQLAlchemy + repositorios
│   ├── rules/packs/             # rule pack Sigma real (7 reglas, YAML)
│   ├── demo_data/                 # generador del escenario de intrusion sintetico
│   └── mitre/                      # catalogo MITRE ATT&CK embebido
└── presentation/
    ├── viewmodels/                   # InvestigationViewModel, IOCManagerViewModel
    └── views/                         # Dashboard, Workbench, ProcessTree, MITRE, Case...
```

## Motor de deteccion Sigma

Parser + evaluador propios (no usa `pySigma`), implementados en
`domain/detection/`:

- Modificadores de campo: `contains`, `startswith`, `endswith`, `re`, `all`.
- Gramatica booleana completa: `and`/`or`/`not`, parentesis, `1 of`/`all of`/`them`.
- Selecciones como lista de mapas (OR de grupos AND), igual que el spec oficial de Sigma.

Verificado contra un escenario de ataque completo con ruido benigno
entrelazado -- ver `tests/integration/test_full_attack_scenario.py`, que
comprueba tanto las detecciones esperadas (recall) como la ausencia de
falsos positivos sobre actividad benigna con forma similar (precision).

## Instalacion y ejecucion

```bash
python3.13 -m venv .venv
source .venv/bin/activate  # Windows: .venv\Scripts\activate
pip install -e ".[dev]"

python -m bluesentinel
```

Al abrir la app, ve a **Investigacion** y pulsa **"Cargar y analizar
escenario"** -- todo el flujo descrito arriba se ejecuta en segundos.

## Tests

```bash
pytest                          # unit + integracion, con cobertura
mypy src                        # type checking estricto
ruff check src tests            # lint
```

~79 tests: parser Sigma, gramatica de condiciones, motor de evaluacion
contra eventos realistas, reconstruccion de arbol de procesos con una
cadena de ataque LOLBin completa, entidades de dominio (IOC, Case con
maquina de estados), y el test de integracion end-to-end del escenario
completo.

## Roadmap

Ver `docs/ARCHITECTURE.md` para el detalle de decisiones de diseño y lo
que queda pendiente (empaquetado PyInstaller, ingesta de EVTX real desde
disco, ampliacion del catalogo MITRE).

## Licencia

MIT
