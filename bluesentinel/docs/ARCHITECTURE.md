# Arquitectura de BlueSentinel

## 1. Visión general

BlueSentinel es una plataforma de escritorio para operaciones de Blue Team
(SOC Analysts, Detection Engineers, Incident Responders) construida con
**Clean Architecture** en 4 capas concéntricas. La regla de dependencia es
estricta: las capas externas dependen de las internas, nunca al revés.

```
┌─────────────────────────────────────────────────────────┐
│  presentation/   (PySide6, MVVM)                          │
│  ┌───────────────────────────────────────────────────┐   │
│  │  infrastructure/  (SQLAlchemy, parsers, IO)         │   │
│  │  ┌───────────────────────────────────────────┐    │   │
│  │  │  application/  (casos de uso, DTOs)         │    │   │
│  │  │  ┌───────────────────────────────────┐    │    │   │
│  │  │  │  domain/  (entidades, reglas puras) │    │    │   │
│  │  │  └───────────────────────────────────┘    │    │   │
│  │  └───────────────────────────────────────────┘    │   │
│  └───────────────────────────────────────────────────┘   │
└─────────────────────────────────────────────────────────┘
```

- **`domain/`**: entidades (`IOC`, `Case`), value objects (`Severity`,
  `IOCType`...), interfaces de repositorio (`Protocol`) y excepciones. Cero
  imports externos (ni SQLAlchemy, ni Qt). 100% testeable con `pytest` puro.
- **`application/`**: casos de uso (`IOCService`) que orquestan entidades de
  dominio a través de las interfaces de repositorio. No conoce SQL ni Qt.
- **`infrastructure/`**: implementaciones concretas — repositorios
  SQLAlchemy, engine/sesión de BD, parsers de EVTX/Sysmon/YARA/STIX,
  logging estructurado.
- **`presentation/`**: MVVM sobre PySide6. Los `ViewModel` exponen señales
  Qt y llaman a `application`; las `View` son widgets "tontos" que solo
  pintan lo que el ViewModel les da.
- **`bootstrap.py`**: composition root — el único punto donde se conectan
  implementaciones concretas con interfaces abstractas.

## 2. Principios SOLID aplicados

| Principio | Dónde se ve |
|---|---|
| **S**ingle Responsibility | `IOCService` solo orquesta casos de uso de IOC; `SQLAlchemyIOCRepository` solo mapea entidad↔fila; `IOCManagerView` solo pinta. |
| **O**pen/Closed | Nuevos tipos de IOC se añaden extendiendo `IOCType` y `_HASH_LENGTHS`/regex, sin tocar la lógica de `IOCService`. |
| **L**iskov Substitution | Cualquier implementación de `IOCRepository` (SQLAlchemy, in-memory fake, futura API remota) es intercambiable sin romper `IOCService`. |
| **I**nterface Segregation | `IOCRepository` expone solo los métodos que `application` necesita — no un CRUD genérico gigante. |
| **D**ependency Inversion | `IOCService` depende de `domain.repositories.IOCRepository` (abstracción), la implementación concreta se inyecta desde `bootstrap.py`. |

## 3. Por qué Clean Architecture aquí (no es dogma, es necesidad del dominio)

Un producto de blue team vive y muere por la confianza en sus datos: un IOC
mal deduplicado, una transición de caso inválida, o un hash mal validado
puede hacer que un analista ignore una amenaza real o pierda tiempo en un
falso positivo. Aislar las reglas de negocio (`domain/`) de SQLite y de Qt
significa que esas reglas se testean con `pytest` puro, en milisegundos, sin
levantar GUI ni base de datos — y se pueden auditar leyendo un solo archivo.

## 4. Modelo de datos

Ver `src/bluesentinel/infrastructure/db/models.py` para el esquema completo.
Tablas principales: `iocs`, `windows_events`, `sysmon_events`, `sigma_rules`,
`sigma_matches`, `mitre_techniques`, `cases`, `case_evidence`,
`case_timeline`, `threat_feed_sources`, `threat_feed_entries`, `yara_rules`,
`yara_scan_results`, `audit_log`.

## 5. Sistema de plugins (diseño, fase 2)

`plugins/` seguirá el patrón de *entry points* de `importlib.metadata`: un
plugin de terceros declara un grupo `bluesentinel.plugins` en su propio
`pyproject.toml`, implementa un `Protocol` `BlueSentinelPlugin` con métodos
`register(app_context) -> QWidget` y BlueSentinel lo descubre y monta como
un módulo más del sidebar, sin recompilar el core.

## 6. Roadmap de implementación

| Fase | Alcance | Estado |
|---|---|---|
| 0 | Esqueleto Clean Architecture, BD, logging, CI | ✅ Hecho |
| 1 | **IOC Manager** completo (dominio, app, infra, UI, tests) | ✅ Hecho |
| 2 | Case Management (máquina de estados ya en `domain/entities/case.py`) + UI | Diseñado, pendiente de UI |
| 3 | Windows Event Log Explorer (parser EVTX vía `python-evtx`) | Pendiente |
| 4 | Sysmon Analyzer (parsing de Event ID 1/3/7/11/22, correlación proceso-padre) | Pendiente |
| 5 | Sigma Rule Engine (parser YAML + motor de evaluación contra eventos ingeridos) | Pendiente |
| 6 | MITRE ATT&CK Explorer (import de bundle STIX oficial, matriz interactiva) | Pendiente |
| 7 | Timeline Reconstruction (fusiona `case_timeline` + eventos + IOC matches) | Pendiente |
| 8 | Threat Feed Importer (STIX/TAXII, CSV, reutiliza `IOCService.ingest_ioc`) | Pendiente |
| 9 | YARA Scanner (`yara-python`, escaneo de directorios/archivos) | Pendiente |
| 10 | PDF Report Generator (`reportlab`, plantilla de informe de caso) | Pendiente |
| 11 | Search Engine global (FTS5 de SQLite sobre todas las tablas) | Pendiente |
| 12 | Dashboard (agregaciones: IOCs activos, casos abiertos por severidad, top técnicas MITRE) | Pendiente |
| 13 | Sistema de plugins productivo | Pendiente |

Cada fase futura sigue el mismo patrón que IOC Manager: entidad de dominio →
interfaz de repositorio → caso de uso → implementación SQLAlchemy →
ViewModel → View → tests unitarios + integración.
