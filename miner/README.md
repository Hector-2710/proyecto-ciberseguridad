# Miner — Vulnerability Extraction Pipeline

> **Component 1/3** del proyecto semestral de Ciberseguridad.
> Extrae vulnerabilidades de repositorios Python mediante CodeQL, Syft y Grype.

---

## Tabla de Contenidos

1. [Visión General](#1-visión-general)
2. [Estructura de Carpetas](#2-estructura-de-carpetas)
3. [Flujo del Pipeline](#3-flujo-del-pipeline)
4. [Módulos del Miner](#4-módulos-del-miner)
5. [Formato de Salida](#5-formato-de-salida)
6. [Uso](#6-uso)
7. [Dev Container](#7-dev-container)
8. [Scripts Heredados](#8-scripts-heredados)
9. [Dependencias](#9-dependencias)

---

## 1. Visión General

El **Miner** es el componente de extracción del sistema. Procesa múltiples repositorios
de forma continua y automatizada, ejecutando tres herramientas de análisis:

| Herramienta | Propósito | Entrada | Salida |
|-------------|-----------|---------|--------|
| **CodeQL** | Análisis estático de seguridad (Java/Python según detección) | Código fuente del repo | SARIF JSON |
| **Syft** | Generación de SBOM (Software Bill of Materials) | Directorio del repo | Syft JSON |
| **Grype** | Detección de vulnerabilidades en dependencias | SBOM generado por Syft | Grype JSON |

El Miner orquesta las tres herramientas, consolida los resultados y produce un
**dataset estructurado único** (`miner_dataset.json`) con todas las vulnerabilidades
encontradas, listas para ser consumidas por el Analyzer y Visualizer.

### Características clave

- **Procesamiento continuo:** Itera sobre repositorios definidos en `data/repos.json`.
- **Reanudación automática:** Si el pipeline se interrumpe, al re-ejecutarlo
  salta los pasos ya completados (clon, CodeQL, SBOM, Grype).
- **Aislamiento de errores:** Un fallo en un repositorio no detiene el
  procesamiento de los demás.
- **Dev Container:** Entorno completamente reproducible con todas las herramientas
  preinstaladas.

---

## 2. Estructura de Carpetas

```
proyecto-ciberseguridad/
│
├── miner/                          ← Componente Miner (autocontenido)
│   │
│   ├── __init__.py                 # Punto de entrada del paquete
│   ├── __main__.py                 # CLI: python __main__.py
│   ├── config.py                   # Carga repos.json, resuelve rutas
│   ├── models.py                   # Dataclasses: Vulnerability, StepResult, PipelineResult
│   ├── pipeline.py                 # Orquestador principal (MinerPipeline)
│   ├── cloner.py                   # Clonado Git con profundidad controlada
│   ├── codeql_scanner.py           # CodeQL: DB + análisis + parseo SARIF
│   ├── syft_scanner.py             # Syft: generación de SBOM
│   ├── grype_scanner.py            # Grype: detección de vulnerabilidades
│   ├── aggregator.py               # Consolida resultados, ordena, guarda JSON
│   ├── README.md                   # Esta documentación
│   ├── requirements.txt            # pandas (CodeQL/Syft/Grype en Dockerfile)
│   │
│   ├── .devcontainer/              ← Dev Container
│   │   ├── Dockerfile              # CodeQL + Syft + Grype + Java + Maven + Gradle
│   │   └── devcontainer.json       # Configuración VS Code
│   │
│   └── data/
│       ├── repos.json              # Repositorios a analizar (url + path)
│       ├── repos/                  # [runtime] Repos clonados (git clone --depth 1)
│       ├── codeql-dbs/             # [runtime] Bases de datos CodeQL
│       └── results/
│           ├── codeql/             # [runtime] Resultados CodeQL (.sarif)
│           ├── sboms/              # [runtime] SBOMs generados (.json)
│           ├── vulnerabilities/    # [runtime] Reportes Grype (.json)
│           └── miner_dataset.json  # [runtime] Dataset unificado final
│
├── analyzer/                       ← Componente 2 (skeleton)
│   ├── .devcontainer/              ← Dev Container (Jupyter + pandas)
│   ├── nbs/                        ← Notebooks de análisis
│   └── data/                       ← Dataset de entrada
│
├── visualizer/                     ← Componente 3 (skeleton)
│   └── .devcontainer/              ← Dev Container (Python + Node.js)
│
├── .gitignore
├── LICENSE
└── README.md
```

### Leyenda de carpetas

| Carpeta | Tipo | Descripción |
|---------|------|-------------|
| `miner/` | **Código fuente** | Paquete Python con toda la lógica del Miner |
| `.devcontainer/` | **Código fuente** | Configuración del entorno de desarrollo |
| `data/repos.json` | **Configuración** | Lista de repositorios a analizar |
| `data/repos/` | **Runtime** | Se crea al clonar; contiene los repositorios |
| `data/results/` | **Runtime** | Se crea al ejecutar; contiene todas las salidas |

---

## 3. Flujo del Pipeline

```
data/repos.json (repos configurados)
        │
        ▼
┌─────────────────────────────────────────────────────────┐
│                  MinerPipeline.run()                     │
│                                                          │
│  Para cada repo:                                         │
│                                                          │
│  ┌──────────┐    ┌──────────┐    ┌──────────┐           │
│  │ 1.CLONE  │───▶│2.CODECL  │───▶│ 3.SYFT   │           │
│  │ git clone│    │ DB create│    │  SBOM    │           │
│  │ --depth1 │    │ analyze  │    │ JSON     │           │
│  └──────────┘    └──────────┘    └──────────┘           │
│       │               │               │                  │
│       ▼               ▼               ▼                  │
│  data/repos/    data/results/   data/results/            │
│  <name>/        codeql/         sboms/                   │
│                 <name>.sarif    <name>.json              │
│                                                          │
│  ┌──────────────────────────────────────┐               │
│  │           4. GRYPE (batch)            │               │
│  │   Escanea todos los SBOMs generados   │               │
│  └──────────────────────────────────────┘               │
│                    │                                      │
│                    ▼                                      │
│           data/results/vulnerabilities/<name>.json        │
│                                                          │
│  ┌──────────────────────────────────────┐               │
│  │           5. AGGREGATOR               │               │
│  │   Consolida CodeQL + Grype + Syft     │               │
│  │   Ordena por severidad, deduplica     │               │
│  └──────────────────────────────────────┘               │
│                    │                                      │
│                    ▼                                      │
│         data/results/miner_dataset.json                  │
└─────────────────────────────────────────────────────────┘
```

### Estrategia de reanudación

Cada etapa verifica si su salida ya existe antes de ejecutarse:

| Etapa | Verificación | Si existe... |
|-------|-------------|--------------|
| Clone | `data/repos/<name>/.git` | Se salta |
| CodeQL DB | `data/codeql-dbs/<name>/codeql-database.yml` | Se salta |
| CodeQL Analyze | `data/results/codeql/<name>.sarif` | Se salta |
| Syft | `data/results/sboms/<name>.json` | Se salta |
| Grype | `data/results/vulnerabilities/<name>.json` | Lee caché, parsea de nuevo |

### Aislamiento de errores

Cada etapa de cada repositorio está envuelta en `try/except`. Si un repo falla:
- El error se registra en el log y en `StepResult`
- El pipeline continúa con el siguiente repositorio
- Si el clonado falla, se saltan CodeQL y Syft para ese repo
- Si CodeQL falla, Syft se ejecuta igual

---

## 4. Módulos del Miner

### 4.1 `config.py` — Configuración

```python
class Config:
    project_root: Path          # Raíz del proyecto
    repos_json: Path            # data/repos.json
    repos_dir: Path             # data/repos/
    results_dir: Path           # data/results/
    codeql_output: Path         # data/results/codeql/
    sbom_output: Path           # data/results/sboms/
    vuln_output: Path           # data/results/vulnerabilities/
    dataset_output: Path        # data/results/miner_dataset.json
    codeql_db_dir: Path         # data/codeql-dbs/
    repositories: list[dict]    # Lista de {url, path} desde repos.json
```

Carga `data/repos.json` y resuelve todas las rutas absolutas. Punto único de
configuración para todo el pipeline.

### 4.2 `models.py` — Modelos de Datos

Tres dataclasses que representan todo el estado del pipeline:

| Clase | Campos clave | Propósito |
|-------|-------------|-----------|
| `Vulnerability` | `vulnerability_id, type, source_tool, repository, location, severity, description, cwe_id, package_name, installed_version, fixed_version, detected_at` | Una vulnerabilidad individual |
| `StepResult` | `repo_name, step_name, status, output_path, error_message` | Resultado de una etapa para un repo |
| `PipelineResult` | `vulnerabilities, step_results, repos_processed, repos_failed, total_vulnerabilities, started_at, finished_at` | Resultado completo del pipeline |

### 4.3 `cloner.py` — Clonado de Repositorios

```python
def clone_repo(url: str, target: Path, depth: int = 1) -> StepResult
```

- Usa `git clone --depth 1 --single-branch` (clon superficial, más rápido)
- Timeout de 600 segundos por repo
- Maneja errores: `TimeoutExpired`, `CalledProcessError`, `OSError`, `FileNotFoundError`
- Si el directorio ya tiene `.git`, lo salta (reanudación)

### 4.4 `codeql_scanner.py` — Análisis CodeQL

**Tres etapas internas:**

#### a) `create_codeql_db(repo_path, db_path) → StepResult`
- Detecta sistema de build: `pom.xml` → Maven, `gradlew` → Gradle wrapper, `build.gradle` → Gradle
- Si no detecta build system, usa autobuild de CodeQL
- Timeout de 30 minutos para creación de DB
- Verifica si la DB ya existe (reanudación)

#### b) `analyze_codeql_db(db_path, output_path) → StepResult`
- Ejecuta `codeql database analyze` con el query suite según lenguaje (`java-code-scanning.qls` o `python-code-scanning.qls`)
- Genera salida en formato `sarif-latest`
- Timeout de 10 minutos
- Verifica si el SARIF ya existe (reanudación)

#### c) `parse_sarif(sarif_path, repo_name) → list[Vulnerability]`
- Parsea el SARIF JSON extrayendo:
  - `ruleId` → `vulnerability_id`
  - `locations[].physicalLocation` → `location` (archivo:línea)
  - `level` → `severity` (error→high, warning→medium, note→low)
  - `message.text` → `description`
  - Tags `external/cwe/*` → `cwe_id`
- Maneja reglas sin `id` de forma segura

#### d) `run_codeql_scan(repo_path, db_dir, output_dir, repo_name) → (vulns, results)`
- Orquesta las tres etapas anteriores para un repositorio

### 4.5 `syft_scanner.py` — Generación de SBOM

```python
class SyftScanner:
    def __init__(self, repos_path, output_path)
    def discover_repositories() -> list[str]
    def generate_sbom(repo_path) -> str
    def save_sbom(repo_name, sbom_data) -> Path
    def run() -> list[StepResult]
```

- Ejecuta `syft dir:<repo> -o syft-json`
- Normaliza la salida: limpia códigos ANSI, extrae el objeto JSON
- Soporta `dry_run` para previsualizar sin ejecutar
- Timeout de 300 segundos por repo

### 4.6 `grype_scanner.py` — Detección de Vulnerabilidades

```python
class GrypeScanner:
    def __init__(self, sboms_dir, output_dir)
    def analyze_sbom(sbom_path) -> (list[Vulnerability], output_path)
    def run() -> (list[Vulnerability], list[StepResult])
```

- Ejecuta `grype sbom:<sbom> -o json`
- Parsea los matches extrayendo:
  - `vulnerability.id` → `vulnerability_id`
  - `vulnerability.severity` → `severity`
  - `artifact.name` → `package_name`
  - `artifact.version` → `installed_version`
  - `vulnerability.fix.versions[0]` → `fixed_version`
  - `vulnerability.cweIds[0]` → `cwe_id`
- Verifica si la salida ya existe (reanudación — lee del caché)
- Timeout de 300 segundos por SBOM
- Se ejecuta en batch sobre todos los SBOMs generados

### 4.7 `aggregator.py` — Consolidación

```python
class Aggregator:
    def add_codeql_results(vulns)
    def add_grype_results(vulns)
    def add_step_results(results)
    def build_dataset() -> PipelineResult
    def save(output_path) -> str
    def summary() -> str
```

- Colecciona vulnerabilidades de todas las fuentes
- Ordena por severidad (critical → high → medium → low)
- Genera resumen estadístico: por severidad, por herramienta, por repositorio
- Guarda el dataset unificado como JSON

### 4.8 `pipeline.py` — Orquestador

```python
class MinerPipeline:
    def run(*, only_repo, skip_codeql, skip_syft, skip_grype, dry_run) -> PipelineResult
```

- Itera sobre todos los repositorios de `Config.repositories`
- Por cada repo ejecuta: Clone → CodeQL → Syft
- Al finalizar todos, ejecuta Grype en batch
- Cada etapa dentro de `try/except` para aislamiento de errores
- Soporta filtrado por repo único (`--only-repo`)
- Soporta saltar etapas individuales (`--skip-codeql`, `--skip-syft`, `--skip-grype`)

### 4.9 `__main__.py` — CLI

```
python -m miner [opciones]

Opciones:
  --repos-json PATH    Ruta al JSON de repositorios (default: data/repos.json)
  --dry-run            Previsualizar sin ejecutar herramientas
  --only-repo REPO     Procesar solo un repositorio por nombre
  --skip-codeql        Omitir análisis CodeQL
  --skip-syft          Omitir generación de SBOM
  --skip-grype         Omitir detección Grype
  --output PATH        Ruta de salida alternativa para el dataset
  --verbose, -v        Logging detallado (DEBUG)
```

---

## 5. Formato de Salida

El archivo `data/results/miner_dataset.json` contiene:

```json
{
  "vulnerabilities": [
    {
      "vulnerability_id": "java/sql-injection",
      "type": "codeql",
      "source_tool": "codeql",
      "repository": "spring-framework",
      "location": "src/main/java/org/.../JdbcTemplate.java:1234",
      "severity": "high",
      "description": "SQL query built from user-controlled sources.",
      "cwe_id": "CWE-89",
      "package_name": null,
      "installed_version": null,
      "fixed_version": null,
      "detected_at": "2026-04-28T14:30:00+00:00"
    },
    {
      "vulnerability_id": "CVE-2024-12345",
      "type": "dependency",
      "source_tool": "grype",
      "repository": "spring-boot",
      "location": "pom.xml",
      "severity": "critical",
      "description": "Remote code execution in Spring Core.",
      "cwe_id": "CWE-502",
      "package_name": "org.springframework:spring-core",
      "installed_version": "5.3.25",
      "fixed_version": "5.3.26",
      "detected_at": "2026-04-28T14:35:00+00:00"
    }
  ],
  "summary": {
    "step_results": [
      {
        "repo_name": "spring-boot",
        "step_name": "clone",
        "status": "success",
        "output_path": "/home/.../data/repos/spring-boot",
        "error_message": null
      }
    ],
    "repos_processed": 30,
    "repos_failed": 3,
    "total_vulnerabilities": 247,
    "started_at": "2026-04-28T14:00:00+00:00",
    "finished_at": "2026-04-28T18:00:00+00:00"
  }
}
```

### Campos del esquema de vulnerabilidad

| Campo | Tipo | Descripción | Ejemplo |
|-------|------|-------------|---------|
| `vulnerability_id` | `str` | ID único (CVE, regla CodeQL, GHSA) | `CVE-2024-12345` |
| `type` | `str` | Categoría del hallazgo | `"codeql"` \| `"dependency"` |
| `source_tool` | `str` | Herramienta que lo detectó | `"codeql"` \| `"grype"` \| `"syft"` |
| `repository` | `str` | Nombre del repositorio | `"spring-boot"` |
| `location` | `str` | Archivo y línea | `"src/main/.../File.java:42"` |
| `severity` | `str` | Severidad canónica | `"critical"` \| `"high"` \| `"medium"` \| `"low"` |
| `description` | `str` | Descripción humana | `"SQL injection in..."` |
| `cwe_id` | `str\|null` | CWE ID si disponible | `"CWE-89"` |
| `package_name` | `str\|null` | Dependencia afectada | `"org.springframework:spring-core"` |
| `installed_version` | `str\|null` | Versión instalada | `"5.3.25"` |
| `fixed_version` | `str\|null` | Versión que corrige | `"5.3.26"` |
| `detected_at` | `str` | Timestamp ISO 8601 | `"2026-04-28T14:30:00+00:00"` |

---

## 6. Uso

### Requisitos previos

- **Recomendado:** Abrir la carpeta `miner/` en VS Code → "Reopen in Container"
- **Alternativa manual:** Instalar CodeQL CLI, Syft, Grype, Java 17, Maven, Gradle

### Comandos principales

Ejecutar desde dentro de la carpeta `miner/` (o desde el proyecto con `python -m miner`):

```bash
# Previsualizar sin ejecutar (no requiere herramientas)
python __main__.py --dry-run

# Procesar un solo repositorio
python __main__.py --only-repo spring-boot

# Procesar todos los repositorios
python __main__.py

# Solo SBOMs + Grype (sin CodeQL — más rápido)
python __main__.py --skip-codeql

# Solo CodeQL (sin dependencias)
python __main__.py --skip-syft --skip-grype

# Modo verboso
python __main__.py --verbose

# Salida personalizada
python __main__.py --output mis_resultados/vulns.json
```

### Salida esperada

```
17:14:30 | INFO     | Miner v0.1.0 — 33 repositories configured
17:14:30 | INFO     | Miner pipeline starting: 33 repos, codeql=True, syft=True, grype=True
17:14:30 | INFO     | ============================================================
17:14:30 | INFO     | [1/33] Processing repository: spring-amqp
17:14:30 | INFO     | Cloning https://github.com/... → data/repos/spring-amqp (depth=1)
17:14:35 | INFO     | Successfully cloned spring-amqp
17:14:35 | INFO     | Creating CodeQL database for spring-amqp...
17:20:01 | INFO     | CodeQL database created for spring-amqp
17:20:01 | INFO     | Analyzing CodeQL database for spring-amqp...
17:21:15 | INFO     | CodeQL analysis complete → data/results/codeql/spring-amqp.sarif
17:21:15 | INFO     | [1/33] Processing data/repos/spring-amqp with Syft
...
17:55:00 | INFO     | ============================================================
17:55:00 | INFO     | Dataset built: 247 vulnerabilities, 132 step results, 30 repos processed
17:55:00 | INFO     | Pipeline complete. 247 vulnerabilities found.
17:55:00 | INFO     |
17:55:00 | INFO     | Total vulnerabilities: 247
17:55:00 | INFO     |
17:55:00 | INFO     | By Severity:
17:55:00 | INFO     |   critical: 12
17:55:00 | INFO     |   high: 89
17:55:00 | INFO     |   medium: 103
17:55:00 | INFO     |   low: 43
17:55:00 | INFO     |
17:55:00 | INFO     | By Tool:
17:55:00 | INFO     |   codeql: 67
17:55:00 | INFO     |   grype: 180
17:55:00 | INFO     |
17:55:00 | INFO     | Top Repositories:
17:55:00 | INFO     |   spring-framework: 45
17:55:00 | INFO     |   spring-security: 32
17:55:00 | INFO     |   spring-boot: 28

Done. 247 vulnerabilities found in 30 repositories (3 failed).
```

---

## 7. Dev Container

El proyecto incluye configuración de Dev Container para **reproducibilidad completa**.

### Herramientas instaladas

| Herramienta | Versión | Propósito |
|-------------|---------|-----------|
| Python | 3.12 | Lenguaje del Miner |
| CodeQL CLI | Latest bundle | Análisis estático de seguridad |
| Syft | Latest | Generación de SBOM |
| Grype | Latest | Detección de vulnerabilidades |
| OpenJDK | 17 | Requerido por CodeQL para Java |
| Maven | Latest | Build de proyectos Java |
| Gradle | Latest | Build de proyectos Java |

### Extensiones VS Code

- `ms-python.python` — Soporte Python
- `ms-python.mypy-type-checker` — Type checking en tiempo real
- `charliermarsh.ruff` — Linting en tiempo real
- `redhat.java` — Soporte Java
- `vscjava.vscode-maven` — Soporte Maven

### Cómo usar

1. Abrir la carpeta `miner/` en VS Code (File → Open Folder → seleccionar `miner/`)
2. VS Code detectará `.devcontainer/` y ofrecerá "Reopen in Container"
3. Aceptar. El contenedor se construye (~5-10 min la primera vez)
4. Una vez dentro, ejecutar: `python __main__.py --dry-run`

### Dockerfile (resumen)

```dockerfile
FROM mcr.microsoft.com/devcontainers/python:3.12

# CodeQL CLI
RUN curl ... codeql-bundle-linux64.tar.gz | tar xz -C /usr/local

# Syft
RUN curl ... syft/install.sh | sh

# Grype
RUN curl ... grype/install.sh | sh

# Java + Maven + Gradle
RUN apt-get install openjdk-17-jdk-headless maven gradle

# Python deps
RUN pip install -r requirements.txt
```

---

## 8. Dependencias

### Python (`requirements.txt`)

```
pandas>=2.0
```

El resto de herramientas (CodeQL, Syft, Grype, Java, Maven, Gradle) se instalan
a través del `Dockerfile` del Dev Container y **no** son dependencias pip.

### Verificación de herramientas

```bash
codeql --version     # >= 2.15
syft version         # >= 0.90
grype version        # >= 0.70
java --version       # >= 17
mvn --version        # >= 3.8
gradle --version     # >= 7.0
```

---

## Resumen de Archivos del Miner

| Archivo | Líneas | Clases/Funciones |
|---------|--------|-----------------|
| `__init__.py` | 12 | Exporta `MinerPipeline`, `Config`, `Vulnerability`, `StepResult`, `PipelineResult` |
| `__main__.py` | 147 | `main()`, CLI con argparse |
| `config.py` | 87 | `Config` |
| `models.py` | 110 | `Vulnerability`, `StepResult`, `PipelineResult` |
| `pipeline.py` | 279 | `MinerPipeline` con 4 stages + error isolation |
| `cloner.py` | 90 | `clone_repo()` |
| `codeql_scanner.py` | 346 | `create_codeql_db()`, `analyze_codeql_db()`, `parse_sarif()`, `run_codeql_scan()` |
| `syft_scanner.py` | 265 | `SyftScanner` |
| `grype_scanner.py` | 221 | `GrypeScanner` |
| `aggregator.py` | 166 | `Aggregator` |
| **Total** | **1,723** | **5 clases, 7 funciones públicas** |

---

*Documentación generada automáticamente al finalizar el pipeline del Miner.*
*Proyecto de Ciberseguridad — Semestre 2026-1*
