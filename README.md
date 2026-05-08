# proyecto-ciberseguridad

Análisis de vulnerabilidades en repositorios open-source del ecosistema HuggingFace
mediante **CodeQL**, **Syft** y **Grype**. Proyecto semestral de Ciberseguridad — 2026.

---

## Arquitectura

El proyecto se divide en **3 componentes independientes** que operan en cadena:

```
┌──────────────┐     ┌──────────────┐     ┌──────────────┐
│    miner     │────▶│   analyzer   │────▶│  visualizer  │
│  extracción  │     │   análisis   │     │  dashboard   │
└──────────────┘     └──────────────┘     └──────────────┘
   dataset.json        notebooks           streamlit app
```

| Componente | Carpeta | Rol | Entorno |
|---|---|---|---|
| **Miner** | `miner/` | Clona repos, ejecuta CodeQL/Syft/Grype, genera dataset unificado | Dev Container: CodeQL + Syft + Grype + Java 21 |
| **Analyzer** | `analyzer/` | Análisis exploratorio en Jupyter Notebooks | Dev Container: JupyterLab + pandas + matplotlib |
| **Visualizer** | `visualizer/` | Dashboard web interactivo con Streamlit | Dev Container: Python + Node.js + plotly |

Cada componente usa su propio **Dev Container** autocontenido (sin docker-compose),
lo que permite trabajo paralelo sin conflictos de dependencias.

---

## Pipeline de extracción (Miner)

```
repos.json (25 repositorios)
    │
    ▼
┌──────────────────────────────────────────────────────┐
│ Para cada repo:                                      │
│                                                      │
│  1. CLONE     git clone --depth 1                    │
│  2. CODEQL    DB creation → analyze → parse SARIF     │
│  3. SYFT      Generación de SBOM                     │
│                                                      │
│ Batch final:                                         │
│  4. GRYPE     Escanea todos los SBOMs                │
│  5. AGGREGATOR  Consolida → miner_dataset.json       │
└──────────────────────────────────────────────────────┘
```

**Herramientas usadas:**

| Herramienta | Propósito | Entrada | Salida |
|---|---|---|---|
| CodeQL | Análisis estático de seguridad (SAST) | Código fuente | SARIF JSON |
| Syft | Generación de SBOM | Directorio del repo | Syft JSON |
| Grype | Detección de vulns en dependencias | SBOM de Syft | Grype JSON |

---

## Repositorios analizados

25 repositorios del ecosistema HuggingFace definidos en [`miner/data/repos.json`](miner/data/repos.json):

`transformers`, `pytorch-image-models`, `diffusers`, `smolagents`, `open-r1`,
`lerobot`, `datasets`, `peft`, `sentence-transformers`, `trl`,
`text-generation-inference`, `skills`, `accelerate`, `ml-intern`,
`alignment-handbook`, `parler-tts`, `nanoVLM`, `speech-to-speech`,
`autotrain-advanced`, `distil-whisper`, `smollm`, `huggingface_hub`,
`optimum`, `datatrove`, `knockknock`

---

## Instrucciones

### Requisitos generales

- VS Code + extensión **Dev Containers**
- Docker

### 1. Miner — Extracción de vulnerabilidades

```bash
# Abrir miner/ en VS Code → "Reopen in Container"
cd miner

# Previsualizar sin ejecutar
python -m miner --dry-run

# Procesar un solo repo
python -m miner --only-repo transformers

# Pipeline completo (todos los repos)
python -m miner

# Saltar etapas específicas
python -m miner --skip-codeql
python -m miner --skip-syft --skip-grype

# Modo verboso
python -m miner --verbose
```

**Salida:** `miner/data/results/miner_dataset.json`

### 2. Analyzer — Análisis exploratorio

```bash
# Abrir analyzer/ en VS Code → "Reopen in Container"
# Copiar el dataset desde el miner:
cp miner/data/results/miner_dataset.json analyzer/data/

# Abrir analyzer/nbs/analisis.ipynb y ejecutar todas las celdas
```

### 3. Visualizer — Dashboard interactivo

```bash
# Abrir visualizer/ en VS Code → "Reopen in Container"
cd visualizer
./run.sh
# Abre http://localhost:8501
```

El visualizador lee el dataset directamente desde `miner/data/results/miner_dataset.json`.

---

## Estructura del proyecto

```
proyecto-ciberseguridad/
├── README.md
├── LICENSE                          # MIT
├── .gitignore
│
├── miner/                           # Componente 1: Extracción
│   ├── __init__.py                  # Paquete Python, v0.1.0
│   ├── __main__.py                  # CLI (python -m miner)
│   ├── config.py                    # Carga repos.json, resuelve rutas
│   ├── models.py                    # Dataclasses: Vulnerability, StepResult, PipelineResult
│   ├── pipeline.py                  # Orquestador principal
│   ├── cloner.py                    # Git clone --depth 1
│   ├── codeql_scanner.py            # CodeQL: DB, análisis, parseo SARIF
│   ├── syft_scanner.py              # Generación de SBOM
│   ├── grype_scanner.py             # Detección de vulnerabilidades
│   ├── aggregator.py                # Consolidación y dataset final
│   ├── requirements.txt             # pandas>=2.0
│   ├── .devcontainer/               # Dockerfile + devcontainer.json
│   ├── data/
│   │   ├── repos.json               # Lista de 25 repos a analizar
│   │   ├── repos/                   # [runtime] Repos clonados
│   │   ├── codeql-dbs/              # [runtime] Bases de datos CodeQL
│   │   └── results/
│   │       ├── codeql/              # [runtime] SARIF
│   │       ├── sboms/               # [runtime] SBOMs
│   │       ├── vulnerabilities/     # [runtime] Grype JSON
│   │       └── miner_dataset.json   # [runtime] Dataset unificado final
│   └── README.md
│
├── analyzer/                        # Componente 2: Análisis
│   ├── nbs/analisis.ipynb           # Notebook de análisis exploratorio
│   ├── data/miner_dataset.json      # Copia del dataset del miner
│   └── .devcontainer/               # Dockerfile + devcontainer.json
│
└── visualizer/                      # Componente 3: Dashboard
    ├── app.py                       # Streamlit app
    ├── run.sh                       # Script de lanzamiento
    ├── requirements.txt             # streamlit, pandas, plotly, matplotlib, seaborn
    ├── .devcontainer/               # Dockerfile + devcontainer.json
    └── README.md
```

---

## Decisiones de diseño

### Pipeline

1. **Clonado superficial (`--depth 1`).** Solo se necesita el código fuente actual
   para análisis estático y de dependencias. Reduce ancho de banda y almacenamiento
   significativamente (repos con miles de commits históricos no aportan a SAST/SBOM).

2. **Aislamiento de errores por repo.** Cada etapa de cada repositorio está
   envuelta en `try/except`. Un fallo en un repo no detiene el pipeline ni afecta
   a los demás. Los errores se registran en `StepResult` y se continúa con el
   siguiente.

3. **Reanudación automática (idempotencia).** Cada etapa verifica si su salida ya
   existe antes de ejecutarse: el clonado comprueba `.git`, CodeQL verifica el
   archivo `codeql-database.yml`, Syft y Grype comprueban la existencia del JSON de
   salida. Esto permite interrumpir y reanudar el pipeline sin reprocesar.

4. **Grype en batch.** Todos los SBOM se generan primero (vía Syft por cada repo)
   y luego Grype los escanea en lote. Esto separa responsabilidades y permite que
   Grype aproveche su caché de vulnerabilidades compartida entre escaneos.

5. **Detección automática de lenguaje y build system.** CodeQL detecta
   automáticamente si un repo es Java (`pom.xml` → Maven, `build.gradle` → Gradle)
   o Python (`pyproject.toml`, `setup.py`, `requirements.txt`, archivos `.py`) y
   selecciona el query suite apropiado.

### Modelado de datos

6. **Dataclasses como modelos.** `Vulnerability`, `StepResult` y `PipelineResult`
   usan `@dataclass` de Python. Esto proporciona serialización limpia vía
   `dataclasses.asdict()`, inmutabilidad efectiva, y un esquema auto-documentado.

7. **Severidad canónica unificada.** Los niveles de SARIF (`error`/`warning`/`note`)
   y los de Grype se normalizan a una escala común (`critical`/`high`/`medium`/`low`)
   para facilitar agregación y visualización.

8. **Esquema de vulnerabilidad extensible.** El modelo `Vulnerability` incluye campos
   para `cwe_id`, `package_name`, `installed_version` y `fixed_version` como opcionales
   (`None`), permitiendo representar tanto hallazgos de SAST como de dependencias en
   un solo formato unificado.

### Infraestructura

9. **Dev Containers autocontenidos.** Cada componente tiene su propio
   `Dockerfile` + `devcontainer.json` con todas las herramientas preinstaladas
   (CodeQL CLI, Syft, Grype, Java, Maven, Gradle en el miner; JupyterLab en el
   analyzer; Node.js + Streamlit en el visualizer). Cero configuración manual del
   entorno. Sin `docker-compose` — cada miembro del equipo trabaja en su propio
   contenedor aislado.

10. **Resultados versionados en git.** Las salidas del pipeline (`results/`) se
    commitean al repositorio para que analyzer y visualizer puedan consumirlas sin
    necesidad de re-ejecutar el miner. Los archivos intermedios voluminosos (repos
    clonados, bases de datos CodeQL) están en `.gitignore`.

11. **Configuración centralizada.** `Config` en `miner/config.py` es el punto único
    de configuración: carga `repos.json` y resuelve todas las rutas absolutas del
    pipeline.

---

## Licencia

MIT — Copyright 2026 Hector. Ver [LICENSE](LICENSE).
