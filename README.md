# proyecto-ciberseguridad

Análisis de vulnerabilidades en repositorios del dataset AIDev.

## Estructura

```
proyecto-ciberseguridad/
├── miner/                ← Componente 1: Extracción de vulnerabilidades
│   ├── .devcontainer/    ←   Dev Container (CodeQL + Syft + Grype + Java)
│   ├── data/             ←   Datos de entrada (repos.json) y salida (results/)
│   ├── *.py              ←   Código fuente del Miner
│   └── README.md
│
├── analyzer/             ← Componente 2: Análisis exploratorio
│   ├── .devcontainer/    ←   Dev Container (Jupyter + pandas + matplotlib)
│   ├── nbs/              ←   Notebooks de análisis
│   └── data/             ←   Dataset de entrada (desde el Miner)
│
├── visualizer/           ← Componente 3: Visualización de resultados
│   └── .devcontainer/    ←   Dev Container (Python + Node.js)
│
├── .gitignore
└── LICENSE
```

## Flujo de trabajo en grupo

Cada miembro abre la carpeta de su componente en VS Code y usa "Reopen in Container":

| Miembro | Carpeta | Entorno |
|---------|---------|---------|
| 1 | `miner/` | CodeQL + Syft + Grype + Java 17 |
| 2 | `analyzer/` | Jupyter + pandas + matplotlib |
| 3 | `visualizer/` | Python + Node.js |

El Miner genera `miner/data/results/miner_dataset.json`, que se copia a
`analyzer/data/` para que el Analyzer lo consuma.

## Herramientas

- **Python 3.12** + **JavaScript** (según especificación del proyecto)
- **CodeQL** — análisis estático de seguridad (Java)
- **Syft** — generación de SBOM
- **Grype** — detección de vulnerabilidades en dependencias
- **Jupyter** — notebooks de análisis
- **Streamlit / Dash** — visualización (a decidir)

## Repositorios analizados

Lista definida en `miner/data/repos.json` (actualmente 5 repositorios de prueba).
