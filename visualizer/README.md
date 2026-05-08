# Visualizador de Análisis de Ciberseguridad

Este visualizador presenta los resultados consolidados del análisis de ciberseguridad de manera clara y comprensible.

## Características

- **Distribución de Vulnerabilidades**: Visualiza la distribución por severidad (crítica, alta, media, baja).
- **Comparación entre Repositorios**: Compara el número de vulnerabilidades por repositorio.
- **Severidad por Repositorio**: Muestra la distribución de severidades para cada repositorio.
- **Tipos de Vulnerabilidades**: Distribución de tipos de vulnerabilidades detectadas.
- **Paquetes Vulnerables**: Top 10 paquetes más vulnerables.
- **Vulnerabilidades Recientes**: Lista de las vulnerabilidades más recientes detectadas.
- **Resumen del Pipeline**: Estadísticas generales del proceso de análisis.

## Requisitos

- Python 3.8+
- Dependencias listadas en `requirements.txt`

## Instalación local

1. Activar el entorno virtual:
   ```bash
   source ../.venv/bin/activate
   ```

2. Instalar dependencias:
   ```bash
   pip install -r requirements.txt
   ```

## Uso local

Ejecutar el visualizador:

```bash
./run.sh
```

O directamente:

```bash
source ../.venv/bin/activate
streamlit run app.py
```

Esto abrirá una interfaz web en el navegador donde podrás explorar las visualizaciones.

## Uso con Docker

El proyecto incluye un Dockerfile en `visualizer/.devcontainer/Dockerfile` que crea la imagen y arranca Streamlit en `0.0.0.0:8501`.

Desde la carpeta `visualizer`, construye la imagen:

```bash
cd /home/marco/Ciberseguridad/proyecto-ciberseguridad/visualizer
docker build -t visualizer-test -f .devcontainer/Dockerfile .
```

Luego ejecuta el contenedor:

```bash
docker run --rm -p 8501:8501 \
  -v "$PWD:/workspace/visualizer:ro" \
  -v "$PWD/../miner:/workspace/miner:ro" \
  -w /workspace/visualizer \
  visualizer-test
```

Abre el navegador en:

```bash
http://localhost:8501
```

> Si prefieres, también puedes usar `docker compose up` desde la raíz del proyecto con el archivo `docker-compose.yml` que está configurado para este visualizador.

## Actualización de Datos

El visualizador lee automáticamente el archivo `miner/data/results/miner_dataset.json` cada vez que se ejecuta. Para actualizar las visualizaciones con nuevos datos, simplemente ejecuta el miner nuevamente y luego refresca la página del visualizador.

## Datos Utilizados

- **Vulnerabilidades**: Detectadas por herramientas como Grype.
- **SBOMs**: Generados por Syft.
- **Análisis de Código**: Resultados de CodeQL (integrados en el resumen del pipeline).