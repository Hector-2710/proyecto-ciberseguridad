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

## Instalación

1. Activar el entorno virtual:
   ```bash
   source ../.venv/bin/activate
   ```

2. Instalar dependencias:
   ```bash
   pip install -r requirements.txt
   ```

## Uso

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

## Actualización de Datos

El visualizador lee automáticamente el archivo `miner/data/results/miner_dataset.json` cada vez que se ejecuta. Para actualizar las visualizaciones con nuevos datos, simplemente ejecuta el miner nuevamente y luego refresca la página del visualizador.

## Datos Utilizados

- **Vulnerabilidades**: Detectadas por herramientas como Grype.
- **SBOMs**: Generados por Syft.
- **Análisis de Código**: Resultados de CodeQL (integrados en el resumen del pipeline).