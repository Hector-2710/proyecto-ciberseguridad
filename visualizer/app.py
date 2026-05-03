import streamlit as st
import pandas as pd
import plotly.express as px
import plotly.graph_objects as go
import json
import os

# Configuración de la página
st.set_page_config(page_title="Visualizador de Análisis de Ciberseguridad", layout="wide")

# Función para cargar datos
@st.cache_data
def load_data():
    json_path = os.path.join(os.path.dirname(__file__), '..', 'miner', 'data', 'results', 'miner_dataset.json')
    with open(json_path, 'r') as f:
        data = json.load(f)
    return data

# Cargar datos
data = load_data()

# Procesar vulnerabilidades
vulnerabilities = pd.DataFrame(data['vulnerabilities'])

# Título
st.title("🔒 Panel de Análisis de Ciberseguridad")

# Estadísticas generales
col1, col2, col3, col4 = st.columns(4)
with col1:
    st.metric("Total de Vulnerabilidades", len(vulnerabilities))
with col2:
    st.metric("Vulnerabilidades Críticas", len(vulnerabilities[vulnerabilities['severity'] == 'critical']))
with col3:
    st.metric("Vulnerabilidades Altas", len(vulnerabilities[vulnerabilities['severity'] == 'high']))
with col4:
    st.metric("Repositorios Únicos", vulnerabilities['repository'].nunique())

# Distribución de severidades
st.header("Distribución de Severidades")
severity_counts = vulnerabilities['severity'].value_counts()
severity_labels = {'critical': 'Crítica', 'high': 'Alta', 'medium': 'Media', 'low': 'Baja'}
severity_counts.index = severity_counts.index.map(severity_labels)
fig_severity = px.pie(severity_counts, values=severity_counts.values, names=severity_counts.index,
                      title="Distribución de Severidad de Vulnerabilidades")
st.plotly_chart(fig_severity, use_container_width=True)

# Vulnerabilidades por repositorio
st.header("Vulnerabilidades por Repositorio")
repo_counts = vulnerabilities.groupby('repository').size().sort_values(ascending=False)
fig_repo = px.bar(repo_counts, x=repo_counts.index, y=repo_counts.values,
                  title="Número de Vulnerabilidades por Repositorio")
fig_repo.update_xaxes(tickangle=45)
st.plotly_chart(fig_repo, use_container_width=True)

# Severidad por repositorio
st.header("Severidad por Repositorio")
severity_repo = vulnerabilities.groupby(['repository', 'severity']).size().unstack().fillna(0)
severity_repo.columns = severity_repo.columns.map(severity_labels)
fig_severity_repo = px.bar(severity_repo, barmode='stack',
                           title="Distribución de Severidad por Repositorio")
st.plotly_chart(fig_severity_repo, use_container_width=True)

# Tipos de vulnerabilidades
st.header("Tipos de Vulnerabilidades")
type_counts = vulnerabilities['type'].value_counts()
type_labels = {'dependency': 'Dependencia', 'code': 'Código'}  # Ajustar según los tipos reales
type_counts.index = type_counts.index.map(lambda x: type_labels.get(x, x))
fig_type = px.pie(type_counts, values=type_counts.values, names=type_counts.index,
                  title="Distribución de Tipos de Vulnerabilidades")
st.plotly_chart(fig_type, use_container_width=True)

# Top packages vulnerables
st.header("Paquetes Más Vulnerables")
package_counts = vulnerabilities['package_name'].value_counts().head(10)
fig_package = px.bar(package_counts, x=package_counts.index, y=package_counts.values,
                     title="Top 10 Paquetes Vulnerables")
fig_package.update_xaxes(tickangle=45)
st.plotly_chart(fig_package, use_container_width=True)

# Tabla de vulnerabilidades recientes
st.header("Vulnerabilidades Recientes")
recent_vulns = vulnerabilities.sort_values('detected_at', ascending=False).head(10)
st.dataframe(recent_vulns[['repository', 'package_name', 'severity', 'description', 'detected_at']].rename(columns={
    'repository': 'Repositorio',
    'package_name': 'Paquete',
    'severity': 'Severidad',
    'description': 'Descripción',
    'detected_at': 'Detectado en'
}))

# Información del summary
st.header("Resumen del Pipeline")
summary = data['summary']
st.write(f"**Repositorios Procesados:** {summary['repos_processed']}")
st.write(f"**Repositorios Fallidos:** {summary['repos_failed']}")
st.write(f"**Total de Vulnerabilidades:** {summary['total_vulnerabilities']}")
st.write(f"**Iniciado en:** {summary['started_at']}")
st.write(f"**Finalizado en:** {summary['finished_at']}")

# Paso results
st.header("Resultados de Pasos")
step_results = pd.DataFrame(summary['step_results'])
st.dataframe(step_results.rename(columns={
    'repo_name': 'Nombre del Repo',
    'step_name': 'Nombre del Paso',
    'status': 'Estado',
    'output_path': 'Ruta de Salida',
    'error_message': 'Mensaje de Error'
}))