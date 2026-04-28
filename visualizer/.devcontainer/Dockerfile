FROM mcr.microsoft.com/devcontainers/python:3.12

# Visualization stack + Node.js (project requires Python & JavaScript)
RUN apt-get update && \
    apt-get install -y --no-install-recommends nodejs npm && \
    apt-get clean && \
    rm -rf /var/lib/apt/lists/*

RUN pip install --no-cache-dir \
    pandas \
    matplotlib \
    seaborn \
    plotly \
    dash \
    streamlit
