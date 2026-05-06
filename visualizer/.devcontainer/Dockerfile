FROM mcr.microsoft.com/devcontainers/python:3.12

# Visualization stack + Node.js (project requires Python & JavaScript)
RUN apt-get update && \
    apt-get install -y --no-install-recommends nodejs npm && \
    apt-get clean && \
    rm -rf /var/lib/apt/lists/*

WORKDIR /workspace/visualizer

COPY requirements.txt /workspace/visualizer/requirements.txt

RUN pip install --no-cache-dir -r /workspace/visualizer/requirements.txt

EXPOSE 8501

CMD ["streamlit", "run", "app.py", "--server.address=0.0.0.0", "--server.port=8501"]
