FROM mcr.microsoft.com/devcontainers/python:3.12

# Install CodeQL CLI bundle
RUN curl -fsSL https://github.com/github/codeql-action/releases/latest/download/codeql-bundle-linux64.tar.gz \
    -o /tmp/codeql.tar.gz && \
    tar xzf /tmp/codeql.tar.gz -C /usr/local && \
    ln -s /usr/local/codeql/codeql /usr/local/bin/codeql && \
    rm /tmp/codeql.tar.gz

# Install Syft
RUN curl -sSfL https://raw.githubusercontent.com/anchore/syft/main/install.sh | \
    sh -s -- -b /usr/local/bin

# Install Grype
RUN curl -sSfL https://raw.githubusercontent.com/anchore/grype/main/install.sh | \
    sh -s -- -b /usr/local/bin

# Install Java 21, Maven, and Gradle (required by CodeQL for Java analysis)
RUN apt-get update && \
    apt-get install -y --no-install-recommends openjdk-21-jdk-headless maven gradle && \
    apt-get clean && \
    rm -rf /var/lib/apt/lists/*

# Install Python dependencies
COPY requirements.txt /tmp/requirements.txt
RUN pip install --no-cache-dir -r /tmp/requirements.txt

# Verify installations
RUN codeql --version && \
    syft version && \
    grype version && \
    java --version && \
    mvn --version && \
    gradle --version
