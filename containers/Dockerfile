FROM kalilinux/kali-rolling:latest

LABEL description="AI Agent Penetration Testing Environment with Comprehensive Automated Tools"

# Build arguments for version pinning
ARG CAIDO_VERSION=0.54.1

# =============================================================================
# ROOT OPERATIONS - All root-level setup consolidated
# =============================================================================

# Initial setup: keyring, upgrade, and create user
RUN apt-get update && \
    apt-get install -y --no-install-recommends kali-archive-keyring sudo && \
    apt-get update && \
    apt-get upgrade -y

# Create pentester user with sudo access
RUN useradd -m -s /bin/bash pentester && \
    usermod -aG sudo pentester && \
    echo "pentester ALL=(ALL) NOPASSWD:ALL" >> /etc/sudoers

# Create all required directories
RUN mkdir -p /home/pentester/configs \
             /home/pentester/wordlists \
             /home/pentester/output \
             /home/pentester/scripts \
             /home/pentester/tools \
             /app/runtime \
             /app/tools \
             /app/certs && \
    chown -R pentester:pentester /app/certs /home/pentester/tools

# Consolidated apt-get installation - all packages in one layer
RUN apt-get update && \
    apt-get install -y --no-install-recommends \
    # Basic utilities
    wget curl git vim nano unzip tar \
    apt-transport-https ca-certificates gnupg lsb-release \
    # Build tools
    build-essential software-properties-common \
    gcc libc6-dev pkg-config libpcap-dev libssl-dev \
    # Python ecosystem
    python3 python3-pip python3-dev python3-venv python3-setuptools \
    # Go
    golang-go \
    # Network utilities
    net-tools dnsutils whois \
    iproute2 iputils-ping netcat-traditional \
    # General utilities
    jq parallel ripgrep grep \
    less man-db procps htop \
    # Security tools from Kali repos
    nmap ncat ndiff \
    sqlmap nuclei subfinder naabu ffuf \
    zaproxy wapiti \
    # Node.js
    nodejs npm pipx \
    # Misc
    libcap2-bin \
    gdb \
    tmux \
    # Browser dependencies for Playwright
    libnss3 libnspr4 libdbus-1-3 libatk1.0-0 libatk-bridge2.0-0 libcups2 libdrm2 libatspi2.0-0 \
    libxcomposite1 libxdamage1 libxfixes3 libxrandr2 libgbm1 libxkbcommon0 libpango-1.0-0 libcairo2 libasound2t64 \
    fonts-unifont fonts-noto-color-emoji fonts-freefont-ttf fonts-dejavu-core ttf-bitstream-vera \
    libnss3-tools && \
    # Cleanup apt cache in same layer to reduce size
    apt-get autoremove -y && \
    apt-get autoclean && \
    rm -rf /var/lib/apt/lists/*

# Set nmap capabilities
RUN setcap cap_net_raw,cap_net_admin,cap_net_bind_service+eip $(which nmap)

# Install Poetry and create venv
RUN curl -sSL https://install.python-poetry.org | POETRY_HOME=/opt/poetry python3 - && \
    ln -s /opt/poetry/bin/poetry /usr/local/bin/poetry && \
    chmod +x /usr/local/bin/poetry && \
    python3 -m venv /app/venv && \
    chown -R pentester:pentester /app/venv /opt/poetry

# Install tools that require root: trufflehog, trivy, caido
RUN curl -sSfL https://raw.githubusercontent.com/trufflesecurity/trufflehog/main/scripts/install.sh | sh -s -- -b /usr/local/bin

RUN curl -sfL https://raw.githubusercontent.com/aquasecurity/trivy/main/contrib/install.sh | sh -s -- -b /usr/local/bin

# Install Caido CLI with version from build arg
WORKDIR /app
RUN ARCH=$(uname -m) && \
    if [ "$ARCH" = "x86_64" ]; then \
        CAIDO_ARCH="x86_64"; \
    elif [ "$ARCH" = "aarch64" ] || [ "$ARCH" = "arm64" ]; then \
        CAIDO_ARCH="aarch64"; \
    else \
        echo "Unsupported architecture: $ARCH" && exit 1; \
    fi && \
    wget -O caido-cli.tar.gz https://caido.download/releases/v${CAIDO_VERSION}/caido-cli-v${CAIDO_VERSION}-linux-${CAIDO_ARCH}.tar.gz && \
    tar -xzf caido-cli.tar.gz && \
    chmod +x caido-cli && \
    rm caido-cli.tar.gz && \
    mv caido-cli /usr/local/bin/

# Set environment variables
ENV PATH="/home/pentester/go/bin:/home/pentester/.local/bin:/home/pentester/.npm-global/bin:/app/venv/bin:$PATH"
ENV VIRTUAL_ENV="/app/venv"
ENV POETRY_HOME="/opt/poetry"
ENV STRIX_SANDBOX_MODE=true
ENV PYTHONPATH=/app
ENV REQUESTS_CA_BUNDLE=/etc/ssl/certs/ca-certificates.crt
ENV SSL_CERT_FILE=/etc/ssl/certs/ca-certificates.crt

# Create workspace and set permissions
RUN mkdir -p /workspace && chown -R pentester:pentester /workspace /app

# Copy project files (as root for proper permissions)
COPY pyproject.toml poetry.lock ./

# =============================================================================
# PENTESTER USER OPERATIONS - All user-level setup consolidated
# =============================================================================

USER pentester

# Generate SSL certificates
RUN openssl ecparam -name prime256v1 -genkey -noout -out /app/certs/ca.key && \
    openssl req -x509 -new -key /app/certs/ca.key \
    -out /app/certs/ca.crt \
    -days 3650 \
    -subj "/C=US/ST=CA/O=Security Testing/CN=Testing Root CA" \
    -addext "basicConstraints=critical,CA:TRUE" \
    -addext "keyUsage=critical,digitalSignature,keyEncipherment,keyCertSign" && \
    openssl pkcs12 -export \
    -out /app/certs/ca.p12 \
    -inkey /app/certs/ca.key \
    -in /app/certs/ca.crt \
    -passout pass:"" \
    -name "Testing Root CA" && \
    chmod 644 /app/certs/ca.crt && \
    chmod 600 /app/certs/ca.key && \
    chmod 600 /app/certs/ca.p12

# Install Go tools
WORKDIR /tmp
RUN go install -v github.com/projectdiscovery/httpx/cmd/httpx@latest && \
    go install -v github.com/projectdiscovery/katana/cmd/katana@latest && \
    go install -v github.com/projectdiscovery/cvemap/cmd/vulnx@latest && \
    go install -v github.com/jaeles-project/gospider@latest && \
    go install -v github.com/projectdiscovery/interactsh/cmd/interactsh-client@latest && \
    go clean -cache -modcache

# Update nuclei templates
RUN nuclei -update-templates

# Install Python tools via pipx
RUN pipx install arjun && \
    pipx install dirsearch && \
    pipx inject dirsearch setuptools && \
    pipx install wafw00f && \
    pipx install semgrep && \
    pipx install bandit

# Setup npm global directory and install npm packages
ENV NPM_CONFIG_PREFIX=/home/pentester/.npm-global
RUN mkdir -p /home/pentester/.npm-global && \
    npm install -g retire@latest && \
    npm install -g eslint@latest && \
    npm install -g js-beautify@latest && \
    npm install -g jshint

# Clone security tools (shallow clone to reduce size)
WORKDIR /home/pentester/tools
RUN git clone --depth 1 https://github.com/aravind0x7/JS-Snooper.git && \
    chmod +x JS-Snooper/js_snooper.sh && \
    git clone --depth 1 https://github.com/xchopath/jsniper.sh.git && \
    chmod +x jsniper.sh/jsniper.sh && \
    git clone --depth 1 https://github.com/ticarpi/jwt_tool.git && \
    chmod +x jwt_tool/jwt_tool.py

# Install Python dependencies
WORKDIR /app
RUN poetry install --no-root --without dev --extras sandbox && \
    poetry run playwright install chromium

# Install jwt_tool requirements and create symlink
RUN /app/venv/bin/pip install -r /home/pentester/tools/jwt_tool/requirements.txt && \
    ln -s /home/pentester/tools/jwt_tool/jwt_tool.py /home/pentester/.local/bin/jwt_tool

# Create README
RUN echo "# Sandbox Environment" > README.md

# Setup shell PATH
RUN echo 'export PATH="/home/pentester/go/bin:/home/pentester/.local/bin:/home/pentester/.npm-global/bin:$PATH"' >> /home/pentester/.bashrc && \
    echo 'export PATH="/home/pentester/go/bin:/home/pentester/.local/bin:/home/pentester/.npm-global/bin:$PATH"' >> /home/pentester/.profile

# =============================================================================
# FINAL ROOT OPERATIONS - CA certificate installation and entrypoint
# =============================================================================

USER root

# Install CA certificate to system trust store
RUN cp /app/certs/ca.crt /usr/local/share/ca-certificates/ca.crt && \
    update-ca-certificates

# Copy application code
COPY strix/__init__.py strix/
COPY strix/runtime/tool_server.py strix/runtime/__init__.py strix/runtime/runtime.py /app/strix/runtime/
COPY strix/tools/__init__.py strix/tools/registry.py strix/tools/executor.py strix/tools/argument_parser.py /app/strix/tools/
COPY strix/tools/browser/ /app/strix/tools/browser/
COPY strix/tools/file_edit/ /app/strix/tools/file_edit/
COPY strix/tools/notes/ /app/strix/tools/notes/
COPY strix/tools/python/ /app/strix/tools/python/
COPY strix/tools/terminal/ /app/strix/tools/terminal/
COPY strix/tools/proxy/ /app/strix/tools/proxy/

# Copy and setup entrypoint
COPY containers/docker-entrypoint.sh /usr/local/bin/docker-entrypoint.sh
RUN chmod +x /usr/local/bin/docker-entrypoint.sh

# =============================================================================
# FINAL SETUP
# =============================================================================

USER pentester
WORKDIR /workspace

ENTRYPOINT ["docker-entrypoint.sh"]
