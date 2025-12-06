FROM kalilinux/kali-rolling:latest

LABEL description="AI Agent Penetration Testing Environment with Comprehensive Automated Tools"

RUN apt-get update && \
    apt-get install -y kali-archive-keyring sudo && \
    apt-get update && \
    apt-get upgrade -y

RUN useradd -m -s /bin/bash pentester && \
    usermod -aG sudo pentester && \
    echo "pentester ALL=(ALL) NOPASSWD:ALL" >> /etc/sudoers

RUN mkdir -p /home/pentester/configs \
             /home/pentester/wordlists \
             /home/pentester/output \
             /home/pentester/scripts \
             /home/pentester/tools \
             /app/runtime \
             /app/tools \
             /app/certs && \
    chown -R pentester:pentester /app/certs /home/pentester/tools

RUN apt-get update && \
    apt-get install -y --no-install-recommends \
    wget curl git vim nano unzip tar \
    apt-transport-https ca-certificates gnupg lsb-release \
    build-essential software-properties-common \
    gcc libc6-dev pkg-config libpcap-dev libssl-dev \
    python3 python3-pip python3-dev python3-venv python3-setuptools \
    golang-go \
    net-tools dnsutils whois \
    jq parallel ripgrep grep \
    less man-db procps htop \
    iproute2 iputils-ping netcat-traditional \
    nmap ncat ndiff \
    sqlmap nuclei subfinder naabu ffuf \
    nodejs npm pipx \
    libcap2-bin \
    gdb \
    tmux \
    libnss3 libnspr4 libdbus-1-3 libatk1.0-0 libatk-bridge2.0-0 libcups2 libdrm2 libatspi2.0-0 \
    libxcomposite1 libxdamage1 libxfixes3 libxrandr2 libgbm1 libxkbcommon0 libpango-1.0-0 libcairo2 libasound2t64 \
    fonts-unifont fonts-noto-color-emoji fonts-freefont-ttf fonts-dejavu-core ttf-bitstream-vera \
    libnss3-tools

RUN setcap cap_net_raw,cap_net_admin,cap_net_bind_service+eip $(which nmap)

USER pentester
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

USER root
RUN cp /app/certs/ca.crt /usr/local/share/ca-certificates/ca.crt && \
    update-ca-certificates

RUN curl -sSL https://install.python-poetry.org | POETRY_HOME=/opt/poetry python3 - && \
    ln -s /opt/poetry/bin/poetry /usr/local/bin/poetry && \
    chmod +x /usr/local/bin/poetry && \
    python3 -m venv /app/venv && \
    chown -R pentester:pentester /app/venv /opt/poetry

USER pentester
WORKDIR /tmp

RUN go install -v github.com/projectdiscovery/httpx/cmd/httpx@latest && \
    go install -v github.com/projectdiscovery/katana/cmd/katana@latest && \
    go install -v github.com/projectdiscovery/cvemap/cmd/vulnx@latest && \
    go install -v github.com/jaeles-project/gospider@latest && \
    go install -v github.com/projectdiscovery/interactsh/cmd/interactsh-client@latest

RUN nuclei -update-templates

RUN pipx install arjun && \
    pipx install dirsearch && \
    pipx inject dirsearch setuptools && \
    pipx install wafw00f

ENV NPM_CONFIG_PREFIX=/home/pentester/.npm-global
RUN mkdir -p /home/pentester/.npm-global

RUN npm install -g retire@latest && \
    npm install -g eslint@latest && \
    npm install -g js-beautify@latest

WORKDIR /home/pentester/tools
RUN git clone https://github.com/aravind0x7/JS-Snooper.git && \
    chmod +x JS-Snooper/js_snooper.sh && \
    git clone https://github.com/xchopath/jsniper.sh.git && \
    chmod +x jsniper.sh/jsniper.sh && \
    git clone https://github.com/ticarpi/jwt_tool.git && \
    chmod +x jwt_tool/jwt_tool.py

USER root

RUN curl -sSfL https://raw.githubusercontent.com/trufflesecurity/trufflehog/main/scripts/install.sh | sh -s -- -b /usr/local/bin

RUN apt-get update && apt-get install -y zaproxy

RUN curl -sfL https://raw.githubusercontent.com/aquasecurity/trivy/main/contrib/install.sh | sh -s -- -b /usr/local/bin

RUN apt-get install -y wapiti

USER pentester

RUN pipx install semgrep && \
    pipx install bandit

RUN npm install -g jshint

USER root

RUN apt-get autoremove -y && \
    apt-get autoclean && \
    rm -rf /var/lib/apt/lists/* /tmp/* /var/tmp/*

ENV PATH="/home/pentester/go/bin:/home/pentester/.local/bin:/home/pentester/.npm-global/bin:/app/venv/bin:$PATH"
ENV VIRTUAL_ENV="/app/venv"
ENV POETRY_HOME="/opt/poetry"

WORKDIR /app

RUN ARCH=$(uname -m) && \
    if [ "$ARCH" = "x86_64" ]; then \
        CAIDO_ARCH="x86_64"; \
    elif [ "$ARCH" = "aarch64" ] || [ "$ARCH" = "arm64" ]; then \
        CAIDO_ARCH="aarch64"; \
    else \
        echo "Unsupported architecture: $ARCH" && exit 1; \
    fi && \
    wget -O caido-cli.tar.gz https://caido.download/releases/v0.48.0/caido-cli-v0.48.0-linux-${CAIDO_ARCH}.tar.gz && \
    tar -xzf caido-cli.tar.gz && \
    chmod +x caido-cli && \
    rm caido-cli.tar.gz && \
    mv caido-cli /usr/local/bin/

ENV STRIX_SANDBOX_MODE=true
ENV PYTHONPATH=/app
ENV REQUESTS_CA_BUNDLE=/etc/ssl/certs/ca-certificates.crt
ENV SSL_CERT_FILE=/etc/ssl/certs/ca-certificates.crt

RUN mkdir -p /workspace && chown -R pentester:pentester /workspace /app

COPY pyproject.toml poetry.lock ./

USER pentester
RUN poetry install --no-root --without dev
RUN poetry run playwright install chromium

RUN /app/venv/bin/pip install -r /home/pentester/tools/jwt_tool/requirements.txt && \
    ln -s /home/pentester/tools/jwt_tool/jwt_tool.py /home/pentester/.local/bin/jwt_tool

RUN echo "# Sandbox Environment" > README.md

COPY strix/__init__.py strix/
COPY strix/runtime/tool_server.py strix/runtime/__init__.py strix/runtime/runtime.py /app/strix/runtime/

COPY strix/tools/__init__.py strix/tools/registry.py strix/tools/executor.py strix/tools/argument_parser.py strix/tools/validation.py /app/strix/tools/

COPY strix/tools/browser/ /app/strix/tools/browser/
COPY strix/tools/file_edit/ /app/strix/tools/file_edit/
COPY strix/tools/notes/ /app/strix/tools/notes/
COPY strix/tools/python/ /app/strix/tools/python/
COPY strix/tools/terminal/ /app/strix/tools/terminal/
COPY strix/tools/proxy/ /app/strix/tools/proxy/

# Security testing tools available in sandbox mode
COPY strix/tools/api_fuzzer/ /app/strix/tools/api_fuzzer/
COPY strix/tools/cors_scanner/ /app/strix/tools/cors_scanner/
COPY strix/tools/graphql_introspection/ /app/strix/tools/graphql_introspection/
COPY strix/tools/hash_identifier/ /app/strix/tools/hash_identifier/
COPY strix/tools/header_analyzer/ /app/strix/tools/header_analyzer/
COPY strix/tools/js_link_extractor/ /app/strix/tools/js_link_extractor/
COPY strix/tools/jwt_analyzer/ /app/strix/tools/jwt_analyzer/
COPY strix/tools/oauth_tester/ /app/strix/tools/oauth_tester/
COPY strix/tools/parameter_miner/ /app/strix/tools/parameter_miner/
COPY strix/tools/payload_encoder/ /app/strix/tools/payload_encoder/
COPY strix/tools/poc_generator/ /app/strix/tools/poc_generator/
COPY strix/tools/request_logger/ /app/strix/tools/request_logger/
COPY strix/tools/response_diff/ /app/strix/tools/response_diff/
COPY strix/tools/secret_scanner/ /app/strix/tools/secret_scanner/
COPY strix/tools/subdomain_enum/ /app/strix/tools/subdomain_enum/
COPY strix/tools/tech_fingerprinter/ /app/strix/tools/tech_fingerprinter/
COPY strix/tools/timing_analyzer/ /app/strix/tools/timing_analyzer/
COPY strix/tools/websocket_client/ /app/strix/tools/websocket_client/

# Reconnaissance tools available in sandbox mode
COPY strix/tools/asn_lookup/ /app/strix/tools/asn_lookup/
COPY strix/tools/dns_resolver/ /app/strix/tools/dns_resolver/
COPY strix/tools/google_dorker/ /app/strix/tools/google_dorker/
COPY strix/tools/ssl_certificate_analyzer/ /app/strix/tools/ssl_certificate_analyzer/
COPY strix/tools/wayback_fetcher/ /app/strix/tools/wayback_fetcher/
COPY strix/tools/whois_lookup/ /app/strix/tools/whois_lookup/

# Testing tools available in sandbox mode
COPY strix/tools/cookie_analyzer/ /app/strix/tools/cookie_analyzer/
COPY strix/tools/rate_limit_tester/ /app/strix/tools/rate_limit_tester/
COPY strix/tools/regex_tester/ /app/strix/tools/regex_tester/
COPY strix/tools/sqli_tester/ /app/strix/tools/sqli_tester/

# Active testing tools available in sandbox mode
COPY strix/tools/command_injection_tester/ /app/strix/tools/command_injection_tester/
COPY strix/tools/http_method_tester/ /app/strix/tools/http_method_tester/
COPY strix/tools/ssrf_tester/ /app/strix/tools/ssrf_tester/
COPY strix/tools/ssti_tester/ /app/strix/tools/ssti_tester/
COPY strix/tools/waf_detector/ /app/strix/tools/waf_detector/
COPY strix/tools/xxe_tester/ /app/strix/tools/xxe_tester/

# Specialized tools available in sandbox mode
COPY strix/tools/cve_lookup/ /app/strix/tools/cve_lookup/
COPY strix/tools/cvss_calculator/ /app/strix/tools/cvss_calculator/
COPY strix/tools/entropy_analyzer/ /app/strix/tools/entropy_analyzer/
COPY strix/tools/polyglot_generator/ /app/strix/tools/polyglot_generator/

# Tool-Prompt Integration tools (batch 6)
COPY strix/tools/idor_tester/ /app/strix/tools/idor_tester/
COPY strix/tools/http_smuggling_tester/ /app/strix/tools/http_smuggling_tester/
COPY strix/tools/business_logic_scanner/ /app/strix/tools/business_logic_scanner/
COPY strix/tools/prototype_pollution_tester/ /app/strix/tools/prototype_pollution_tester/
COPY strix/tools/crlf_injection_tester/ /app/strix/tools/crlf_injection_tester/
COPY strix/tools/deserialization_scanner/ /app/strix/tools/deserialization_scanner/
COPY strix/tools/graphql_security_tester/ /app/strix/tools/graphql_security_tester/

# Authentication & Cache Security tools (batch 7)
COPY strix/tools/cache_poisoning_tester/ /app/strix/tools/cache_poisoning_tester/
COPY strix/tools/mfa_bypass_tester/ /app/strix/tools/mfa_bypass_tester/
COPY strix/tools/auth_tester/ /app/strix/tools/auth_tester/

# UI & NoSQL Security tools (batch 8)
COPY strix/tools/clickjacking_tester/ /app/strix/tools/clickjacking_tester/
COPY strix/tools/nosql_injection_tester/ /app/strix/tools/nosql_injection_tester/

# Infrastructure & CI/CD Security tools (batch 9)
COPY strix/tools/port_scanner/ /app/strix/tools/port_scanner/
COPY strix/tools/ci_pipeline_analyzer/ /app/strix/tools/ci_pipeline_analyzer/
COPY strix/tools/aws_iam_analyzer/ /app/strix/tools/aws_iam_analyzer/
COPY strix/tools/secrets_extractor/ /app/strix/tools/secrets_extractor/
COPY strix/tools/service_version_detector/ /app/strix/tools/service_version_detector/

# AD/Network & Exploitation tools (batch 10)
COPY strix/tools/smb_enumerator/ /app/strix/tools/smb_enumerator/
COPY strix/tools/ldap_enumerator/ /app/strix/tools/ldap_enumerator/
COPY strix/tools/kerberos_tester/ /app/strix/tools/kerberos_tester/
COPY strix/tools/credential_validator/ /app/strix/tools/credential_validator/
COPY strix/tools/privilege_escalation_checker/ /app/strix/tools/privilege_escalation_checker/
COPY strix/tools/reverse_shell_generator/ /app/strix/tools/reverse_shell_generator/

# Authentication & API Testing tools (batch 11)
COPY strix/tools/password_sprayer/ /app/strix/tools/password_sprayer/
COPY strix/tools/ntlm_tester/ /app/strix/tools/ntlm_tester/
COPY strix/tools/jwt_forge/ /app/strix/tools/jwt_forge/
COPY strix/tools/smart_fuzzer/ /app/strix/tools/smart_fuzzer/
COPY strix/tools/encoding_detector/ /app/strix/tools/encoding_detector/
COPY strix/tools/wordlist_generator/ /app/strix/tools/wordlist_generator/
COPY strix/tools/openapi_parser/ /app/strix/tools/openapi_parser/
COPY strix/tools/batch_request_tester/ /app/strix/tools/batch_request_tester/

# Cloud & Infrastructure tools (batch 12)
COPY strix/tools/gcp_iam_analyzer/ /app/strix/tools/gcp_iam_analyzer/
COPY strix/tools/azure_rbac_analyzer/ /app/strix/tools/azure_rbac_analyzer/
COPY strix/tools/evidence_collector/ /app/strix/tools/evidence_collector/
COPY strix/tools/terraform_scanner/ /app/strix/tools/terraform_scanner/
COPY strix/tools/github_actions_auditor/ /app/strix/tools/github_actions_auditor/
COPY strix/tools/cloud_storage_scanner/ /app/strix/tools/cloud_storage_scanner/
COPY strix/tools/differential_analyzer/ /app/strix/tools/differential_analyzer/
COPY strix/tools/container_image_scanner/ /app/strix/tools/container_image_scanner/

RUN echo 'export PATH="/home/pentester/go/bin:/home/pentester/.local/bin:/home/pentester/.npm-global/bin:$PATH"' >> /home/pentester/.bashrc && \
    echo 'export PATH="/home/pentester/go/bin:/home/pentester/.local/bin:/home/pentester/.npm-global/bin:$PATH"' >> /home/pentester/.profile

USER root
COPY containers/docker-entrypoint.sh /usr/local/bin/docker-entrypoint.sh
RUN chmod +x /usr/local/bin/docker-entrypoint.sh

USER pentester
WORKDIR /workspace

ENTRYPOINT ["docker-entrypoint.sh"]
