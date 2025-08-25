FROM python:3.11-slim

# Install system dependencies
RUN apt-get update && apt-get install -y \
    nmap \
    net-tools \
    iputils-ping \
    curl \
    gcc \
    python3-dev \
    arp-scan \
    sudo \
    libcap2-bin \
    && rm -rf /var/lib/apt/lists/*

# Configure sudo for nmap and arp-scan
RUN echo "ALL ALL=(ALL) NOPASSWD: /usr/bin/nmap" >> /etc/sudoers && \
    echo "ALL ALL=(ALL) NOPASSWD: /usr/sbin/arp-scan" >> /etc/sudoers

# Update Nmap scripts (do this before setting capabilities)
RUN nmap --script-updatedb || echo "Script update will be done at runtime"

# Set capabilities for nmap to run without sudo
RUN setcap cap_net_raw,cap_net_admin,cap_net_bind_service+eip /usr/bin/nmap || echo "Capabilities will be set at runtime"

WORKDIR /app

# Copy requirements and install Python dependencies
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy application code
COPY . .

# Create data directories
RUN mkdir -p /app/data/scans

# Set permissions
RUN chmod +x /app/app_clean.py

EXPOSE 8080 8765

CMD ["python", "app_clean.py"]
