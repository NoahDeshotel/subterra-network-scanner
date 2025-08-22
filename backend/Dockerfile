FROM python:3.11-slim

# Install system dependencies
RUN apt-get update && apt-get install -y \
    nmap \
    net-tools \
    iputils-ping \
    curl \
    gcc \
    python3-dev \
    && rm -rf /var/lib/apt/lists/*

# Update Nmap scripts
RUN nmap --script-updatedb

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
