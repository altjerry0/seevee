# SeeVee API Service Docker Image
FROM python:3.11-slim

# Set working directory
WORKDIR /app

# Install system dependencies for compilation (if needed)
RUN apt-get update && apt-get install -y \
    gcc \
    && rm -rf /var/lib/apt/lists/*

# Copy requirements first for better caching
COPY requirements.txt .

# Install Python dependencies
RUN pip install --no-cache-dir -r requirements.txt

# Copy application code
COPY seevee.py .
COPY api_server.py .

# Create directory for database (can be mounted as volume)
RUN mkdir -p /app/data

# Set environment variables
ENV PYTHONPATH=/app
ENV API_HOST=0.0.0.0
ENV API_PORT=8000
ENV UPDATE_DB_ON_STARTUP=true

# Expose API port
EXPOSE 8000

# Health check
HEALTHCHECK --interval=30s --timeout=10s --start-period=60s --retries=3 \
    CMD python -c "import requests; requests.get('http://localhost:8000/health')" || exit 1

# Default command
CMD ["python", "api_server.py"] 