# Multi-stage build for TransferD Web Application
FROM python:3.11-slim as builder

# Set environment variables
ENV PYTHONDONTWRITEBYTECODE=1
ENV PYTHONUNBUFFERED=1

# Install system dependencies
RUN apt-get update && apt-get install -y \
    gcc \
    libffi-dev \
    && rm -rf /var/lib/apt/lists/*

# Create and set working directory
WORKDIR /app

# Copy requirements and install Python dependencies
COPY requirements-docker.txt .
RUN pip install --no-cache-dir --user -r requirements-docker.txt

# Production stage
FROM python:3.11-slim

# Set environment variables
ENV PYTHONDONTWRITEBYTECODE=1
ENV PYTHONUNBUFFERED=1
ENV PYTHONPATH=/app

# Install runtime dependencies
RUN apt-get update && apt-get install -y \
    curl \
    && rm -rf /var/lib/apt/lists/* \
    && groupadd -r transferd && useradd -r -g transferd transferd

# Create application directory
WORKDIR /app

# Copy Python dependencies from builder stage
COPY --from=builder /root/.local /home/transferd/.local

# Make sure scripts in .local are usable
ENV PATH=/home/transferd/.local/bin:$PATH

# Copy application files
COPY app.py .
COPY templates/ templates/
COPY static/ static/

# Create downloads directory with proper permissions
RUN mkdir -p /app/downloads && chown -R transferd:transferd /app

# Switch to non-root user
USER transferd

# Expose ports
EXPOSE 8080

# Health check
HEALTHCHECK --interval=30s --timeout=10s --start-period=5s --retries=3 \
    CMD curl -f http://localhost:8080/ || exit 1

# Start the application
CMD ["python", "app.py"]