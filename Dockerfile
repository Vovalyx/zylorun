FROM python:3.12-slim

ENV PYTHONUNBUFFERED=1 \
    PORT=8000

WORKDIR /app

# git: repository scans. libpq5: PostgreSQL. curl, ping, nmap: the built-in diagnostic tools.
RUN apt-get update && apt-get install -y --no-install-recommends \
    git \
    curl \
    libpq5 \
    iputils-ping \
    nmap \
    && rm -rf /var/lib/apt/lists/*

# Install python dependencies
COPY tester/backend/requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy backend source code
COPY tester/backend .

# Run as an unprivileged user
RUN useradd --create-home --uid 10001 appuser && chown -R appuser:appuser /app
USER appuser

EXPOSE 8000

HEALTHCHECK --interval=30s --timeout=5s --start-period=40s --retries=3 \
    CMD curl -fsS "http://127.0.0.1:${PORT:-8000}/health" || exit 1

# Bind dynamically to the port provided by Render / cloud provider
CMD ["sh", "-c", "uvicorn app.main:app --host 0.0.0.0 --port ${PORT:-8000}"]
