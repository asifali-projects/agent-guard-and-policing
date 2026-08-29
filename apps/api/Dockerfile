# Build context is the repo root (see infra/docker-compose.yml).
FROM python:3.11-slim AS base

ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    PIP_NO_CACHE_DIR=1

WORKDIR /app

# Install dependencies first for layer caching.
COPY apps/api/pyproject.toml ./
RUN pip install --upgrade pip && pip install "hatchling" && \
    python -c "import tomllib,subprocess,sys; \
d=tomllib.load(open('pyproject.toml','rb')); \
subprocess.check_call([sys.executable,'-m','pip','install',*d['project']['dependencies']])"

COPY apps/api/ ./
RUN pip install --no-deps -e .

EXPOSE 8000

HEALTHCHECK --interval=15s --timeout=3s --start-period=10s --retries=5 \
    CMD python -c "import urllib.request,sys; sys.exit(0 if urllib.request.urlopen('http://localhost:8000/healthz').status==200 else 1)"

CMD ["uvicorn", "agentguard_api.main:app", "--host", "0.0.0.0", "--port", "8000"]
