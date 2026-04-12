FROM python:3.11-slim

WORKDIR /app

# Install system dependencies (gcc needed for pyahocorasick)
RUN apt-get update && apt-get install -y --no-install-recommends \
    curl \
    gcc \
    g++ \
    build-essential \
    && rm -rf /var/lib/apt/lists/*

# Copy requirements first for Docker layer caching
COPY server/requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Download spaCy English model (required by Presidio)
RUN python -m spacy download en_core_web_lg

# Copy entire project
COPY . /app/

# Set environment variables
ENV PYTHONPATH=/app
ENV PYTHONUNBUFFERED=1
ENV HOST=0.0.0.0
ENV PORT=7860

# Expose ports (7860 for HF Spaces, 8000 for OpenEnv SDK evaluator)
EXPOSE 7860
EXPOSE 8000

# Health check uses PORT env var
HEALTHCHECK --interval=30s --timeout=5s --retries=3 \
    CMD curl -f http://localhost:${PORT}/health || exit 1

# Run server on PORT (default 7860 for HF, overridden to 8000 by evaluator via env_vars)
CMD ["sh", "-c", "python -m uvicorn server.app:app --host 0.0.0.0 --port ${PORT}"]
