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

# Expose port
EXPOSE 7860

# Health check
HEALTHCHECK --interval=30s --timeout=5s --retries=3 \
    CMD curl -f http://localhost:7860/health || exit 1

# Run FastAPI + Gradio server
CMD ["python", "-m", "uvicorn", "server.app:app", "--host", "0.0.0.0", "--port", "7860"]
