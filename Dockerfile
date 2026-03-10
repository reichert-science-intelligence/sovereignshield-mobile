# SovereignShield Mobile — Shiny for Python on HuggingFace Spaces
# Port 7860 required by Spaces
FROM python:3.11-slim

WORKDIR /app

RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential \
    && rm -rf /var/lib/apt/lists/*

RUN pip install --no-cache-dir --upgrade pip

# Install torch CPU-only first to prevent heavy GPU download
RUN pip install --no-cache-dir \
    torch --index-url https://download.pytorch.org/whl/cpu

COPY Artifacts/ .

RUN pip install --no-cache-dir \
    -r project/sovereignshield_mobile/requirements.txt

RUN pip install --no-cache-dir \
    chromadb sentence-transformers pandas plotnine

RUN mkdir -p /tmp/chroma_db

WORKDIR /app/Artifacts

EXPOSE 7860

CMD ["shiny", "run", "project/sovereignshield_mobile/app.py", \
     "--host", "0.0.0.0", "--port", "7860"]
