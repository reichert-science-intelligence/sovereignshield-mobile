FROM python:3.11-slim

RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential \
    && rm -rf /var/lib/apt/lists/*

RUN pip install --no-cache-dir --upgrade pip

RUN pip install --no-cache-dir \
    torch --index-url https://download.pytorch.org/whl/cpu

WORKDIR /app/Artifacts

COPY Artifacts/ .

RUN pip install --no-cache-dir \
    gotrue==1.3.0 \
    httpx==0.27.2 \
    python-dotenv==1.0.0 \
    supabase==2.3.0

RUN pip install --no-cache-dir \
    -r project/sovereignshield_mobile/requirements.txt

RUN pip install --no-cache-dir \
    "numpy<2.0" \
    chromadb sentence-transformers pandas plotnine

RUN mkdir -p /tmp/chroma_db

EXPOSE 7860

CMD ["shiny", "run", "project/sovereignshield_mobile/app.py", \
     "--host", "0.0.0.0", "--port", "7860"]
