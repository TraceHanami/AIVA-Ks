FROM python:3.12-slim

WORKDIR /app

COPY ai/feature_extraction/requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY ai ./ai

CMD ["python", "-m", "ai.feature_extraction.extractor"]
