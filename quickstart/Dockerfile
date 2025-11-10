# ---
# title: Quickstart demo Dockerfile
# purpose: Containerize the minimal Flask app for local Strix testing.
# ---
FROM python:3.11-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1

WORKDIR /app

RUN pip install --no-cache-dir flask==3.0.0

COPY app/ /app/

EXPOSE 5000

CMD ["python", "main.py"]
