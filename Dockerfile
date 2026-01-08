FROM python:3.11-slim

RUN apt-get update \
    && apt-get install -y --no-install-recommends iputils-ping openssh-client \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

COPY requirements.txt /app/requirements.txt
RUN pip install --no-cache-dir -r /app/requirements.txt

COPY app /app/app

ENV THREEJ_DB_PATH=/data/threejnotif.db

VOLUME ["/data"]
EXPOSE 8000

CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8000"]
