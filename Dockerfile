FROM node:20-alpine AS ui

WORKDIR /ui
COPY ui/package.json /ui/package.json
COPY ui/postcss.config.cjs /ui/postcss.config.cjs
COPY ui/tailwind.config.cjs /ui/tailwind.config.cjs
COPY ui/input.css /ui/input.css

RUN npm install --no-audit --no-fund

# Tailwind scans templates/scripts for class usage.
COPY app/templates /app/templates
COPY app/static /app/static

RUN npx tailwindcss -c /ui/tailwind.config.cjs -i /ui/input.css -o /ui/tailwindadmin.css --minify

FROM node:20-alpine AS spa

WORKDIR /spa
COPY frontend/package.json /spa/package.json
RUN npm install --no-audit --no-fund
COPY frontend /spa
RUN npm run build

FROM python:3.11-slim

ARG THREEJ_VERSION=unknown
ARG THREEJ_VERSION_DATE=unknown

RUN apt-get update \
    && apt-get install -y --no-install-recommends \
        ca-certificates \
        curl \
        docker.io \
        git \
        gnupg \
        apt-transport-https \
        iputils-ping \
        openssh-client \
    && curl -fsSL https://packagecloud.io/install/repositories/ookla/speedtest-cli/script.deb.sh | bash \
    && apt-get install -y --no-install-recommends speedtest \
    && rm -rf /var/lib/apt/lists/*

RUN mkdir -p /usr/local/lib/docker/cli-plugins \
    && curl -fsSL https://github.com/docker/compose/releases/download/v2.29.7/docker-compose-linux-x86_64 \
        -o /usr/local/lib/docker/cli-plugins/docker-compose \
    && chmod +x /usr/local/lib/docker/cli-plugins/docker-compose

WORKDIR /app

COPY requirements.txt /app/requirements.txt
RUN pip install --no-cache-dir -r /app/requirements.txt

COPY app /app/app
COPY --from=ui /ui/tailwindadmin.css /app/app/static/tailwindadmin.css
COPY --from=spa /spa/dist /app/app/static/spa

ENV THREEJ_DB_PATH=/data/threejnotif.db
ENV THREEJ_VERSION=${THREEJ_VERSION}
ENV THREEJ_VERSION_DATE=${THREEJ_VERSION_DATE}

VOLUME ["/data"]
EXPOSE 8000

CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8000"]
