# MobileAgent - Go backend + Flutter Web frontend

# Stage 1: build backend
FROM golang:1.22-bookworm AS backend-builder
WORKDIR /src/backend-go
COPY backend-go/go.mod backend-go/go.sum ./
RUN go mod download
COPY backend-go/ ./
RUN CGO_ENABLED=1 GOOS=linux go build -o /out/mobileagent-server ./cmd/server

# Stage 2: build frontend
FROM ghcr.io/cirruslabs/flutter:stable AS frontend-builder
WORKDIR /src/frontend
COPY frontend/pubspec.yaml frontend/pubspec.lock ./
RUN flutter pub get
COPY frontend/ ./
RUN flutter build web --release --no-web-resources-cdn

# Stage 3: runtime
FROM debian:bookworm-slim

RUN apt-get update && apt-get install -y --no-install-recommends \
    bash \
    binutils \
    ca-certificates \
    curl \
    git \
    python3 \
    python3-pip \
    python3-venv \
    openjdk-17-jre-headless \
    tar \
    unzip \
    xz-utils \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

COPY --from=backend-builder /out/mobileagent-server /app/backend-go/mobileagent-server
COPY backend-go/configs /app/backend-go/configs
COPY --from=frontend-builder /src/frontend/build/web /app/frontend-web
COPY start.sh /app/start.sh
COPY tools/setup.sh /app/tools/setup.sh

RUN mkdir -p \
    /app/backend-go/data/uploads \
    /app/backend-go/data/workspace \
    /app/backend-go/data/memory \
    /app/backend-go/data/market \
    /app/backend-go/data/skills \
    /app/tools/bin \
    && chmod +x /app/tools/setup.sh \
    && /app/tools/setup.sh

ENV MOBILEAGENT_BACKEND_PORT=8320
ENV MOBILEAGENT_FRONTEND_PORT=9999
ENV PATH="/app/tools/bin:${PATH}"

EXPOSE 8320 9999

HEALTHCHECK --interval=30s --timeout=5s --retries=3 \
    CMD curl -fsS http://localhost:8320/health || exit 1

CMD ["/bin/sh", "-c", "cd /app/backend-go && ./mobileagent-server -config configs/config.yaml & cd /app/frontend-web && python3 -m http.server 9999 --bind 0.0.0.0"]
