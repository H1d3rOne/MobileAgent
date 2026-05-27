# Build stage
FROM golang:1.22-alpine AS builder

RUN apk add --no-cache git gcc musl-dev

WORKDIR /app
COPY go.mod go.sum ./
RUN go mod download

COPY . .
RUN CGO_ENABLED=1 GOOS=linux go build -o /mobileagent-server ./cmd/server/

# Runtime stage
FROM alpine:3.19

RUN apk add --no-cache ca-certificates android-tools

WORKDIR /app
COPY --from=builder /mobileagent-server .
COPY configs/config.yaml ./configs/config.yaml

RUN mkdir -p /app/data/uploads /app/data/workspace /app/data/memory

EXPOSE 8080

CMD ["./mobileagent-server", "-config", "configs/config.yaml"]
