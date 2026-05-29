#!/usr/bin/env bash
set -euo pipefail

# === MobileAgent 一键启动脚本 ===
# 前端: Flutter Web (localhost:9999)
# 后端: Go Server  (localhost:8320)

PROJECT_ROOT="$(cd "$(dirname "$0")" && pwd)"
BACKEND_DIR="$PROJECT_ROOT/backend-go"
FRONTEND_DIR="$PROJECT_ROOT/frontend"
BACKEND_PORT=8320
FRONTEND_PORT=9999
LOG_DIR="/tmp/mobileagent"
BACKEND_LOG="$LOG_DIR/backend.log"
FRONTEND_LOG="$LOG_DIR/frontend.log"
BACKEND_PID_FILE="$LOG_DIR/backend.pid"
FRONTEND_PID_FILE="$LOG_DIR/frontend.pid"

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
NC='\033[0m'

log_info()  { echo -e "${GREEN}[INFO]${NC} $1"; }
log_warn()  { echo -e "${YELLOW}[WARN]${NC} $1"; }
log_error() { echo -e "${RED}[ERROR]${NC} $1"; }

check_port() {
    lsof -iTCP:"$1" -sTCP:LISTEN -P -n &>/dev/null
}

wait_for_port() {
    local port=$1 name=$2 count=0
    while [ $count -lt 30 ]; do
        if check_port "$port"; then return 0; fi
        sleep 1
        count=$((count + 1))
    done
    return 1
}

# --- Helper: stop individual services ---

cmd_stop_backend() {
    local pids=""

    if [ -f "$BACKEND_PID_FILE" ]; then
        local pid
        pid="$(cat "$BACKEND_PID_FILE" 2>/dev/null || true)"
        if [ -n "$pid" ]; then
            pids="$pids $pid"
        fi
        rm -f "$BACKEND_PID_FILE"
    fi

    local port_pids
    port_pids="$(lsof -iTCP:"$BACKEND_PORT" -sTCP:LISTEN -P -n -t 2>/dev/null | tr '\n' ' ')"
    if [ -n "$port_pids" ]; then
        pids="$pids $port_pids"
    fi

    pids="$(printf '%s\n' $pids | awk 'NF && !seen[$0]++')"
    if [ -z "$pids" ]; then
        log_info "Backend already stopped ✅"
        return
    fi

    log_info "Stopping backend process(es): $(echo "$pids" | tr '\n' ' ')"
    while read -r pid; do
        [ -z "$pid" ] && continue
        kill "$pid" 2>/dev/null || true
    done <<< "$pids"

    sleep 1

    while read -r pid; do
        [ -z "$pid" ] && continue
        if kill -0 "$pid" 2>/dev/null; then
            kill -9 "$pid" 2>/dev/null || true
        fi
    done <<< "$pids"

    log_info "Backend stopped ✅"
}

cmd_stop_frontend() {
    local pids=""

    if [ -f "$FRONTEND_PID_FILE" ]; then
        local pid
        pid="$(cat "$FRONTEND_PID_FILE" 2>/dev/null || true)"
        if [ -n "$pid" ]; then
            pids="$pids $pid"
        fi
        rm -f "$FRONTEND_PID_FILE"
    fi

    local port_pids
    port_pids="$(lsof -iTCP:"$FRONTEND_PORT" -sTCP:LISTEN -P -n -t 2>/dev/null | tr '\n' ' ')"
    if [ -n "$port_pids" ]; then
        pids="$pids $port_pids"
    fi

    pids="$(printf '%s\n' $pids | awk 'NF && !seen[$0]++')"
    if [ -z "$pids" ]; then
        log_info "Frontend already stopped ✅"
        return
    fi

    log_info "Stopping frontend process(es): $(echo "$pids" | tr '\n' ' ')"
    while read -r pid; do
        [ -z "$pid" ] && continue
        pkill -P "$pid" 2>/dev/null || true
        kill "$pid" 2>/dev/null || true
    done <<< "$pids"

    sleep 1

    while read -r pid; do
        [ -z "$pid" ] && continue
        pkill -P "$pid" 2>/dev/null || true
        if kill -0 "$pid" 2>/dev/null; then
            kill -9 "$pid" 2>/dev/null || true
        fi
    done <<< "$pids"

    log_info "Frontend stopped ✅"
}

# --- Commands ---

cmd_setup_tools() {
    log_info "Running tools setup..."
    bash "$PROJECT_ROOT/tools/setup.sh"
}

cmd_start() {
    mkdir -p "$LOG_DIR"

    # Check if tools are installed
    if [ ! -f "$PROJECT_ROOT/tools/bin/adb" ]; then
        log_warn "Tools not installed. Run './tools/setup.sh' first or use './start.sh setup' to install."
        log_warn "Falling back to system PATH for tools..."
    fi

    # Set cleanup trap only for start command
    trap 'log_info "Stopping services..."; \
        cmd_stop_backend; \
        cmd_stop_frontend' EXIT INT TERM

    if check_port "$BACKEND_PORT" || [ -f "$BACKEND_PID_FILE" ]; then
        log_warn "Backend already running or PID file exists, restarting..."
        cmd_stop_backend
    fi

    if check_port "$FRONTEND_PORT" || [ -f "$FRONTEND_PID_FILE" ]; then
        log_warn "Frontend already running or PID file exists, restarting..."
        cmd_stop_frontend
    fi

    log_info "Building backend..."
    (cd "$BACKEND_DIR" && go build -o build/mobileagent-server ./cmd/server/)

    log_info "Starting backend on port $BACKEND_PORT..."
    (cd "$BACKEND_DIR" && ./build/mobileagent-server -config configs/config.yaml) \
        > "$BACKEND_LOG" 2>&1 &
    echo $! > "$BACKEND_PID_FILE"

    if wait_for_port "$BACKEND_PORT" "Backend"; then
        log_info "Backend ready ✅ (PID: $(cat "$BACKEND_PID_FILE"))"
    else
        log_error "Backend failed to start. See $BACKEND_LOG"
        tail -20 "$BACKEND_LOG"
        exit 1
    fi

    log_info "Building frontend (web release)..."
    (cd "$FRONTEND_DIR" && flutter build web --release --no-web-resources-cdn) >> "$FRONTEND_LOG" 2>&1
    if [ ! -f "$FRONTEND_DIR/build/web/index.html" ]; then
        log_error "Frontend build failed. See $FRONTEND_LOG"
        tail -40 "$FRONTEND_LOG"
        exit 1
    fi

    log_info "Starting frontend on port $FRONTEND_PORT..."
    (cd "$FRONTEND_DIR/build/web" && python3 -m http.server "$FRONTEND_PORT" --bind 0.0.0.0) \
        >> "$FRONTEND_LOG" 2>&1 &
    echo $! > "$FRONTEND_PID_FILE"

    if wait_for_port "$FRONTEND_PORT" "Frontend"; then
        log_info "Frontend ready ✅ (PID: $(cat "$FRONTEND_PID_FILE"))"
    else
        log_error "Frontend failed to start. See $FRONTEND_LOG"
        tail -20 "$FRONTEND_LOG"
        exit 1
    fi

    echo ""
    echo -e "${CYAN}=================================${NC}"
    echo -e "${CYAN}  MobileAgent is running! 🚀${NC}"
    echo -e "${CYAN}=================================${NC}"
    echo -e "  Frontend:  ${GREEN}http://localhost:$FRONTEND_PORT${NC}"
    echo -e "  Backend:   ${GREEN}http://localhost:$BACKEND_PORT${NC}"
    echo -e "  Logs:      $LOG_DIR/"
    echo ""
    log_info "Press Ctrl+C to stop all services"

    wait
}

cmd_stop() {
    log_info "Stopping MobileAgent..."
    cmd_stop_backend
    cmd_stop_frontend
}

cmd_restart() {
    cmd_stop
    sleep 2
    cmd_start
}

cmd_status() {
    echo -e "${CYAN}MobileAgent Status:${NC}"
    if check_port "$BACKEND_PORT"; then
        PID=$(lsof -iTCP:"$BACKEND_PORT" -sTCP:LISTEN -P -n -t 2>/dev/null | head -1)
        echo -e "  Backend:   ${GREEN}RUNNING${NC} (PID: $PID, port: $BACKEND_PORT)"
    else
        echo -e "  Backend:   ${RED}STOPPED${NC}"
    fi
    if check_port "$FRONTEND_PORT"; then
        PID=$(lsof -iTCP:"$FRONTEND_PORT" -sTCP:LISTEN -P -n -t 2>/dev/null | head -1)
        echo -e "  Frontend:  ${GREEN}RUNNING${NC} (PID: $PID, port: $FRONTEND_PORT)"
    else
        echo -e "  Frontend:  ${RED}STOPPED${NC}"
    fi
}

cmd_logs() {
    local target="${1:-all}"
    case "$target" in
        backend|b)  tail -f "$BACKEND_LOG" ;;
        frontend|f) tail -f "$FRONTEND_LOG" ;;
        all|*)      tail -f "$BACKEND_LOG" "$FRONTEND_LOG" ;;
    esac
}

# --- Main ---
case "${1:-start}" in
    start)   cmd_start ;;
    stop)    cmd_stop ;;
    restart) cmd_restart ;;
    status)  cmd_status ;;
    setup)   cmd_setup_tools ;;
    logs)    cmd_logs "${2:-all}" ;;
    *)
        echo "Usage: $0 {start|stop|restart|status|logs|setup}"
        echo ""
        echo "Commands:"
        echo "  start    Build & start both services (default)"
        echo "  stop     Stop all services"
        echo "  restart  Stop then start"
        echo "  status   Check if services are running"
        echo "  setup    Download Android tools to tools/bin/"
        echo "  logs     Tail logs (backend|frontend|all)"
        exit 1
        ;;
esac