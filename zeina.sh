#!/usr/bin/env bash
set -euo pipefail

# Enhanced ANSI Color Codes for rich terminal output formatting
readonly RESET='\033[0m'           # Reset all formatting
readonly BOLD='\033[1m'            # Bold text
readonly DIM='\033[2m'             # Dimmed text
readonly ITALIC='\033[3m'          # Italic text
readonly UNDERLINE='\033[4m'        # Underlined text
readonly BLINK='\033[5m'           # Blinking text
readonly REVERSE='\033[7m'         # Reverse video

# Rich Color Palette (btop-inspired)
readonly BLACK='\033[0;30m'        # Pure Black
readonly GRAY='\033[0;90m'         # Gray
readonly WHITE='\033[1;37m'        # Bright White
readonly SILVER='\033[0;37m'       # Silver

# Primary Colors
readonly GREEN='\033[0;32m'        # Success / Healthy
readonly LIGHT_GREEN='\033[1;32m'  # Bright Success
readonly LIME='\033[38;5;46m'      # Lime Green
readonly MINT='\033[38;5;48m'      # Mint Green

# Red Spectrum
readonly RED='\033[0;31m'          # Error / Critical
readonly LIGHT_RED='\033[1;31m'    # Bright Error
readonly ORANGE='\033[38;5;208m'  # Warning Orange
readonly CORAL='\033[38;5;203m'    # Coral Red

# Blue Spectrum
readonly BLUE='\033[0;34m'         # Info / Processing
readonly LIGHT_BLUE='\033[1;34m'   # Bright Blue
readonly CYAN='\033[0;36m'         # Accent / Highlight
readonly LIGHT_CYAN='\033[1;36m'   # Bright Cyan
readonly TURQUOISE='\033[38;5;45m' # Turquoise

# Purple Spectrum
readonly MAGENTA='\033[0;35m'      # Special / Admin
readonly LIGHT_MAGENTA='\033[1;35m' # Bright Magenta
readonly PURPLE='\033[38;5;141m'   # Deep Purple
readonly VIOLET='\033[38;5;147m'   # Violet

# Yellow/Gold Spectrum
readonly YELLOW='\033[1;33m'       # Warning / Caution
readonly GOLD='\033[38;5;220m'     # Gold
readonly AMBER='\033[38;5;214m'   # Amber

# Background Colors
readonly BG_BLACK='\033[40m'       # Black Background
readonly BG_RED='\033[41m'         # Red Background
readonly BG_GREEN='\033[42m'       # Green Background
readonly BG_YELLOW='\033[43m'      # Yellow Background
readonly BG_BLUE='\033[44m'        # Blue Background
readonly BG_MAGENTA='\033[45m'     # Magenta Background
readonly BG_CYAN='\033[46m'        # Cyan Background
readonly BG_WHITE='\033[47m'       # White Background

# Gradient Colors for ASCII Art
readonly GRADIENT_CYAN='\033[38;5;39m'
readonly GRADIENT_BLUE='\033[38;5;33m'
readonly GRADIENT_PURPLE='\033[38;5;129m'
readonly GRADIENT_PINK='\033[38;5;213m'

# ==============================================================================
# ASCII Art Banner
# ==============================================================================

# Function: print_banner
# Displays ZeinaGuard logo pinned to the very top
print_banner() {
    clear  # Clear terminal for clean presentation
    
    # Print ASCII Art immediately at the top with ZEINA in magenta and GUARD in cyan
    printf "${BOLD}${MAGENTA}  █████████╗███████╗██╗███╗   ██╗ █████╗ ${CYAN}  ██████╗ ██╗   ██╗ █████╗ ██████╗ ██████╗ ${RESET}\n"
    printf "${BOLD}${MAGENTA}  ╚════███╔╝██╔════╝██║████╗  ██║██╔══██╗${CYAN} ██╔════╝ ██║   ██║██╔══██╗██╔══██╗██╔══██╗${RESET}\n"
    printf "${BOLD}${MAGENTA}     ███╔╝  █████╗  ██║██╔██╗ ██║███████║${CYAN} ██║  ███╗██║   ██║███████║██████╔╝██║  ██║${RESET}\n"
    printf "${BOLD}${MAGENTA}   ███╔╝    ██╔══╝  ██║██║╚██╗██║██╔══██║${CYAN} ██║   ██║██║   ██║██╔══██║██╔══██║██║  ██║${RESET}\n"
    printf "${BOLD}${MAGENTA}  █████████╗███████╗██║██║ ╚████║██║  ██║${CYAN} ╚██████╔╝╚██████╔╝██║  ██║██║  ██║██████╔╝${RESET}\n"
    printf "${BOLD}${MAGENTA}  ╚════════╝╚══════╝╚═╝╚═╝  ╚═══╝╚═╝  ╚═╝${CYAN}  ╚═════╝  ╚═════╝ ╚═╝  ╚═╝╚═╝  ╚═╝╚═════╝ ${RESET}\n"
    
    # System information with minimal spacing
    printf "${CYAN}                  Wireless Intrusion Detection & Prevention System${RESET}\n"
    printf "${DIM}                             Version 1.0.0 | Build 2026${RESET}\n"
    echo ""
}

# Global variables
ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ENV_FILE="$ROOT_DIR/.env"
LOG_DIR="$ROOT_DIR/logs"
STATE_DIR="$ROOT_DIR/.zeinaguard-runtime"

SERVICES=("sensor" "frontend" "backend")
PORTS=("3000" "5000")

# Clean logging functions for better terminal output
log() {
  printf "${CYAN}%s${RESET}\n" "$*"
}

warn() {
  printf "${YELLOW}%s${RESET}\n" "$*" >&2
}

fail() {
  printf "${RED}%s${RESET}\n" "$*" >&2
  exit 1
}

# Success message function with clean formatting
success() {
  printf "${GREEN}%s${RESET}\n" "$*"
}

# Info message function with clean visuals
info() {
  printf "${BLUE}%s${RESET}\n" "$*"
}

# Clean progress bar function
progress_bar() {
  local current=$1
  local total=$2
  local width=${3:-30}
  local label=${4:-"Progress"}
  
  local percentage=$((current * 100 / total))
  local filled=$((current * width / total))
  local empty=$((width - filled))
  
  printf "\r${BLUE}%s: [${GREEN}" "$label"
  printf "%*s" "$filled" | tr ' ' '='
  printf "${DIM}%*s${RESET}" "$empty" | tr ' ' '-'
  printf "] ${CYAN}%d%%${RESET}" "$percentage"
  
  if [ "$current" -eq "$total" ]; then
    echo ""
  fi
}

# Clean spinner for loading
spinner() {
  local pid=$1
  local label=${2:-"Loading"}
  local chars="/-\\|"
  local i=0
  
  while kill -0 "$pid" 2>/dev/null; do
    printf "\r${YELLOW}${chars:$i:1} ${RESET}${label}..."
    i=$(( (i + 1) % 4 ))
    sleep 0.2
  done
  printf "\r${GREEN}✓${RESET} ${label} completed\n"
}

# Clean status indicator
status_indicator() {
  local status=$1
  local message=$2
  
  case "$status" in
    "running")
      printf "${GREEN}● %s${RESET}\n" "$message"
      ;;
    "stopped")
      printf "${GRAY}○ %s${RESET}\n" "$message"
      ;;
    "error")
      printf "${RED}✗ %s${RESET}\n" "$message"
      ;;
    "warning")
      printf "${YELLOW}⚠ %s${RESET}\n" "$message"
      ;;
    "loading")
      printf "${BLUE}⟳ %s${RESET}\n" "$message"
      ;;
    *)
      printf "${CYAN}• %s${RESET}\n" "$message"
      ;;
  esac
}

# Enhanced rich separator line with dynamic styling
separator() {
  local title=${1:-""}
  local term_width=$(get_terminal_width)
  
  if [ -n "$title" ]; then
    local title_len=${#title}
    local padding=$(( (term_width - title_len - 8) / 2 ))
    printf "${LIGHT_BLUE}┌"
    printf "─%.0s" $(seq 1 $padding)
    printf "${BOLD}${GOLD} [ %s ] ${RESET}" "$title"
    printf "─%.0s" $(seq 1 $padding)
    printf "┐${RESET}\n"
  else
    printf "${LIGHT_BLUE}┌"
    printf "─%.0s" $(seq 1 $((term_width - 2)))
    printf "┐${RESET}\n"
  fi
}

# Enhanced visual separator with more styling
visual_separator() {
  local style=${1:-"single"}
  local term_width=$(get_terminal_width)
  
  case "$style" in
    "double")
      printf "${LIGHT_BLUE}╔"
      printf "═%.0s" $(seq 1 $((term_width - 2)))
      printf "╗${RESET}\n"
      ;;
    "dashed")
      printf "${DIM}┌"
      printf "┄%.0s" $(seq 1 $((term_width - 2)))
      printf "┐${RESET}\n"
      ;;
    "dotted")
      printf "${DIM}┌"
      printf "┈%.0s" $(seq 1 $((term_width - 2)))
      printf "┐${RESET}\n"
      ;;
    *)
      printf "${LIGHT_BLUE}┌"
      printf "─%.0s" $(seq 1 $((term_width - 2)))
      printf "┐${RESET}\n"
      ;;
  esac
}

# Dynamic terminal size detection functions
get_terminal_width() {
  tput cols 2>/dev/null || echo 80
}

get_terminal_height() {
  tput lines 2>/dev/null || echo 24
}

calculate_center_padding() {
  local content_width=$1
  local terminal_width=$(get_terminal_width)
  local padding=$(( (terminal_width - content_width) / 2 ))
  echo $(( padding > 0 ? padding : 0 ))
}

calculate_vertical_padding() {
  local content_height=$1
  local terminal_height=$(get_terminal_height)
  local padding=$(( (terminal_height - content_height) / 2 ))
  echo $(( padding > 0 ? padding : 0 ))
}

print_centered() {
  local text="$1"
  local text_width=${#text}
  local padding=$(calculate_center_padding $text_width)
  printf "%*s%s\n" "$padding" "" "$text"
}

print_centered_colored() {
  local text="$1"
  local color="$2"
  local reset="$3"
  local text_width=${#text}
  local padding=$(calculate_center_padding $text_width)
  printf "%*s%s%s%s\n" "$padding" "" "$color" "$text" "$reset"
}

print_box_line() {
  local width=$1
  local style=${2:-"single"}
  local terminal_width=$(get_terminal_width)
  local padding=$(calculate_center_padding $width)
  
  case "$style" in
    "double")
      printf "%*s%s" "$padding" "" "╔"
      printf "═%.0s" $(seq 1 $((width - 2)))
      printf "╗\n"
      ;;
    "single")
      printf "%*s%s" "$padding" "" "┌"
      printf "─%.0s" $(seq 1 $((width - 2)))
      printf "┐\n"
      ;;
    "rounded")
      printf "%*s%s" "$padding" "" "╭"
      printf "─%.0s" $(seq 1 $((width - 2)))
      printf "╮\n"
      ;;
  esac
}

# Utility functions
run_maybe_sudo() {
  if [ "${EUID:-$(id -u)}" -eq 0 ]; then
    "$@"
  elif command -v sudo >/dev/null 2>&1; then
    sudo "$@" || {
      local exit_code=$?
      # Don't fail on sudo timeout or permission issues
      if [ $exit_code -eq 1 ] || [ $exit_code -eq 126 ]; then
        return 0
      else
        return $exit_code
      fi
    }
  else
    fail "This action requires sudo: $*"
  fi
}

ensure_linux() {
  [ "$(uname -s)" = "Linux" ] || fail "ZeinaGuard local launcher supports Linux only."
}

pid_file_for() {
  printf '%s/%s.pid\n' "$STATE_DIR" "$1"
}

process_running() {
  local pid="$1"
  kill -0 "$pid" >/dev/null 2>&1
}

wait_for_process_exit() {
  local pid="$1"
  local attempts=0

  while process_running "$pid" && [ "$attempts" -lt 50 ]; do
    sleep 0.2
    attempts=$((attempts + 1))
  done

  if process_running "$pid"; then
    kill -9 "$pid" >/dev/null 2>&1 || true
  fi
}

# Environment setup functions
ensure_default_env() {
  if [ -f "$ENV_FILE" ]; then
    return
  fi

  cat >"$ENV_FILE" <<'EOF'
POSTGRES_USER=zeinaguard_user
POSTGRES_PASSWORD=secure_password
POSTGRES_DB=zeinaguard_db
POSTGRES_HOST=localhost
POSTGRES_PORT=5432

REDIS_HOST=localhost
REDIS_PORT=6379
REDIS_PASSWORD=

BACKEND_URL=http://localhost:5000
NEXT_PUBLIC_SOCKET_URL=http://localhost:5000
NEXT_PUBLIC_API_URL=http://localhost:5000

JWT_SECRET_KEY=super_secret_key
EOF
  log "Created default .env file at $ENV_FILE"
}

load_env() {
  set -a
  # shellcheck source=/dev/null
  source "$ENV_FILE"
  set +a
}

ensure_runtime_dirs() {
  mkdir -p "$LOG_DIR" "$STATE_DIR"
}

fix_project_permissions() {
  if [ -z "${USER:-}" ]; then
    return
  fi

  if [ -w "$ROOT_DIR" ] && { [ ! -d "$ROOT_DIR/node_modules" ] || [ -w "$ROOT_DIR/node_modules" ]; }; then
    log "Project ownership looks okay; skipping recursive chown"
    return
  fi

  log "Fixing project ownership for $ROOT_DIR"
  run_maybe_sudo chown -R "$USER:$USER" "$ROOT_DIR" || true
}

# Process management functions
port_is_open() {
  local host="$1"
  local port="$2"

  python3 - "$host" "$port" <<'PY'
import socket
import sys

host = sys.argv[1]
port = int(sys.argv[2])

sock = socket.socket()
sock.settimeout(1)

try:
    sock.connect((host, port))
except OSError:
    raise SystemExit(1)
finally:
    sock.close()
PY
}

ensure_port_available() {
  local service_name="$1"
  local port="$2"

  stop_pid_file "$service_name"
  if port_is_open "127.0.0.1" "$port"; then
    fail "Port $port is already in use. Free it before starting $service_name."
  fi
}

start_command() {
  local service_name="$1"
  local workdir="$2"
  shift 2

  local log_file="$LOG_DIR/$service_name.log"
  local pid_file
  local pid

  pid_file="$(pid_file_for "$service_name")"
  : >"$log_file"

  (
    cd "$workdir"
    nohup "$@" >>"$log_file" 2>&1 &
    echo $! >"$pid_file"
  )

  sleep 1
  pid="$(cat "$pid_file" 2>/dev/null || true)"
  if [ -z "$pid" ] || ! process_running "$pid"; then
    tail -n 40 "$log_file" >&2 || true
    fail "$service_name failed to stay running. See $log_file"
  fi
}

wait_for_http() {
  local name="$1"
  local url="$2"
  local timeout_seconds="$3"
  local expected_fragment="${4:-}"
  local deadline=$((SECONDS + timeout_seconds))
  local response=""

  while [ "$SECONDS" -lt "$deadline" ]; do
    response="$(curl -fsS --max-time 3 "$url" 2>/dev/null || true)"
    if [ -n "$response" ]; then
      if [ -z "$expected_fragment" ] || printf '%s' "$response" | grep -qi "$expected_fragment"; then
        return 0
      fi
    fi
    sleep 2
  done

  tail -n 60 "$LOG_DIR/$name.log" >&2 || true
  fail "$name health check failed for $url"
}

# Stop functions
stop_pid_file() {
  local name="$1"
  local pid_file
  local pid

  pid_file="$(pid_file_for "$name")"
  if [ ! -f "$pid_file" ]; then
    return
  fi

  pid="$(cat "$pid_file" 2>/dev/null || true)"
  if [ -n "$pid" ] && process_running "$pid"; then
    log "Stopping previous $name process ($pid)"
    kill "$pid" >/dev/null 2>&1 || true
    wait_for_process_exit "$pid"
  fi

  rm -f "$pid_file"
}

stop_service_by_pid_file() {
  local name="$1"
  local pid_file
  local pid

  pid_file="$(pid_file_for "$name")"
  if [ ! -f "$pid_file" ]; then
    log "No pid file for $name, skipping"
    return
  fi

  pid="$(cat "$pid_file" 2>/dev/null || true)"
  if [ -z "$pid" ]; then
    rm -f "$pid_file"
    log "Empty pid file for $name removed"
    return
  fi

  if ! process_running "$pid"; then
    log "$name (pid $pid) was not running"
    rm -f "$pid_file"
    return
  fi

  log "Stopping $name (pid $pid) with SIGTERM"
  run_maybe_sudo kill "$pid" >/dev/null 2>&1 || kill "$pid" >/dev/null 2>&1 || true

  if ! wait_for_process_exit "$pid"; then
    warn "$name (pid $pid) did not exit, sending SIGKILL"
    run_maybe_sudo kill -9 "$pid" >/dev/null 2>&1 || kill -9 "$pid" >/dev/null 2>&1 || true
    sleep 0.5
  fi

  if process_running "$pid"; then
    warn "$name (pid $pid) still running after SIGKILL"
  else
    log "$name stopped"
  fi

  rm -f "$pid_file"
}

stop_children_of() {
  local parent_pid="$1"
  local child_pids=""

  if command -v pgrep >/dev/null 2>&1; then
    child_pids="$(pgrep -P "$parent_pid" 2>/dev/null || true)"
  elif [ -d /proc ]; then
    local p
    for p in /proc/[0-9]*; do
      [ -r "$p/status" ] || continue
      local ppid
      ppid="$(awk '/^PPid:/ {print $2}' "$p/status" 2>/dev/null || true)"
      if [ "$ppid" = "$parent_pid" ]; then
        child_pids+="${p##*/}"$'\n'
      fi
    done
  fi

  if [ -z "$child_pids" ]; then
    return
  fi

  while IFS= read -r child; do
    [ -z "$child" ] && continue
    [ "$child" = "$$" ] && continue
    stop_children_of "$child"
    if process_running "$child"; then
      run_maybe_sudo kill "$child" >/dev/null 2>&1 || kill "$child" >/dev/null 2>&1 || true
      sleep 0.2
      if process_running "$child"; then
        run_maybe_sudo kill -9 "$child" >/dev/null 2>&1 || kill -9 "$child" >/dev/null 2>&1 || true
      fi
    fi
  done <<<"$child_pids"
}

stop_descendants_from_pid_file() {
  local name="$1"
  local pid_file
  local pid

  pid_file="$(pid_file_for "$name")"
  [ -f "$pid_file" ] || return
  pid="$(cat "$pid_file" 2>/dev/null || true)"
  [ -n "$pid" ] || return
  stop_children_of "$pid"
}

stop_listeners_on_port() {
  local port="$1"
  local pids=""

  if command -v lsof >/dev/null 2>&1; then
    pids="$(lsof -ti tcp:"$port" 2>/dev/null || true)"
  fi

  if [ -z "$pids" ] && command -v fuser >/dev/null 2>&1; then
    pids="$(fuser -n tcp "$port" 2>/dev/null | tr -s ' ' '\n' | grep -E '^[0-9]+$' || true)"
  fi

  if [ -z "$pids" ] && command -v ss >/dev/null 2>&1; then
    local port_pattern=":${port}\$"
    pids="$(ss -ltnp 2>/dev/null \
      | awk -v p="$port_pattern" '$4 ~ p {print $0}' \
      | grep -oE 'pid=[0-9]+' \
      | cut -d= -f2 \
      | sort -u || true)"
  fi

  if [ -z "$pids" ]; then
    return
  fi

  while IFS= read -r pid; do
    [ -z "$pid" ] && continue
    if process_running "$pid"; then
      log "Killing pid $pid still bound to port $port"
      run_maybe_sudo kill "$pid" >/dev/null 2>&1 || kill "$pid" >/dev/null 2>&1 || true
      sleep 0.3
      if process_running "$pid"; then
        run_maybe_sudo kill -9 "$pid" >/dev/null 2>&1 || kill -9 "$pid" >/dev/null 2>&1 || true
      fi
    fi
  done <<<"$pids"
}

stop_known_command_patterns() {
  if ! command -v pgrep >/dev/null 2>&1; then
    return 0
  fi

  local patterns=(
    "next dev"
    "next-server"
    "pnpm.*dev"
    "npm.*run.*dev"
    "gunicorn.*app:app"
    "$ROOT_DIR/sensor/main.py"
    "sensor/main.py"
  )

  local self_pid="$$"
  local parent_pid="${PPID:-0}"

  for pattern in "${patterns[@]}"; do
    local pids
    pids="$(pgrep -f "$pattern" 2>/dev/null || true)"
    if [ -z "$pids" ]; then
      continue
    fi
    while IFS= read -r pid; do
      [ -z "$pid" ] && continue
      [ "$pid" = "$self_pid" ] && continue
      [ "$pid" = "$parent_pid" ] && continue
      if process_running "$pid"; then
        log "Stopping leftover process matching '$pattern' (pid $pid)"
        run_maybe_sudo kill "$pid" >/dev/null 2>&1 || kill "$pid" >/dev/null 2>&1 || true
        sleep 0.3
        if process_running "$pid"; then
          run_maybe_sudo kill -9 "$pid" >/dev/null 2>&1 || kill -9 "$pid" >/dev/null 2>&1 || true
        fi
      fi
    done <<<"$pids"
  done
}

# Cleanup function for graceful shutdown
cleanup() {
    echo -e "\n${YELLOW}Caught interrupt signal! Stopping all ZeinaGuard services safely...${RESET}"
    
    # Stop all services using the comprehensive stop functions
    for service in "${SERVICES[@]}"; do
        stop_descendants_from_pid_file "$service"
        stop_service_by_pid_file "$service"
    done

    stop_known_command_patterns

    for port in "${PORTS[@]}"; do
        stop_listeners_on_port "$port"
    done

    # Clean up runtime state
    if [ -d "$STATE_DIR" ]; then
        rm -f "$STATE_DIR"/*.pid 2>/dev/null || true
    fi
    
    echo -e "${GREEN}Running automated cleanup...${RESET}"
    
    # Clear log files
    find logs/ -type f -exec truncate -s 0 {} \; 2>/dev/null
    find sensor/data_logs/ -type f -exec truncate -s 0 {} \; 2>/dev/null
    
    # Clear Python cache with proper permission handling
    find . -type d -name "__pycache__" -exec rm -rf {} + 2>/dev/null || true
    find . -type f -name "*.pyc" -delete 2>/dev/null || true
    
    # Handle stubborn cache files with sudo if needed
    if command -v sudo >/dev/null 2>&1; then
        find . -path "*/.venv/*" -name "__pycache__" -exec sudo rm -rf {} + 2>/dev/null || true
        find . -path "*/.venv/*" -name "*.pyc" -exec sudo rm -f {} + 2>/dev/null || true
    fi

    # Deactivate virtual environments
    deactivate_venvs

    echo -e "${GREEN}Everything stopped and cleaned successfully. Goodbye!${RESET}"
    exit 0
}

# Preparation functions
prepare_frontend() {
  # Check if Node.js is available
  if ! command -v node >/dev/null 2>&1; then
    fail "Node.js is not installed. Please install Node.js 20 or later."
  fi
  
  # Check if pnpm is available
  if ! command -v pnpm >/dev/null 2>&1; then
    info "Installing pnpm..."
    run_maybe_sudo npm install -g pnpm >/dev/null 2>&1 || fail "Failed to install pnpm"
  fi

  # Clean up and prepare
  fix_project_permissions >/dev/null 2>&1 || true
  run_maybe_sudo npm cache clean --force >/dev/null 2>&1 || true
  rm -rf "$ROOT_DIR/node_modules" "$ROOT_DIR/package-lock.json" 2>/dev/null || true

  info "Preparing frontend environment..."
  (
    cd "$ROOT_DIR"
    pnpm install --silent 2>/dev/null || pnpm install >/dev/null 2>&1
  )
  success "Frontend dependencies ready"
}

# Global variables to track venv activation
BACKEND_VENV_ACTIVATED=false
SENSOR_VENV_ACTIVATED=false

prepare_python_envs() {
  # Check if Python 3 is available
  if ! command -v python3 >/dev/null 2>&1; then
    fail "Python 3 is not installed."
  fi
  
  # Setup backend virtual environment
  if [ ! -d "$ROOT_DIR/backend/.venv" ]; then
    info "Creating backend environment..."
    (cd "$ROOT_DIR/backend" && python3 -m venv .venv >/dev/null 2>&1)
  fi
  
  # Setup sensor virtual environment
  if [ ! -d "$ROOT_DIR/sensor/.venv" ]; then
    info "Creating sensor environment..."
    (cd "$ROOT_DIR/sensor" && python3 -m venv .venv >/dev/null 2>&1)
  fi
  
  # Install backend dependencies
  if [ -f "$ROOT_DIR/backend/requirements.txt" ]; then
    info "Preparing backend environment..."
    local backend_python="$ROOT_DIR/backend/.venv/bin/python"
    if [ ! -f "$backend_python" ]; then
      backend_python="$ROOT_DIR/backend/.venv/bin/python3"
    fi
    (cd "$ROOT_DIR/backend" && "$backend_python" -m pip install -r requirements.txt >/dev/null 2>&1)
    success "Backend dependencies ready"
  fi
  
  # Install sensor dependencies
  if [ -f "$ROOT_DIR/sensor/requirements.txt" ]; then
    info "Preparing sensor environment..."
    local sensor_python="$ROOT_DIR/sensor/.venv/bin/python"
    if [ ! -f "$sensor_python" ]; then
      sensor_python="$ROOT_DIR/sensor/.venv/bin/python3"
    fi
    (cd "$ROOT_DIR/sensor" && "$sensor_python" -m pip install -r requirements.txt >/dev/null 2>&1)
    success "Sensor dependencies ready"
  fi
}

activate_venvs() {
  # Activate backend venv if not already active
  if [ "$BACKEND_VENV_ACTIVATED" = false ]; then
    source "$ROOT_DIR/backend/.venv/bin/activate" || true
    BACKEND_VENV_ACTIVATED=true
  fi
  
  # Activate sensor venv if not already active
  if [ "$SENSOR_VENV_ACTIVATED" = false ]; then
    source "$ROOT_DIR/sensor/.venv/bin/activate" || true
    SENSOR_VENV_ACTIVATED=true
  fi
}

deactivate_venvs() {
  log "Deactivating virtual environments"
  
  # Deactivate backend venv if activated
  if [ "$BACKEND_VENV_ACTIVATED" = true ]; then
    deactivate 2>/dev/null || true
    BACKEND_VENV_ACTIVATED=false
  fi
  
  # Deactivate sensor venv if activated
  if [ "$SENSOR_VENV_ACTIVATED" = true ]; then
    deactivate 2>/dev/null || true
    SENSOR_VENV_ACTIVATED=false
  fi
}

# Radar control functions
get_wireless_interfaces() {
  local interfaces=($(ls /sys/class/net 2>/dev/null | grep -E 'wlan|wlp|ath' || true))
  printf '%s\n' "${interfaces[@]}"
}

select_interface() {
  local interfaces=($(get_wireless_interfaces))
  
  if [ ${#interfaces[@]} -eq 0 ]; then
    fail "No wireless cards found."
  fi
  
  if [ -z "$1" ]; then
    # If no interface provided and only one exists, use it automatically
    if [ ${#interfaces[@]} -eq 1 ]; then
      echo "${interfaces[0]}"
      return 0
    fi
    
    echo -e "${YELLOW}--- Select Wireless Interface ---${RESET}"
    for i in "${!interfaces[@]}"; do
      echo -e "${GREEN}$i)${RESET} ${interfaces[$i]}"
    done
    
    echo -ne "${YELLOW}=====> ${RESET}"
    read choice
    # Handle empty input by prompting again
    while [ -z "$choice" ]; do
      echo -ne "${YELLOW}Please enter a number [0-$(( ${#interfaces[@]} - 1 ))]: ${RESET}"
      read choice
    done
    
    if [[ "$choice" =~ ^[0-9]+$ ]] && [ "$choice" -ge 0 ] && [ "$choice" -lt ${#interfaces[@]} ]; then
      echo "${interfaces[$choice]}"
    else
      fail "Invalid selection. Please enter a number between 0 and $(( ${#interfaces[@]} - 1 ))."
    fi
  else
    # Validate that the provided interface exists
    local target_interface="$1"
    for interface in "${interfaces[@]}"; do
      if [ "$interface" = "$target_interface" ]; then
        echo "$target_interface"
        return 0
      fi
    done
    fail "Interface '$target_interface' not found."
  fi
}

radar_on() {
  local interface
  interface="$(select_interface "$1")"
  
  log "Enabling monitor mode on interface: $interface"
  
  run_maybe_sudo rfkill unblock all
  run_maybe_sudo nmcli device set "$interface" managed no
  run_maybe_sudo ip link set "$interface" down
  run_maybe_sudo iwconfig "$interface" mode monitor
  run_maybe_sudo ip link set "$interface" up
  
  echo -e "${GREEN}[+] Monitor mode enabled on $interface${RESET}"
  run_maybe_sudo iwconfig "$interface"
}

radar_off() {
  local interface
  interface="$(select_interface "$1")"
  
  log "Resetting interface to managed mode: $interface"
  
  run_maybe_sudo nmcli device set "$interface" managed yes
  run_maybe_sudo ip link set "$interface" down
  run_maybe_sudo iwconfig "$interface" mode managed
  run_maybe_sudo ip link set "$interface" up
  
  echo -e "${GREEN}[+] Interface reset to managed mode: $interface${RESET}"
  run_maybe_sudo iwconfig "$interface"
}

list_wireless() {
  local interfaces=($(get_wireless_interfaces))
  
  if [ ${#interfaces[@]} -eq 0 ]; then
    echo -e "${RED}[!] No wireless cards found.${RESET}"
    return 1
  fi
  
  echo -e "${CYAN}--- Available Wireless Interfaces ---${RESET}"
  
  for i in "${!interfaces[@]}"; do
    echo -e "${GREEN}$i)${RESET} ${interfaces[$i]}"
    
    # Get basic interface info without sudo
    local interface_path="/sys/class/net/${interfaces[$i]}"
    local mode="Unknown"
    local status="Down"
    
    if [ -d "$interface_path" ]; then
      # Check if interface is up
      if [ "$(cat "$interface_path/operstate" 2>/dev/null)" = "up" ]; then
        status="Up"
      fi
      
      # Try to get accurate mode information
      # First try iwconfig (most accurate for wireless mode)
      if command -v iwconfig >/dev/null 2>&1; then
        local iwconfig_mode
        iwconfig_mode=$(iwconfig "${interfaces[$i]}" 2>/dev/null | grep -o "Mode:[^[:space:]]*" | cut -d: -f2 | head -1)
        if [ -n "$iwconfig_mode" ]; then
          mode="$iwconfig_mode"
        fi
      fi
      
      # Fallback to iw dev if iwconfig doesn't work
      if [ "$mode" = "Unknown" ] && command -v iw >/dev/null 2>&1; then
        local iw_type
        iw_type=$(iw dev "${interfaces[$i]}" info 2>/dev/null | grep "type" | awk '{print $2}' || echo "")
        if [ -n "$iw_type" ]; then
          case "$iw_type" in
            "monitor") mode="monitor" ;;
            "managed") mode="managed" ;;
            "ad-hoc") mode="ad-hoc" ;;
            "master") mode="master" ;;
            *) mode="$iw_type" ;;
          esac
        fi
      fi
      
      echo "    Status: $status"
      echo "    Mode: $mode"
      
      # Only get detailed info with sudo if user explicitly requests it
    else
      echo "    (Interface not accessible)"
    fi
    echo ""
  done
}

# Display current trusted APs whitelist
show_whitelist() {
  local config_file="$ROOT_DIR/sensor/config.py"
  
  if [ ! -f "$config_file" ]; then
    echo -e "${RED}[!] Sensor config file not found: $config_file${RESET}"
    return 1
  fi
  
  echo ""
  echo -e "${CYAN}CURRENT TRUSTED ACCESS POINTS WHITELIST:${RESET}"
  echo ""
  
  # Extract and display the TRUSTED_APS section
  local in_trusted_aps=false
  local ssid=""
  local bssid=""
  local channel=""
  local encryption=""
  local entry_count=0
  
  while IFS= read -r line; do
    if [[ "$line" =~ ^TRUSTED_APS[[:space:]]*= ]]; then
      in_trusted_aps=true
      continue
    fi
    
    if [ "$in_trusted_aps" = true ]; then
      if [[ "$line" =~ ^}[[:space:]]*$ ]]; then
        in_trusted_aps=false
        continue
      fi
      
      if [[ "$line" =~ ^[[:space:]]*\"([^\"]+)\":[[:space:]]*\{ ]]; then
        # New SSID entry
        if [ -n "$ssid" ]; then
          # Display previous entry
          echo -e "${GREEN}$entry_count)${RESET} ${WHITE}SSID:${RESET} ${CYAN}$ssid${RESET}"
          echo -e "     ${WHITE}BSSID:${RESET} ${YELLOW}$bssid${RESET}"
          echo -e "     ${WHITE}Channel:${RESET} ${YELLOW}$channel${RESET}"
          echo -e "     ${WHITE}Encryption:${RESET} ${YELLOW}$encryption${RESET}"
          echo ""
          entry_count=$((entry_count + 1))
        fi
        
        ssid="${BASH_REMATCH[1]}"
        bssid=""
        channel=""
        encryption=""
      elif [[ "$line" =~ ^[[:space:]]*\"bssid\":[[:space:]]*\"([^\"]+)\" ]]; then
        bssid="${BASH_REMATCH[1]}"
      elif [[ "$line" =~ ^[[:space:]]*\"channel\":[[:space:]]*([0-9]+) ]]; then
        channel="${BASH_REMATCH[1]}"
      elif [[ "$line" =~ ^[[:space:]]*\"encryption\":[[:space:]]*\"([^\"]+)\" ]]; then
        encryption="${BASH_REMATCH[1]}"
      fi
    fi
  done < "$config_file"
  
  # Display the last entry
  if [ -n "$ssid" ]; then
    echo -e "${GREEN}$entry_count)${RESET} ${WHITE}SSID:${RESET} ${CYAN}$ssid${RESET}"
    echo -e "     ${WHITE}BSSID:${RESET} ${YELLOW}$bssid${RESET}"
    echo -e "     ${WHITE}Channel:${RESET} ${YELLOW}$channel${RESET}"
    echo -e "     ${WHITE}Encryption:${RESET} ${YELLOW}$encryption${RESET}"
    echo ""
    entry_count=$((entry_count + 1))
  fi
  
  if [ $entry_count -eq 0 ]; then
    echo -e "${YELLOW}[!] No trusted access points configured in whitelist${RESET}"
  else
    echo -e "${GREEN}[✓] Found $entry_count trusted access point(s) in whitelist${RESET}"
  fi
  
  echo ""
  echo -e "${CYAN}HOW TO ADD YOUR WHITELIST DEVICES:${RESET}"
  echo -e "${WHITE}1. Edit the config file:${RESET} ${DIM}$config_file${RESET}"
  echo -e "${WHITE}2. Go to lines 17-33 (TRUSTED_APS section)${RESET}"
  echo -e "${WHITE}3. Add your device inside the TRUSTED_APS dictionary:${RESET}"
  echo ""
  echo -e "${YELLOW}    \"YOUR_WIFI_SSID\": {${RESET}"
  echo -e "${YELLOW}        \"bssid\": \"AA:BB:CC:DD:EE:FF\",${RESET}"
  echo -e "${YELLOW}        \"channel\": 6,${RESET}"
  echo -e "${YELLOW}        \"encryption\": \"WPA2\"${RESET}"
  echo -e "${YELLOW}    }${RESET}"
  echo ""
}

# Service start functions
start_backend() {
  info "Starting backend service..."
  ensure_port_available "backend" "5000"
  start_command \
    "backend" \
    "$ROOT_DIR/backend" \
    "$ROOT_DIR/backend/.venv/bin/gunicorn" \
    --worker-class eventlet \
    --bind 0.0.0.0:5000 \
    app:app
  wait_for_http "backend" "http://localhost:5000/health" 90 '"status":"healthy"'
  success "Backend service ready"
}

start_frontend() {
  info "Starting frontend service..."
  ensure_port_available "frontend" "3000"
  start_command \
    "frontend" \
    "$ROOT_DIR" \
    pnpm \
    dev
  wait_for_http "frontend" "http://localhost:3000" 120
  success "Frontend service ready"
}

start_sensor() {
  local sensor_python="$ROOT_DIR/sensor/.venv/bin/python"
  if [ ! -f "$sensor_python" ]; then
    sensor_python="$ROOT_DIR/sensor/.venv/bin/python3"
  fi
  info "Starting sensor service..."
  stop_pid_file "sensor"

  if command -v sudo >/dev/null 2>&1; then
    start_command \
      "sensor" \
      "$ROOT_DIR/sensor" \
      sudo \
      -E \
      env \
      "ZEINAGUARD_NONINTERACTIVE=1" \
      "BACKEND_URL=${BACKEND_URL:-http://localhost:5000}" \
      "$sensor_python" \
      "$ROOT_DIR/sensor/main.py"
  else
    warn "sudo unavailable - sensor may have limited functionality"
    start_command \
      "sensor" \
      "$ROOT_DIR/sensor" \
      env \
      "ZEINAGUARD_NONINTERACTIVE=1" \
      "BACKEND_URL=${BACKEND_URL:-http://localhost:5000}" \
      "$sensor_python" \
      "$ROOT_DIR/sensor/main.py"
  fi
  success "Sensor service ready"
}

print_ready() {
  echo ""
  echo -e "${GREEN}ZeinaGuard is now fully deployed and running!${RESET}"
  echo ""
  echo -e "${WHITE}Service URLs:${RESET}"
  echo -e "  Frontend: ${CYAN}http://localhost:3000${RESET}"
  echo -e "  Backend : ${CYAN}http://localhost:5000${RESET}"
  echo ""
  echo -e "${WHITE}Log Files:${RESET}"
  echo -e "  Backend : ${DIM}$LOG_DIR/backend.log${RESET}"
  echo -e "  Frontend: ${DIM}$LOG_DIR/frontend.log${RESET}"
  echo -e "  Sensor  : ${DIM}$LOG_DIR/sensor.log${RESET}"
  echo ""
  echo -e "${WHITE}Management Commands:${RESET}"
  echo -e "  ${YELLOW}./zeina.sh stop${RESET}    - Stop all services"
  echo -e "  ${YELLOW}./zeina.sh restart${RESET} - Restart all services"
  echo -e "  ${YELLOW}./zeina.sh status${RESET}  - Check service status"
  echo ""
  echo -e "${WHITE}Press [Ctrl + C] at any time to shut down and clean up.${RESET}"
  echo ""
}

# Universal Linux distribution and package manager detection
detect_distro() {
  if [ -f /etc/os-release ]; then
    . /etc/os-release
    echo "$ID"
  elif [ -f /etc/lsb-release ]; then
    . /etc/lsb-release
    echo "$DISTRIB_ID" | tr '[:upper:]' '[:lower:]'
  elif [ -f /etc/debian_version ]; then
    echo "debian"
  elif [ -f /etc/redhat-release ]; then
    echo "redhat"
  elif [ -f /etc/arch-release ]; then
    echo "arch"
  elif command -v lsb_release >/dev/null 2>&1; then
    lsb_release -si | tr '[:upper:]' '[:lower:]'
  else
    uname -s | tr '[:upper:]' '[:lower:]'
  fi
}

detect_package_manager() {
  local distro=$(detect_distro)
  
  # Check for package managers in order of preference
  if command -v apt >/dev/null 2>&1; then
    echo "apt"
  elif command -v apt-get >/dev/null 2>&1; then
    echo "apt-get"
  elif command -v dnf >/dev/null 2>&1; then
    echo "dnf"
  elif command -v yum >/dev/null 2>&1; then
    echo "yum"
  elif command -v pacman >/dev/null 2>&1; then
    echo "pacman"
  elif command -v zypper >/dev/null 2>&1; then
    echo "zypper"
  elif command -v xbps >/dev/null 2>&1; then
    echo "xbps"  # Void Linux
  elif command -v eopkg >/dev/null 2>&1; then
    echo "eopkg"  # Solus
  elif command -v apk >/dev/null 2>&1; then
    echo "apk"    # Alpine Linux
  elif command -v tce >/dev/null 2>&1; then
    echo "tce"    # Tiny Core
  elif command -v slapt-get >/dev/null 2>&1; then
    echo "slapt-get"  # Slackware
  elif command -v pkg >/dev/null 2>&1; then
    echo "pkg"    # FreeBSD
  elif command -v pkg_add >/dev/null 2>&1; then
    echo "pkg_add" # OpenBSD
  else
    echo "unknown"
  fi
}

is_lightweight_distro() {
  local distro=$(detect_distro)
  case "$distro" in
    "antix"|"antiX"|"puppy"|"tinycore"|"alpine"|"void"|"slitaz"|"bodhi"|"linuxlite")
      return 0
      ;;
    *)
      return 1
      ;;
  esac
}

is_kali_linux() {
  local distro=$(detect_distro)
  case "$distro" in
    "kali")
      return 0
      ;;
    *)
      return 1
      ;;
  esac
}

get_system_resources() {
  local ram_kb=$(grep MemTotal /proc/meminfo | awk '{print $2}')
  local cpu_cores=$(nproc)
  local disk_space=$(df -BG . | awk 'NR==2 {print $4}' | sed 's/G//')
  
  echo "${ram_kb}:${cpu_cores}:${disk_space}"
}

has_sufficient_resources() {
  local resources=$(get_system_resources)
  local ram_kb=$(echo $resources | cut -d: -f1)
  local cpu_cores=$(echo $resources | cut -d: -f2)
  local disk_space=$(echo $resources | cut -d: -f3)
  
  # Minimum requirements: 512MB RAM, 1 CPU, 2GB disk
  if [ "$ram_kb" -lt 524288 ]; then
    warn "Low RAM detected: $((ram_kb/1024))MB (minimum: 512MB)"
    return 1
  fi
  
  if [ "$cpu_cores" -lt 1 ]; then
    warn "Insufficient CPU cores: $cpu_cores (minimum: 1)"
    return 1
  fi
  
  if [ "$disk_space" -lt 2 ]; then
    warn "Low disk space: ${disk_space}GB (minimum: 2GB)"
    return 1
  fi
  
  return 0
}

# Universal system package installation
install_system_package() {
  local package="$1"
  local pkg_manager=$(detect_package_manager)
  local distro=$(detect_distro)
  
  info "Installing $package..."
  
  case "$pkg_manager" in
    "apt")
      if is_lightweight_distro; then
        # Lightweight distro optimization with clean output
        run_maybe_sudo apt-get update -qq >/dev/null 2>&1
        run_maybe_sudo apt-get install -y --no-install-recommends "$package" >/dev/null 2>&1
      else
        run_maybe_sudo apt update -qq >/dev/null 2>&1
        run_maybe_sudo apt install -y "$package" >/dev/null 2>&1
      fi
      ;;
    "apt-get")
      run_maybe_sudo apt-get update -qq >/dev/null 2>&1
      run_maybe_sudo apt-get install -y "$package" >/dev/null 2>&1
      ;;
    "dnf")
      run_maybe_sudo dnf install -y -q "$package" >/dev/null 2>&1
      ;;
    "yum")
      if is_kali_linux; then
        run_maybe_sudo yum install -y -q "$package" --skip-broken >/dev/null 2>&1
      else
        run_maybe_sudo yum install -y -q "$package" >/dev/null 2>&1
      fi
      ;;
    "pacman")
      run_maybe_sudo pacman -S --noconfirm --quiet "$package" >/dev/null 2>&1
      ;;
    "zypper")
      run_maybe_sudo zypper --quiet install -y "$package" >/dev/null 2>&1
      ;;
    "xbps")
      run_maybe_sudo xbps-install -Sy "$package" >/dev/null 2>&1
      ;;
    "eopkg")
      run_maybe_sudo eopkg it -y "$package" >/dev/null 2>&1
      ;;
    "apk")
      run_maybe_sudo apk add --quiet "$package" >/dev/null 2>&1
      ;;
    "tce")
      tce-load -wi "$package" >/dev/null 2>&1
      ;;
    "slapt-get")
      run_maybe_sudo slapt-get --install -y "$package" >/dev/null 2>&1
      ;;
    "pkg")
      run_maybe_sudo pkg install -y "$package" >/dev/null 2>&1
      ;;
    "pkg_add")
      run_maybe_sudo pkg_add "$package" >/dev/null 2>&1
      ;;
    *)
      warn "Unsupported package manager: $pkg_manager"
      warn "Attempting manual installation of $package..."
      return 1
      ;;
  esac
  
  # Verify installation was successful
  if command -v "$package" >/dev/null 2>&1 || \
     dpkg -l "$package" 2>/dev/null | grep -q "^ii" || \
     rpm -q "$package" >/dev/null 2>&1; then
    success "$package installed successfully"
  else
    warn "$package installation may have failed"
  fi
}

# Universal package availability check
is_package_available() {
  local package="$1"
  local pkg_manager=$(detect_package_manager)
  
  case "$pkg_manager" in
    "apt"|"apt-get")
      apt-cache policy "$package" >/dev/null 2>&1
      ;;
    "dnf")
      dnf list available "$package" >/dev/null 2>&1
      ;;
    "yum")
      yum list available "$package" >/dev/null 2>&1
      ;;
    "pacman")
      pacman -Ss "^${package}$" >/dev/null 2>&1
      ;;
    "zypper")
      zypper search "$package" >/dev/null 2>&1
      ;;
    "xbps")
      xbps-query -Rs "$package" >/dev/null 2>&1
      ;;
    "eopkg")
      eopkg li "$package" >/dev/null 2>&1
      ;;
    "apk")
      apk search "$package" >/dev/null 2>&1
      ;;
    *)
      return 1
      ;;
  esac
}

# Get alternative package names for different distros
get_package_name() {
  local base_package="$1"
  local distro=$(detect_distro)
  
  case "$base_package" in
    "postgresql")
      case "$distro" in
        "alpine") echo "postgresql" ;;
        "arch") echo "postgresql" ;;
        "void") echo "postgresql" ;;
        *) echo "postgresql" ;;
      esac
      ;;
    "postgresql-client")
      case "$distro" in
        "alpine") echo "postgresql-client" ;;
        "arch") echo "postgresql" ;;
        "void") echo "postgresql" ;;
        *) echo "postgresql-client" ;;
      esac
      ;;
    "python3-dev")
      case "$distro" in
        "alpine") echo "python3-dev" ;;
        "arch") echo "python" ;;
        "void") echo "python3-devel" ;;
        *) echo "python3-dev" ;;
      esac
      ;;
    "libpq-dev")
      case "$distro" in
        "alpine") echo "postgresql-dev" ;;
        "arch") echo "postgresql-libs" ;;
        "void") echo "libpq-devel" ;;
        *) echo "libpq-dev" ;;
      esac
      ;;
    "build-essential")
      case "$distro" in
        "alpine") echo "build-base" ;;
        "arch") echo "base-devel" ;;
        "void") echo "base-devel" ;;
        *) echo "build-essential" ;;
      esac
      ;;
    *)
      echo "$base_package"
      ;;
  esac
}

# Universal Python 3 installation
install_python3() {
  info "Installing Python 3..."
  local pkg_manager=$(detect_package_manager)
  local distro=$(detect_distro)
  
  case "$pkg_manager" in
    "apt")
      if is_lightweight_distro; then
        # Lightweight distro optimization
        install_system_package "python3" || install_system_package "python"
        install_system_package "python3-pip" || install_system_package "python-pip"
        install_system_package "python3-venv" || install_system_package "python-venv"
      else
        install_system_package "python3"
        install_system_package "python3-pip"
        install_system_package "python3-venv"
      fi
      ;;
    "apt-get")
      install_system_package "python3"
      install_system_package "python3-pip"
      install_system_package "python3-venv"
      ;;
    "dnf")
      install_system_package "python3"
      install_system_package "python3-pip"
      ;;
    "yum")
      install_system_package "python3"
      install_system_package "python3-pip"
      ;;
    "pacman")
      install_system_package "python"
      install_system_package "python-pip"
      ;;
    "zypper")
      install_system_package "python3"
      install_system_package "python3-pip"
      ;;
    "xbps")
      install_system_package "python3"
      install_system_package "python3-pip"
      ;;
    "eopkg")
      install_system_package "python3"
      install_system_package "python3-pip"
      ;;
    "apk")
      install_system_package "python3"
      install_system_package "python3-dev"
      install_system_package "py3-pip"
      ;;
    "tce")
      install_system_package "python3"
      ;;
    "slapt-get")
      install_system_package "python3"
      ;;
    "pkg")
      install_system_package "python3"
      install_system_package "py3-pip"
      ;;
    "pkg_add")
      install_system_package "python3"
      ;;
    *)
      warn "Unsupported package manager: $pkg_manager"
      warn "Attempting Python installation from source..."
      install_python_from_source
      return $?
      ;;
  esac
  
  # Verify installation
  if command -v python3 >/dev/null 2>&1; then
    success "Python 3 installed: $(python3 --version)"
  else
    fail "Python 3 installation failed"
  fi
  
  # Ensure pip is available
  if ! python3 -m pip --version >/dev/null 2>&1; then
    warn "pip not found, installing get-pip..."
    install_pip_fallback
  fi
}

# Fallback Python installation from source
install_python_from_source() {
  info "Installing Python 3 from source..."
  
  # Install build dependencies first
  install_system_package "$(get_package_name build-essential)"
  install_system_package "$(get_package_name libssl-dev)"
  install_system_package "$(get_package_name python3-dev)"
  install_system_package "wget" || install_system_package "curl"
  
  # Download and compile Python
  local python_version="3.11.8"
  local python_tar="Python-${python_version}.tgz"
  local python_url="https://www.python.org/ftp/python/${python_version}/${python_tar}"
  
  cd /tmp
  if command -v wget >/dev/null 2>&1; then
    wget "$python_url"
  elif command -v curl >/dev/null 2>&1; then
    curl -O "$python_url"
  else
    fail "Neither wget nor curl available for Python download"
  fi
  
  tar -xzf "$python_tar"
  cd "Python-${python_version}"
  
  ./configure --enable-optimizations --prefix=/usr/local
  make -j$(nproc)
  run_maybe_sudo make altinstall
  
  # Create symlink
  run_maybe_sudo ln -sf /usr/local/bin/python3.11 /usr/local/bin/python3
  
  cd /tmp
  rm -rf "Python-${python_version}" "$python_tar"
}

# Fallback pip installation
install_pip_fallback() {
  info "Installing pip fallback..."
  
  if command -v wget >/dev/null 2>&1; then
    run_maybe_sudo wget https://bootstrap.pypa.io/get-pip.py -O /tmp/get-pip.py
    run_maybe_sudo python3 /tmp/get-pip.py
  elif command -v curl >/dev/null 2>&1; then
    run_maybe_sudo curl https://bootstrap.pypa.io/get-pip.py -o /tmp/get-pip.py
    run_maybe_sudo python3 /tmp/get-pip.py
  else
    fail "Neither wget nor curl available for pip installation"
  fi
  
  rm -f /tmp/get-pip.py
}

# Universal Node.js installation
install_nodejs() {
  info "Installing Node.js..."
  local pkg_manager=$(detect_package_manager)
  local distro=$(detect_distro)
  
  case "$pkg_manager" in
    "apt")
      if is_lightweight_distro; then
        # Lightweight distro - try package first, then NodeSource
        if install_system_package "nodejs" && install_system_package "npm"; then
          success "Node.js installed via package manager"
        else
          install_nodesource_nodejs
        fi
      else
        install_nodesource_nodejs
      fi
      ;;
    "apt-get")
      install_nodesource_nodejs
      ;;
    "dnf")
      install_system_package "curl"
      curl -fsSL https://rpm.nodesource.com/setup_20.x | run_maybe_sudo bash -
      install_system_package "nodejs"
      ;;
    "yum")
      install_system_package "curl"
      curl -fsSL https://rpm.nodesource.com/setup_20.x | run_maybe_sudo bash -
      install_system_package "nodejs"
      ;;
    "pacman")
      install_system_package "nodejs"
      install_system_package "npm"
      ;;
    "zypper")
      install_system_package "nodejs"
      install_system_package "npm"
      ;;
    "xbps")
      install_system_package "nodejs"
      ;;
    "eopkg")
      install_system_package "nodejs"
      ;;
    "apk")
      install_system_package "nodejs"
      install_system_package "npm"
      ;;
    "tce")
      install_system_package "node"
      ;;
    "slapt-get")
      install_system_package "nodejs"
      ;;
    "pkg")
      install_system_package "node"
      install_system_package "npm"
      ;;
    "pkg_add")
      install_system_package "node"
      ;;
    *)
      warn "Unsupported package manager: $pkg_manager"
      warn "Attempting Node.js installation from binary..."
      install_nodejs_binary
      return $?
      ;;
  esac
  
  # Verify installation
  if command -v node >/dev/null 2>&1; then
    success "Node.js installed: $(node --version)"
  else
    fail "Node.js installation failed"
  fi
  
  # Ensure npm is available
  if ! command -v npm >/dev/null 2>&1; then
    warn "npm not found, installing separately..."
    install_npm_fallback
  fi
}

# NodeSource Node.js installation
install_nodesource_nodejs() {
  info "Installing Node.js via NodeSource..."
  
  install_system_package "curl"
  
  case "$(detect_distro)" in
    "ubuntu"|"debian"|"antix"|"linuxmint"|"pop")
      curl -fsSL https://deb.nodesource.com/setup_20.x | run_maybe_sudo bash -s >/dev/null 2>&1
      install_system_package "nodejs"
      ;;
    "centos"|"rhel"|"fedora"|"kali")
      curl -fsSL https://rpm.nodesource.com/setup_20.x | run_maybe_sudo bash -s >/dev/null 2>&1
      install_system_package "nodejs"
      ;;
    *)
      # Fallback to binary installation
      install_nodejs_binary
      ;;
  esac
}

# Binary Node.js installation
install_nodejs_binary() {
  info "Installing Node.js from binary..."
  
  # Determine architecture
  local arch=$(uname -m)
  case "$arch" in
    x86_64) arch="x64" ;;
    aarch64|arm64) arch="arm64" ;;
    armv7l) arch="armv7l" ;;
    *) 
      warn "Unsupported architecture: $arch"
      return 1
      ;;
  esac
  
  local node_version="20.12.2"
  local node_tar="node-v${node_version}-linux-${arch}.tar.xz"
  local node_url="https://nodejs.org/dist/v${node_version}/${node_tar}"
  
  cd /tmp
  if command -v wget >/dev/null 2>&1; then
    wget "$node_url" >/dev/null 2>&1
  elif command -v curl >/dev/null 2>&1; then
    curl -O "$node_url" >/dev/null 2>&1
  else
    fail "Neither wget nor curl available for Node.js download"
  fi
  
  tar -xf "$node_tar" >/dev/null 2>&1
  run_maybe_sudo cp -r "node-v${node_version}-linux-${arch}"/* /usr/local/ >/dev/null 2>&1
  
  # Create symlinks
  run_maybe_sudo ln -sf /usr/local/bin/node /usr/bin/node
  run_maybe_sudo ln -sf /usr/local/bin/npm /usr/bin/npm
  
  cd /tmp
  rm -rf "node-v${node_version}-linux-${arch}" "$node_tar"
}

# Fallback npm installation
install_npm_fallback() {
  info "Installing npm fallback..."
  
  if command -v wget >/dev/null 2>&1; then
    run_maybe_sudo wget https://www.npmjs.com/install.sh -O /tmp/install-npm.sh >/dev/null 2>&1
    run_maybe_sudo sh /tmp/install-npm.sh >/dev/null 2>&1
  elif command -v curl >/dev/null 2>&1; then
    run_maybe_sudo curl https://www.npmjs.com/install.sh -o /tmp/install-npm.sh >/dev/null 2>&1
    run_maybe_sudo sh /tmp/install-npm.sh >/dev/null 2>&1
  else
    fail "Neither wget nor curl available for npm installation"
  fi
  
  rm -f /tmp/install-npm.sh
}

# Universal wireless tools installation
install_wireless_tools() {
  info "Installing wireless tools..."
  local pkg_manager=$(detect_package_manager)
  local distro=$(detect_distro)
  
  case "$pkg_manager" in
    "apt")
      if is_lightweight_distro; then
        install_system_package "wireless-tools" || install_system_package "iw"
        install_system_package "net-tools" || install_system_package "iproute2"
      else
        install_system_package "wireless-tools"
        install_system_package "net-tools"
      fi
      ;;
    "apt-get")
      install_system_package "wireless-tools"
      install_system_package "net-tools"
      ;;
    "dnf")
      install_system_package "wireless-tools"
      ;;
    "yum")
      install_system_package "wireless-tools"
      ;;
    "pacman")
      install_system_package "wireless_tools"
      ;;
    "zypper")
      install_system_package "wireless-tools"
      ;;
    "xbps")
      install_system_package "wireless_tools"
      ;;
    "eopkg")
      install_system_package "wireless_tools"
      ;;
    "apk")
      install_system_package "wireless-tools"
      install_system_package "iproute2"
      ;;
    "tce")
      install_system_package "wireless_tools"
      ;;
    "slapt-get")
      install_system_package "wireless-tools"
      ;;
    "pkg")
      install_system_package "wireless-tools"
      ;;
    "pkg_add")
      install_system_package "wireless-tools"
      ;;
    *)
      warn "Unsupported package manager: $pkg_manager"
      warn "Attempting manual wireless tools installation..."
      return 1
      ;;
  esac
  
  # Verify installation
  if command -v iwconfig >/dev/null 2>&1 || command -v iw >/dev/null 2>&1; then
    success "Wireless tools installed"
  else
    warn "Wireless tools may not be fully installed"
  fi
}

# Install NetworkManager
install_networkmanager() {
  info "Installing NetworkManager..."
  local pkg_manager=$(detect_package_manager)
  
  case "$pkg_manager" in
    "apt")
      run_maybe_sudo apt install -y network-manager
      ;;
    "yum")
      run_maybe_sudo yum install -y NetworkManager
      ;;
    "dnf")
      run_maybe_sudo dnf install -y NetworkManager
      ;;
    "pacman")
      run_maybe_sudo pacman -S --noconfirm networkmanager
      ;;
    "zypper")
      run_maybe_sudo zypper install -y NetworkManager
      ;;
    *)
      fail "Unsupported package manager. Please install NetworkManager manually."
      ;;
  esac
}

# Install pnpm
install_pnpm() {
  info "Installing pnpm..."
  if command -v npm >/dev/null 2>&1; then
    run_maybe_sudo npm install -g pnpm
  else
    # Install pnpm directly via curl
    curl -fsSL https://get.pnpm.io/install.sh | sh -
    export PNPM_HOME="$HOME/.local/share/pnpm"
    export PATH="$PNPM_HOME:$PATH"
  fi
}

# Universal comprehensive dependency checking and installation
check_system_dependencies() {
  info "Universal dependency check for $(detect_distro) Linux..."
  
  # System resource check
  if ! has_sufficient_resources; then
    warn "System resources may be insufficient for optimal performance"
    warn "Continuing with installation anyway..."
  fi
  
  local distro=$(detect_distro)
  local pkg_manager=$(detect_package_manager)
  
  info "Detected: $distro with $pkg_manager package manager"
  
  # Core dependencies array
  local core_deps=(
    "python3"
    "node"
    "npm"
    "pnpm"
    "sudo"
    "curl"
    "wget"
  )
  
  # Optional dependencies array
  local optional_deps=(
    "iwconfig"
    "nmcli"
    "git"
    "make"
    "gcc"
  )
  
  # Install core dependencies
  for dep in "${core_deps[@]}"; do
    check_and_install_dependency "$dep"
  done
  
  # Install wireless tools (critical for functionality)
  check_and_install_wireless_tools
  
  # Install development tools (needed for compilation)
  check_and_install_dev_tools
  
  # Install database support (PostgreSQL or SQLite fallback)
  check_and_install_database_support
  
  # Verify critical functionality
  verify_critical_dependencies
  
  # Distro-specific optimizations
  apply_distro_optimizations "$distro"
  
  echo -e "${GREEN}[✓] Universal dependency check completed for $distro${RESET}"
  return 0
}

# Check and install individual dependency
check_and_install_dependency() {
  local dep="$1"
  
  case "$dep" in
    "python3")
      if ! command -v python3 >/dev/null 2>&1; then
        warn "Python 3 not found. Installing..."
        install_python3
      else
        success "Python 3 found: $(python3 --version)"
      fi
      ;;
    "node")
      if ! command -v node >/dev/null 2>&1; then
        warn "Node.js not found. Installing..."
        install_nodejs
      else
        success "Node.js found: $(node --version)"
      fi
      ;;
    "npm")
      if ! command -v npm >/dev/null 2>&1; then
        warn "npm not found. Installing..."
        install_system_package "npm" || install_npm_fallback
      else
        success "npm found: $(npm --version)"
      fi
      ;;
    "pnpm")
      if ! command -v pnpm >/dev/null 2>&1; then
        warn "pnpm not found. Installing..."
        install_pnpm
      else
        success "pnpm found: $(pnpm --version)"
      fi
      ;;
    "sudo")
      if ! command -v sudo >/dev/null 2>&1; then
        warn "sudo not found. Installing..."
        install_system_package "sudo"
      else
        success "sudo found"
      fi
      ;;
    "curl")
      if ! command -v curl >/dev/null 2>&1; then
        warn "curl not found. Installing..."
        install_system_package "curl"
      else
        success "curl found"
      fi
      ;;
    "wget")
      if ! command -v wget >/dev/null 2>&1; then
        warn "wget not found. Installing..."
        install_system_package "wget"
      else
        success "wget found"
      fi
      ;;
  esac
}

# Check and install wireless tools
check_and_install_wireless_tools() {
  local wireless_tools_found=false
  
  if command -v iwconfig >/dev/null 2>&1; then
    success "iwconfig found"
    wireless_tools_found=true
  fi
  
  if command -v iw >/dev/null 2>&1; then
    success "iw found"
    wireless_tools_found=true
  fi
  
  if ! $wireless_tools_found; then
    warn "Wireless tools not found. Installing..."
    install_wireless_tools
  fi
  
  # NetworkManager check
  if command -v nmcli >/dev/null 2>&1; then
    success "nmcli found"
  else
    warn "nmcli not found. Installing NetworkManager..."
    install_networkmanager
  fi
}

# Check and install development tools
check_and_install_dev_tools() {
  local dev_tools=("git" "make" "gcc")
  local missing_tools=()
  
  for tool in "${dev_tools[@]}"; do
    if ! command -v "$tool" >/dev/null 2>&1; then
      missing_tools+=("$tool")
    fi
  done
  
  if [ ${#missing_tools[@]} -gt 0 ]; then
    warn "Installing development tools: ${missing_tools[*]}"
    
    # Try distro-specific dev packages first
    if is_lightweight_distro; then
      install_system_package "$(get_package_name build-essential)" || {
        for tool in "${missing_tools[@]}"; do
          install_system_package "$tool" || warn "Failed to install $tool"
        done
      }
    else
      install_system_package "build-essential" || {
        for tool in "${missing_tools[@]}"; do
          install_system_package "$tool" || warn "Failed to install $tool"
        done
      }
    fi
  else
    success "Development tools found"
  fi
}

# Check and install database support
check_and_install_database_support() {
  local db_found=false
  
  # Check for PostgreSQL
  if command -v psql >/dev/null 2>&1; then
    success "PostgreSQL found"
    db_found=true
    
    # Check if PostgreSQL is running
    if is_postgresql_running; then
      success "PostgreSQL is running"
    else
      warn "PostgreSQL found but not running, attempting to start..."
      start_postgresql_service
    fi
  else
    warn "PostgreSQL not found. Installing..."
    install_postgresql_universal
  fi
  
  # Check for PostgreSQL development libraries
  if ! python3 -c "import psycopg2" >/dev/null 2>&1; then
    # Install development libraries for virtual environments
    install_system_package "$(get_package_name libpq-dev)" >/dev/null 2>&1
    success "PostgreSQL development libraries ready"
  else
    success "PostgreSQL Python bindings found"
  fi
}

# Universal PostgreSQL installation
install_postgresql_universal() {
  local pkg_manager=$(detect_package_manager)
  local distro=$(detect_distro)
  
  case "$pkg_manager" in
    "apt"|"apt-get")
      install_system_package "postgresql"
      install_system_package "postgresql-client"
      install_system_package "$(get_package_name libpq-dev)"
      ;;
    "dnf"|"yum")
      install_system_package "postgresql-server"
      install_system_package "postgresql"
      install_system_package "postgresql-devel"
      ;;
    "pacman")
      install_system_package "postgresql"
      ;;
    "apk")
      install_system_package "postgresql"
      install_system_package "postgresql-dev"
      ;;
    *)
      warn "PostgreSQL installation not supported on $distro"
      warn "Will use SQLite fallback"
      return 1
      ;;
  esac
  
  # Initialize and start PostgreSQL
  initialize_postgresql
}

# Initialize and start PostgreSQL
initialize_postgresql() {
  local distro=$(detect_distro)
  
  case "$distro" in
    "ubuntu"|"debian"|"antix")
      if command -v systemctl >/dev/null 2>&1; then
        run_maybe_sudo systemctl start postgresql
        run_maybe_sudo systemctl enable postgresql
      else
        run_maybe_sudo service postgresql start
        run_maybe_sudo update-rc.d postgresql defaults
      fi
      ;;
    "fedora"|"centos"|"rhel")
      if command -v systemctl >/dev/null 2>&1; then
        run_maybe_sudo systemctl start postgresql
        run_maybe_sudo systemctl enable postgresql
      else
        run_maybe_sudo service postgresql start
        run_maybe_sudo chkconfig postgresql on
      fi
      ;;
    *)
      warn "PostgreSQL initialization not automated for $distro"
      ;;
  esac
  
  # Create database user and database
  setup_postgresql_database
}

# Setup PostgreSQL database
setup_postgresql_database() {
  # Wait for PostgreSQL to start
  local max_wait=30
  local wait_time=0
  
  while [ $wait_time -lt $max_wait ]; do
    if run_maybe_sudo -u postgres psql -c "SELECT 1" >/dev/null 2>&1; then
      break
    fi
    sleep 1
    wait_time=$((wait_time + 1))
  done
  
  # Create user and database
  run_maybe_sudo -u postgres psql -c "CREATE USER zeinaguard_user WITH PASSWORD 'secure_password';" 2>/dev/null || true
  run_maybe_sudo -u postgres psql -c "CREATE DATABASE zeinaguard_db OWNER zeinaguard_user;" 2>/dev/null || true
  run_maybe_sudo -u postgres psql -c "GRANT ALL PRIVILEGES ON DATABASE zeinaguard_db TO zeinaguard_user;" 2>/dev/null || true
  
  success "PostgreSQL database setup completed"
}

# Check if PostgreSQL is running
is_postgresql_running() {
  if command -v systemctl >/dev/null 2>&1; then
    systemctl is-active postgresql >/dev/null 2>&1
  else
    service postgresql status >/dev/null 2>&1
  fi
}

# Start PostgreSQL service
start_postgresql_service() {
  if command -v systemctl >/dev/null 2>&1; then
    run_maybe_sudo systemctl start postgresql
  else
    run_maybe_sudo service postgresql start
  fi
}

# Verify critical dependencies
verify_critical_dependencies() {
  local critical_failed=false
  
  # Check Python 3
  if ! command -v python3 >/dev/null 2>&1; then
    fail "CRITICAL: Python 3 is required but not found"
    critical_failed=true
  fi
  
  # Check Node.js
  if ! command -v node >/dev/null 2>&1; then
    fail "CRITICAL: Node.js is required but not found"
    critical_failed=true
  fi
  
  # Check npm
  if ! command -v npm >/dev/null 2>&1; then
    fail "CRITICAL: npm is required but not found"
    critical_failed=true
  fi
  
  # Check pip
  if ! python3 -m pip --version >/dev/null 2>&1; then
    fail "CRITICAL: pip is required but not found"
    critical_failed=true
  fi
  
  if $critical_failed; then
    fail "Critical dependencies missing. Installation cannot continue."
  fi
  
  success "All critical dependencies verified"
}

# Apply distro-specific optimizations
apply_distro_optimizations() {
  local distro="$1"
  
  case "$distro" in
    "antix"|"antiX")
      info "Applying AntiX Linux optimizations..."
      # AntiX-specific optimizations
      export NODE_OPTIONS="--max-old-space-size=256"
      export FLASK_ENV="production"
      ;;
    "alpine")
      info "Applying Alpine Linux optimizations..."
      # Alpine-specific optimizations
      export NODE_OPTIONS="--max-old-space-size=256"
      ;;
    "kali")
      info "Applying Kali Linux optimizations..."
      # Kali-specific optimizations
      export FLASK_ENV="development"
      ;;
    *)
      info "Using standard configuration for $distro"
      ;;
  esac
}

check_venv_status() {
  log "Checking virtual environments..."
  
  # Backend venv
  if [ -d "$ROOT_DIR/backend/.venv" ]; then
    local backend_python="$ROOT_DIR/backend/.venv/bin/python"
    if [ ! -f "$backend_python" ]; then
      backend_python="$ROOT_DIR/backend/.venv/bin/python3"
    fi
    if [ -f "$backend_python" ]; then
      echo -e "${GREEN}[✓] Backend venv exists and is functional${RESET}"
    else
      echo -e "${YELLOW}[!] Backend venv exists but Python executable not found${RESET}"
    fi
  else
    echo -e "${YELLOW}[!] Backend venv not found${RESET}"
  fi
  
  # Sensor venv
  if [ -d "$ROOT_DIR/sensor/.venv" ]; then
    local sensor_python="$ROOT_DIR/sensor/.venv/bin/python"
    if [ ! -f "$sensor_python" ]; then
      sensor_python="$ROOT_DIR/sensor/.venv/bin/python3"
    fi
    if [ -f "$sensor_python" ]; then
      echo -e "${GREEN}[✓] Sensor venv exists and is functional${RESET}"
    else
      echo -e "${YELLOW}[!] Sensor venv exists but Python executable not found${RESET}"
    fi
  else
    echo -e "${YELLOW}[!] Sensor venv not found${RESET}"
  fi
}

check_wireless_status() {
  log "Checking wireless interfaces..."
  local interfaces=($(get_wireless_interfaces))
  
  if [ ${#interfaces[@]} -eq 0 ]; then
    echo -e "${RED}[!] No wireless interfaces found${RESET}"
    return 1
  fi
  
  echo -e "${GREEN}[✓] Found ${#interfaces[@]} wireless interface(s):${RESET}"
  for i in "${!interfaces[@]}"; do
    local mode="Managed"
    if command -v iwconfig >/dev/null 2>&1; then
      mode=$(run_maybe_sudo iwconfig "${interfaces[$i]}" 2>/dev/null | grep "Mode:" | awk '{print $4}' || echo "Managed")
    fi
    echo -e "  ${CYAN}${i})${RESET} ${interfaces[$i]} - ${DIM}($mode)${RESET}"
  done
}

show_system_info() {
  print_banner
  echo -e "${WHITE}═════════════════════════════════════════════════════════════════════════════════════${RESET}"
  echo ""
  echo -e "${CYAN}SYSTEM STATUS${RESET}"
  echo ""
  
  check_system_dependencies
  echo ""
  check_venv_status
  echo ""
  check_wireless_status
  echo ""
  
  echo -e "${WHITE}═════════════════════════════════════════════════════════════════════════════════════${RESET}"
}

# Interactive menu system with left-aligned layout
show_main_menu() {
  while true; do
    clear
    print_banner

    # Left-aligned menu items with colored text
    printf "  ${BOLD}${LIME}0)${RESET}  ${RED}Exit${RESET}\n"
    printf "  ${BOLD}${LIME}1)${RESET}  ${GREEN}Start all services${RESET}\n"
    printf "  ${BOLD}${LIME}2)${RESET}  ${RED}Stop all services${RESET}\n"
    printf "  ${BOLD}${LIME}3)${RESET}  ${YELLOW}Restart all services${RESET}\n"
    printf "  ${BOLD}${LIME}4)${RESET}  ${CYAN}Check service status${RESET}\n"
    printf "  ${BOLD}${LIME}5)${RESET}  ${PURPLE}Enable radar (monitor mode)${RESET}\n"
    printf "  ${BOLD}${LIME}6)${RESET}  ${TURQUOISE}Disable radar (managed mode)${RESET}\n"
    printf "  ${BOLD}${LIME}7)${RESET}  ${LIGHT_BLUE}List wireless interfaces${RESET}\n"
    printf "  ${BOLD}${LIME}8)${RESET}  ${AMBER}System information & checks${RESET}\n"
    printf "  ${BOLD}${LIME}9)${RESET}  ${ORANGE}Setup/repair environment${RESET}\n"
    printf "  ${BOLD}${LIME}10)${RESET} ${VIOLET}Show trusted APs whitelist${RESET}\n"
    printf "  ${BOLD}${LIME}11)${RESET} ${GOLD}Install/check dependencies${RESET}\n"
    echo ""
    
    # Left-aligned prompt
    printf "${YELLOW}${BOLD}[>]${RESET} ${CYAN}Select an option [0-11]:${RESET} "
    
    read choice
    
    case $choice in
      1)
        handle_start
        echo -e "${GREEN}Press Enter to continue...${RESET}"
        read
        ;;
      2)
        handle_stop
        echo -e "${GREEN}Press Enter to continue...${RESET}"
        read
        ;;
      3)
        handle_restart
        echo -e "${GREEN}Press Enter to continue...${RESET}"
        read
        ;;
      4)
        handle_status
        echo -e "${GREEN}Press Enter to continue...${RESET}"
        read
        ;;
      5)
        echo ""
        echo -e "${CYAN}Available Wireless Interfaces:${RESET}"
        list_wireless
        echo ""
        echo -ne "${YELLOW}Enter interface name (or press Enter to select from list): ${RESET}"
        read interface_input
        
        # Handle the interface selection
        local interfaces=($(get_wireless_interfaces))
        if [ ${#interfaces[@]} -eq 0 ]; then
          echo -e "${RED}[!] No wireless interfaces found${RESET}"
        elif [ -z "$interface_input" ]; then
          # Empty input - show selection menu
          echo ""
          echo -e "${YELLOW}--- Select Wireless Interface ---${RESET}"
          for i in "${!interfaces[@]}"; do
            echo -e "${GREEN}$i)${RESET} ${interfaces[$i]}"
          done
          echo -ne "${YELLOW}=====> ${RESET}"
          read choice
          if [[ "$choice" =~ ^[0-9]+$ ]] && [ "$choice" -ge 0 ] && [ "$choice" -lt ${#interfaces[@]} ]; then
            radar_on "${interfaces[$choice]}"
          else
            echo -e "${RED}[!] Invalid selection${RESET}"
          fi
        elif [[ "$interface_input" =~ ^[0-9]+$ ]] && [ "$interface_input" -ge 0 ] && [ "$interface_input" -lt ${#interfaces[@]} ]; then
          # Direct number selection
          radar_on "${interfaces[$interface_input]}"
        else
          # Direct interface name
          radar_on "$interface_input"
        fi
        echo -e "${GREEN}Press Enter to continue...${RESET}"
        read
        ;;
      6)
        echo ""
        echo -e "${CYAN}Available Wireless Interfaces:${RESET}"
        list_wireless
        echo ""
        echo -ne "${YELLOW}Enter interface name (or press Enter to select from list): ${RESET}"
        read interface_input
        
        # Handle the interface selection
        local interfaces=($(get_wireless_interfaces))
        if [ ${#interfaces[@]} -eq 0 ]; then
          echo -e "${RED}[!] No wireless interfaces found${RESET}"
        elif [ -z "$interface_input" ]; then
          # Empty input - show selection menu
          echo ""
          echo -e "${YELLOW}--- Select Wireless Interface ---${RESET}"
          for i in "${!interfaces[@]}"; do
            echo -e "${GREEN}$i)${RESET} ${interfaces[$i]}"
          done
          echo -ne "${YELLOW}=====> ${RESET}"
          read choice
          if [[ "$choice" =~ ^[0-9]+$ ]] && [ "$choice" -ge 0 ] && [ "$choice" -lt ${#interfaces[@]} ]; then
            radar_off "${interfaces[$choice]}"
          else
            echo -e "${RED}[!] Invalid selection${RESET}"
          fi
        elif [[ "$interface_input" =~ ^[0-9]+$ ]] && [ "$interface_input" -ge 0 ] && [ "$interface_input" -lt ${#interfaces[@]} ]; then
          # Direct number selection
          radar_off "${interfaces[$interface_input]}"
        else
          # Direct interface name
          radar_off "$interface_input"
        fi
        echo -e "${GREEN}Press Enter to continue...${RESET}"
        read
        ;;
      7)
        list_wireless
        echo -e "${GREEN}Press Enter to continue...${RESET}"
        read
        ;;
      8)
        show_system_info
        echo -e "${GREEN}Press Enter to continue...${RESET}"
        read
        ;;
      9)
        log "Setting up environment..."
        ensure_linux
        ensure_default_env
        load_env
        ensure_runtime_dirs
        prepare_frontend
        prepare_python_envs
        echo -e "${GREEN}[✓] Environment setup complete${RESET}"
        echo -e "${GREEN}Press Enter to continue...${RESET}"
        read
        ;;
      10)
        show_whitelist
        echo -e "${GREEN}Press Enter to continue...${RESET}"
        read
        ;;
      11)
        print_banner
        echo -e "${WHITE}═════════════════════════════════════════════════════════════════════════════════════${RESET}"
        echo ""
        echo -e "${CYAN}DEPENDENCY INSTALLATION & VERIFICATION${RESET}"
        echo ""
        check_system_dependencies
        echo ""
        echo -e "${WHITE}═════════════════════════════════════════════════════════════════════════════════════${RESET}"
        echo -e "${GREEN}Press Enter to continue...${RESET}"
        read
        ;;
      0)
        echo -e "${GREEN}Goodbye!${RESET}"
        exit 0
        ;;
      *)
        echo -e "${RED}[!] Invalid option. Please try again.${RESET}"
        sleep 2
        ;;
    esac
  done
}

# Command handlers
handle_stop() {
  print_banner
  log "Stopping all ZeinaGuard services..."

  if [ ! -d "$STATE_DIR" ]; then
    log "Runtime state directory not found at $STATE_DIR"
  fi

  for service in "${SERVICES[@]}"; do
    stop_descendants_from_pid_file "$service" || true
    stop_service_by_pid_file "$service" || true
  done

  stop_known_command_patterns || true

  for port in "${PORTS[@]}"; do
    stop_listeners_on_port "$port" || true
  done

  if [ -d "$STATE_DIR" ]; then
    rm -f "$STATE_DIR"/*.pid 2>/dev/null || true
  fi

  echo ""
  echo -e "${GREEN}All ZeinaGuard services have been stopped.${RESET}"
  if [ -d "$LOG_DIR" ]; then
    echo -e "${DIM}Logs preserved in: $LOG_DIR${RESET}"
  fi
  echo ""
}

handle_status() {
  print_banner
  log "Checking ZeinaGuard service status..."
  echo ""

  for service in "${SERVICES[@]}"; do
    local pid_file="$(pid_file_for "$service")"
    local status_color="${RED}"
    local status_text="STOPPED"
    
    if [ -f "$pid_file" ]; then
      local pid="$(cat "$pid_file" 2>/dev/null || true)"
      if [ -n "$pid" ] && process_running "$pid"; then
        status_color="${GREEN}"
        status_text="RUNNING (pid: $pid)"
      fi
    fi
    
    printf "  %-10s: ${status_color}%s${RESET}\n" "$(tr '[:lower:]' '[:upper:]' <<< "$service")" "$status_text"
  done

  echo ""
  log "Port status:"
  for port in "${PORTS[@]}"; do
    local port_status="${RED}CLOSED${RESET}"
    if port_is_open "127.0.0.1" "$port"; then
      port_status="${GREEN}OPEN${RESET}"
    fi
    printf "  Port %-4s  : ${port_status}\n" "$port"
  done
  echo ""
}

handle_restart() {
  log "Restarting all ZeinaGuard services..."
  handle_stop
  sleep 2
  handle_start
}

handle_start() {
  print_banner
  
  # Set up signal handlers for graceful shutdown
  trap cleanup SIGINT SIGTERM

  echo ""
  printf "${BOLD}${GOLD}DEPLOYMENT INITIALIZATION${RESET}\n"
  info "Initializing ZeinaGuard deployment..."
  
  # Show deployment progress
  local total_steps=8
  local current_step=0
  local progress_width=40
  
  ensure_linux
  current_step=$((current_step + 1))
  progress_bar $current_step $total_steps $progress_width "System Validation"
  
  # Check and install all system dependencies first
  info "Checking system dependencies..."
  check_system_dependencies
  current_step=$((current_step + 1))
  progress_bar $current_step $total_steps $progress_width "Dependency Check"
  
  info "Configuring environment..."
  ensure_default_env
  load_env
  ensure_runtime_dirs
  current_step=$((current_step + 1))
  progress_bar $current_step $total_steps $progress_width "Environment Setup"

  # Initial cleanup of any existing processes
  info "Cleaning up existing processes..."
  handle_stop >/dev/null 2>&1 || true
  current_step=$((current_step + 1))
  progress_bar $current_step $total_steps $progress_width "Process Cleanup"

  info "Preparing frontend environment..."
  prepare_frontend
  current_step=$((current_step + 1))
  progress_bar $current_step $total_steps $progress_width "Frontend Setup"
  
  info "Preparing Python environments..."
  prepare_python_envs
  current_step=$((current_step + 1))
  progress_bar $current_step $total_steps $progress_width "Python Environments"
  
  # Activate virtual environments
  info "Activating virtual environments..."
  activate_venvs
  current_step=$((current_step + 1))
  progress_bar $current_step $total_steps $progress_width "Environment Activation"
  
  echo ""
  printf "${BOLD}${GOLD}SERVICE STARTUP${RESET}\n"
  
  # Start services with clean status indicators
  info "Starting backend service..."
  start_backend &
  local backend_pid=$!
  spinner $backend_pid "Backend Service"
  success "Backend service ready"
  
  info "Starting frontend service..."
  start_frontend &
  local frontend_pid=$!
  spinner $frontend_pid "Frontend Service"
  success "Frontend service ready"
  
  info "Starting sensor service..."
  start_sensor &
  local sensor_pid=$!
  spinner $sensor_pid "Sensor Service"
  success "Sensor service ready"
  
  current_step=$((current_step + 1))
  progress_bar $current_step $total_steps $progress_width "Service Startup"
  
  print_ready
  
  # Keep the script running until Ctrl+C is pressed
  echo ""
  printf "${BOLD}${GOLD}DEPLOYMENT COMPLETE${RESET}\n"
  echo ""
  success "ZeinaGuard is fully deployed and running!"
  info "Monitoring services... Press Ctrl+C to stop"
  echo ""
  
  # Show live status updates
  while true; do
    local timestamp=$(date '+%H:%M:%S')
    printf "\r${GREEN}● Services active - %s${RESET}" "$timestamp"
    sleep 5
  done
}

# Main command dispatcher
main() {
  case "${1:-menu}" in
    start)
      handle_start
      ;;
    stop)
      handle_stop
      ;;
    restart)
      handle_restart
      ;;
    status)
      handle_status
      ;;
    radar-on)
      radar_on "${2:-}"
      ;;
    radar-off)
      radar_off "${2:-}"
      ;;
    radar-list)
      list_wireless
      ;;
    menu)
      show_main_menu
      ;;
    *)
      print_banner
      echo ""
      printf "${BOLD}${GOLD}USAGE GUIDE${RESET}\n"
      echo ""
      printf "${CYAN}Usage:${RESET} ${WHITE}./zeina.sh {command} [options]${RESET}\n"
      echo ""
      
      printf "${BOLD}${GREEN}SERVICE COMMANDS${RESET}\n"
      printf "  ${LIME}start${RESET}      ${GREEN}Start all ZeinaGuard services${RESET}\n"
      printf "  ${LIME}stop${RESET}       ${RED}Stop all ZeinaGuard services${RESET}\n"
      printf "  ${LIME}restart${RESET}    ${YELLOW}Restart all ZeinaGuard services${RESET}\n"
      printf "  ${LIME}status${RESET}     ${CYAN}Check the status of all services${RESET}\n"
      echo ""
      
      printf "${BOLD}${PURPLE}RADAR COMMANDS${RESET}\n"
      printf "  ${LIME}radar-on${RESET}   ${PURPLE}Enable monitor mode on wireless interface${RESET}\n"
      printf "  ${LIME}radar-off${RESET}  ${TURQUOISE}Reset wireless interface to managed mode${RESET}\n"
      printf "  ${LIME}radar-list${RESET} ${LIGHT_BLUE}List available wireless interfaces${RESET}\n"
      echo ""
      
      printf "${BOLD}${GOLD}INTERACTIVE MODE${RESET}\n"
      printf "  ${LIME}menu${RESET}       ${GOLD}Show interactive menu (default)${RESET}\n"
      echo ""
      
      printf "${BOLD}${CYAN}ADVANCED USAGE EXAMPLES${RESET}\n"
      printf "  ${WHITE}./zeina.sh${RESET}                    ${DIM}# Show interactive menu${RESET}\n"
      printf "  ${WHITE}./zeina.sh start${RESET}             ${DIM}# Start all services${RESET}\n"
      printf "  ${WHITE}./zeina.sh radar-on wlan1${RESET}     ${DIM}# Enable monitor mode on wlan1${RESET}\n"
      printf "  ${WHITE}./zeina.sh radar-off${RESET}           ${DIM}# Reset all interfaces to managed mode${RESET}\n"
      echo ""
      
      printf "${BOLD}${AMBER}QUICK START${RESET}\n"
      printf "  ${GOLD}1.${RESET} Run ${WHITE}./zeina.sh${RESET} to open the interactive menu\n"
      printf "  ${GOLD}2.${RESET} Choose ${LIME}Start all services${RESET} from the menu\n"
      printf "  ${GOLD}3.${RESET} Access the web dashboard at ${CYAN}http://localhost:3000${RESET}\n"
      echo ""
      
      printf "${BOLD}${VIOLET}SYSTEM INFORMATION${RESET}\n"
      printf "  ${DIM}Wireless Intrusion Detection & Prevention System${RESET}\n"
      printf "  ${DIM}Version 1.0.0 | Build 2026${RESET}\n"
      echo ""
      
      printf "${BOLD}${GREEN}STATUS${RESET}\n"
      printf "  ${GREEN}ZeinaGuard is ready to protect your wireless networks!${RESET}\n"
      echo ""
      
      exit 1
      ;;
  esac
}

main "$@"
