#!/usr/bin/env bash
set -euo pipefail

# Color Codes
readonly RESET='\033[0m'
readonly BOLD='\033[1m'
readonly DIM='\033[2m'
readonly WHITE='\033[1;37m'
readonly GREEN='\033[0;32m'
readonly LIME='\033[38;5;46m'
readonly RED='\033[0;31m'
readonly BLUE='\033[0;34m'
readonly LIGHT_BLUE='\033[1;34m'
readonly CYAN='\033[0;36m'
readonly TURQUOISE='\033[38;5;45m'
readonly MAGENTA='\033[0;35m'
readonly PURPLE='\033[38;5;141m'
readonly YELLOW='\033[1;33m'
readonly GOLD='\033[38;5;220m'

# Check for root privileges
if [ "$EUID" -ne 0 ]; then
  echo -e "Must be run with ${RED}${BOLD}root${RESET} privileges!"
  echo -e "Please run: ${YELLOW}${BOLD}sudo ./zeina.sh${RESET}"
  exit 1
fi

# ZeinaGuard Banner ( pinned to the very top )
print_banner() {
    clear
    echo ""
    printf "${BOLD}${MAGENTA}  █████████╗███████╗██╗███╗   ██╗ █████╗ ${CYAN}  ██████╗ ██╗   ██╗ █████╗ ██████╗ ██████╗ ${RESET}\n"
    printf "${BOLD}${MAGENTA}  ╚════███╔╝██╔════╝██║████╗  ██║██╔══██╗${CYAN} ██╔════╝ ██║   ██║██╔══██╗██╔══██╗██╔══██╗${RESET}\n"
    printf "${BOLD}${MAGENTA}     ███╔╝  █████╗  ██║██╔██╗ ██║███████║${CYAN} ██║  ███╗██║   ██║███████║██████╔╝██║  ██║${RESET}\n"
    printf "${BOLD}${MAGENTA}   ███╔╝    ██╔══╝  ██║██║╚██╗██║██╔══██║${CYAN} ██║   ██║██║   ██║██╔══██║██╔══██║██║  ██║${RESET}\n"
    printf "${BOLD}${MAGENTA}  █████████╗███████╗██║██║ ╚████║██║  ██║${CYAN} ╚██████╔╝╚██████╔╝██║  ██║██║  ██║██████╔╝${RESET}\n"
    printf "${BOLD}${MAGENTA}  ╚════════╝╚══════╝╚═╝╚═╝  ╚═══╝╚═╝  ╚═╝${CYAN}  ╚═════╝  ╚═════╝ ╚═╝  ╚═╝╚═╝  ╚═╝╚═════╝ ${RESET}\n"
    
    printf "${CYAN}                  Wireless Intrusion Detection & Prevention System${RESET}\n"
    printf "${DIM}                               Version 1.0 | Build 2026${RESET}\n"
    echo ""
}

# Global variables
ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ENV_FILE="$ROOT_DIR/.env"
LOG_DIR="$ROOT_DIR/logs"
STATE_DIR="$ROOT_DIR/.zeinaguard-runtime"
DEFAULT_INTERFACE_FILE="$STATE_DIR/selected_interface"

SERVICES=("sensor" "frontend" "backend")
PORTS=("3000" "5000")

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

success() {
  printf "${GREEN}%s${RESET}\n" "$*"
}

info() {
  printf "${BLUE}%s${RESET}\n" "$*"
}


run_maybe_sudo() {
  if [ "${EUID:-$(id -u)}" -eq 0 ]; then
    "$@"
  elif command -v sudo >/dev/null 2>&1; then
    sudo "$@" || {
      local exit_code=$?
      if [ $exit_code -eq 1 ] || [ $exit_code -eq 126 ]; then
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

  process_running "$pid" && return 1
  return 0
}


ensure_default_env() {
  if [ -f "$ENV_FILE" ]; then
    return
  fi
  local random_jwt_secret
  random_jwt_secret=$(openssl rand -hex 32 2>/dev/null || tr -dc 'a-zA-Z0-9' < /dev/urandom | head -c 64)

  cat >"$ENV_FILE" <<EOF
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

# Dynamically generated secure random secret
JWT_SECRET_KEY=${random_jwt_secret}

# Sensor registration pre-shared key (leave empty for open dev registration).
# Set a strong value in production to prevent unauthorised sensor auto-creation.
SENSOR_REGISTRATION_KEY=

# PostgreSQL connection pool settings (QueuePool — greenlet-safe via eventlet).
DB_POOL_SIZE=10
DB_POOL_MAX_OVERFLOW=20
DB_POOL_TIMEOUT_SECONDS=30
DB_POOL_RECYCLE_SECONDS=1800
EOF
  log "Created default .env file at $ENV_FILE"
}

load_env() {
  if [ ! -f "$ENV_FILE" ]; then return 0; fi
  local line key val
  while IFS= read -r line || [ -n "$line" ]; do
    case "$line" in
      ''|'#'*) continue ;;
    esac
    if [[ "$line" =~ ^([A-Za-z_][A-Za-z0-9_]*)=(.*)$ ]]; then
      key="${BASH_REMATCH[1]}"
      val="${BASH_REMATCH[2]}"
      if [[ "$val" =~ ^\"(.*)\"$  ]]; then val="${BASH_REMATCH[1]}"; fi
      if [[ "$val" =~ ^\'(.*)\'$  ]]; then val="${BASH_REMATCH[1]}"; fi
      export "$key=$val"
    fi
  done < "$ENV_FILE"
}

ensure_api_token() {
  local python_bin="$ROOT_DIR/backend/.venv/bin/python"
  if [ ! -x "$python_bin" ]; then
    python_bin="$ROOT_DIR/backend/.venv/bin/python3"
  fi
  
  if [ -z "${API_TOKEN:-}" ] || ! grep -Eq "^API_TOKEN=[a-zA-Z0-9_.-]+" "$ENV_FILE" 2>/dev/null; then
    log "Generating new API_TOKEN for Sensor and Frontend authentication..."
    local token=$("$python_bin" -c "
import jwt, datetime, os
payload = {
    'client_type': 'sensor',
    'exp': datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(days=365)
}
print(jwt.encode(payload, os.environ.get('JWT_SECRET_KEY', 'default'), algorithm='HS256'))
" 2>/dev/null || echo "")

    if [ -n "$token" ]; then
      printf '\nAPI_TOKEN=%s\n' "$token" >> "$ENV_FILE"
      printf 'NEXT_PUBLIC_API_TOKEN=%s\n' "$token" >> "$ENV_FILE"
      
      success "API_TOKEN and NEXT_PUBLIC_API_TOKEN generated and added to .env"
      load_env
    else
      warn "Could not generate API_TOKEN using PyJWT. The sensor may fail to authenticate."
    fi
  fi
}

ensure_runtime_dirs() {
  mkdir -p "$LOG_DIR" "$STATE_DIR"
}

save_default_interface() {
  local iface="$1"
  printf '%s\n' "$iface" > "$DEFAULT_INTERFACE_FILE"
  success "Default interface set to: $iface"
}

get_default_interface() {
  if [ -f "$DEFAULT_INTERFACE_FILE" ]; then
    head -n1 "$DEFAULT_INTERFACE_FILE" 2>/dev/null
  fi
}

clear_default_interface() {
  rm -f "$DEFAULT_INTERFACE_FILE"
  log "Default interface cleared"
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

  stop_service_by_pid_file "$service_name"
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
    cd "$workdir" || exit 1
    nohup "$@" >>"$log_file" 2>&1 &
    echo $! >"$pid_file"
  )

  local waited_ms=0
  while [ ! -s "$pid_file" ] && [ "$waited_ms" -lt 3000 ]; do
    sleep 0.1
    waited_ms=$((waited_ms + 100))
  done

  pid=""
  [ -f "$pid_file" ] && pid="$(<"$pid_file")"
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


stop_service_by_pid_file() {
  local name="$1"
  local pid_file
  local pid

  pid_file="$(pid_file_for "$name")"
  if [ ! -f "$pid_file" ]; then
    log "No pid file for $name, skipping"
    return
  fi

  pid="$(<"$pid_file")"
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
  pid="$(<"$pid_file")"
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
    if [ "$ROOT_DIR" = "/" ] || [ "$ROOT_DIR" = "/home" ]; then
    fail "Refusing to cleanup in $ROOT_DIR - too dangerous"
    fi
    find "$ROOT_DIR" -type d -name "__pycache__" -exec rm -rf {} + 2>/dev/null || true
    find "$ROOT_DIR" -type f -name "*.pyc" -delete 2>/dev/null || true
    
    # Handle stubborn cache files with sudo if needed
    if command -v sudo >/dev/null 2>&1; then
        find "$ROOT_DIR" -path "*/.venv/*" -name "__pycache__" -exec sudo rm -rf {} + 2>/dev/null || true
        find "$ROOT_DIR" -path "*/.venv/*" -name "*.pyc" -exec sudo rm -f {} + 2>/dev/null || true
    fi

    echo -e "${GREEN}Everything stopped and cleaned successfully. Goodbye!${RESET}"
    exit 0
}

# Preparation functions
prepare_frontend() {
  # Check if Node.js is available
  if ! command -v node >/dev/null 2>&1; then
    fail "Node.js is not installed. Please install Node.js 20 or later."
  fi
  
  # Check and install pnpm using the universal dependency checker
  check_and_install_dependency "pnpm"

  # Clean up and prepare
  fix_project_permissions >/dev/null 2>&1 || true
  local pkg_json="$ROOT_DIR/package.json"
  local node_mod="$ROOT_DIR/node_modules"
  
  if [ ! -d "$node_mod" ] || [ "$pkg_json" -nt "$node_mod" ]; then
    info "Preparing frontend environment (changes detected)..."
    (
      cd "$ROOT_DIR"
      pnpm install --silent 2>/dev/null || pnpm install >/dev/null 2>&1
    )
    success "Frontend dependencies ready"
  else
    log "Frontend node_modules up-to-date"
  fi
}

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


get_wireless_interfaces() {
    local interfaces=($(ls /sys/class/net 2>/dev/null | grep -E 'wlan|wlp|ath|wlx' || true))
    
    # Method 2: Use iw dev (more reliable for USB adapters)
    if command -v iw >/dev/null 2>&1; then
        local iw_interfaces=$(iw dev 2>/dev/null | grep -E '^\s*Interface' | awk '{print $2}')
        for iface in $iw_interfaces; do
            if [[ ! " ${interfaces[@]} " =~ " ${iface} " ]]; then
                interfaces+=("$iface")
            fi
        done
    fi
    
    # Method 3: Use iwconfig as fallback
    if command -v iwconfig >/dev/null 2>&1; then
        local iwconfig_interfaces=$(iwconfig 2>/dev/null | grep -E '^\w+' | grep -v '^lo' | awk '{print $1}')
        for iface in $iwconfig_interfaces; do
            if [[ ! " ${interfaces[@]} " =~ " ${iface} " ]]; then
                interfaces+=("$iface")
            fi
        done
    fi
    
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
  if [ -n "$1" ]; then
    interface="$1"
  else
    interface="$(select_interface "")"
  fi
  
  save_default_interface "$interface"
  
  log "Enabling monitor mode on interface: $interface"
  
  run_maybe_sudo rfkill unblock all
  run_maybe_sudo nmcli device set "$interface" managed no 2>/dev/null || true
  run_maybe_sudo ip link set "$interface" down
  run_maybe_sudo iwconfig "$interface" mode monitor
  run_maybe_sudo ip link set "$interface" up
  
  echo -e "${GREEN}[+] Monitor mode enabled on $interface${RESET}"
  run_maybe_sudo iwconfig "$interface"
}

radar_off() {
  local interface
  if [ -n "$1" ]; then
    interface="$1"
  else
    interface="$(get_default_interface)"
    if [ -z "$interface" ]; then
      interface="$(select_interface "")"
    fi
  fi
  
  log "Resetting interface to managed mode: $interface"
  
  run_maybe_sudo nmcli device set "$interface" managed yes 2>/dev/null || true
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

# Service start functions
start_backend() {
  ensure_port_available "backend" "5000"
  start_command \
    "backend" \
    "$ROOT_DIR/backend" \
    "$ROOT_DIR/backend/.venv/bin/gunicorn" \
    --worker-class eventlet \
    --bind 0.0.0.0:5000 \
    app:app
  wait_for_http "backend" "http://localhost:5000/health" 90 '"status":"healthy"'
}

start_frontend() {
  ensure_port_available "frontend" "3000"
  start_command \
    "frontend" \
    "$ROOT_DIR" \
    pnpm \
    dev
  wait_for_http "frontend" "http://localhost:3000" 120
}

start_sensor() {
  local sensor_python="$ROOT_DIR/sensor/.venv/bin/python"
  if [ ! -f "$sensor_python" ]; then
    sensor_python="$ROOT_DIR/sensor/.venv/bin/python3"
  fi
  stop_service_by_pid_file "sensor"

  local interface
  interface="$(get_default_interface)"
  
  if [ -z "$interface" ]; then
    warn "No default wireless interface set!"
    warn "Sensor will auto-select."
  fi

  load_env
  export API_TOKEN="${API_TOKEN:-}"
  export BACKEND_URL="${BACKEND_URL:-http://localhost:5000}"
  export ZEINAGUARD_NONINTERACTIVE=1
  export SENSOR_INTERFACE="${interface:-}"

  local cmd=(
    "$sensor_python"
    "$ROOT_DIR/sensor/main.py"
  )

  start_command \
    "sensor" \
    "$ROOT_DIR/sensor" \
    "${cmd[@]}"
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


get_system_resources() {
  local ram_kb=$(grep MemTotal /proc/meminfo | awk '{print $2}')
  local cpu_cores=$(nproc)
  local disk_space=$(df -BG . | awk 'NR==2 {print $4}' | sed 's/G//')
  
  echo "${ram_kb}:${cpu_cores}:${disk_space}"
}

has_sufficient_resources() {
  local resources=$(get_system_resources)
  local ram_kb=$(echo "$resources" | cut -d: -f1)
  local cpu_cores=$(echo "$resources" | cut -d: -f2)
  local disk_space=$(echo "$resources" | cut -d: -f3)
  
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
      run_maybe_sudo yum install -y -q "$package" >/dev/null 2>&1
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
    return 1
  fi
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
    "ubuntu"|"debian"|"antix"|"linuxmint"|"pop"|"kali")
      curl -fsSL https://deb.nodesource.com/setup_20.x | run_maybe_sudo bash -s >/dev/null 2>&1
      install_system_package "nodejs"
      ;;
    "centos"|"rhel"|"fedora")
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
        
        if ! python3 -m pip --version >/dev/null 2>&1; then
          warn "pip not found. Installing python3-pip..."
          install_system_package "python3-pip" || install_pip_fallback
        fi
        
        if ! python3 -c "import ensurepip" >/dev/null 2>&1; then
          warn "venv support missing. Installing python3-venv..."
          install_system_package "python3-venv" || true
        fi
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
    
    install_system_package "$(get_package_name build-essential)" || {
      for tool in "${missing_tools[@]}"; do
        install_system_package "$tool" || warn "Failed to install $tool"
      done
    }
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
    if is_postgresql_running; then
      success "PostgreSQL is running"
    else
      warn "PostgreSQL found but not running, attempting to start..."
      start_postgresql_service
    fi
    setup_postgresql_database
  else
    warn "PostgreSQL not found. Installing..."
    install_postgresql_universal
  fi
  
  if ! python3 -c "import psycopg2" >/dev/null 2>&1; then
    install_system_package "$(get_package_name libpq-dev)" >/dev/null 2>&1
    success "PostgreSQL development libraries ready"
  fi

  # Check and Install Redis (CRITICAL FOR BACKEND WS/QUEUES)
  if command -v redis-server >/dev/null 2>&1 || command -v redis-cli >/dev/null 2>&1; then
    success "Redis found"
    if command -v systemctl >/dev/null 2>&1; then
      run_maybe_sudo systemctl start redis-server 2>/dev/null || run_maybe_sudo systemctl start redis 2>/dev/null || true
    fi
  else
    warn "Redis not found. Installing..."
    install_system_package "redis-server" || install_system_package "redis"
    if command -v systemctl >/dev/null 2>&1; then
      run_maybe_sudo systemctl enable --now redis-server 2>/dev/null || run_maybe_sudo systemctl enable --now redis 2>/dev/null || true
    fi
    success "Redis installed and started"
  fi
}

# Universal PostgreSQL installation
install_postgresql_universal() {
  local pkg_manager=$(detect_package_manager)
  local distro=$(detect_distro)
  
  case "$pkg_manager" in
    "apt"|"apt-get")
      install_system_package "postgresql"
      install_system_package "$(get_package_name postgresql-client)"
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
    "ubuntu"|"debian"|"antix"|"mx")
      if [ -d /run/systemd/system ] && command -v systemctl >/dev/null 2>&1; then
        run_maybe_sudo systemctl start postgresql
        run_maybe_sudo systemctl enable postgresql
      else
        run_maybe_sudo service postgresql start || run_maybe_sudo /etc/init.d/postgresql start || true
        run_maybe_sudo update-rc.d postgresql defaults || true
      fi
      ;;
    "fedora"|"centos"|"rhel")
      if [ -d /run/systemd/system ] && command -v systemctl >/dev/null 2>&1; then
        run_maybe_sudo systemctl start postgresql
        run_maybe_sudo systemctl enable postgresql
      else
        run_maybe_sudo service postgresql start || run_maybe_sudo /etc/init.d/postgresql start || true
        run_maybe_sudo chkconfig postgresql on || true
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
    if sudo -u postgres psql -c "SELECT 1" >/dev/null 2>&1; then
      break
    fi
    sleep 1
    wait_time=$((wait_time + 1))
  done
  
  # Load env variables to ensure sync with .env file
  load_env
  
  # Create user and database dynamically
  local db_user="${POSTGRES_USER:-zeinaguard_user}"
  local db_name="${POSTGRES_DB:-zeinaguard_db}"
  local db_pass="${POSTGRES_PASSWORD:-secure_password}"
  
  # 1. Create user or update password if user already exists
  sudo -u postgres psql -c "CREATE USER ${db_user} WITH PASSWORD '${db_pass}';" 2>/dev/null || \
  sudo -u postgres psql -c "ALTER USER ${db_user} WITH PASSWORD '${db_pass}';"
  
  # 2. Create the database
  sudo -u postgres psql -c "CREATE DATABASE ${db_name} OWNER ${db_user};" 2>/dev/null || true
  
  # 3. Grant full privileges to the user
  sudo -u postgres psql -c "GRANT ALL PRIVILEGES ON DATABASE ${db_name} TO ${db_user};" 2>/dev/null || true
  
  # 4. Fix Public Schema permissions (Required for PostgreSQL 15+)
  sudo -u postgres psql -d "${db_name}" -c "GRANT ALL ON SCHEMA public TO ${db_user};" 2>/dev/null || true
  
  success "PostgreSQL database setup completed"
}

# Check if PostgreSQL is running
is_postgresql_running() {
  if [ -d /run/systemd/system ] && command -v systemctl >/dev/null 2>&1; then
    systemctl is-active postgresql >/dev/null 2>&1
  else
    service postgresql status >/dev/null 2>&1 || /etc/init.d/postgresql status >/dev/null 2>&1
  fi
}

# Start PostgreSQL service
start_postgresql_service() {
  if [ -d /run/systemd/system ] && command -v systemctl >/dev/null 2>&1; then
    run_maybe_sudo systemctl start postgresql
  else
    run_maybe_sudo service postgresql start || run_maybe_sudo /etc/init.d/postgresql start
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


# Interactive menu system with left-aligned layout
show_main_menu() {
  while true; do
    clear
    print_banner

    printf "  ${BOLD}${LIME}0)${RESET}  ${RED}Exit${RESET}\n"
    printf "  ${BOLD}${LIME}1)${RESET}  ${PURPLE}Install ZeinaGuard (First Time Setup)${RESET}\n"
    printf "  ${BOLD}${LIME}2)${RESET}  ${GREEN}Start all services${RESET}\n"
    printf "  ${BOLD}${LIME}3)${RESET}  ${RED}Stop all services${RESET}\n"
    printf "  ${BOLD}${LIME}4)${RESET}  ${YELLOW}Restart all services${RESET}\n"
    printf "  ${BOLD}${LIME}5)${RESET}  ${CYAN}Check service status${RESET}\n"
    printf "  ${BOLD}${LIME}6)${RESET}  ${PURPLE}Enable Monitor mode${RESET}\n"
    printf "  ${BOLD}${LIME}7)${RESET}  ${TURQUOISE}Disable Monitor mode${RESET}\n"
    printf "  ${BOLD}${LIME}8)${RESET}  ${LIGHT_BLUE}List wireless interfaces${RESET}\n"
    printf "  ${BOLD}${LIME}9)${RESET}  ${RED}Factory Reset (Wipe Database & RAM Cache)${RESET}\n"
    printf "  ${BOLD}${LIME}10)${RESET} ${GOLD}Set default wireless interface${RESET}\n"
    echo ""
    
    printf "${YELLOW}${BOLD}[>]${RESET} ${CYAN}Select an option [0-10]:${RESET} "
    
    read choice
    
    case $choice in
      0)
        exit 0
        ;;
      1)
        handle_install
        echo -e "${GREEN}Press Enter to continue...${RESET}"
        read
        ;;
      2)
        handle_start
        echo -e "${GREEN}Press Enter to continue...${RESET}"
        read
        ;;
      3)
        handle_stop
        echo -e "${GREEN}Press Enter to continue...${RESET}"
        read
        ;;
      4)
        handle_restart
        echo -e "${GREEN}Press Enter to continue...${RESET}"
        read
        ;;
      5)
        handle_status
        echo -e "${GREEN}Press Enter to continue...${RESET}"
        read
        ;;
      6)
        while true; do
          echo ""
          list_wireless
          echo -ne "${YELLOW}Enter interface number: ${RESET}"
          read -r sub_choice
          
          local interfaces=($(get_wireless_interfaces))
          
          if [[ "$sub_choice" =~ ^[0-9]+$ ]] && [ "$sub_choice" -ge 0 ] && [ "$sub_choice" -lt "${#interfaces[@]}" ]; then
            radar_on "${interfaces[$sub_choice]}"
            break
          else
            echo -e "${RED}[!] Invalid selection ('$sub_choice'), try again.${RESET}"
            sleep 1
          fi
        done
        echo -e "${GREEN}Press Enter to continue...${RESET}"
        read
        ;;
      7)
        while true; do
          echo ""
          list_wireless
          echo -ne "${YELLOW}Enter interface number: ${RESET}"
          read -r sub_choice
          
          local interfaces=($(get_wireless_interfaces))
          
          if [[ "$sub_choice" =~ ^[0-9]+$ ]] && [ "$sub_choice" -ge 0 ] && [ "$sub_choice" -lt "${#interfaces[@]}" ]; then
            radar_off "${interfaces[$sub_choice]}"
            break
          else
            echo -e "${RED}[!] Invalid selection ('$sub_choice'), try again.${RESET}"
            sleep 1
          fi
        done
        echo -e "${GREEN}Press Enter to continue...${RESET}"
        read
        ;;
      8)
        list_wireless
        echo -e "${GREEN}Press Enter to continue...${RESET}"
        read
        ;;
      9)
        echo ""
        echo -e "⚠️ WARNING: Initiating ZeinaGuard Factory Reset..."
        
        load_env
        
        stop_descendants_from_pid_file "backend" || true
        stop_service_by_pid_file "backend" || true
        
        sudo -u postgres psql -d "${POSTGRES_DB:-zeinaguard_db}" -c "TRUNCATE TABLE threats, wifi_networks CASCADE;" 2>/dev/null || \
        PGPASSWORD="${POSTGRES_PASSWORD:-secure_password}" psql -U "${POSTGRES_USER:-zeinaguard_user}" -d "${POSTGRES_DB:-zeinaguard_db}" -h "${POSTGRES_HOST:-localhost}" -p "${POSTGRES_PORT:-5432}" -c "TRUNCATE TABLE threats, wifi_networks CASCADE;"
        
        echo -e "✅ Factory Reset Complete! System is now at Zero State."
        echo -e "${GREEN}Press Enter to continue...${RESET}"
        read
        ;;
      10)
        set_default_interface
        echo -e "${GREEN}Press Enter to continue...${RESET}"
        read
        ;;
      *)
        echo -e "${RED}[!] Invalid option. Select an option [0-10].${RESET}"
        sleep 2
        ;;
    esac
  done
}


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
      local pid=""
      [ -f "$pid_file" ] && pid="$(<"$pid_file")"
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
  handle_stop >/dev/null 2>&1
  sleep 1
  handle_start
}

set_default_interface() {
  print_banner
  info "Select your default wireless interface for the sensor..."
  echo ""
  
  local interfaces=()
  mapfile -t interfaces < <(get_wireless_interfaces)
  
  if [ ${#interfaces[@]} -eq 0 ]; then
    fail "No wireless cards found."
  fi
  
  echo -e "${CYAN}--- Available Wireless Interfaces ---${RESET}"
  for i in "${!interfaces[@]}"; do
    local current_mark=""
    if [ -f "$DEFAULT_INTERFACE_FILE" ] && [ "$(head -n1 "$DEFAULT_INTERFACE_FILE" 2>/dev/null)" = "${interfaces[$i]}" ]; then
      current_mark=" ${GREEN}(current default)${RESET}"
    fi
    echo -e "${GREEN}$i)${RESET} ${interfaces[$i]}${current_mark}"
  done
  echo ""
  
  echo -ne "${YELLOW}Select interface [0-$(( ${#interfaces[@]} - 1 ))]: ${RESET}"
  read -r choice
  
  if [[ "$choice" =~ ^[0-9]+$ ]] && [ "$choice" -ge 0 ] && [ "$choice" -lt ${#interfaces[@]} ]; then
    save_default_interface "${interfaces[$choice]}"
  else
    fail "Invalid selection."
  fi
}

handle_install() {
  print_banner
  echo ""
  printf "${BOLD}${GOLD}SYSTEM INSTALLATION & SETUP${RESET}\n"
  info "Please wait while ZeinaGuard installs required dependencies..."
  echo ""

  ensure_linux
  ensure_default_env 
  check_system_dependencies
  load_env
  ensure_runtime_dirs
  prepare_frontend
  prepare_python_envs
  ensure_api_token
  
  echo ""
  success "Installation Complete! ZeinaGuard is ready."
  info "You can now use 'Start all services' from the menu."
  echo ""
}

handle_start() {
  print_banner
  trap cleanup SIGINT SIGTERM

  if [ ! -f "$ENV_FILE" ] || [ ! -d "$ROOT_DIR/backend/.venv" ]; then
    echo -e "${RED}[!] ZeinaGuard is not installed yet!${RESET}"
    echo -e "${YELLOW}Please select option '1' (Install ZeinaGuard) from the menu first.${RESET}"
    echo ""
    return 1
  fi

  printf "${YELLOW}Starting services silently, please wait...${RESET}\r"
  {
    load_env
    ensure_runtime_dirs
    handle_stop 2>/dev/null || true
    ensure_api_token
    
    start_backend &
    start_frontend &
    start_sensor &
    wait
  } >/dev/null

  printf "\033[2K\r"
  echo -e "${GREEN}frontend worked at http://localhost:3000${RESET}"
  echo -e "${GREEN}backend worked at http://localhost:5000${RESET}"
  echo -e "${GREEN}sensors are working${RESET}"
  echo ""
}

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
      printf "${CYAN}Usage:${RESET} ${WHITE}sudo ./zeina.sh${RESET}\n"
      echo ""
      exit 1
      ;;
  esac
}
main "$@"