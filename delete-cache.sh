#!/usr/bin/env bash
set -euo pipefail

# Enhanced ANSI Color Codes for rich terminal output formatting (matching zeina.sh)
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

print_banner() {
    clear
    
    # Print ASCII Art immediately at the top with ZEINA in magenta and GUARD in cyan
    printf "${BOLD}${MAGENTA}  █████████╗███████╗██╗███╗   ██╗ █████╗ ${CYAN}  ██████╗ ██╗   ██╗ █████╗ ██████╗ ██████╗ ${RESET}\n"
    printf "${BOLD}${MAGENTA}  ╚════███╔╝██╔════╝██║████╗  ██║██╔══██╗${CYAN} ██╔════╝ ██║   ██║██╔══██╗██╔══██╗██╔══██╗${RESET}\n"
    printf "${BOLD}${MAGENTA}     ███╔╝  █████╗  ██║██╔██╗ ██║███████║${CYAN} ██║  ███╗██║   ██║███████║██████╔╝██║  ██║${RESET}\n"
    printf "${BOLD}${MAGENTA}   ███╔╝    ██╔══╝  ██║██║╚██╗██║██╔══██║${CYAN} ██║   ██║██║   ██║██╔══██║██╔══██║██║  ██║${RESET}\n"
    printf "${BOLD}${MAGENTA}  █████████╗███████╗██║██║ ╚████║██║  ██║${CYAN} ╚██████╔╝╚██████╔╝██║  ██║██║  ██║██████╔╝${RESET}\n"
    printf "${BOLD}${MAGENTA}  ╚════════╝╚══════╝╚═╝╚═╝  ╚═══╝╚═╝  ╚═╝${CYAN}  ╚═════╝  ╚═════╝ ╚═╝  ╚═╝╚═╝  ╚═╝╚═════╝ ${RESET}\n"
    
    # System information with minimal spacing
    printf "${CYAN}                         Project Cache Cleanup Utility${RESET}\n"
    printf "${DIM}                           Version 1.0.0 | Build 2026${RESET}\n"
    echo ""
}

# Global variables
ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
TOTAL_SIZE_BEFORE=0
TOTAL_SIZE_AFTER=0

# Clean logging functions for better terminal output (matching zeina.sh)
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

# Calculate directory size
get_dir_size() {
    local dir_path="$1"
    if [ -d "$dir_path" ]; then
        du -sk "$dir_path" 2>/dev/null | cut -f1 || echo "0"
    else
        echo "0"
    fi
}

# Format size for human readable output
format_size() {
    local size_kb="$1"
    if [ "$size_kb" -ge 1048576 ]; then
        echo "$(( size_kb / 1048576 ))GB"
    elif [ "$size_kb" -ge 1024 ]; then
        echo "$(( size_kb / 1024 ))MB"
    else
        echo "${size_kb}KB"
    fi
}

# Clean Node.js cache and dependencies
clean_node_cache() {
    log "Cleaning Node.js cache and dependencies..."
    
    local size_before=0
    local size_after=0
    
    # Clean node_modules
    if [ -d "$ROOT_DIR/node_modules" ]; then
        size_before=$(get_dir_size "$ROOT_DIR/node_modules")
        log "Removing node_modules ($(format_size $size_before))..."
        rm -rf "$ROOT_DIR/node_modules"
        size_after=$(get_dir_size "$ROOT_DIR/node_modules")
        TOTAL_SIZE_BEFORE=$((TOTAL_SIZE_BEFORE + size_before))
    fi
    
    # Clean npm cache
    if command -v npm >/dev/null 2>&1; then
        log "Clearing npm cache..."
        if command -v sudo >/dev/null 2>&1; then
            sudo npm cache clean --force >/dev/null 2>&1 || true
        else
            npm cache clean --force >/dev/null 2>&1 || true
        fi
    fi
    
    # Clean pnpm cache
    if command -v pnpm >/dev/null 2>&1; then
        log "Clearing pnpm cache..."
        pnpm store prune >/dev/null 2>&1 || true
    fi
    
    # Clean yarn cache
    if command -v yarn >/dev/null 2>&1; then
        log "Clearing yarn cache..."
        yarn cache clean >/dev/null 2>&1 || true
    fi
    
    success "Node.js cache cleaned"
}

# Clean Python cache and virtual environments
clean_python_cache() {
    log "Cleaning Python cache and virtual environments..."
    
    local size_before=0
    local size_after=0
    
    # Clean backend venv
    if [ -d "$ROOT_DIR/backend/.venv" ]; then
        size_before=$(get_dir_size "$ROOT_DIR/backend/.venv")
        log "Removing backend virtual environment ($(format_size $size_before))..."
        rm -rf "$ROOT_DIR/backend/.venv" 2>/dev/null || {
            if command -v sudo >/dev/null 2>&1; then
                sudo rm -rf "$ROOT_DIR/backend/.venv" 2>/dev/null || true
            fi
        }
        TOTAL_SIZE_BEFORE=$((TOTAL_SIZE_BEFORE + size_before))
    fi
    
    # Clean sensor venv
    if [ -d "$ROOT_DIR/sensor/.venv" ]; then
        size_before=$(get_dir_size "$ROOT_DIR/sensor/.venv")
        log "Removing sensor virtual environment ($(format_size $size_before))..."
        rm -rf "$ROOT_DIR/sensor/.venv" 2>/dev/null || {
            if command -v sudo >/dev/null 2>&1; then
                sudo rm -rf "$ROOT_DIR/sensor/.venv" 2>/dev/null || true
            fi
        }
        TOTAL_SIZE_BEFORE=$((TOTAL_SIZE_BEFORE + size_before))
    fi
    
    # Clean Python cache files
    log "Removing Python cache files..."
    find "$ROOT_DIR" -type d -name "__pycache__" -exec rm -rf {} + 2>/dev/null || true
    find "$ROOT_DIR" -type f -name "*.pyc" -delete 2>/dev/null || true
    find "$ROOT_DIR" -type f -name "*.pyo" -delete 2>/dev/null || true
    find "$ROOT_DIR" -type d -name "*.egg-info" -exec rm -rf {} + 2>/dev/null || true
    find "$ROOT_DIR" -type d -name ".pytest_cache" -exec rm -rf {} + 2>/dev/null || true
    
    # Handle stubborn cache files with sudo if needed
    if command -v sudo >/dev/null 2>&1; then
        find "$ROOT_DIR" -path "*/.venv/*" -name "__pycache__" -exec sudo rm -rf {} + 2>/dev/null || true
        find "$ROOT_DIR" -path "*/.venv/*" -name "*.pyc" -exec sudo rm -f {} + 2>/dev/null || true
        find "$ROOT_DIR" -path "*/.venv/*" -name "*.pyo" -exec sudo rm -f {} + 2>/dev/null || true
    fi
    
    success "Python cache cleaned"
}

# Clean logs and runtime files
clean_logs_runtime() {
    log "Cleaning logs and runtime files..."
    
    local size_before=0
    
    # Clean log files
    if [ -d "$ROOT_DIR/logs" ]; then
        size_before=$(get_dir_size "$ROOT_DIR/logs")
        log "Clearing log files ($(format_size $size_before))..."
        find "$ROOT_DIR/logs" -type f -exec truncate -s 0 {} \; 2>/dev/null || true
        TOTAL_SIZE_BEFORE=$((TOTAL_SIZE_BEFORE + size_before))
    fi
    
    # Clean sensor data logs
    if [ -d "$ROOT_DIR/sensor/data_logs" ]; then
        size_before=$(get_dir_size "$ROOT_DIR/sensor/data_logs")
        log "Removing sensor data logs ($(format_size $size_before))..."
        rm -rf "$ROOT_DIR/sensor/data_logs"/* 2>/dev/null || true
        # Recreate the directory if it was completely removed
        mkdir -p "$ROOT_DIR/sensor/data_logs" 2>/dev/null || true
        TOTAL_SIZE_BEFORE=$((TOTAL_SIZE_BEFORE + size_before))
    fi
    
    # Clean runtime state
    if [ -d "$ROOT_DIR/.zeinaguard-runtime" ]; then
        size_before=$(get_dir_size "$ROOT_DIR/.zeinaguard-runtime")
        log "Removing runtime state ($(format_size $size_before))..."
        rm -rf "$ROOT_DIR/.zeinaguard-runtime"
        TOTAL_SIZE_BEFORE=$((TOTAL_SIZE_BEFORE + size_before))
    fi
    
    success "Logs and runtime files cleaned"
}

# Clean build artifacts and temporary files
clean_build_artifacts() {
    log "Cleaning build artifacts and temporary files..."
    
    local size_before=0
    
    # Clean Next.js build
    if [ -d "$ROOT_DIR/.next" ]; then
        size_before=$(get_dir_size "$ROOT_DIR/.next")
        log "Removing Next.js build cache ($(format_size $size_before))..."
        rm -rf "$ROOT_DIR/.next"
        TOTAL_SIZE_BEFORE=$((TOTAL_SIZE_BEFORE + size_before))
    fi
    
    # Clean frontend build
    if [ -d "$ROOT_DIR/app/.next" ]; then
        size_before=$(get_dir_size "$ROOT_DIR/app/.next")
        log "Removing frontend build cache ($(format_size $size_before))..."
        rm -rf "$ROOT_DIR/app/.next"
        TOTAL_SIZE_BEFORE=$((TOTAL_SIZE_BEFORE + size_before))
    fi
    
    # Clean dist folders
    find "$ROOT_DIR" -type d -name "dist" -exec rm -rf {} + 2>/dev/null || true
    find "$ROOT_DIR" -type d -name "build" -exec rm -rf {} + 2>/dev/null || true
    
    # Clean temporary files
    find "$ROOT_DIR" -name "*.tmp" -delete 2>/dev/null || true
    find "$ROOT_DIR" -name "*.temp" -delete 2>/dev/null || true
    find "$ROOT_DIR" -name ".DS_Store" -delete 2>/dev/null || true
    find "$ROOT_DIR" -name "Thumbs.db" -delete 2>/dev/null || true
    
    # Clean lock files (optional - uncomment if needed)
    # find "$ROOT_DIR" -name "*.lock" -delete 2>/dev/null || true
    # find "$ROOT_DIR" -name "package-lock.json" -delete 2>/dev/null || true
    
    success "Build artifacts cleaned"
}

# Clean Git cache
clean_git_cache() {
    log "Cleaning Git cache..."
    
    if [ -d "$ROOT_DIR/.git" ]; then
        local size_before=0
        size_before=$(get_dir_size "$ROOT_DIR/.git/objects")
        log "Cleaning Git objects ($(format_size $size_before))..."
        git -C "$ROOT_DIR" gc --aggressive --prune=now >/dev/null 2>&1 || true
        TOTAL_SIZE_BEFORE=$((TOTAL_SIZE_BEFORE + size_before))
    fi
    
    success "Git cache cleaned"
}

# Clean IDE and editor files
clean_ide_files() {
    log "Cleaning IDE and editor files..."
    
    # Clean VS Code
    if [ -d "$ROOT_DIR/.vscode" ]; then
        rm -rf "$ROOT_DIR/.vscode"
    fi
    
    # Clean PyCharm
    find "$ROOT_DIR" -type d -name ".idea" -exec rm -rf {} + 2>/dev/null || true
    find "$ROOT_DIR" -type d -name ".vs" -exec rm -rf {} + 2>/dev/null || true
    
    # Clean Vim
    find "$ROOT_DIR" -name "*.swp" -delete 2>/dev/null || true
    find "$ROOT_DIR" -name "*.swo" -delete 2>/dev/null || true
    find "$ROOT_DIR" -name ".netrwhist" -delete 2>/dev/null || true
    
    # Clean Emacs
    find "$ROOT_DIR" -name "*~" -delete 2>/dev/null || true
    find "$ROOT_DIR" -name ".#*" -delete 2>/dev/null || true
    
    success "IDE files cleaned"
}

# Show disk usage summary
show_disk_usage() {
    info "Calculating disk usage..."
    
    local total_size=$(get_dir_size "$ROOT_DIR")
    local available_space=$(df -h "$ROOT_DIR" | awk 'NR==2 {print $4}')
    
    echo ""
    printf "${BOLD}${GOLD}DISK USAGE SUMMARY${RESET}\n"
    printf "  Project size: ${WHITE}$(format_size $total_size)${RESET}\n"
    printf "  Available space: ${WHITE}${available_space}${RESET}\n"
    echo ""
}

# Interactive menu with left-aligned layout (matching zeina.sh)
show_menu() {
    while true; do
        clear
        print_banner
        
        # Left-aligned menu title
        echo ""
        printf "${BOLD}${GOLD}CACHE CLEANUP MENU${RESET}\n"
        echo ""
        
        # Left-aligned menu items with colored text
        printf "  ${BOLD}${LIME}0)${RESET} ${RED}Exit${RESET}\n"
        printf "  ${BOLD}${LIME}1)${RESET} ${GREEN}Clean everything (recommended for sharing)${RESET}\n"
        printf "  ${BOLD}${LIME}2)${RESET} ${CYAN}Clean Node.js cache only${RESET}\n"
        printf "  ${BOLD}${LIME}3)${RESET} ${TURQUOISE}Clean Python cache only${RESET}\n"
        printf "  ${BOLD}${LIME}4)${RESET} ${PURPLE}Clean logs and runtime only${RESET}\n"
        printf "  ${BOLD}${LIME}5)${RESET} ${VIOLET}Clean build artifacts only${RESET}\n"
        printf "  ${BOLD}${LIME}6)${RESET} ${AMBER}Clean Git cache only${RESET}\n"
        printf "  ${BOLD}${LIME}7)${RESET} ${ORANGE}Clean IDE files only${RESET}\n"
        printf "  ${BOLD}${LIME}8)${RESET} ${YELLOW}Show current disk usage${RESET}\n"
        echo ""
        
        # Left-aligned prompt
        printf "${YELLOW}${BOLD}[>]${RESET} ${CYAN}Select an option [0-8]:${RESET} "
        
        read choice
        
        case $choice in
            1)
                clean_all
                success "Press Enter to continue..."
                read
                ;;
            2)
                clean_node_cache
                success "Press Enter to continue..."
                read
                ;;
            3)
                clean_python_cache
                success "Press Enter to continue..."
                read
                ;;
            4)
                clean_logs_runtime
                success "Press Enter to continue..."
                read
                ;;
            5)
                clean_build_artifacts
                success "Press Enter to continue..."
                read
                ;;
            6)
                clean_git_cache
                success "Press Enter to continue..."
                read
                ;;
            7)
                clean_ide_files
                success "Press Enter to continue..."
                read
                ;;
            8)
                show_disk_usage
                success "Press Enter to continue..."
                read
                ;;
            0)
                success "Goodbye!"
                exit 0
                ;;
            *)
                warn "Invalid option. Please try again."
                sleep 2
                ;;
        esac
    done
}

# Clean everything
clean_all() {
    print_banner
    echo ""
    warn "WARNING: This will remove all cache, temporary files, and virtual environments!"
    warn "   This is perfect for sharing the project but requires re-setup afterwards."
    echo ""
    printf "${YELLOW}${BOLD}[>]${RESET} ${CYAN}Are you sure you want to continue? (y/N):${RESET} "
    read confirm
    
    if [[ "$confirm" =~ ^[Yy]$ ]]; then
        info "Starting comprehensive cleanup..."
        
        TOTAL_SIZE_BEFORE=0
        clean_node_cache
        clean_python_cache
        clean_logs_runtime
        clean_build_artifacts
        clean_git_cache
        clean_ide_files
        
        local total_size_after=$(get_dir_size "$ROOT_DIR")
        local space_freed=$((TOTAL_SIZE_BEFORE))
        
        echo ""
        success "Cleanup completed successfully!"
        info "Summary:"
        printf "  Space freed: ${WHITE}$(format_size $space_freed)${RESET}\n"
        printf "  Project size: ${WHITE}$(format_size $total_size_after)${RESET}\n"
        echo ""
        warn "Note: You'll need to run './zeina.sh' to re-setup the environment."
        echo ""
    else
        warn "Cleanup cancelled."
    fi
}

# Main function
main() {
    case "${1:-menu}" in
        all)
            clean_all
            ;;
        node)
            clean_node_cache
            ;;
        python)
            clean_python_cache
            ;;
        logs)
            clean_logs_runtime
            ;;
        build)
            clean_build_artifacts
            ;;
        git)
            clean_git_cache
            ;;
        ide)
            clean_ide_files
            ;;
        usage)
            show_disk_usage
            ;;
        menu)
            show_menu
            ;;
        *)
            echo "Usage: $0 {all|node|python|logs|build|git|ide|usage|menu}"
            echo ""
            echo "Commands:"
            echo "  all    - Clean everything (recommended for sharing)"
            echo "  node   - Clean Node.js cache and dependencies"
            echo "  python - Clean Python cache and virtual environments"
            echo "  logs   - Clean logs and runtime files"
            echo "  build  - Clean build artifacts"
            echo "  git    - Clean Git cache"
            echo "  ide    - Clean IDE and editor files"
            echo "  usage  - Show current disk usage"
            echo "  menu   - Show interactive menu (default)"
            echo ""
            echo "Interactive Mode:"
            echo "  ./delete-cache.sh              - Show interactive menu"
            exit 1
            ;;
    esac
}

# Make script executable
chmod +x "$0" 2>/dev/null || true

main "$@"
