import argparse
from datetime import datetime
import logging
import os
import subprocess
import sys
import threading
import traceback
from pathlib import Path


ROOT_DIR = Path(__file__).resolve().parent
VENV_DIR = ROOT_DIR / ".venv"
REQUIREMENTS_FILE = ROOT_DIR / "requirements.txt"
BOOTSTRAP_FLAG = "ZEINAGUARD_VENV_ACTIVE"
DEFAULT_SENSOR_LOG_FILE = ROOT_DIR.parent / "logs" / "sensor.log"
LOGGER = logging.getLogger("zeinaguard.sensor.main")


def configure_logging():
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s %(levelname)s %(name)s: %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S",
        handlers=[logging.StreamHandler(sys.stdout)],
        force=True,
    )


def sensor_log_file() -> Path:
    configured_path = os.getenv("SENSOR_LOG_FILE", "").strip()
    return Path(configured_path) if configured_path else DEFAULT_SENSOR_LOG_FILE


def append_crash_report(message, exc_info):
    log_path = sensor_log_file()
    log_path.parent.mkdir(parents=True, exist_ok=True)
    timestamp = datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S")
    crash_report = "".join(traceback.format_exception(*exc_info))
    with log_path.open("a", encoding="utf-8") as handle:
        handle.write(f"{timestamp} CRITICAL {message}\n")
        handle.write(crash_report)
        if not crash_report.endswith("\n"):
            handle.write("\n")


def install_thread_exception_logging():
    def _thread_excepthook(args):
        exc_info = (args.exc_type, args.exc_value, args.exc_traceback)
        LOGGER.error("Unhandled exception in thread %s", args.thread.name, exc_info=exc_info)
        append_crash_report(f"Unhandled exception in thread {args.thread.name}", exc_info)

    threading.excepthook = _thread_excepthook


def _venv_python_path():
    if os.name == "nt":
        return VENV_DIR / "Scripts" / "python.exe"
    return VENV_DIR / "bin" / "python"


def ensure_virtualenv():
    import shutil

    def running_inside_target_venv():
        try:
            return Path(sys.prefix).resolve() == VENV_DIR.resolve()
        except OSError:
            return Path(sys.prefix) == VENV_DIR

    if running_inside_target_venv() and _venv_python_path().exists():
        return

    if os.environ.get(BOOTSTRAP_FLAG) == "1" and running_inside_target_venv():
        return

    marker = VENV_DIR / ".requirements-installed"

    def log(message):
        print(message, flush=True)

    def run_command(command, error_message, capture_output=False):
        try:
            return subprocess.run(
                command,
                check=True,
                text=True,
                capture_output=capture_output,
            )
        except FileNotFoundError:
            raise RuntimeError(f"{error_message}: command not found: {command[0]}")
        except subprocess.CalledProcessError as exc:
            details = ""
            if exc.stderr:
                details = exc.stderr.strip()
            elif exc.stdout:
                details = exc.stdout.strip()
            suffix = f": {details}" if details else f" (exit code {exc.returncode})"
            raise RuntimeError(f"{error_message}{suffix}")

    def pip_available(python_path):
        try:
            subprocess.run(
                [str(python_path), "-m", "pip", "--version"],
                check=True,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
            )
            return True
        except (FileNotFoundError, subprocess.CalledProcessError):
            return False

    def remove_venv():
        if not VENV_DIR.exists():
            return
        try:
            shutil.rmtree(VENV_DIR)
        except OSError as exc:
            raise RuntimeError(f"Failed to remove broken virtual environment: {exc}")

    def create_venv():
        log("[Bootstrap] Creating virtual environment...")
        run_command(
            [sys.executable, "-m", "venv", str(VENV_DIR)],
            "Failed to create virtual environment",
        )

    def install_system_dependencies():
        if os.name == "nt":
            raise RuntimeError("Automatic system dependency installation is only supported on Debian/Ubuntu")
        log("[Bootstrap] Installing system dependencies...")
        run_command(
            ["sudo", "apt-get", "update"],
            "Failed to update apt package lists",
        )
        run_command(
            ["sudo", "apt-get", "install", "-y", "python3-venv", "python3-pip"],
            "Failed to install python3-venv and python3-pip",
        )

    def validate_venv():
        python_path = _venv_python_path()
        if not VENV_DIR.exists():
            return False, "missing", python_path
        if not python_path.exists():
            return False, "python-missing", python_path
        if not pip_available(python_path):
            return False, "pip-missing", python_path
        return True, "", python_path

    try:
        is_valid, reason, venv_python = validate_venv()

        if not is_valid and reason != "missing":
            log("[Bootstrap] Existing venv is broken -> recreating...")
            remove_venv()

        if not VENV_DIR.exists():
            create_venv()
            venv_python = _venv_python_path()

        log("[Bootstrap] Ensuring pip is available...")
        try:
            run_command(
                [str(venv_python), "-m", "ensurepip", "--upgrade"],
                "Failed to bootstrap pip inside the virtual environment",
            )
        except RuntimeError:
            install_system_dependencies()
            if VENV_DIR.exists():
                log("[Bootstrap] Existing venv is broken -> recreating...")
                remove_venv()
            create_venv()
            venv_python = _venv_python_path()
            log("[Bootstrap] Ensuring pip is available...")
            run_command(
                [str(venv_python), "-m", "ensurepip", "--upgrade"],
                "Failed to bootstrap pip inside the virtual environment after reinstalling system dependencies",
            )

        if not pip_available(venv_python):
            install_system_dependencies()
            if VENV_DIR.exists():
                log("[Bootstrap] Existing venv is broken -> recreating...")
                remove_venv()
            create_venv()
            venv_python = _venv_python_path()
            log("[Bootstrap] Ensuring pip is available...")
            run_command(
                [str(venv_python), "-m", "ensurepip", "--upgrade"],
                "Failed to bootstrap pip inside the recreated virtual environment",
            )
            if not pip_available(venv_python):
                raise RuntimeError("pip is still unavailable after recreating the virtual environment")

        log("[Bootstrap] Installing dependencies...")
        run_command(
            [str(venv_python), "-m", "pip", "install", "--upgrade", "pip", "setuptools", "wheel"],
            "Failed to upgrade pip, setuptools, and wheel",
        )
        run_command(
            [str(venv_python), "-m", "pip", "install", "-r", str(REQUIREMENTS_FILE)],
            "Failed to install sensor requirements",
        )

        log("[Bootstrap] Verifying dependencies...")
        verification_script = (
            "import psutil\n"
            "import requests\n"
            "import rich\n"
            "import socketio\n"
            "import websocket\n"
            "from scapy.all import sniff\n"
        )
        try:
            run_command(
                [str(venv_python), "-c", verification_script],
                "Failed to verify installed sensor dependencies",
            )
        except RuntimeError:
            log("[Bootstrap] Missing dependency detected -> reinstalling requirements...")
            run_command(
                [str(venv_python), "-m", "pip", "install", "-r", str(REQUIREMENTS_FILE)],
                "Failed to reinstall sensor requirements",
            )
            run_command(
                [str(venv_python), "-c", verification_script],
                "Failed to verify installed sensor dependencies after reinstall",
            )
        log("[Bootstrap] All dependencies loaded successfully")
        marker.write_text("ok\n", encoding="utf-8")

        if not running_inside_target_venv():
            log("[Bootstrap] Sensor environment ready")
            env = dict(os.environ)
            env[BOOTSTRAP_FLAG] = "1"
            os.execve(str(venv_python), [str(venv_python), __file__, *sys.argv[1:]], env)

        log("[Bootstrap] Sensor environment ready")
    except RuntimeError as exc:
        log(f"[Bootstrap] Failed to prepare sensor environment: {exc}")
        raise SystemExit(1)
    except Exception as exc:
        log(f"[Bootstrap] Failed to prepare sensor environment: {exc}")
        raise SystemExit(1)


def parse_args():
    parser = argparse.ArgumentParser(add_help=True)
    parser.add_argument("--test", action="store_true", help="Run a lightweight sensor self-test and exit")
    parser.add_argument("--dry-run", action="store_true", help="Run the supervisor sensor dry-run probe and exit")
    return parser.parse_args()


def run_self_test():
    ensure_virtualenv()
    configure_logging()

    import config
    from communication.api_client import APIClient  # noqa: F401
    from communication.ws_client import WSClient  # noqa: F401
    from detection.threat_manager import ThreatManager  # noqa: F401
    from monitoring.sniffer import start_monitoring  # noqa: F401
    from runtime_state import update_status  # noqa: F401

    available_interfaces = set(config.list_wireless_interfaces())
    requested_interface = os.getenv("SENSOR_INTERFACE") or config.get_interface()

    if hasattr(os, "geteuid") and os.geteuid() != 0:
        print("[Sensor Test] Root privileges are required for the sensor self-test.", flush=True)
        return 1

    if (
        requested_interface
        and requested_interface not in available_interfaces
        and not Path(f"/sys/class/net/{requested_interface}").exists()
    ):
        print(
            f"[Sensor Test] Requested interface '{requested_interface}' is unavailable. "
            f"Detected interfaces: {', '.join(sorted(available_interfaces))}",
            flush=True,
        )
        return 1

    print(
        "[Sensor Test] OK",
        {
            "backend_url": config.BACKEND_URL,
            "interface": requested_interface,
            "interfaces_detected": sorted(available_interfaces),
        },
        flush=True,
    )
    return 0


def main():
    ensure_virtualenv()
    configure_logging()
    install_thread_exception_logging()

    import config
    from communication.api_client import APIClient
    from communication.ws_client import WSClient
    from detection.threat_manager import ThreatManager
    from monitoring.sniffer import start_monitoring
    from runtime_state import update_status

    if hasattr(os, "geteuid") and os.geteuid() != 0:
        print("Warning: not running as root. Packet capture may fail.")

    selected_interface = config.select_wireless_interface()
    update_status(
        sensor_status="starting",
        backend_status="connecting",
        message=f"Booting sensor on {selected_interface}",
    )

    startup_timeout = int(os.getenv("SENSOR_BACKEND_READY_TIMEOUT_SECONDS", "15"))
    api = APIClient(backend_url=config.BACKEND_URL)
    api.wait_for_backend_ready(timeout_seconds=startup_timeout)
    token = api.authenticate_sensor(strict=True)
    update_status(
        backend_status="authenticated",
        message="Backend authenticated",
    )

    sensor_registration_key = (
        os.getenv("ZEINAGUARD_SENSOR_REGISTRATION_KEY")
        or os.getenv("ZEINAGUARD_SENSOR_ID")
    )
    print(
        "Starting WS client:",
        {
            "backend_url": config.BACKEND_URL,
            "interface": selected_interface,
            "registration_key": sensor_registration_key or "auto-hostname",
        },
    )
    ws_client = WSClient(
        backend_url=config.BACKEND_URL,
        token=token,
        sensor_id=sensor_registration_key,
    )
    ws_thread = threading.Thread(target=ws_client.start, daemon=True, name="WSClient")
    ws_thread.start()
    # ws_client.wait_until_ready(timeout_seconds=startup_timeout)

    threat_manager = ThreatManager()
    threading.Thread(target=threat_manager.start, daemon=True, name="ThreatManager").start()

    update_status(sensor_status="monitoring", message="Wireless monitoring active")
    start_monitoring()
    raise RuntimeError("Sensor monitoring loop exited unexpectedly")


def run():
    args = parse_args()
    if args.test or args.dry_run:
        return run_self_test()
    main()
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(run())
    except KeyboardInterrupt:
        raise SystemExit(130)
    except Exception:
        exc_info = sys.exc_info()
        LOGGER.exception("Sensor startup failed")
        append_crash_report("Sensor startup failed", exc_info)
        raise SystemExit(1)
