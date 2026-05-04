import logging
import os
import time

import requests


LOGGER = logging.getLogger("zeinaguard.sensor.api")
BACKEND_READY_TIMEOUT_SECONDS = int(os.getenv("SENSOR_BACKEND_READY_TIMEOUT_SECONDS", "15"))
BACKEND_READY_RETRY_INTERVAL_SECONDS = float(os.getenv("SENSOR_BACKEND_READY_RETRY_INTERVAL_SECONDS", "1"))
BACKEND_REQUEST_TIMEOUT_SECONDS = float(os.getenv("SENSOR_BACKEND_REQUEST_TIMEOUT_SECONDS", "2"))


class APIClient:
    def __init__(self, backend_url=None):
        self.backend_url = (backend_url or "http://localhost:5000").rstrip("/")
        self.username = "admin"
        self.password = "admin123"
        self.token = None

    def wait_for_backend_ready(self, timeout_seconds=BACKEND_READY_TIMEOUT_SECONDS):
        from runtime_state import update_status

        health_url = f"{self.backend_url}/health"
        ready_url = f"{self.backend_url}/ready"
        socket_url = f"{self.backend_url}/socket.io/?transport=polling&EIO=4&t=sensor-startup"
        deadline = time.monotonic() + timeout_seconds
        attempt = 0
        last_error = "backend did not respond"

        while time.monotonic() < deadline:
            attempt += 1
            try:
                update_status(
                    backend_status="connecting",
                    message=f"Waiting for backend readiness (attempt {attempt})",
                )

                health_response = requests.get(health_url, timeout=BACKEND_REQUEST_TIMEOUT_SECONDS)
                health_response.raise_for_status()
                health_payload = health_response.json()
                if health_payload.get("status") != "healthy":
                    raise RuntimeError(f"/health returned unexpected status: {health_payload}")

                ready_response = requests.get(ready_url, timeout=BACKEND_REQUEST_TIMEOUT_SECONDS)
                ready_response.raise_for_status()
                ready_payload = ready_response.json()
                if not ready_payload.get("ready"):
                    raise RuntimeError(f"/ready returned not-ready payload: {ready_payload}")

                socket_response = requests.get(socket_url, timeout=BACKEND_REQUEST_TIMEOUT_SECONDS)
                socket_response.raise_for_status()
                if "sid" not in socket_response.text:
                    raise RuntimeError("Socket.IO polling handshake did not return a session id")

                update_status(backend_status="ready", message="Backend HTTP and Socket.IO are ready")
                LOGGER.info("[Backend] readiness gate passed for %s", self.backend_url)
                return
            except (requests.exceptions.RequestException, ValueError, RuntimeError) as exc:
                last_error = str(exc)
                LOGGER.warning("[Backend] readiness attempt %s failed: %s", attempt, exc)
                time.sleep(BACKEND_READY_RETRY_INTERVAL_SECONDS)

        update_status(
            backend_status="offline",
            message=f"Backend readiness timed out after {timeout_seconds}s",
        )
        raise RuntimeError(
            f"Backend at {self.backend_url} was not ready within {timeout_seconds}s: {last_error}"
        )

    def authenticate_sensor(self, *, strict=False):
        from runtime_state import update_status

        url = f"{self.backend_url}/api/auth/login"
        payload = {
            "username": self.username,
            "password": self.password,
        }

        try:
            update_status(backend_status="authenticating", message="Authenticating with backend")
            response = requests.post(url, json=payload, timeout=5)

            if response.status_code != 200:
                message = f"Authentication failed ({response.status_code})"
                update_status(
                    backend_status="offline",
                    message=message,
                )
                if strict:
                    raise RuntimeError(message)
                return None

            data = response.json()
            self.token = data.get("access_token") or data.get("token")
            if not self.token:
                message = "No token in backend response"
                update_status(backend_status="offline", message=message)
                if strict:
                    raise RuntimeError(message)
                return None

            update_status(backend_status="authenticated", message="Authentication successful")
            return self.token
        except (requests.exceptions.RequestException, ValueError) as exc:
            message = f"Backend connection error: {exc}"
            update_status(backend_status="offline", message=message)
            if strict:
                raise RuntimeError(message) from exc
            return None

    def get_headers(self):
        if not self.token:
            return {}

        return {
            "Authorization": f"Bearer {self.token}",
            "Content-Type": "application/json",
        }
