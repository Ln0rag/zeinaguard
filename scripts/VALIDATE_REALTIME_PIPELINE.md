# ZeinaGuard Realtime Validation

Use this checklist after backend, dashboard, and sensor are running.

## 1. Start services

Start the backend with your normal command and confirm `GET /health` returns `200`.

Start the dashboard and open the live page:

```text
http://localhost:3000/dashboard
```

If your deployment serves the dashboard from another host or port, use that address instead.

Start the sensor:

```text
python .\sensor\main.py
```

Expected sensor startup behavior:

- `.venv` is created automatically if missing
- `requirements.txt` is installed when needed
- wireless interfaces are listed
- the selected interface is stored and used for monitoring

## 2. Validate scan flow

Wait for scan traffic and confirm the dashboard live table begins filling in.

Expected logs:

- Sensor: `[QUEUE] queued network_scan`
- Sensor: `[SEND] event=network_scan`
- Backend: `[RECEIVED FROM SENSOR] event=network_scan`
- Backend: `[EMIT TO DASHBOARD] event=network_scan`
- Dashboard: `[EVENT RECEIVED] network_scan`

Pass condition:

- networks appear on the dashboard without polling
- the UI remains responsive under continuous updates

## 3. Validate targeted attack flow

From the dashboard live table, click `Attack` on a specific row.

The command payload must contain:

```json
{
  "sensor_id": 1,
  "target_bssid": "AA:BB:CC:DD:EE:FF",
  "channel": 6,
  "action": "deauth"
}
```

Expected logs:

- Dashboard: `[SOCKET EMIT] attack_command`
- Backend: `[FORWARD COMMAND] event=attack_command`
- Sensor: `[COMMAND RECEIVED] attack_command`

Pass condition:

- backend validates `sensor_id`
- command is forwarded only to the selected sensor
- no sensor executes a command for another sensor id

## 4. Validate attack acknowledgment

After the sensor executes the command, confirm the acknowledgment loop completes.

Expected logs:

- Sensor: `[ATTACK EXECUTED]`
- Sensor: `[QUEUE] queued attack_ack`
- Backend: `[RECEIVED FROM SENSOR] event=attack_ack`
- Backend: `[EMIT TO DASHBOARD] event=attack_ack`
- Dashboard: `[EVENT RECEIVED] attack_ack`

Pass condition:

- dashboard shows a success or failure notification
- activity stream includes the acknowledgment

## 5. Validate live sensor status

Wait at least 5 seconds after the sensor connects.

Expected logs:

- Sensor: `[QUEUE] queued sensor_status`
- Sensor: `[SEND] event=sensor_status`
- Backend: `[RECEIVED FROM SENSOR] event=sensor_status`
- Backend: `[EMIT TO DASHBOARD] event=sensor_status`
- Dashboard: `[EVENT RECEIVED] sensor_status`

Pass condition:

- dashboard sensor card updates in real time
- CPU and memory values are real metrics from `psutil`
- uptime increases over time

## 6. Optional helper script

You can run the companion script for endpoint checks and guided verification:

```powershell
.\scripts\validate-realtime-pipeline.ps1
```

Optional log paths:

```powershell
.\scripts\validate-realtime-pipeline.ps1 `
  -BackendLogPath .\backend.log `
  -SensorLogPath .\sensor.log `
  -DashboardLogPath .\dashboard.log
```
