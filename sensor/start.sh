#!/usr/bin/env bash
echo "Starting ZeinaGuard..."
mkdir -p logs

echo "Starting Frontend (Port 3000)..."
pnpm dev > logs/frontend.log 2>&1 &

echo "Starting Backend (Port 5000)..."
(cd backend && ./.venv/bin/python app.py > ../logs/backend.log 2>&1) &

echo "Starting Sensor (Root)..."
(cd sensor && sudo ./.venv/bin/python main.py > ../logs/sensor.log 2>&1) &

echo "All services running! Dashboard: http://localhost:3000"
