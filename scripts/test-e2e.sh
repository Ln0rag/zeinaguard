#!/bin/bash
# ZeinaGuard Pro - E2E Health Check Script
# Run after starting services locally: bash ./run.sh

set -e

API_URL="${API_URL:-http://localhost:5000}"
BASE_URL="${BASE_URL:-http://localhost:3000}"

echo "=========================================="
echo "ZeinaGuard Pro - E2E Health Check"
echo "=========================================="
echo ""
echo "API: $API_URL"
echo ""

# 1. Backend health
echo "1. Backend health..."
if curl -sf "$API_URL/health" > /dev/null; then
  echo "   ✓ Backend healthy"
else
  echo "   ✗ Backend unhealthy"
  exit 1
fi

# 2. Public API endpoints
echo "2. API endpoints..."
for EP in "/api/sensors" "/api/alerts" "/api/dashboard/overview" "/api/dashboard/incident-summary"; do
  STATUS=$(curl -s -o /dev/null -w "%{http_code}" "$API_URL$EP")
  if [ "$STATUS" = "200" ]; then
    echo "   ✓ $EP (200)"
  else
    echo "   ✗ $EP ($STATUS)"
  fi
done

echo ""
echo "=========================================="
echo "Health check complete"
echo "=========================================="
echo ""
echo "Manual checks:"
echo "  - Dashboard: $BASE_URL (redirects to /dashboard)"
echo "  - Incidents: $BASE_URL/incidents"
echo ""
