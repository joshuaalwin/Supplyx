#!/usr/bin/env bash
# MLPro — start the full stack
# Usage: ./start.sh

set -e
cd "$(dirname "$0")"

GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

step() { echo -e "\n${GREEN}▶ $1${NC}"; }
info() { echo -e "  ${YELLOW}$1${NC}"; }

step "Starting Postgres + MinIO"
docker compose up -d postgres minio minio-init

step "Waiting for Postgres"
until docker compose ps postgres | grep -q "healthy"; do sleep 2; done
info "Postgres ready"

step "Starting MLflow"
docker compose up -d mlflow
until docker compose ps mlflow | grep -q "healthy"; do sleep 3; done
info "MLflow ready"

step "Starting Airflow"
docker compose up -d airflow-init
until docker compose ps airflow-init 2>/dev/null | grep -qE "Exit|Exited"; do sleep 3; done
docker compose up -d airflow-webserver airflow-scheduler
info "Airflow starting (takes ~30s)"

step "Starting Grafana"
docker compose up -d grafana

step "Starting API"
docker compose up -d api
until docker compose logs --tail=5 api 2>/dev/null | grep -q "startup complete"; do sleep 2; done
info "API ready"

step "All services up"
docker compose ps

echo ""
echo -e "${GREEN}Services:${NC}"
echo "  Airflow   → http://localhost:8080  (admin / admin)"
echo "  MLflow    → http://localhost:5000"
echo "  API       → http://localhost:8000/api/health"
echo "  Grafana   → http://localhost:3000  (admin / admin)"
echo "  MinIO     → http://localhost:9001  (minioadmin / minioadmin)"
echo ""

# Quick API health check
HEALTH=$(curl -s http://localhost:8000/api/health 2>/dev/null)
if echo "$HEALTH" | grep -q '"model_loaded":true'; then
    echo -e "${GREEN}✓ Model loaded and ready${NC}"
elif echo "$HEALTH" | grep -q '"model_loaded":false'; then
    echo -e "${YELLOW}⚠ API is up but model not loaded yet — run: docker compose restart api${NC}"
else
    echo -e "${YELLOW}⚠ API not responding — check: docker compose logs api${NC}"
fi
