#!/usr/bin/env bash
# MLPro — one command to start the full stack
# Usage: ./start.sh

set -e
cd "$(dirname "$0")"

GREEN='\033[0;32m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
NC='\033[0m'

step()  { echo -e "\n${GREEN}▶ $1${NC}"; }
info()  { echo -e "  ${YELLOW}$1${NC}"; }
error() { echo -e "  ${RED}✗ $1${NC}"; }

# Check Docker is running
if ! docker info > /dev/null 2>&1; then
    error "Docker is not running. Start Docker and try again."
    exit 1
fi

step "Building images (first run takes ~3 min)"
docker compose build --quiet

step "Starting Postgres + MinIO"
docker compose up -d postgres minio minio-init
until docker compose ps postgres | grep -q "healthy"; do sleep 2; done
info "Postgres ready"

step "Starting MLflow"
docker compose up -d mlflow
until docker compose ps mlflow | grep -q "healthy"; do sleep 3; done
info "MLflow ready"

step "Initializing Airflow"
docker compose up -d airflow-init
until docker compose ps airflow-init 2>/dev/null | grep -qE "Exit|Exited"; do sleep 3; done

step "Starting Airflow + Grafana"
docker compose up -d airflow-webserver airflow-scheduler grafana

step "Starting API"
docker compose up -d api
until docker compose logs --tail=5 api 2>/dev/null | grep -q "startup complete"; do sleep 2; done

echo ""
echo -e "${GREEN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
echo -e "${GREEN}  MLPro is running${NC}"
echo -e "${GREEN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
echo ""
echo "  API      → http://localhost:8000/api/health"
echo "  Airflow  → http://localhost:8080   (admin / admin)"
echo "  MLflow   → http://localhost:5000"
echo "  Grafana  → http://localhost:3000   (admin / admin)"
echo "  MinIO    → http://localhost:9001   (minioadmin / minioadmin)"
echo ""

HEALTH=$(curl -s http://localhost:8000/api/health 2>/dev/null)
if echo "$HEALTH" | grep -q '"model_loaded":true'; then
    echo -e "${GREEN}  ✓ Model loaded — ready to score packages${NC}"
else
    echo -e "${YELLOW}  ⚠ API up but model not loaded — run: docker compose restart api${NC}"
fi
echo ""
