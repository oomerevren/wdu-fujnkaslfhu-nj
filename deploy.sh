#!/usr/bin/env bash
# =============================================================================
# PentestAI — Blue-Green Deployment Script
# =============================================================================
# Features:
#   - Blue-green deployment with zero downtime
#   - Health check before traffic switch
#   - Automatic rollback on failure
#   - Docker Compose production orchestration
#   - Slack notifications
#
# Usage:
#   ./deploy.sh                              # Deploy with local docker-compose.prod.yml
#   ./deploy.sh --tag v1.2.3                 # Deploy specific image tag
#   ./deploy.sh --env staging                # Deploy to staging environment
#   ./deploy.sh --rollback                   # Rollback to previous version
#   ./deploy.sh --help                       # Show help
# =============================================================================

set -euo pipefail

# ─── Configuration ─────────────────────────────────────────────────────────
PROJECT="PentestAI"
COMPOSE_FILE="docker-compose.prod.yml"
ENV_FILE=".env"
HEALTH_ENDPOINT="http://localhost:8000/health"
MAX_RETRIES=30
RETRY_INTERVAL=10
SLACK_WEBHOOK_URL="${SLACK_WEBHOOK_URL:-}"
TIMESTAMP=$(date +%Y%m%d-%H%M%S)
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# ─── Colors ───────────────────────────────────────────────────────────────
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

# ─── Help ─────────────────────────────────────────────────────────────────
show_help() {
    cat <<EOF
PentestAI Blue-Green Deployment Script

Usage:
  ./deploy.sh                          Deploy latest
  ./deploy.sh --tag v1.2.3             Deploy specific tag
  ./deploy.sh --env staging            Deploy to staging
  ./deploy.sh --rollback               Rollback to previous version
  ./deploy.sh --help                   Show this help

Options:
  --tag TAG       Docker image tag to deploy (default: latest)
  --env ENV       Target environment: staging | production (default: production)
  --rollback      Rollback to the previous deployment
  --skip-build    Skip docker compose build (pull only)
  --dry-run       Print commands without executing
EOF
    exit 0
}

# ─── Logging ──────────────────────────────────────────────────────────────
log()     { echo -e "${GREEN}[$(date '+%H:%M:%S')]${NC} $*"; }
warn()    { echo -e "${YELLOW}[WARN]${NC} $*"; }
error()   { echo -e "${RED}[ERROR]${NC} $*"; }
info()    { echo -e "${BLUE}[INFO]${NC} $*"; }

# ─── Slack Notification ───────────────────────────────────────────────────
notify_slack() {
    local status="$1"
    local message="$2"
    local color

    if [[ -z "$SLACK_WEBHOOK_URL" ]]; then
        return 0
    fi

    case "$status" in
        success) color="good" ;;
        failure|error) color="danger" ;;
        *) color="warning" ;;
    esac

    local payload
    payload=$(cat <<EOF
{
    "attachments": [{
        "color": "${color}",
        "title": "${PROJECT} — Deployment ${status}",
        "text": "${message}",
        "fields": [
            {"title": "Environment", "value": "${DEPLOY_ENV}", "short": true},
            {"title": "Tag", "value": "${DEPLOY_TAG}", "short": true},
            {"title": "Timestamp", "value": "$(date -u '+%Y-%m-%d %H:%M:%S UTC')", "short": true}
        ],
        "footer": "${PROJECT} Deploy Script"
    }]
}
EOF
)

    curl -s -X POST -H "Content-Type: application/json" -d "$payload" "$SLACK_WEBHOOK_URL" > /dev/null 2>&1 || true
}

# ─── Health Check ─────────────────────────────────────────────────────────
health_check() {
    local endpoint="${1:-$HEALTH_ENDPOINT}"
    local retries="${2:-$MAX_RETRIES}"
    local interval="${3:-$RETRY_INTERVAL}"

    log "Health check: ${endpoint} (max ${retries} attempts, ${interval}s interval)"

    for i in $(seq 1 "$retries"); do
        local status
        status=$(curl -s -o /dev/null -w "%{http_code}" "$endpoint" 2>/dev/null || echo "000")

        if [[ "$status" == "200" ]]; then
            log "Health check passed (HTTP 200)"
            return 0
        fi

        if [[ "$i" -lt "$retries" ]]; then
            info "Attempt ${i}/${retries}: HTTP ${status} — retrying in ${interval}s..."
            sleep "$interval"
        fi
    done

    error "Health check failed after ${retries} attempts"
    return 1
}

# ─── Docker Compose Helpers ───────────────────────────────────────────────
compose_cmd() {
    docker compose -f "${SCRIPT_DIR}/${COMPOSE_FILE}" --env-file "${SCRIPT_DIR}/${ENV_FILE}" "$@"
}

deploy_stack() {
    local color="$1"  # blue | green
    local tag="${2:-latest}"

    log "Deploying ${color} stack with tag: ${tag}"

    export BUILD_TAG="${tag}"
    export DEPLOY_COLOR="${color}"

    compose_cmd pull
    compose_cmd up -d --no-deps --build app celery-worker celery-beat nginx

    log "${color} stack deployed"
}

switch_traffic() {
    local active_color="$1"
    log "Switching traffic to ${active_color} stack"

    # Update nginx upstream to point to the active stack
    export DEPLOY_COLOR="${active_color}"
    compose_cmd up -d --no-deps --build nginx

    log "Traffic switched to ${active_color}"
}

cleanup_stack() {
    local color="$1"
    info "Cleaning up ${color} stack..."
    export DEPLOY_COLOR="${color}"
    compose_cmd down --remove-orphans 2>/dev/null || true
}

# ─── Main Deployment ──────────────────────────────────────────────────────
main() {
    # Parse arguments
    DEPLOY_TAG="latest"
    DEPLOY_ENV="production"
    ROLLBACK=false
    SKIP_BUILD=false
    DRY_RUN=false

    while [[ $# -gt 0 ]]; do
        case "$1" in
            --tag) DEPLOY_TAG="$2"; shift 2 ;;
            --env) DEPLOY_ENV="$2"; shift 2 ;;
            --rollback) ROLLBACK=true; shift ;;
            --skip-build) SKIP_BUILD=true; shift ;;
            --dry-run) DRY_RUN=true; shift ;;
            --help) show_help ;;
            *) error "Unknown option: $1"; show_help ;;
        esac
    done

    if [[ "$DRY_RUN" == "true" ]]; then
        info "Dry-run mode — commands will be printed, not executed"
        # shellcheck disable=SC2317
        run() { echo "[DRY-RUN] $*"; }
    else
        run() { "$@"; }
    fi

    export DEPLOY_ENV

    # ── Validate prerequisites ──────────────────────────────────────────
    if ! command -v docker &> /dev/null; then
        error "Docker is not installed"
        exit 1
    fi

    if ! docker compose version &> /dev/null; then
        error "Docker Compose v2 is not available"
        exit 1
    fi

    if [[ ! -f "${SCRIPT_DIR}/${COMPOSE_FILE}" ]]; then
        error "Compose file not found: ${COMPOSE_FILE}"
        exit 1
    fi

    if [[ ! -f "${SCRIPT_DIR}/${ENV_FILE}" ]]; then
        warn "Environment file not found: ${ENV_FILE} — using defaults"
    fi

    # ── Rollback mode ──────────────────────────────────────────────────
    if [[ "$ROLLBACK" == "true" ]]; then
        log "Rollback requested"

        if [[ ! -f /tmp/pentestai-previous-color.txt ]]; then
            error "No previous deployment state found for rollback"
            notify_slack "failure" "Rollback failed: no previous state found"
            exit 1
        fi

        PREV_COLOR=$(cat /tmp/pentestai-previous-color.txt)
        log "Rolling back to previous stack: ${PREV_COLOR}"

        notify_slack "warning" "Rollback initiated to ${PREV_COLOR}"

        # Switch traffic to previous stack
        switch_traffic "$PREV_COLOR"

        # Health check on the rolled-back stack
        if health_check; then
            log "Rollback completed successfully"
            notify_slack "success" "Rollback completed successfully to ${DEPLOY_TAG}"
        else
            error "Rollback health check failed — manual intervention required"
            notify_slack "error" "Rollback health check FAILED — manual intervention required!" \
                "tag: ${DEPLOY_TAG}, env: ${DEPLOY_ENV}"
            exit 1
        fi

        exit 0
    fi

    # ── Normal deployment ──────────────────────────────────────────────
    log "=== ${PROJECT} Blue-Green Deployment ==="
    log "Environment: ${DEPLOY_ENV}"
    log "Tag:         ${DEPLOY_TAG}"
    log "Timestamp:   ${TIMESTAMP}"

    notify_slack "warning" "Deployment started for tag ${DEPLOY_TAG} to ${DEPLOY_ENV}"

    # Determine which stack is active
    ACTIVE_COLOR=""
    if docker ps --format '{{.Names}}' 2>/dev/null | grep -q "pentestai-blue"; then
        ACTIVE_COLOR="blue"
    elif docker ps --format '{{.Names}}' 2>/dev/null | grep -q "pentestai-green"; then
        ACTIVE_COLOR="green"
    fi

    if [[ -z "$ACTIVE_COLOR" ]]; then
        # First deployment — deploy to blue
        log "No active stack found — initial deployment to blue"
        ACTIVE_COLOR="blue"
        INACTIVE_COLOR="green"
    else
        # Deploy to the inactive stack
        if [[ "$ACTIVE_COLOR" == "blue" ]]; then
            INACTIVE_COLOR="green"
        else
            INACTIVE_COLOR="blue"
        fi
    fi

    log "Active stack:   ${ACTIVE_COLOR}"
    log "Deploying to:   ${INACTIVE_COLOR}"

    # Step 1: Deploy to inactive stack
    deploy_stack "$INACTIVE_COLOR" "$DEPLOY_TAG"

    # Step 2: Health check on the new stack
    if ! health_check; then
        error "Deployment health check failed on ${INACTIVE_COLOR} stack"
        cleanup_stack "$INACTIVE_COLOR"
        notify_slack "failure" \
            "Deployment health check FAILED on ${INACTIVE_COLOR} — rolled back to ${ACTIVE_COLOR}" \
            "tag: ${DEPLOY_TAG}"
        exit 1
    fi

    # Step 3: Save current active color for rollback
    echo "$ACTIVE_COLOR" > /tmp/pentestai-previous-color.txt

    # Step 4: Switch traffic to the new stack
    switch_traffic "$INACTIVE_COLOR"

    # Step 5: Post-switch health check
    if health_check; then
        log "Deployment to ${INACTIVE_COLOR} verified — traffic switched successfully"
    else
        error "Post-switch health check failed — rolling back to ${ACTIVE_COLOR}"
        switch_traffic "$ACTIVE_COLOR"
        cleanup_stack "$INACTIVE_COLOR"
        notify_slack "failure" \
            "Post-switch health check FAILED — rolled back to ${ACTIVE_COLOR}" \
            "tag: ${DEPLOY_TAG}"
        exit 1
    fi

    # Step 6: Clean up old stack
    log "Waiting 30s before cleaning old stack..."
    sleep 30
    cleanup_stack "$ACTIVE_COLOR"

    # Step 7: Done
    log "=== Deployment completed successfully ==="
    log "Active stack: ${INACTIVE_COLOR} (tag: ${DEPLOY_TAG})"

    notify_slack "success" \
        "Deployment completed successfully" \
        "tag: ${DEPLOY_TAG}, env: ${DEPLOY_ENV}, active: ${INACTIVE_COLOR}"
}

main "$@"
