#!/bin/bash

################################################################################
# Prisma Cloud WAAS Batch Deployment Script
################################################################################
#
# This script automates the deployment of multiple WAAS policies across
# different environments and policy types.
#
# Usage:
#   ./batch_deploy.sh [options]
#
# Options:
#   -e, --environment    Environment (dev, staging, production)
#   -d, --dry-run        Show what would be deployed without deploying
#   -v, --verbose        Enable verbose output
#   -b, --backup         Backup existing policies before deployment
#   -h, --help           Show this help message
#
# Examples:
#   # Deploy all policies to production
#   ./batch_deploy.sh -e production
#
#   # Dry run for staging
#   ./batch_deploy.sh -e staging --dry-run
#
#   # Deploy with backup
#   ./batch_deploy.sh -e production --backup --verbose
#
################################################################################

set -euo pipefail

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Default values
ENVIRONMENT=""
DRY_RUN=false
VERBOSE=false
BACKUP=false
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
POLICIES_DIR="${SCRIPT_DIR}/policies"
BACKUP_DIR="${SCRIPT_DIR}/backups"
LOG_DIR="${SCRIPT_DIR}/logs"
TIMESTAMP=$(date +%Y%m%d_%H%M%S)
LOG_FILE="${LOG_DIR}/deployment_${TIMESTAMP}.log"

# Create directories if they don't exist
mkdir -p "${POLICIES_DIR}" "${BACKUP_DIR}" "${LOG_DIR}"

################################################################################
# Functions
################################################################################

print_header() {
    echo -e "${BLUE}"
    echo "╔════════════════════════════════════════════════════════════════════╗"
    echo "║        Prisma Cloud WAAS Batch Deployment Tool                    ║"
    echo "╚════════════════════════════════════════════════════════════════════╝"
    echo -e "${NC}"
}

log() {
    local level=$1
    shift
    local message="$@"
    local timestamp=$(date '+%Y-%m-%d %H:%M:%S')
    
    echo "[${timestamp}] [${level}] ${message}" >> "${LOG_FILE}"
    
    case "${level}" in
        INFO)
            echo -e "${GREEN}✓${NC} ${message}"
            ;;
        WARN)
            echo -e "${YELLOW}⚠${NC} ${message}"
            ;;
        ERROR)
            echo -e "${RED}✗${NC} ${message}"
            ;;
        *)
            echo "${message}"
            ;;
    esac
}

show_help() {
    cat << EOF
Prisma Cloud WAAS Batch Deployment Script

Usage: $0 [options]

Options:
    -e, --environment ENV    Environment to deploy to (dev, staging, production)
    -d, --dry-run           Show what would be deployed without deploying
    -v, --verbose           Enable verbose output
    -b, --backup            Backup existing policies before deployment
    -h, --help              Show this help message

Environment Variables:
    PRISMA_CONSOLE_URL      Prisma Cloud console URL (required)
    PRISMA_USERNAME         Prisma Cloud username (required)
    PRISMA_PASSWORD         Prisma Cloud password (required)

Directory Structure:
    policies/
        ├── dev/
        │   ├── container/
        │   │   └── dev-api-policy.yaml
        │   ├── host/
        │   └── serverless/
        ├── staging/
        └── production/

Examples:
    # Deploy all production policies
    ./batch_deploy.sh -e production

    # Dry run for staging
    ./batch_deploy.sh -e staging --dry-run

    # Deploy with backup and verbose output
    ./batch_deploy.sh -e production --backup --verbose

EOF
}

check_requirements() {
    log "INFO" "Checking requirements..."
    
    # Check Python
    if ! command -v python3 &> /dev/null; then
        log "ERROR" "Python 3 is not installed"
        exit 1
    fi
    
    # Check required Python packages
    if ! python3 -c "import requests, yaml" 2>/dev/null; then
        log "ERROR" "Required Python packages not installed"
        log "INFO" "Run: pip install -r requirements.txt"
        exit 1
    fi
    
    # Check deployment script
    if [ ! -f "${SCRIPT_DIR}/deploy_waas_policy.py" ]; then
        log "ERROR" "deploy_waas_policy.py not found"
        exit 1
    fi
    
    # Check environment variables
    if [ -z "${PRISMA_CONSOLE_URL:-}" ]; then
        log "ERROR" "PRISMA_CONSOLE_URL environment variable not set"
        exit 1
    fi
    
    if [ -z "${PRISMA_USERNAME:-}" ]; then
        log "ERROR" "PRISMA_USERNAME environment variable not set"
        exit 1
    fi
    
    if [ -z "${PRISMA_PASSWORD:-}" ]; then
        log "ERROR" "PRISMA_PASSWORD environment variable not set"
        exit 1
    fi
    
    log "INFO" "All requirements met"
}

validate_environment() {
    local env=$1
    
    case "${env}" in
        dev|development)
            ENVIRONMENT="dev"
            ;;
        staging|stage)
            ENVIRONMENT="staging"
            ;;
        prod|production)
            ENVIRONMENT="production"
            ;;
        *)
            log "ERROR" "Invalid environment: ${env}"
            log "INFO" "Valid environments: dev, staging, production"
            exit 1
            ;;
    esac
}

backup_policies() {
    local policy_type=$1
    local backup_file="${BACKUP_DIR}/${ENVIRONMENT}_${policy_type}_${TIMESTAMP}.json"
    
    log "INFO" "Backing up ${policy_type} policies to ${backup_file}..."
    
    if python3 "${SCRIPT_DIR}/deploy_waas_policy.py" \
        "${PRISMA_CONSOLE_URL}" \
        "${PRISMA_USERNAME}" \
        "${PRISMA_PASSWORD}" \
        "${policy_type}" \
        --export \
        "${backup_file}" >> "${LOG_FILE}" 2>&1; then
        log "INFO" "Backup successful: ${backup_file}"
        return 0
    else
        log "WARN" "Backup failed for ${policy_type}"
        return 1
    fi
}

deploy_policy() {
    local policy_file=$1
    local policy_type=$2
    local policy_name=$(basename "${policy_file}" .yaml)
    
    log "INFO" "Deploying ${policy_name} (${policy_type})..."
    
    if [ "${DRY_RUN}" = true ]; then
        log "INFO" "[DRY RUN] Would deploy: ${policy_file}"
        return 0
    fi
    
    if [ "${VERBOSE}" = true ]; then
        python3 "${SCRIPT_DIR}/deploy_waas_policy.py" \
            "${PRISMA_CONSOLE_URL}" \
            "${PRISMA_USERNAME}" \
            "${PRISMA_PASSWORD}" \
            "${policy_type}" \
            "${policy_file}" 2>&1 | tee -a "${LOG_FILE}"
        local result=${PIPESTATUS[0]}
    else
        python3 "${SCRIPT_DIR}/deploy_waas_policy.py" \
            "${PRISMA_CONSOLE_URL}" \
            "${PRISMA_USERNAME}" \
            "${PRISMA_PASSWORD}" \
            "${policy_type}" \
            "${policy_file}" >> "${LOG_FILE}" 2>&1
        local result=$?
    fi
    
    if [ ${result} -eq 0 ]; then
        log "INFO" "Successfully deployed: ${policy_name}"
        return 0
    else
        log "ERROR" "Failed to deploy: ${policy_name}"
        return 1
    fi
}

deploy_policies_for_type() {
    local policy_type=$1
    local type_dir="${POLICIES_DIR}/${ENVIRONMENT}/${policy_type}"
    local success_count=0
    local failure_count=0
    
    if [ ! -d "${type_dir}" ]; then
        log "WARN" "No ${policy_type} policies found for ${ENVIRONMENT}"
        return 0
    fi
    
    # Backup if requested
    if [ "${BACKUP}" = true ] && [ "${DRY_RUN}" = false ]; then
        backup_policies "${policy_type}"
    fi
    
    log "INFO" "Processing ${policy_type} policies..."
    
    # Find all YAML files
    while IFS= read -r -d '' policy_file; do
        if deploy_policy "${policy_file}" "${policy_type}"; then
            ((success_count++))
        else
            ((failure_count++))
        fi
    done < <(find "${type_dir}" -name "*.yaml" -o -name "*.yml" -print0)
    
    log "INFO" "${policy_type} deployment complete: ${success_count} succeeded, ${failure_count} failed"
    
    return ${failure_count}
}

generate_summary() {
    local total_success=$1
    local total_failure=$2
    
    echo ""
    echo -e "${BLUE}═══════════════════════════════════════════════════════════${NC}"
    echo -e "${BLUE}                    Deployment Summary                      ${NC}"
    echo -e "${BLUE}═══════════════════════════════════════════════════════════${NC}"
    echo ""
    echo "Environment:        ${ENVIRONMENT}"
    echo "Timestamp:          $(date '+%Y-%m-%d %H:%M:%S')"
    echo "Dry Run:            ${DRY_RUN}"
    echo "Backup:             ${BACKUP}"
    echo ""
    echo -e "Total Success:      ${GREEN}${total_success}${NC}"
    echo -e "Total Failures:     ${RED}${total_failure}${NC}"
    echo ""
    echo "Log File:           ${LOG_FILE}"
    if [ "${BACKUP}" = true ]; then
        echo "Backup Location:    ${BACKUP_DIR}"
    fi
    echo -e "${BLUE}═══════════════════════════════════════════════════════════${NC}"
    echo ""
}

send_notification() {
    local status=$1
    local message=$2
    
    # Slack notification (if webhook is configured)
    if [ -n "${SLACK_WEBHOOK_URL:-}" ]; then
        local color="good"
        [ "${status}" = "failure" ] && color="danger"
        
        curl -X POST "${SLACK_WEBHOOK_URL}" \
            -H 'Content-Type: application/json' \
            -d "{
                \"attachments\": [{
                    \"color\": \"${color}\",
                    \"title\": \"WAAS Policy Deployment - ${ENVIRONMENT}\",
                    \"text\": \"${message}\",
                    \"footer\": \"Prisma Cloud\",
                    \"ts\": $(date +%s)
                }]
            }" &> /dev/null || true
    fi
    
    # Email notification (if configured)
    if [ -n "${NOTIFICATION_EMAIL:-}" ] && command -v mail &> /dev/null; then
        echo "${message}" | mail -s "WAAS Deployment - ${ENVIRONMENT} - ${status}" "${NOTIFICATION_EMAIL}" || true
    fi
}

main() {
    print_header
    
    log "INFO" "Starting batch deployment..."
    log "INFO" "Environment: ${ENVIRONMENT}"
    log "INFO" "Dry Run: ${DRY_RUN}"
    log "INFO" "Backup: ${BACKUP}"
    log "INFO" "Log File: ${LOG_FILE}"
    echo ""
    
    check_requirements
    
    local total_success=0
    local total_failure=0
    
    # Deploy each policy type
    for policy_type in container host serverless app-embedded; do
        if deploy_policies_for_type "${policy_type}"; then
            # Count successes from log
            local count=$(grep -c "Successfully deployed" "${LOG_FILE}" || echo 0)
            ((total_success += count))
        else
            # Count failures from log
            local count=$(grep -c "Failed to deploy" "${LOG_FILE}" || echo 0)
            ((total_failure += count))
        fi
        echo ""
    done
    
    # Generate summary
    generate_summary ${total_success} ${total_failure}
    
    # Send notification
    if [ ${total_failure} -eq 0 ]; then
        send_notification "success" "Successfully deployed ${total_success} WAAS policies to ${ENVIRONMENT}"
        log "INFO" "Deployment completed successfully"
        exit 0
    else
        send_notification "failure" "Deployment completed with ${total_failure} failures and ${total_success} successes"
        log "ERROR" "Deployment completed with failures"
        exit 1
    fi
}

################################################################################
# Parse command line arguments
################################################################################

while [[ $# -gt 0 ]]; do
    case $1 in
        -e|--environment)
            validate_environment "$2"
            shift 2
            ;;
        -d|--dry-run)
            DRY_RUN=true
            shift
            ;;
        -v|--verbose)
            VERBOSE=true
            shift
            ;;
        -b|--backup)
            BACKUP=true
            shift
            ;;
        -h|--help)
            show_help
            exit 0
            ;;
        *)
            log "ERROR" "Unknown option: $1"
            show_help
            exit 1
            ;;
    esac
done

# Check if environment was specified
if [ -z "${ENVIRONMENT}" ]; then
    log "ERROR" "Environment not specified"
    show_help
    exit 1
fi

# Run main function
main
