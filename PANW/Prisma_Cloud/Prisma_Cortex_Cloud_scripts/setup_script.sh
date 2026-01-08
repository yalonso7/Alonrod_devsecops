#!/bin/bash

################################################################################
# Prisma Cloud WAAS Deployment Toolkit - Setup Script
################################################################################
#
# This script automates the initial setup of the WAAS deployment toolkit
#
# Usage:
#   ./setup.sh [options]
#
# Options:
#   --skip-deps       Skip dependency installation
#   --docker          Setup Docker environment
#   --ci-cd           Setup CI/CD templates
#   --help            Show this help message
#
################################################################################

set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
MAGENTA='\033[0;35m'
CYAN='\033[0;36m'
NC='\033[0m' # No Color

# Configuration
SKIP_DEPS=false
SETUP_DOCKER=false
SETUP_CICD=false
PYTHON_MIN_VERSION="3.7"

################################################################################
# Functions
################################################################################

print_banner() {
    echo -e "${BLUE}"
    cat << "EOF"
╔═══════════════════════════════════════════════════════════════════════════╗
║                                                                           ║
║   ██████╗ ██████╗ ██╗███████╗███╗   ███╗ █████╗                         ║
║   ██╔══██╗██╔══██╗██║██╔════╝████╗ ████║██╔══██╗                        ║
║   ██████╔╝██████╔╝██║███████╗██╔████╔██║███████║                        ║
║   ██╔═══╝ ██╔══██╗██║╚════██║██║╚██╔╝██║██╔══██║                        ║
║   ██║     ██║  ██║██║███████║██║ ╚═╝ ██║██║  ██║                        ║
║   ╚═╝     ╚═╝  ╚═╝╚═╝╚══════╝╚═╝     ╚═╝╚═╝  ╚═╝                        ║
║                                                                           ║
║              WAAS Deployment Toolkit Setup                                ║
║                                                                           ║
╚═══════════════════════════════════════════════════════════════════════════╝
EOF
    echo -e "${NC}"
}

log_info() {
    echo -e "${GREEN}✓${NC} $1"
}

log_warn() {
    echo -e "${YELLOW}⚠${NC} $1"
}

log_error() {
    echo -e "${RED}✗${NC} $1"
}

log_step() {
    echo -e "${CYAN}➜${NC} $1"
}

check_command() {
    if command -v "$1" &> /dev/null; then
        log_info "$1 is installed"
        return 0
    else
        log_warn "$1 is not installed"
        return 1
    fi
}

compare_versions() {
    local version1=$1
    local version2=$2
    
    if [[ "$(printf '%s\n' "$version1" "$version2" | sort -V | head -n1)" == "$version2" ]]; then
        return 0
    else
        return 1
    fi
}

check_python_version() {
    if ! check_command python3; then
        log_error "Python 3 is required but not installed"
        return 1
    fi
    
    local python_version=$(python3 --version | cut -d' ' -f2)
    log_info "Python version: $python_version"
    
    if compare_versions "$python_version" "$PYTHON_MIN_VERSION"; then
        log_info "Python version meets minimum requirement ($PYTHON_MIN_VERSION)"
        return 0
    else
        log_error "Python version $python_version is below minimum requirement $PYTHON_MIN_VERSION"
        return 1
    fi
}

create_directory_structure() {
    log_step "Creating directory structure..."
    
    directories=(
        "policies/dev/container"
        "policies/dev/host"
        "policies/dev/serverless"
        "policies/staging/container"
        "policies/staging/host"
        "policies/staging/serverless"
        "policies/production/container"
        "policies/production/host"
        "policies/production/serverless"
        "logs"
        "backups"
        "scripts"
        "config"
        "docs"
    )
    
    for dir in "${directories[@]}"; do
        if [ ! -d "$dir" ]; then
            mkdir -p "$dir"
            touch "$dir/.gitkeep"
            log_info "Created: $dir"
        else
            log_info "Already exists: $dir"
        fi
    done
}

install_python_dependencies() {
    log_step "Installing Python dependencies..."
    
    if [ ! -f "requirements.txt" ]; then
        log_error "requirements.txt not found"
        return 1
    fi
    
    # Create virtual environment
    if [ ! -d "venv" ]; then
        log_step "Creating virtual environment..."
        python3 -m venv venv
        log_info "Virtual environment created"
    fi
    
    # Activate virtual environment
    source venv/bin/activate
    
    # Upgrade pip
    log_step "Upgrading pip..."
    pip install --upgrade pip > /dev/null 2>&1
    
    # Install dependencies
    log_step "Installing required packages..."
    pip install -r requirements.txt
    
    log_info "Python dependencies installed"
}

create_env_file() {
    log_step "Creating environment configuration..."
    
    if [ -f ".env" ]; then
        log_warn ".env file already exists, skipping creation"
        return 0
    fi
    
    if [ ! -f ".env.example" ]; then
        log_error ".env.example not found"
        return 1
    fi
    
    cp .env.example .env
    log_info "Created .env file from template"
    log_warn "Please edit .env file and add your Prisma Cloud credentials"
}

setup_git_hooks() {
    log_step "Setting up Git hooks..."
    
    if [ ! -d ".git" ]; then
        log_warn "Not a git repository, skipping Git hooks"
        return 0
    fi
    
    # Create pre-commit hook
    cat > .git/hooks/pre-commit << 'EOF'
#!/bin/bash
# Pre-commit hook to prevent committing sensitive data

echo "Running pre-commit checks..."

# Check for sensitive data
if git diff --cached | grep -i -E "password|secret|api[_-]?key|token" | grep -v ".env.example"; then
    echo "ERROR: Possible sensitive data detected in staged files!"
    echo "Please review and remove before committing."
    exit 1
fi

# Check for .env file
if git diff --cached --name-only | grep -E "^\.env$"; then
    echo "ERROR: Attempting to commit .env file!"
    echo "This file should never be committed."
    exit 1
fi

echo "Pre-commit checks passed"
exit 0
EOF
    
    chmod +x .git/hooks/pre-commit
    log_info "Git pre-commit hook installed"
}

verify_deployment_script() {
    log_step "Verifying deployment script..."
    
    if [ ! -f "deploy_waas_policy.py" ]; then
        log_error "deploy_waas_policy.py not found"
        return 1
    fi
    
    # Make executable
    chmod +x deploy_waas_policy.py
    chmod +x batch_deploy.sh 2>/dev/null || true
    
    # Test syntax
    python3 -m py_compile deploy_waas_policy.py
    
    log_info "Deployment script verified"
}

setup_docker_environment() {
    log_step "Setting up Docker environment..."
    
    if ! check_command docker; then
        log_error "Docker is not installed"
        log_info "Please install Docker: https://docs.docker.com/get-docker/"
        return 1
    fi
    
    if [ ! -f "Dockerfile" ]; then
        log_error "Dockerfile not found"
        return 1
    fi
    
    log_step "Building Docker image..."
    docker build -t prisma-waas-deployer:latest .
    
    log_info "Docker image built successfully"
    log_info "Run with: docker-compose run --rm waas-deployer --help"
}

setup_cicd_templates() {
    log_step "Setting up CI/CD templates..."
    
    # Create .github directory for GitHub Actions
    if [ ! -d ".github/workflows" ]; then
        mkdir -p .github/workflows
        log_info "Created .github/workflows directory"
    fi
    
    # Create docs directory
    if [ ! -d "docs/cicd" ]; then
        mkdir -p docs/cicd
        log_info "Created docs/cicd directory"
    fi
    
    log_info "CI/CD templates setup complete"
    log_info "Available templates:"
    log_info "  - .github/workflows/deploy-waas.yml (GitHub Actions)"
    log_info "  - .gitlab-ci.yml (GitLab CI)"
    log_info "  - azure-pipelines.yml (Azure DevOps)"
    log_info "  - Jenkinsfile (Jenkins)"
}

run_initial_tests() {
    log_step "Running initial tests..."
    
    # Test Python import
    python3 << 'EOF'
import sys
try:
    import requests
    import yaml
    print("✓ All required Python modules are importable")
except ImportError as e:
    print(f"✗ Missing module: {e}")
    sys.exit(1)
EOF
    
    # Test deployment script help
    if python3 deploy_waas_policy.py --help > /dev/null 2>&1; then
        log_info "Deployment script is functional"
    else
        log_error "Deployment script test failed"
        return 1
    fi
}

generate_quick_start_guide() {
    log_step "Generating quick start guide..."
    
    cat > QUICKSTART.md << 'EOF'
# Quick Start Guide

## 1. Configure Credentials

Edit the `.env` file with your Prisma Cloud credentials:

```bash
vim .env
```

Required fields:
- `PRISMA_CONSOLE_URL`
- `PRISMA_USERNAME_DEV`
- `PRISMA_PASSWORD_DEV`

## 2. Test Connection

```bash
# Activate virtual environment
source venv/bin/activate

# Test authentication
python3 deploy_waas_policy.py \
  $PRISMA_CONSOLE_URL \
  $PRISMA_USERNAME_DEV \
  $PRISMA_PASSWORD_DEV \
  container \
  --export test-export.json
```

## 3. Create Your First Policy

```bash
# Copy sample policy
cp sample-waas-policy.yaml policies/dev/container/my-policy.yaml

# Edit policy
vim policies/dev/container/my-policy.yaml

# Deploy to development
python3 deploy_waas_policy.py \
  $PRISMA_CONSOLE_URL \
  $PRISMA_USERNAME_DEV \
  $PRISMA_PASSWORD_DEV \
  container \
  policies/dev/container/my-policy.yaml
```

## 4. Batch Deployment

```bash
# Deploy all development policies
./batch_deploy.sh -e dev --verbose
```

## 5. Next Steps

- Review the full [README.md](README.md)
- Explore [sample policies](policies/)
- Set up [CI/CD integration](docs/cicd/)
- Configure [alerting](docs/alerting.md)

## Troubleshooting

Run `./setup.sh --help` for setup options
Check logs in `logs/` directory
EOF
    
    log_info "Quick start guide created: QUICKSTART.md"
}

print_summary() {
    echo ""
    echo -e "${MAGENTA}═══════════════════════════════════════════════════════════${NC}"
    echo -e "${MAGENTA}                    Setup Complete!                         ${NC}"
    echo -e "${MAGENTA}═══════════════════════════════════════════════════════════${NC}"
    echo ""
    echo -e "${GREEN}✓ Directory structure created${NC}"
    echo -e "${GREEN}✓ Python dependencies installed${NC}"
    echo -e "${GREEN}✓ Environment configuration ready${NC}"
    echo -e "${GREEN}✓ Deployment scripts verified${NC}"
    echo ""
    echo -e "${YELLOW}Next Steps:${NC}"
    echo -e "  1. Edit ${CYAN}.env${NC} file with your credentials"
    echo -e "  2. Review ${CYAN}QUICKSTART.md${NC} for usage examples"
    echo -e "  3. Test connection: ${CYAN}source venv/bin/activate${NC}"
    echo -e "  4. Deploy your first policy"
    echo ""
    echo -e "${YELLOW}Important Files:${NC}"
    echo -e "  • ${CYAN}.env${NC}                    - Environment configuration"
    echo -e "  • ${CYAN}deploy_waas_policy.py${NC}   - Main deployment script"
    echo -e "  • ${CYAN}batch_deploy.sh${NC}         - Batch deployment script"
    echo -e "  • ${CYAN}sample-waas-policy.yaml${NC} - Example policy"
    echo -e "  • ${CYAN}QUICKSTART.md${NC}           - Quick start guide"
    echo -e "  • ${CYAN}README.md${NC}               - Full documentation"
    echo ""
    echo -e "${MAGENTA}═══════════════════════════════════════════════════════════${NC}"
    echo ""
}

show_help() {
    cat << EOF
Prisma Cloud WAAS Deployment Toolkit - Setup Script

Usage: $0 [options]

Options:
    --skip-deps       Skip Python dependency installation
    --docker          Setup Docker environment
    --ci-cd           Setup CI/CD templates
    --help            Show this help message

Examples:
    # Full setup
    ./setup.sh

    # Setup without installing dependencies
    ./setup.sh --skip-deps

    # Setup with Docker
    ./setup.sh --docker

    # Setup with CI/CD templates
    ./setup.sh --ci-cd

For more information, visit: https://docs.paloaltonetworks.com/
EOF
}

################################################################################
# Main
################################################################################

main() {
    print_banner
    
    log_step "Starting setup process..."
    echo ""
    
    # Check prerequisites
    log_step "Checking prerequisites..."
    if ! check_python_version; then
        log_error "Prerequisites check failed"
        exit 1
    fi
    
    check_command git || log_warn "Git not found, some features will be disabled"
    check_command docker || log_warn "Docker not found, Docker features will be disabled"
    echo ""
    
    # Create directory structure
    create_directory_structure
    echo ""
    
    # Install dependencies
    if [ "$SKIP_DEPS" = false ]; then
        install_python_dependencies
        echo ""
    else
        log_warn "Skipping dependency installation"
        echo ""
    fi
    
    # Create environment file
    create_env_file
    echo ""
    
    # Setup Git hooks
    setup_git_hooks
    echo ""
    
    # Verify deployment script
    verify_deployment_script
    echo ""
    
    # Setup Docker if requested
    if [ "$SETUP_DOCKER" = true ]; then
        setup_docker_environment
        echo ""
    fi
    
    # Setup CI/CD if requested
    if [ "$SETUP_CICD" = true ]; then
        setup_cicd_templates
        echo ""
    fi
    
    # Run tests
    run_initial_tests
    echo ""
    
    # Generate quick start guide
    generate_quick_start_guide
    echo ""
    
    # Print summary
    print_summary
}

################################################################################
# Parse arguments
################################################################################

while [[ $# -gt 0 ]]; do
    case $1 in
        --skip-deps)
            SKIP_DEPS=true
            shift
            ;;
        --docker)
            SETUP_DOCKER=true
            shift
            ;;
        --ci-cd)
            SETUP_CICD=true
            shift
            ;;
        --help|-h)
            show_help
            exit 0
            ;;
        *)
            log_error "Unknown option: $1"
            show_help
            exit 1
            ;;
    esac
done

# Run main function
main
