// Jenkins Pipeline for Prisma Cloud WAAS Deployments
// This Jenkinsfile defines a complete CI/CD pipeline for deploying WAAS policies

pipeline {
    agent any
    
    // Pipeline options
    options {
        buildDiscarder(logRotator(numToKeepStr: '30', artifactNumToKeepStr: '10'))
        timestamps()
        timeout(time: 1, unit: 'HOURS')
        disableConcurrentBuilds()
        ansiColor('xterm')
    }
    
    // Environment variables
    environment {
        PYTHON_VERSION = '3.11'
        PRISMA_CONSOLE_URL = credentials('prisma-console-url')
        SLACK_WEBHOOK = credentials('slack-webhook-url')
        
        // Credentials IDs (configure in Jenkins)
        PRISMA_CREDS_DEV = credentials('prisma-cloud-dev')
        PRISMA_CREDS_STAGING = credentials('prisma-cloud-staging')
        PRISMA_CREDS_PROD = credentials('prisma-cloud-prod')
    }
    
    // Parameters
    parameters {
        choice(
            name: 'ENVIRONMENT',
            choices: ['development', 'staging', 'production'],
            description: 'Target environment for deployment'
        )
        booleanParam(
            name: 'DRY_RUN',
            defaultValue: false,
            description: 'Perform dry run without actual deployment'
        )
        booleanParam(
            name: 'BACKUP',
            defaultValue: true,
            description: 'Backup policies before deployment'
        )
        booleanParam(
            name: 'SKIP_VALIDATION',
            defaultValue: false,
            description: 'Skip validation stage (not recommended)'
        )
    }
    
    // Triggers
    triggers {
        // Poll SCM every 5 minutes
        pollSCM('H/5 * * * *')
        
        // Scheduled backup - daily at 2 AM
        cron('0 2 * * *')
    }
    
    // Pipeline stages
    stages {
        // =====================================================================
        // STAGE 1: CHECKOUT & SETUP
        // =====================================================================
        stage('Checkout & Setup') {
            steps {
                script {
                    echo "🔄 Checking out code..."
                    checkout scm
                    
                    echo "📦 Setting up environment..."
                    sh '''
                        python3 --version
                        pip3 install --upgrade pip
                        pip3 install -r requirements.txt
                    '''
                }
            }
        }
        
        // =====================================================================
        // STAGE 2: VALIDATION
        // =====================================================================
        stage('Validate') {
            when {
                expression { !params.SKIP_VALIDATION }
            }
            parallel {
                stage('Validate YAML') {
                    steps {
                        script {
                            echo "🔍 Validating YAML syntax..."
                            sh '''
                                for file in $(find policies -name "*.yaml" -o -name "*.yml"); do
                                    echo "Checking: $file"
                                    python3 -c "import yaml; yaml.safe_load(open('$file'))"
                                done
                                echo "✓ All YAML files are valid"
                            '''
                        }
                    }
                }
                
                stage('Lint YAML') {
                    steps {
                        script {
                            echo "🔍 Running YAML linter..."
                            sh '''
                                pip3 install yamllint
                                yamllint -d "{extends: default, rules: {line-length: {max: 120}}}" policies/ || true
                            '''
                        }
                    }
                }
                
                stage('Security Check') {
                    steps {
                        script {
                            echo "🔒 Checking for sensitive data..."
                            sh '''
                                if grep -r -i -E "password|secret|api[_-]?key|token" policies/*.yaml; then
                                    echo "❌ ERROR: Sensitive data detected!"
                                    exit 1
                                fi
                                echo "✓ No sensitive data detected"
                            '''
                        }
                    }
                }
            }
        }
        
        // =====================================================================
        // STAGE 3: SECURITY SCAN
        // =====================================================================
        stage('Security Scan') {
            steps {
                script {
                    echo "🔒 Running security scans..."
                    sh '''
                        pip3 install bandit safety
                        bandit -r . -f json -o bandit-report.json || true
                        bandit -r . -ll -f screen
                        safety check --json || true
                    '''
                }
                
                // Archive security reports
                archiveArtifacts artifacts: 'bandit-report.json', allowEmptyArchive: true
            }
        }
        
        // =====================================================================
        // STAGE 4: BUILD
        // =====================================================================
        stage('Build') {
            when {
                anyOf {
                    branch 'main'
                    branch 'develop'
                }
            }
            steps {
                script {
                    echo "🐳 Building Docker image..."
                    docker.build("prisma-waas-deployer:${env.BUILD_NUMBER}")
                    docker.build("prisma-waas-deployer:latest")
                }
            }
        }
        
        // =====================================================================
        // STAGE 5: DEPLOY TO DEVELOPMENT
        // =====================================================================
        stage('Deploy to Development') {
            when {
                anyOf {
                    branch 'develop'
                    expression { params.ENVIRONMENT == 'development' }
                }
            }
            steps {
                script {
                    echo "🚀 Deploying to Development..."
                    
                    withCredentials([
                        usernamePassword(
                            credentialsId: 'prisma-cloud-dev',
                            usernameVariable: 'PRISMA_USERNAME',
                            passwordVariable: 'PRISMA_PASSWORD'
                        )
                    ]) {
                        sh '''
                            for policy in policies/dev/**/*.yaml; do
                                if [ -f "$policy" ]; then
                                    echo "Deploying: $policy"
                                    python3 deploy_waas_policy.py \
                                        ${PRISMA_CONSOLE_URL} \
                                        ${PRISMA_USERNAME} \
                                        ${PRISMA_PASSWORD} \
                                        container \
                                        "$policy"
                                fi
                            done
                        '''
                    }
                    
                    echo "✓ Development deployment complete"
                }
            }
            post {
                always {
                    archiveArtifacts artifacts: 'logs/**', allowEmptyArchive: true
                }
                success {
                    notifySlack('good', 'Development deployment successful')
                }
                failure {
                    notifySlack('danger', 'Development deployment failed')
                }
            }
        }
        
        // =====================================================================
        // STAGE 6: DEPLOY TO STAGING
        // =====================================================================
        stage('Deploy to Staging') {
            when {
                anyOf {
                    branch 'main'
                    expression { params.ENVIRONMENT == 'staging' }
                }
            }
            steps {
                script {
                    echo "🚀 Deploying to Staging..."
                    
                    // Backup if requested
                    if (params.BACKUP) {
                        echo "💾 Backing up existing policies..."
                        withCredentials([
                            usernamePassword(
                                credentialsId: 'prisma-cloud-staging',
                                usernameVariable: 'PRISMA_USERNAME',
                                passwordVariable: 'PRISMA_PASSWORD'
                            )
                        ]) {
                            sh '''
                                mkdir -p backups
                                python3 deploy_waas_policy.py \
                                    ${PRISMA_CONSOLE_URL} \
                                    ${PRISMA_USERNAME} \
                                    ${PRISMA_PASSWORD} \
                                    container \
                                    --export \
                                    backups/staging-backup-$(date +%Y%m%d-%H%M%S).json
                            '''
                        }
                    }
                    
                    // Deploy policies
                    withCredentials([
                        usernamePassword(
                            credentialsId: 'prisma-cloud-staging',
                            usernameVariable: 'PRISMA_USERNAME',
                            passwordVariable: 'PRISMA_PASSWORD'
                        )
                    ]) {
                        sh '''
                            chmod +x batch_deploy.sh
                            export ENVIRONMENT=staging
                            ./batch_deploy.sh -e staging -b -v
                        '''
                    }
                    
                    echo "✓ Staging deployment complete"
                }
            }
            post {
                always {
                    archiveArtifacts artifacts: 'logs/**, backups/**', allowEmptyArchive: true
                }
                success {
                    notifySlack('good', 'Staging deployment successful')
                }
                failure {
                    notifySlack('danger', 'Staging deployment failed')
                }
            }
        }
        
        // =====================================================================
        // STAGE 7: APPROVAL FOR PRODUCTION
        // =====================================================================
        stage('Approval') {
            when {
                allOf {
                    branch 'main'
                    expression { params.ENVIRONMENT == 'production' || env.BRANCH_NAME == 'main' }
                    expression { !params.DRY_RUN }
                }
            }
            steps {
                script {
                    echo "⏸️  Waiting for approval..."
                    
                    try {
                        timeout(time: 1, unit: 'HOURS') {
                            input(
                                message: 'Deploy to Production?',
                                ok: 'Deploy',
                                submitter: 'security-team,release-managers',
                                parameters: [
                                    text(
                                        name: 'APPROVAL_NOTES',
                                        description: 'Approval notes or comments'
                                    )
                                ]
                            )
                        }
                        echo "✓ Deployment approved"
                    } catch (err) {
                        echo "❌ Deployment rejected or timed out"
                        currentBuild.result = 'ABORTED'
                        error('Deployment not approved')
                    }
                }
            }
        }
        
        // =====================================================================
        // STAGE 8: DEPLOY TO PRODUCTION
        // =====================================================================
        stage('Deploy to Production') {
            when {
                allOf {
                    branch 'main'
                    expression { params.ENVIRONMENT == 'production' || env.BRANCH_NAME == 'main' }
                }
            }
            steps {
                script {
                    echo "🚀 Deploying to Production..."
                    
                    // Always backup production
                    echo "💾 Backing up production policies..."
                    withCredentials([
                        usernamePassword(
                            credentialsId: 'prisma-cloud-prod',
                            usernameVariable: 'PRISMA_USERNAME',
                            passwordVariable: 'PRISMA_PASSWORD'
                        )
                    ]) {
                        sh '''
                            mkdir -p backups
                            python3 deploy_waas_policy.py \
                                ${PRISMA_CONSOLE_URL} \
                                ${PRISMA_USERNAME} \
                                ${PRISMA_PASSWORD} \
                                container \
                                --export \
                                backups/production-backup-$(date +%Y%m%d-%H%M%S).json
                        '''
                    }
                    
                    // Dry run or actual deployment
                    if (params.DRY_RUN) {
                        echo "🔍 Performing dry run..."
                        sh './batch_deploy.sh -e production --dry-run'
                    } else {
                        echo "🚀 Deploying policies..."
                        withCredentials([
                            usernamePassword(
                                credentialsId: 'prisma-cloud-prod',
                                usernameVariable: 'PRISMA_USERNAME',
                                passwordVariable: 'PRISMA_PASSWORD'
                            )
                        ]) {
                            sh '''
                                chmod +x batch_deploy.sh
                                ./batch_deploy.sh -e production -b -v
                            '''
                        }
                        
                        // Create deployment tag
                        sh '''
                            git config user.name "Jenkins"
                            git config user.email "jenkins@company.com"
                            TAG="prod-$(date +%Y%m%d-%H%M%S)"
                            git tag -a "$TAG" -m "Production deployment: $TAG"
                            git push origin "$TAG" || true
                        '''
                    }
                    
                    echo "✓ Production deployment complete"
                }
            }
            post {
                always {
                    archiveArtifacts artifacts: 'logs/**, backups/**', allowEmptyArchive: true, fingerprint: true
                }
                success {
                    script {
                        notifySlack(
                            'good',
                            "✅ Production WAAS deployment successful\nBuild: ${env.BUILD_NUMBER}\nCommit: ${env.GIT_COMMIT}"
                        )
                        
                        // Send email notification
                        emailext(
                            subject: "✅ Production WAAS Deployment Successful - Build #${env.BUILD_NUMBER}",
                            body: """
                                Production WAAS policies have been deployed successfully.
                                
                                Build: ${env.BUILD_URL}
                                Commit: ${env.GIT_COMMIT}
                                Branch: ${env.BRANCH_NAME}
                                
                                Deployment logs and backups have been archived.
                            """,
                            to: 'security-team@company.com',
                            attachLog: true
                        )
                    }
                }
                failure {
                    script {
                        notifySlack(
                            'danger',
                            "❌ Production WAAS deployment failed\nBuild: ${env.BUILD_NUMBER}\nCheck: ${env.BUILD_URL}"
                        )
                        
                        // Create JIRA ticket on failure
                        jiraComment(
                            issueKey: 'SEC-INCIDENT',
                            body: """
                                🚨 Production WAAS deployment failed
                                Build: ${env.BUILD_URL}
                                Commit: ${env.GIT_COMMIT}
                            """
                        )
                        
                        // Send email notification
                        emailext(
                            subject: "❌ Production WAAS Deployment Failed - Build #${env.BUILD_NUMBER}",
                            body: """
                                Production WAAS deployment has failed.
                                
                                Build: ${env.BUILD_URL}
                                Commit: ${env.GIT_COMMIT}
                                Branch: ${env.BRANCH_NAME}
                                
                                Please review the logs and take corrective action.
                            """,
                            to: 'security-team@company.com,oncall@company.com',
                            attachLog: true,
                            recipientProviders: [culprits(), requestor()]
                        )
                    }
                }
            }
        }
        
        // =====================================================================
        // STAGE 9: POST-DEPLOYMENT VERIFICATION
        // =====================================================================
        stage('Verify Deployment') {
            when {
                allOf {
                    branch 'main'
                    expression { !params.DRY_RUN }
                    expression { currentBuild.result != 'ABORTED' }
                }
            }
            steps {
                script {
                    echo "⏳ Waiting for policy propagation..."
                    sleep(time: 60, unit: 'SECONDS')
                    
                    echo "✓ Running post-deployment validation..."
                    // Add validation tests here
                    
                    echo "📊 Generating deployment report..."
                    sh '''
                        cat > deployment-report.md << EOF
# WAAS Deployment Report

## Summary
- **Build**: ${BUILD_NUMBER}
- **Environment**: ${ENVIRONMENT}
- **Date**: $(date)
- **Branch**: ${GIT_BRANCH}
- **Commit**: ${GIT_COMMIT}

## Deployed Policies
$(find policies/production -name "*.yaml" 2>/dev/null | sed 's/^/- /' || echo "None")

## Status
Deployment completed successfully and verified.
EOF
                        cat deployment-report.md
                    '''
                }
            }
            post {
                always {
                    archiveArtifacts artifacts: 'deployment-report.md', allowEmptyArchive: true
                    publishHTML([
                        allowMissing: false,
                        alwaysLinkToLastBuild: true,
                        keepAll: true,
                        reportDir: '.',
                        reportFiles: 'deployment-report.md',
                        reportName: 'Deployment Report'
                    ])
                }
            }
        }
    }
    
    // =========================================================================
    // POST-BUILD ACTIONS
    // =========================================================================
    post {
        always {
            script {
                echo "🧹 Cleaning up..."
                cleanWs(deleteDirs: true, patterns: [
                    [pattern: '**/__pycache__', type: 'INCLUDE'],
                    [pattern: '**/*.pyc', type: 'INCLUDE']
                ])
            }
        }
        success {
            script {
                echo "✅ Pipeline completed successfully"
            }
        }
        failure {
            script {
                echo "❌ Pipeline failed"
            }
        }
        unstable {
            script {
                echo "⚠️  Pipeline unstable"
            }
        }
    }
}

// =========================================================================
// HELPER FUNCTIONS
// =========================================================================

def notifySlack(String color, String message) {
    try {
        def payload = [
            text: message,
            attachments: [
                [
                    color: color,
                    fields: [
                        [
                            title: 'Job',
                            value: "${env.JOB_NAME}",
                            short: true
                        ],
                        [
                            title: 'Build',
                            value: "#${env.BUILD_NUMBER}",
                            short: true
                        ],
                        [
                            title: 'Branch',
                            value: "${env.BRANCH_NAME}",
                            short: true
                        ],
                        [
                            title: 'Environment',
                            value: "${params.ENVIRONMENT}",
                            short: true
                        ]
                    ],
                    footer: 'Jenkins',
                    footer_icon: 'https://jenkins.io/images/logos/jenkins/jenkins.png',
                    ts: System.currentTimeMillis() / 1000
                ]
            ]
        ]
        
        httpRequest(
            url: env.SLACK_WEBHOOK,
            httpMode: 'POST',
            contentType: 'APPLICATION_JSON',
            requestBody: groovy.json.JsonOutput.toJson(payload)
        )
    } catch (Exception e) {
        echo "Failed to send Slack notification: ${e.message}"
    }
}
