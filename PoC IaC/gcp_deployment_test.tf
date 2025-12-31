# GCP Comprehensive Terraform Configuration (HCL Format)
# Intentional Security Issues for Testing Scanners

terraform {
  required_version = ">= 1.0"
  required_providers {
    google = {
      source  = "hashicorp/google"
      version = "~> 5.0"
    }
  }
}

provider "google" {
  project = var.project_id
  region  = var.region
}

variable "project_id" {
  description = "GCP Project ID"
  type        = string
}

variable "region" {
  description = "GCP region"
  type        = string
  default     = "us-central1"
}

variable "zone" {
  description = "GCP zone"
  type        = string
  default     = "us-central1-a"
}

variable "environment" {
  description = "Environment name"
  type        = string
  default     = "test"
}

# ==================== NETWORKING ====================

# VPC Network
resource "google_compute_network" "test_network" {
  name                    = "test-network"
  auto_create_subnetworks = false
  description             = "Test VPC network for security scanning"
}

# Subnet without flow logs
resource "google_compute_subnetwork" "test_subnet" {
  name                     = "test-subnet"
  ip_cidr_range            = "10.0.0.0/24"
  region                   = var.region
  network                  = google_compute_network.test_network.id
  private_ip_google_access = false # Issue: Private Google access disabled

  # Issue: Flow logs not enabled
  log_config {
    aggregation_interval = "INTERVAL_10_MIN"
    flow_sampling        = 0.5
    metadata             = "INCLUDE_ALL_METADATA"
  }
}

# Additional subnet
resource "google_compute_subnetwork" "test_subnet_2" {
  name          = "test-subnet-2"
  ip_cidr_range = "10.0.2.0/24"
  region        = var.region
  network       = google_compute_network.test_network.id
  # Issue: Private Google access disabled
  # Issue: No flow logs configured
}

# Firewall - SSH open to world
resource "google_compute_firewall" "allow_ssh_from_anywhere" {
  name    = "allow-ssh-from-anywhere"
  network = google_compute_network.test_network.name

  allow {
    protocol = "tcp"
    ports    = ["22"]
  }

  source_ranges = ["0.0.0.0/0"] # Issue: SSH open to internet
  priority      = 1000

  log_config {
    metadata = "INCLUDE_ALL_METADATA"
  }
}

# Firewall - RDP open to world
resource "google_compute_firewall" "allow_rdp_from_anywhere" {
  name    = "allow-rdp-from-anywhere"
  network = google_compute_network.test_network.name

  allow {
    protocol = "tcp"
    ports    = ["3389"]
  }

  source_ranges = ["0.0.0.0/0"] # Issue: RDP open to internet
  priority      = 1000
}

# Firewall - Database port open
resource "google_compute_firewall" "allow_database_from_anywhere" {
  name    = "allow-database-from-anywhere"
  network = google_compute_network.test_network.name

  allow {
    protocol = "tcp"
    ports    = ["3306", "5432", "1433", "27017"]
  }

  source_ranges = ["0.0.0.0/0"] # Issue: Database ports open to internet
  priority      = 1000
}

# Firewall - Allow all egress
resource "google_compute_firewall" "allow_all_egress" {
  name      = "allow-all-egress"
  network   = google_compute_network.test_network.name
  direction = "EGRESS"

  allow {
    protocol = "all"
  }

  destination_ranges = ["0.0.0.0/0"]
  priority           = 1000
}

# ==================== COMPUTE INSTANCES ====================

# Compute Instance with multiple issues
resource "google_compute_instance" "test_vm_instance" {
  name         = "test-vm-instance"
  machine_type = "n1-standard-1"
  zone         = var.zone

  # Issue: No shielded VM configuration
  # shielded_instance_config {
  #   enable_secure_boot          = true
  #   enable_vtpm                 = true
  #   enable_integrity_monitoring = true
  # }

  boot_disk {
    initialize_params {
      image = "debian-cloud/debian-11"
      size  = 10
      type  = "pd-standard"
      # Issue: Disk encryption not configured with customer-managed key
    }
  }

  # Additional disk without encryption
  attached_disk {
    source = google_compute_disk.unencrypted_disk.id
  }

  network_interface {
    network    = google_compute_network.test_network.name
    subnetwork = google_compute_subnetwork.test_subnet.name

    # Issue: Public IP assigned
    access_config {
      # Ephemeral public IP
    }
  }

  service_account {
    email  = google_service_account.test_service_account.email
    scopes = ["cloud-platform"] # Issue: Overly broad scope
  }

  # Issue: Hardcoded secrets in metadata
  metadata = {
    startup-script = <<-EOF
      #!/bin/bash
      export API_KEY="hardcoded-key-12345"
      export SECRET_TOKEN="super-secret-token-67890"
      echo "admin:password123" > /tmp/creds.txt
      echo "db_password=MyP@ssw0rd!" >> /etc/environment
    EOF
    
    # Issue: Serial port access enabled
    serial-port-enable = "true"
  }

  # Issue: IP forwarding enabled
  can_ip_forward = true

  # Issue: Deletion protection not enabled
  deletion_protection = false

  tags = ["web", "test", "public"]

  labels = {
    environment = var.environment
    managed_by  = "terraform"
  }
}

# Windows instance with issues
resource "google_compute_instance" "windows_instance" {
  name         = "windows-test-instance"
  machine_type = "n1-standard-2"
  zone         = var.zone

  boot_disk {
    initialize_params {
      image = "windows-cloud/windows-2019"
      size  = 50
    }
  }

  network_interface {
    network    = google_compute_network.test_network.name
    subnetwork = google_compute_subnetwork.test_subnet.name

    access_config {} # Issue: Public IP
  }

  # Issue: Default service account with broad scopes
  service_account {
    email = "default"
    scopes = [
      "https://www.googleapis.com/auth/compute",
      "https://www.googleapis.com/auth/devstorage.full_control"
    ]
  }

  # Issue: Windows password in metadata
  metadata = {
    windows-startup-script-ps1 = <<-EOF
      $password = ConvertTo-SecureString "P@ssw0rd123!" -AsPlainText -Force
    EOF
  }

  tags = ["windows", "rdp"]
}

# ==================== STORAGE ====================

# Cloud Storage Bucket with issues
resource "google_storage_bucket" "test_storage_bucket" {
  name          = "test-storage-bucket-${var.project_id}"
  location      = "US"
  storage_class = "STANDARD"
  force_destroy = true

  # Issue: Uniform bucket level access not enabled
  uniform_bucket_level_access {
    enabled = false # Issue: Uniform access not enabled
  }

  # Issue: No versioning enabled
  versioning {
    enabled = false # Issue: Versioning disabled
  }

  # Issue: No lifecycle rules configured
  # Issue: No retention policy
  # Issue: Public access possible

  # Issue: No encryption with customer-managed key
  # encryption {
  #   default_kms_key_name = google_kms_crypto_key.bucket_key.id
  # }

  labels = {
    environment = var.environment
    sensitive   = "true"
  }
}

# Storage Bucket IAM binding - public access
resource "google_storage_bucket_iam_member" "bucket_public_access" {
  bucket = google_storage_bucket.test_storage_bucket.name
  role   = "roles/storage.objectViewer"
  member = "allUsers" # Issue: Bucket publicly readable
}

# Another bucket with different issues
resource "google_storage_bucket" "data_bucket" {
  name     = "data-bucket-${var.project_id}"
  location = "US"

  # Issue: No logging configured
  # logging {
  #   log_bucket = google_storage_bucket.log_bucket.name
  # }

  # Issue: CORS allowing all origins
  cors {
    origin          = ["*"] # Issue: Allows all origins
    method          = ["GET", "HEAD", "PUT", "POST", "DELETE"]
    response_header = ["*"]
    max_age_seconds = 3600
  }

  website {
    main_page_suffix = "index.html"
    not_found_page   = "404.html"
  }
}

# Storage Bucket for sensitive data without encryption
resource "google_storage_bucket" "sensitive_data_bucket" {
  name          = "sensitive-data-${var.project_id}"
  location      = "US"
  storage_class = "STANDARD"

  # Issue: No customer-managed encryption
  # Issue: No access logs
  # Issue: No retention policy

  labels = {
    data_classification = "confidential"
    compliance          = "pci-dss"
  }
}

# ==================== CLOUD SQL ====================

# Cloud SQL Instance without proper security
resource "google_sql_database_instance" "test_sql_instance" {
  name             = "test-sql-instance-${var.environment}"
  database_version = "MYSQL_8_0"
  region           = var.region

  settings {
    tier              = "db-f1-micro"
    availability_type = "ZONAL" # Issue: No high availability

    # Issue: Backups disabled
    backup_configuration {
      enabled                        = false # Issue: Backups disabled
      binary_log_enabled             = false
      start_time                     = "03:00"
      point_in_time_recovery_enabled = false
    }

    ip_configuration {
      ipv4_enabled = true

      # Issue: Database accessible from anywhere
      authorized_networks {
        name  = "allow-all"
        value = "0.0.0.0/0" # Issue: Allow all IPs
      }

      require_ssl = false # Issue: SSL not required

      # Issue: Private IP not configured
      # private_network = google_compute_network.test_network.id
    }

    # Issue: Automatic storage increase disabled
    disk_autoresize       = false
    disk_autoresize_limit = 0

    # Issue: Potentially insecure flags
    database_flags {
      name  = "local_infile"
      value = "on" # Issue: Potentially insecure flag
    }

    database_flags {
      name  = "skip_show_database"
      value = "off"
    }

    # Issue: Maintenance window not configured for minimal impact
    maintenance_window {
      day  = 1
      hour = 0 # Issue: Maintenance during business hours
    }
  }

  # Issue: Deletion protection disabled
  deletion_protection = false
}

# PostgreSQL instance with issues
resource "google_sql_database_instance" "postgres_instance" {
  name             = "postgres-instance-${var.environment}"
  database_version = "POSTGRES_14"
  region           = var.region

  settings {
    tier = "db-custom-1-3840"

    backup_configuration {
      enabled = false # Issue: No backups
    }

    ip_configuration {
      ipv4_enabled = true
      
      authorized_networks {
        name  = "public-access"
        value = "0.0.0.0/0"
      }
    }

    # Issue: No encryption at rest with customer key
  }

  deletion_protection = false
}

# SQL Database
resource "google_sql_database" "test_database" {
  name     = "testdb"
  instance = google_sql_database_instance.test_sql_instance.name
  charset  = "utf8mb4"
}

# SQL User with weak configuration
resource "google_sql_user" "test_sql_user" {
  name     = "admin"
  instance = google_sql_database_instance.test_sql_instance.name
  password = "WeakPassword123" # Issue: Weak password in config
  # Issue: No host restriction (connects from anywhere)
}

# Root user with default password
resource "google_sql_user" "root_user" {
  name     = "root"
  instance = google_sql_database_instance.test_sql_instance.name
  password = "root123" # Issue: Weak root password
}

# ==================== IAM & SERVICE ACCOUNTS ====================

# Service Account with broad permissions
resource "google_service_account" "test_service_account" {
  account_id   = "test-service-account"
  display_name = "Test Service Account"
  description  = "Service account for testing"
}

# Another service account
resource "google_service_account" "app_service_account" {
  account_id   = "app-service-account"
  display_name = "Application Service Account"
}

# Service account key (Issue: Keys should be avoided)
resource "google_service_account_key" "app_key" {
  service_account_id = google_service_account.app_service_account.name
  # Issue: Service account keys are security risks
}

# IAM Policy Binding - Owner role
resource "google_project_iam_member" "overly_permissive_binding" {
  project = var.project_id
  role    = "roles/owner" # Issue: Owner role assigned
  member  = "serviceAccount:${google_service_account.test_service_account.email}"
}

# Editor role to service account
resource "google_project_iam_member" "editor_binding" {
  project = var.project_id
  role    = "roles/editor" # Issue: Editor role too permissive
  member  = "serviceAccount:${google_service_account.app_service_account.email}"
}

# Public IAM binding
resource "google_project_iam_member" "public_viewer" {
  project = var.project_id
  role    = "roles/viewer"
  member  = "allUsers" # Issue: Project accessible to all users
}

# Authenticated users binding
resource "google_project_iam_member" "authenticated_users" {
  project = var.project_id
  role    = "roles/browser"
  member  = "allAuthenticatedUsers" # Issue: All authenticated users can browse
}

# ==================== CLOUD FUNCTIONS ====================

# Cloud Function without proper configuration
resource "google_cloudfunctions_function" "test_cloud_function" {
  name        = "test-function"
  runtime     = "python39"
  entry_point = "hello_world"
  region      = var.region

  available_memory_mb   = 256
  timeout               = 60
  max_instances         = 100
  source_archive_bucket = google_storage_bucket.function_bucket.name
  source_archive_object = google_storage_bucket_object.function_zip.name

  # Issue: Unauthenticated HTTP trigger
  trigger_http = true

  # Issue: Hardcoded secrets
  environment_variables = {
    API_KEY         = "hardcoded-api-key-67890"     # Issue: Hardcoded secret
    DB_PASSWORD     = "admin123"                    # Issue: Hardcoded database password
    SECRET_TOKEN    = "my-secret-token-123"         # Issue: Hardcoded token
    DATABASE_URL    = "postgresql://user:pass@host" # Issue: Credentials in environment
    STRIPE_API_KEY  = "sk_test_123456789"           # Issue: API key in environment
  }

  # Issue: No VPC connector
  # vpc_connector = google_vpc_access_connector.connector.name

  # Issue: Uses default service account
  # service_account_email = google_service_account.function_sa.email

  # Issue: Ingress not restricted
  ingress_settings = "ALLOW_ALL"

  labels = {
    environment = var.environment
  }
}

# Function bucket
resource "google_storage_bucket" "function_bucket" {
  name          = "function-bucket-${var.project_id}"
  location      = "US"
  force_destroy = true
}

# Dummy function zip
resource "google_storage_bucket_object" "function_zip" {
  name   = "function.zip"
  bucket = google_storage_bucket.function_bucket.name
  source = "function.zip"
}

# Allow unauthenticated access to function
resource "google_cloudfunctions_function_iam_member" "invoker" {
  project        = google_cloudfunctions_function.test_cloud_function.project
  region         = google_cloudfunctions_function.test_cloud_function.region
  cloud_function = google_cloudfunctions_function.test_cloud_function.name

  role   = "roles/cloudfunctions.invoker"
  member = "allUsers" # Issue: Function publicly accessible
}

# ==================== PUB/SUB ====================

# Pub/Sub Topic without encryption
resource "google_pubsub_topic" "test_pubsub_topic" {
  name = "test-topic"

  # Issue: No customer-managed encryption key
  # kms_key_name = google_kms_crypto_key.pubsub_key.id

  # Issue: No message retention
  message_retention_duration = "86400s"

  labels = {
    environment = var.environment
  }
}

# Pub/Sub Topic IAM - public publisher
resource "google_pubsub_topic_iam_member" "public_publisher" {
  topic  = google_pubsub_topic.test_pubsub_topic.name
  role   = "roles/pubsub.publisher"
  member = "allUsers" # Issue: Anyone can publish
}

# Pub/Sub Subscription
resource "google_pubsub_subscription" "test_subscription" {
  name  = "test-subscription"
  topic = google_pubsub_topic.test_pubsub_topic.name

  # Issue: No dead letter policy
  # Issue: No expiration policy
  # Issue: No retry policy

  ack_deadline_seconds = 20

  labels = {
    environment = var.environment
  }
}

# ==================== BIGQUERY ====================

# BigQuery Dataset with issues
resource "google_bigquery_dataset" "test_bigquery_dataset" {
  dataset_id                 = "test_dataset"
  location                   = "US"
  description                = "Test dataset for scanning"
  default_table_expiration_ms = 0 # Issue: No default expiration

  # Issue: No default encryption specified
  # default_encryption_configuration {
  #   kms_key_name = google_kms_crypto_key.bigquery_key.id
  # }

  access {
    role          = "READER"
    special_group = "allAuthenticatedUsers" # Issue: Accessible to all authenticated users
  }

  access {
    role          = "OWNER"
    user_by_email = google_service_account.test_service_account.email
  }

  labels = {
    environment = var.environment
    sensitive   = "true"
  }
}

# BigQuery Table without encryption
resource "google_bigquery_table" "test_table" {
  dataset_id = google_bigquery_dataset.test_bigquery_dataset.dataset_id
  table_id   = "test_table"

  schema = <<EOF
[
  {
    "name": "user_id",
    "type": "STRING",
    "mode": "REQUIRED"
  },
  {
    "name": "email",
    "type": "STRING",
    "mode": "NULLABLE"
  },
  {
    "name": "credit_card",
    "type": "STRING",
    "mode": "NULLABLE"
  }
]
EOF

  # Issue: No encryption with customer-managed key
  # Issue: Sensitive data without protection

  labels = {
    contains_pii = "true"
  }
}

# ==================== KMS ====================

# KMS Key Ring
resource "google_kms_key_ring" "test_kms_keyring" {
  name     = "test-keyring"
  location = var.region
}

# KMS Crypto Key with long rotation
resource "google_kms_crypto_key" "test_crypto_key" {
  name            = "test-key"
  key_ring        = google_kms_key_ring.test_kms_keyring.id
  rotation_period = "31536000s" # Issue: 365 days rotation period (too long)

  # Issue: No versioning template
  # Issue: Purpose not specified for specific use

  lifecycle {
    prevent_destroy = false
  }

  labels = {
    environment = var.environment
  }
}

# KMS Key IAM - overly permissive
resource "google_kms_crypto_key_iam_member" "crypto_key_encrypter" {
  crypto_key_id = google_kms_crypto_key.test_crypto_key.id
  role          = "roles/cloudkms.cryptoKeyEncrypterDecrypter"
  member        = "allAuthenticatedUsers" # Issue: All authenticated users can use key
}

# ==================== COMPUTE DISKS ====================

# Compute Disk without encryption
resource "google_compute_disk" "unencrypted_disk" {
  name = "unencrypted-disk"
  type = "pd-standard"
  zone = var.zone
  size = 10

  # Issue: No disk encryption key specified
  # disk_encryption_key {
  #   kms_key_self_link = google_kms_crypto_key.disk_key.id
  # }

  labels = {
    environment = var.environment
  }
}

# SSD disk without encryption
resource "google_compute_disk" "ssd_disk" {
  name = "ssd-disk"
  type = "pd-ssd"
  zone = var.zone
  size = 50

  # Issue: No encryption with customer-managed key
  # Issue: No snapshot schedule

  labels = {
    performance = "high"
  }
}

# Disk snapshot without encryption
resource "google_compute_snapshot" "test_snapshot" {
  name        = "test-snapshot"
  source_disk = google_compute_disk.unencrypted_disk.name
  zone        = var.zone

  # Issue: No encryption with customer-managed key
  # snapshot_encryption_key {
  #   kms_key_self_link = google_kms_crypto_key.snapshot_key.id
  # }

  labels = {
    environment = var.environment
  }
}

# ==================== GKE (KUBERNETES ENGINE) ====================

# GKE Cluster with multiple issues
resource "google_container_cluster" "test_gke_cluster" {
  name     = "test-gke-cluster"
  location = var.region

  # Issue: Legacy ABAC enabled
  enable_legacy_abac = true # Issue: Legacy authorization enabled

  # Issue: Basic authentication not disabled
  master_auth {
    client_certificate_config {
      issue_client_certificate = true # Issue: Client certificates enabled
    }
  }

  # Issue: Network policy not enabled
  network_policy {
    enabled  = false # Issue: Network policy disabled
    provider = "PROVIDER_UNSPECIFIED"
  }

  # Issue: Private cluster not configured
  private_cluster_config {
    enable_private_nodes    = false # Issue: Private nodes not enabled
    enable_private_endpoint = false
    # master_ipv4_cidr_block = "172.16.0.0/28"
  }

  # Issue: Master authorized networks not configured
  # master_authorized_networks_config {
  #   cidr_blocks {
  #     cidr_block   = "10.0.0.0/8"
  #     display_name = "internal"
  #   }
  # }

  # Issue: Binary authorization not enabled
  # binary_authorization {
  #   evaluation_mode = "PROJECT_SINGLETON_POLICY_ENFORCE"
  # }

  # Issue: Database encryption not enabled
  # database_encryption {
  #   state    = "ENCRYPTED"
  #   key_name = google_kms_crypto_key.gke_key.id
  # }

  # Issue: Workload identity not enabled
  workload_identity_config {
    workload_pool = "" # Issue: Workload identity disabled
  }

  # Issue: Monitoring and logging not comprehensive
  logging_config {
    enable_components = ["SYSTEM_COMPONENTS"] # Issue: Missing workload logging
  }

  monitoring_config {
    enable_components = ["SYSTEM_COMPONENTS"] # Issue: Missing workload monitoring
  }

  # Issue: Maintenance window not optimized
  maintenance_policy {
    daily_maintenance_window {
      start_time = "03:00" # Issue: No exclusion windows
    }
  }

  # We can't create a cluster with no node pool
  remove_default_node_pool = true
  initial_node_count       = 1

  network    = google_compute_network.test_network.name
  subnetwork = google_compute_subnetwork.test_subnet.name

  # Issue: Addons not optimally configured
  addons_config {
    http_load_balancing {
      disabled = false
    }
    horizontal_pod_autoscaling {
      disabled = true # Issue: HPA disabled
    }
    network_policy_config {
      disabled = true # Issue: Network policy addon disabled
    }
  }

  # Issue: No resource usage export
  # resource_usage_export_config {
  #   enable_network_egress_metering = true
  #   bigquery_destination {
  #     dataset_id = google_bigquery_dataset.gke_usage.dataset_id
  #   }
  # }
}

# GKE Node Pool with issues
resource "google_container_node_pool" "test_node_pool" {
  name       = "test-node-pool"
  location   = var.region
  cluster    = google_container_cluster.test_gke_cluster.name
  node_count = 1

  # Issue: Auto-scaling not configured
  # autoscaling {
  #   min_node_count = 1
  #   max_node_count = 3
  # }

  # Issue: Auto-upgrade disabled
  management {
    auto_repair  = false # Issue: Auto-repair disabled
    auto_upgrade = false # Issue: Auto-upgrade disabled
  }

  node_config {
    machine_type = "e2-medium"
    disk_size_gb = 20
    disk_type    = "pd-standard"

    # Issue: Overly broad OAuth scopes
    oauth_scopes = [
      "https://www.googleapis.com/auth/cloud-platform" # Issue: Broad scope
    ]

    # Issue: Shielded instance config not enabled
    # shielded_instance_config {
    #   enable_secure_boot          = true
    #   enable_integrity_monitoring = true
    # }

    # Issue: Workload metadata config not secure
    workload_metadata_config {
      mode = "GCE_METADATA" # Issue: Should use GKE_METADATA
    }

    # Issue: Metadata concealment not configured
    # metadata = {
    #   disable-legacy-endpoints = "true"
    # }

    # Issue: No boot disk encryption with customer key
    # boot_disk_kms_key = google_kms_crypto_key.node_boot_disk_key.id

    service_account = google_service_account.test_service_account.email

    tags = ["gke-node", "test"]

    labels = {
      environment = var.environment
    }
  }
}

# ==================== CLOUD DNS ====================

# DNS Managed Zone without DNSSEC
resource "google_dns_managed_zone" "test_zone" {
  name        = "test-zone"
  dns_name    = "test.example.com."
  description = "Test DNS zone"

  # Issue: DNSSEC not enabled
  dnssec_config {
    state = "off" # Issue: DNSSEC disabled
  }

  # Issue: No logging
  # cloud_logging_config {
  #   enable_logging = true
  # }

  visibility = "public" # Issue: Public zone without protection

  labels = {
    environment = var.environment
  }
}

# ==================== SECRET MANAGER ====================

# Secret without proper protection
resource "google_secret_manager_secret" "test_secret" {
  secret_id = "test-secret"

  replication {
    automatic = true
  }

  # Issue: No customer-managed encryption
  # No rotation policy
  # No expiration

  labels = {
    environment = var.environment
    sensitive   = "true"
  }
}

# Secret version with hardcoded value
resource "google_secret_manager_secret_version" "test_secret_version" {
  secret = google_secret_manager_secret.test_secret.id

  secret_data = "my-super-secret-password-123" # Issue: Hardcoded secret value
}

# Secret IAM - overly permissive
resource "google_secret_manager_secret_iam_member" "secret_accessor" {
  secret_id = google_secret_manager_secret.test_secret.id
  role      = "roles/secretmanager.secretAccessor"
  member    = "allAuthenticatedUsers" # Issue: All authenticated users can access
}

# ==================== LOAD BALANCER ====================

# Global IP address
resource "google_compute_global_address" "lb_ip" {
  name = "test-lb-ip"
}

# Backend service without logging
resource "google_compute_backend_service" "test_backend" {
  name                  = "test-backend"
  protocol              = "HTTP"
  port_name             = "http"
  timeout_sec           = 30
  enable_cdn            = false # Issue: CDN not enabled
  health_checks         = [google_compute_http_health_check.test_health_check.id]
  load_balancing_scheme = "EXTERNAL"

  # Issue: No logging configured
  # log_config {
  #   enable      = true
  #   sample_rate = 1.0
  # }

  # Issue: No security policy
  # security_policy = google_compute_security_policy.policy.id

  backend {
    group = google_compute_instance_group.test_ig.id
  }
}

# Health check without SSL
resource "google_compute_http_health_check" "test_health_check" {
  name                = "test-health-check"
  request_path        = "/"
  check_interval_sec  = 5
  timeout_sec         = 5
  healthy_threshold   = 2
  unhealthy_threshold = 2
  port                = 80 # Issue: HTTP instead of HTTPS
}

# Instance group
resource "google_compute_instance_group" "test_ig" {
  name = "test-instance-group"
  zone = var.zone

  instances = [
    google_compute_instance.test_vm_instance.id
  ]

  named_port {
    name = "http"
    port = 80
  }
}

# ==================== CLOUD RUN ====================

# Cloud Run service without authentication
resource "google_cloud_run_service" "test_service" {
  name     = "test-service"
  location = var.region

  template {
    spec {
      containers {
        image = "gcr.io/cloudrun/hello"

        # Issue: Hardcoded secrets in environment
        env {
          name  = "API_KEY"
          value = "hardcoded-api-key-abc123"
        }

        env {
          name  = "DATABASE_PASSWORD"
          value = "db_password_xyz"
        }
      }

      # Issue: No service account specified (uses default)
      # service_account_name = google_service_account.cloudrun_sa.email
    }

    metadata {
      annotations = {
        "autoscaling.knative.dev/maxScale" = "100"
        # Issue: No VPC connector
        # "run.googleapis.com/vpc-access-connector" = google_vpc_access_connector.connector.name
      }
    }
  }

  traffic {
    percent         = 100
    latest_revision = true
  }
}

# Allow unauthenticated access to Cloud Run
resource "google_cloud_run_service_iam_member" "noauth" {
  service  = google_cloud_run_service.test_service.name
  location = google_cloud_run_service.test_service.location
  role     = "roles/run.invoker"
  member   = "allUsers" # Issue: Public access to Cloud Run
}

# ==================== COMPOSER (AIRFLOW) ====================

# Cloud Composer environment with issues
resource "google_composer_environment" "test_composer" {
  name   = "test-composer-env"
  region = var.region

  config {
    node_count = 3

    node_config {
      zone         = var.zone
      machine_type = "n1-standard-1"

      # Issue: Overly broad OAuth scopes
      oauth_scopes = [
        "https://www.googleapis.com/auth/cloud-platform"
      ]

      service_account = google_service_account.test_service_account.email

      # Issue: No disk encryption with customer key
    }

    software_config {
      image_version = "composer-1.20.12-airflow-2.5.3"

      # Issue: Hardcoded secrets in environment variables
      env_variables = {
        AIRFLOW_VAR_API_KEY      = "hardcoded-airflow-key"
        AIRFLOW_VAR_DB_PASSWORD  = "airflow_db_pass_123"
      }
    }

    # Issue: Private environment not configured
    private_environment_config {
      enable_private_endpoint = false
    }

    # Issue: Web server not requiring authentication properly
    # web_server_network_access_control {
    #   allowed_ip_range {
    #     value = "0.0.0.0/0"  # Issue if uncommented
    #   }
    # }
  }
}

# ==================== DATAFLOW ====================

# Dataflow job with issues (represented as config)
# Note: Dataflow jobs are typically created through SDK, but showing configuration issues

# ==================== MEMORYSTORE (REDIS) ====================

# Redis instance without auth and encryption
resource "google_redis_instance" "test_redis" {
  name           = "test-redis-instance"
  memory_size_gb = 1
  region         = var.region

  # Issue: No AUTH string configured
  auth_enabled = false # Issue: Authentication disabled

  # Issue: Transit encryption disabled
  transit_encryption_mode = "DISABLED" # Issue: No encryption in transit

  # Issue: No customer-managed encryption at rest
  # customer_managed_key = google_kms_crypto_key.redis_key.id

  # Issue: Connected to authorized network (not private)
  authorized_network = google_compute_network.test_network.id

  redis_version = "REDIS_6_X"
  display_name  = "Test Redis Instance"

  labels = {
    environment = var.environment
  }
}

# ==================== BIGTABLE ====================

# Bigtable instance without encryption
resource "google_bigtable_instance" "test_bigtable" {
  name = "test-bigtable-instance"

  cluster {
    cluster_id   = "test-cluster"
    zone         = var.zone
    num_nodes    = 1
    storage_type = "HDD"

    # Issue: No customer-managed encryption
    # kms_key_name = google_kms_crypto_key.bigtable_key.id
  }

  deletion_protection = false # Issue: Deletion protection disabled

  labels = {
    environment = var.environment
  }
}

# Bigtable IAM - overly permissive
resource "google_bigtable_instance_iam_member" "bigtable_user" {
  instance = google_bigtable_instance.test_bigtable.name
  role     = "roles/bigtable.admin"
  member   = "allAuthenticatedUsers" # Issue: All authenticated users are admins
}

# ==================== SPANNER ====================

# Spanner instance without proper configuration
resource "google_spanner_instance" "test_spanner" {
  name         = "test-spanner-instance"
  config       = "regional-${var.region}"
  display_name = "Test Spanner Instance"
  num_nodes    = 1

  # Issue: No customer-managed encryption
  # encryption_config {
  #   kms_key_name = google_kms_crypto_key.spanner_key.id
  # }

  labels = {
    environment = var.environment
  }
}

# Spanner database
resource "google_spanner_database" "test_spanner_db" {
  instance = google_spanner_instance.test_spanner.name
  name     = "test-database"
  
  deletion_protection = false # Issue: No deletion protection

  ddl = [
    "CREATE TABLE users (user_id INT64, email STRING(MAX), password STRING(MAX)) PRIMARY KEY(user_id)",
  ]
}

# Spanner IAM - public access
resource "google_spanner_database_iam_member" "spanner_user" {
  instance = google_spanner_instance.test_spanner.name
  database = google_spanner_database.test_spanner_db.name
  role     = "roles/spanner.databaseReader"
  member   = "allAuthenticatedUsers" # Issue: All authenticated users can read
}

# ==================== DATAPROC ====================

# Dataproc cluster with issues
resource "google_dataproc_cluster" "test_dataproc" {
  name   = "test-dataproc-cluster"
  region = var.region

  cluster_config {
    staging_bucket = google_storage_bucket.dataproc_staging.name

    master_config {
      num_instances = 1
      machine_type  = "n1-standard-2"
      disk_config {
        boot_disk_type    = "pd-standard"
        boot_disk_size_gb = 30
        # Issue: No encryption with customer-managed key
      }
    }

    worker_config {
      num_instances = 2
      machine_type  = "n1-standard-2"
      disk_config {
        boot_disk_size_gb = 30
      }
    }

    # Issue: No encryption configuration
    encryption_config {
      # kms_key_name = google_kms_crypto_key.dataproc_key.id
    }

    # Issue: No security configuration
    # security_config {
    #   kerberos_config {
    #     enable_kerberos = true
    #   }
    # }

    gce_cluster_config {
      zone = var.zone
      
      # Issue: Internal IP only not configured
      internal_ip_only = false

      # Issue: Overly broad scopes
      service_account_scopes = [
        "https://www.googleapis.com/auth/cloud-platform"
      ]

      service_account = google_service_account.test_service_account.email

      # Issue: Metadata with secrets
      metadata = {
        "startup-script" = "export SECRET_KEY='hardcoded-secret-123'"
      }
    }
  }
}

# Dataproc staging bucket
resource "google_storage_bucket" "dataproc_staging" {
  name          = "dataproc-staging-${var.project_id}"
  location      = "US"
  force_destroy = true

  # Issue: No encryption, no versioning, no lifecycle
}

# ==================== OUTPUTS ====================

output "network_name" {
  description = "Network Name"
  value       = google_compute_network.test_network.name
}

output "instance_name" {
  description = "Instance Name"
  value       = google_compute_instance.test_vm_instance.name
}

output "instance_public_ip" {
  description = "Instance Public IP"
  value       = google_compute_instance.test_vm_instance.network_interface[0].access_config[0].nat_ip
}

output "bucket_name" {
  description = "Bucket Name"
  value       = google_storage_bucket.test_storage_bucket.name
}

output "bucket_url" {
  description = "Bucket URL"
  value       = google_storage_bucket.test_storage_bucket.url
}

output "sql_instance_name" {
  description = "SQL Instance Name"
  value       = google_sql_database_instance.test_sql_instance.name
}

output "sql_instance_connection" {
  description = "SQL Instance Connection Name"
  value       = google_sql_database_instance.test_sql_instance.connection_name
}

output "gke_cluster_name" {
  description = "GKE Cluster Name"
  value       = google_container_cluster.test_gke_cluster.name
}

output "gke_cluster_endpoint" {
  description = "GKE Cluster Endpoint"
  value       = google_container_cluster.test_gke_cluster.endpoint
  sensitive   = true
}

output "function_url" {
  description = "Cloud Function URL"
  value       = google_cloudfunctions_function.test_cloud_function.https_trigger_url
}

output "cloudrun_url" {
  description = "Cloud Run URL"
  value       = google_cloud_run_service.test_service.status[0].url
}
    