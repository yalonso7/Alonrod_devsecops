# AWS Terraform Configuration (HCL Format) - aws-test.tf
# Intentional Security Issues for Testing Scanners

terraform {
  required_version = ">= 1.0"
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 5.0"
    }
  }
}

provider "aws" {
  region = var.aws_region
}

variable "aws_region" {
  description = "AWS region"
  type        = string
  default     = "us-east-1"
}

variable "environment" {
  description = "Environment name"
  type        = string
  default     = "test"
}

# VPC Configuration
resource "aws_vpc" "test_vpc" {
  cidr_block           = "10.0.0.0/16"
  enable_dns_hostnames = true
  enable_dns_support   = true

  tags = {
    Name        = "${var.environment}-vpc"
    Environment = var.environment
  }
}

# Public Subnet
resource "aws_subnet" "public_subnet" {
  vpc_id                  = aws_vpc.test_vpc.id
  cidr_block              = "10.0.1.0/24"
  map_public_ip_on_launch = true # Issue: Auto-assign public IPs
  availability_zone       = data.aws_availability_zones.available.names[0]

  tags = {
    Name = "public-subnet"
  }
}

data "aws_availability_zones" "available" {
  state = "available"
}

# Security Group with issues
resource "aws_security_group" "insecure_sg" {
  name        = "insecure-security-group"
  description = "Test security group with issues"
  vpc_id      = aws_vpc.test_vpc.id

  # Issue: SSH open to world
  ingress {
    description = "SSH from anywhere"
    from_port   = 22
    to_port     = 22
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  # Issue: RDP open to world
  ingress {
    description = "RDP from anywhere"
    from_port   = 3389
    to_port     = 3389
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }

  tags = {
    Name = "insecure-sg"
  }
}

# S3 Bucket with issues
resource "aws_s3_bucket" "test_bucket" {
  bucket = "test-bucket-${data.aws_caller_identity.current.account_id}"

  tags = {
    Environment = var.environment
  }
}

# Issue: Public access allowed
resource "aws_s3_bucket_public_access_block" "test_bucket_pab" {
  bucket = aws_s3_bucket.test_bucket.id

  block_public_acls       = false
  block_public_policy     = false
  ignore_public_acls      = false
  restrict_public_buckets = false
}

# Issue: Versioning disabled
resource "aws_s3_bucket_versioning" "test_bucket_versioning" {
  bucket = aws_s3_bucket.test_bucket.id

  versioning_configuration {
    status = "Disabled"
  }
}

data "aws_caller_identity" "current" {}

# IAM Role with overly permissive policy
resource "aws_iam_role" "overly_permissive_role" {
  name = "test-admin-role"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect = "Allow"
        Principal = {
          Service = "ec2.amazonaws.com"
        }
        Action = "sts:AssumeRole"
      }
    ]
  })
}

# Issue: Full admin access
resource "aws_iam_role_policy_attachment" "admin_access" {
  role       = aws_iam_role.overly_permissive_role.name
  policy_arn = "arn:aws:iam::aws:policy/AdministratorAccess"
}

# RDS Subnet Group
resource "aws_db_subnet_group" "test_db_subnet" {
  name       = "test-db-subnet"
  subnet_ids = [aws_subnet.public_subnet.id]
}

# RDS Instance without encryption
resource "aws_db_instance" "test_database" {
  identifier              = "test-db"
  engine                  = "mysql"
  engine_version          = "8.0"
  instance_class          = "db.t3.micro"
  allocated_storage       = 20
  username                = "admin"
  password                = "TestPassword123!" # Issue: Hardcoded password
  db_subnet_group_name    = aws_db_subnet_group.test_db_subnet.name
  vpc_security_group_ids  = [aws_security_group.insecure_sg.id]
  publicly_accessible     = true  # Issue: Publicly accessible
  storage_encrypted       = false # Issue: Not encrypted
  backup_retention_period = 0     # Issue: No backups
  skip_final_snapshot     = true
}

# Lambda Function
resource "aws_lambda_function" "test_lambda" {
  filename      = "lambda.zip"
  function_name = "test-function"
  role          = aws_iam_role.lambda_role.arn
  handler       = "index.handler"
  runtime       = "python3.9"

  # Issue: Hardcoded secrets
  environment {
    variables = {
      API_KEY      = "hardcoded-api-key-12345"
      DATABASE_URL = "mysql://admin:password@localhost/db"
    }
  }
}

resource "aws_iam_role" "lambda_role" {
  name = "test-lambda-role"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect = "Allow"
        Principal = {
          Service = "lambda.amazonaws.com"
        }
        Action = "sts:AssumeRole"
      }
    ]
  })
}

resource "aws_iam_role_policy_attachment" "lambda_admin" {
  role       = aws_iam_role.lambda_role.name
  policy_arn = "arn:aws:iam::aws:policy/AdministratorAccess"
}

# CloudWatch Log Group without retention
resource "aws_cloudwatch_log_group" "test_log_group" {
  name = "/aws/lambda/test-function"
}

# EBS Volume without encryption
resource "aws_ebs_volume" "test_volume" {
  availability_zone = data.aws_availability_zones.available.names[0]
  size              = 10
  encrypted         = false

  tags = {
    Name = "test-volume"
  }
}

# EC2 Instance with issues
resource "aws_instance" "test_instance" {
  ami                    = data.aws_ami.ubuntu.id
  instance_type          = "t2.micro"
  subnet_id              = aws_subnet.public_subnet.id
  vpc_security_group_ids = [aws_security_group.insecure_sg.id]

  root_block_device {
    volume_size = 8
    encrypted   = false # Issue: Not encrypted
  }

  # Issue: Hardcoded credentials
  user_data = <<-EOF
              #!/bin/bash
              export API_KEY="hardcoded-key-98765"
              echo "admin:password123" > /tmp/credentials.txt
              EOF

  metadata_options {
    http_endpoint = "enabled"
    http_tokens   = "optional" # Issue: IMDSv2 not required
  }

  tags = {
    Name = "test-instance"
  }
}

data "aws_ami" "ubuntu" {
  most_recent = true
  owners      = ["099720109477"]

  filter {
    name   = "name"
    values = ["ubuntu/images/hvm-ssd/ubuntu-focal-20.04-amd64-server-*"]
  }
}

# KMS Key without rotation
resource "aws_kms_key" "test_key" {
  description             = "Test KMS key"
  deletion_window_in_days = 7
  enable_key_rotation     = false
}

# SNS Topic without encryption
resource "aws_sns_topic" "test_topic" {
  name = "test-topic"
}

# SQS Queue without encryption
resource "aws_sqs_queue" "test_queue" {
  name = "test-queue"
}

output "vpc_id" {
  value = aws_vpc.test_vpc.id
}

output "bucket_name" {
  value = aws_s3_bucket.test_bucket.id
}

output "security_group_id" {
  value = aws_security_group.insecure_sg.id
}