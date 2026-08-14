# rds_lab.tf

# =====================================================================
# COMMON RDS NETWORKING PREREQUISITES
# =====================================================================
data "aws_vpc" "default_rds" {
  count   = var.deploy_rds ? 1 : 0
  default = true
}

data "aws_subnets" "default_rds" {
  count = var.deploy_rds ? 1 : 0
  filter {
    name   = "vpc-id"
    values = [data.aws_vpc.default_rds[0].id]
  }
}

resource "aws_db_subnet_group" "lab_subnet_group" {
  count      = var.deploy_rds ? 1 : 0
  name       = "msc-lab-rds-subnet-group"
  subnet_ids = data.aws_subnets.default_rds[0].ids

  tags = {
    Name = "msc-lab-rds-subnet-group"
  }
}

# =====================================================================
# SCENARIO 1: CRITICAL RISK RDS INSTANCE
# Flaws: Publicly Accessible, Unencrypted Storage, Backups Disabled (0 days)
# =====================================================================
resource "aws_db_instance" "critical_rds" {
  count                  = var.deploy_rds ? 1 : 0
  identifier             = "msc-lab-london-critical-db"
  allocated_storage      = 20
  max_allocated_storage  = 20
  engine                 = "mysql"
  engine_version         = "8.0"
  instance_class         = "db.t3.micro"
  username               = "admin"
  password               = "LabPassword123!"
  db_subnet_group_name   = aws_db_subnet_group.lab_subnet_group[0].name
  skip_final_snapshot    = true

  # Security Vulnerabilities
  publicly_accessible    = true   # CRITICAL: Exposed to public internet
  storage_encrypted      = false  # HIGH: Storage unencrypted
  backup_retention_period = 0      # MEDIUM: Automated backups disabled
  multi_az               = false  # Single AZ
  iam_database_authentication_enabled = false

  tags = {
    Name        = "msc-lab-london-critical-db"
    Environment = "MSc-Lab"
  }
}

# =====================================================================
# SCENARIO 2: PERFECT / COMPLIANT RDS INSTANCE (FREE TIER COMPLIANT)
# Controls: Private, Storage Encrypted, 1-Day Backups (Free Tier Max), IAM Auth Enabled
# =====================================================================
resource "aws_db_instance" "perfect_rds" {
  count                  = var.deploy_rds ? 1 : 0
  identifier             = "msc-lab-london-perfect-db"
  allocated_storage      = 20
  max_allocated_storage  = 20
  engine                 = "mysql"
  engine_version         = "8.0"
  instance_class         = "db.t3.micro"
  username               = "admin"
  password               = "SecureLabPassword123!"
  db_subnet_group_name   = aws_db_subnet_group.lab_subnet_group[0].name
  skip_final_snapshot    = true

  # Hardened Controls (Free Tier Friendly)
  publicly_accessible    = false  # Private
  storage_encrypted      = true   # Encrypted with default KMS key
  backup_retention_period = 1      # 1-day automated backups (Max for Free Tier)
  multi_az               = false  # Single AZ (Free Tier)
  iam_database_authentication_enabled = true # IAM Auth enabled

  tags = {
    Name        = "msc-lab-london-perfect-db"
    Environment = "MSc-Lab"
  }
}
