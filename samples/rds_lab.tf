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
# Triggers:
# - RDS-01 (CRITICAL: 9.6): Publicly Accessible
# - RDS-02 (HIGH: 7.8): Storage Unencrypted
# - RDS-03 (HIGH: 7.2): Backups Disabled (0 days)
# - RDS-04 (MEDIUM: 5.8): Single-AZ Deployment
# - RDS-05 (MEDIUM: 5.0): Auto Minor Upgrades Disabled
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
  publicly_accessible        = true   # RDS-01: CRITICAL (9.6)
  storage_encrypted          = false  # RDS-02: HIGH (7.8)
  backup_retention_period    = 0      # RDS-03: HIGH (7.2)
  multi_az                   = false  # RDS-04: MEDIUM (5.8)
  auto_minor_version_upgrade = false  # RDS-05: MEDIUM (5.0)

  tags = {
    Name        = "msc-lab-london-critical-db"
    Environment = "MSc-Lab"
  }
}

# =====================================================================
# SCENARIO 2: PERFECT / COMPLIANT RDS INSTANCE
# Controls:
# - Private Subnet Routing (publicly_accessible = false)
# - Storage Encrypted at Rest (storage_encrypted = true)
# - Automated Backups Enabled (backup_retention_period = 7)
# - Multi-AZ High Availability (multi_az = true)
# - Auto Minor Version Security Patching (auto_minor_version_upgrade = true)
# Result: ADVISORY: 0.0
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

  # Hardened Baseline Controls
  publicly_accessible        = false # Passes RDS-01
  storage_encrypted          = true  # Passes RDS-02
  backup_retention_period    = 1     # Passes RDS-03
  multi_az                   = true  # Passes RDS-04
  auto_minor_version_upgrade = true  # Passes RDS-05

  tags = {
    Name        = "msc-lab-london-perfect-db"
    Environment = "MSc-Lab"
  }
}