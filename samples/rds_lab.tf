# Looking up default VPC and subnets for database deployment
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

# Creating an RDS database subnet group across default subnets
resource "aws_db_subnet_group" "lab_subnet_group" {
  count      = var.deploy_rds ? 1 : 0
  name       = "msc-lab-rds-subnet-group"
  subnet_ids = data.aws_subnets.default_rds[0].ids

  tags = {
    Name = "msc-lab-rds-subnet-group"
  }
}

# Scenario 1: Critical Risk RDS Instance (Public Access, Unencrypted, No Backups, Single-AZ)

# Deploying an exposed database with encryption and automated backups disabled
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

  publicly_accessible        = true
  storage_encrypted          = false
  backup_retention_period    = 0
  multi_az                   = false
  auto_minor_version_upgrade = false

  tags = {
    Name        = "msc-lab-london-critical-db"
    Environment = "MSc-Lab"
  }
}

# Scenario 2: Compliant Baseline RDS Instance (Zero Exposure)

# Deploying a hardened private database with encryption, Multi-AZ, and automated backups
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

  publicly_accessible        = false
  storage_encrypted          = true
  backup_retention_period    = 1
  multi_az                   = true
  auto_minor_version_upgrade = true

  tags = {
    Name        = "msc-lab-london-perfect-db"
    Environment = "MSc-Lab"
  }
}