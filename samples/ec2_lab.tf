# ec2_lab.tf

# ---------------------------------------------------------------------
# DATA SOURCES: LONDON (eu-west-2)
# ---------------------------------------------------------------------
data "aws_vpc" "london_default" {
  default = true
}

data "aws_subnets" "london_default" {
  filter {
    name   = "vpc-id"
    values = [data.aws_vpc.london_default.id]
  }
}

data "aws_ami" "london_amazon_linux" {
  most_recent = true
  owners      = ["amazon"]
  filter {
    name   = "name"
    values = ["al2023-ami-2023.*-x86_64"]
  }
}

# ---------------------------------------------------------------------
# DATA SOURCES: IRELAND (eu-west-1)
# ---------------------------------------------------------------------
data "aws_vpc" "ireland_default" {
  provider = aws.eu_west_1
  default  = true
}

data "aws_subnets" "ireland_default" {
  provider = aws.eu_west_1
  filter {
    name   = "vpc-id"
    values = [data.aws_vpc.ireland_default.id]
  }
}

data "aws_ami" "ireland_amazon_linux" {
  provider    = aws.eu_west_1
  most_recent = true
  owners      = ["amazon"]
  filter {
    name   = "name"
    values = ["al2023-ami-2023.*-x86_64"]
  }
}

# =====================================================================
# LONDON REGION (eu-west-2) EC2 INSTANCES
# =====================================================================

# SCENARIO 1: CRITICAL RISK EC2 (London)
resource "aws_security_group" "ec2_critical_london_sg" {
  count       = var.deploy_ec2 ? 1 : 0
  name        = "msc-lab-london-critical-sg"
  description = "CRITICAL: Unrestricted SSH & MySQL"
  vpc_id      = data.aws_vpc.london_default.id

  ingress {
    from_port   = 22
    to_port     = 22
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  ingress {
    from_port   = 3306
    to_port     = 3306
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }
}

resource "aws_instance" "ec2_critical_london" {
  count                       = var.deploy_ec2 ? 1 : 0
  ami                         = data.aws_ami.london_amazon_linux.id
  instance_type               = "t3.micro"
  subnet_id                   = data.aws_subnets.london_default.ids[0]
  vpc_security_group_ids      = [aws_security_group.ec2_critical_london_sg[0].id]
  associate_public_ip_address = true

  metadata_options {
    http_endpoint = "enabled"
    http_tokens   = "optional"
  }

  root_block_device {
    encrypted   = false
    volume_type = "gp3"
    volume_size = 8
  }

  tags = {
    Name = "msc-lab-london-critical"
  }
}

# SCENARIO 2: PERFECT / COMPLIANT EC2 (London)
resource "aws_security_group" "ec2_perfect_london_sg" {
  count       = var.deploy_ec2 ? 1 : 0
  name        = "msc-lab-london-perfect-sg"
  description = "PERFECT: Internal VPC traffic only"
  vpc_id      = data.aws_vpc.london_default.id

  ingress {
    from_port   = 443
    to_port     = 443
    protocol    = "tcp"
    cidr_blocks = [data.aws_vpc.london_default.cidr_block]
  }

  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }
}

resource "aws_instance" "ec2_perfect_london" {
  count                       = var.deploy_ec2 ? 1 : 0
  ami                         = data.aws_ami.london_amazon_linux.id
  instance_type               = "t3.micro"
  subnet_id                   = data.aws_subnets.london_default.ids[0]
  vpc_security_group_ids      = [aws_security_group.ec2_perfect_london_sg[0].id]
  associate_public_ip_address = false

  metadata_options {
    http_endpoint = "enabled"
    http_tokens   = "required"
  }

  root_block_device {
    encrypted   = true
    volume_type = "gp3"
    volume_size = 8
  }

  tags = {
    Name = "msc-lab-london-perfect"
  }
}

# =====================================================================
# IRELAND REGION (eu-west-1) EC2 INSTANCE
# =====================================================================

# SCENARIO 3: HIGH RISK EC2 (Ireland)
resource "aws_security_group" "ec2_high_ireland_sg" {
  provider    = aws.eu_west_1
  count       = var.deploy_ec2 ? 1 : 0
  name        = "msc-lab-ireland-high-sg"
  description = "HIGH: Unrestricted RDP exposure"
  vpc_id      = data.aws_vpc.ireland_default.id

  ingress {
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
}

resource "aws_instance" "ec2_high_ireland" {
  provider                    = aws.eu_west_1
  count                       = var.deploy_ec2 ? 1 : 0
  ami                         = data.aws_ami.ireland_amazon_linux.id
  instance_type               = "t3.micro"
  subnet_id                   = data.aws_subnets.ireland_default.ids[0]
  vpc_security_group_ids      = [aws_security_group.ec2_high_ireland_sg[0].id]
  associate_public_ip_address = true

  metadata_options {
    http_endpoint = "enabled"
    http_tokens   = "optional"
  }

  root_block_device {
    encrypted   = false
    volume_type = "gp3"
    volume_size = 8
  }

  tags = {
    Name = "msc-lab-ireland-high"
  }
}
