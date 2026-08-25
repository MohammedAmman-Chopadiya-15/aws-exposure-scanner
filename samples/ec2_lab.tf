# Looking up default VPC and subnets in London (eu-west-2)
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

# Looking up default VPC and subnets in N. Virginia (us-east-1)
data "aws_vpc" "us_east_1_default" {
  provider = aws.us_east_1
  default  = true
}

data "aws_subnets" "us_east_1_default" {
  provider = aws.us_east_1
  filter {
    name   = "vpc-id"
    values = [data.aws_vpc.us_east_1_default.id]
  }
}

data "aws_ami" "us_east_1_amazon_linux" {
  provider    = aws.us_east_1
  most_recent = true
  owners      = ["amazon"]
  filter {
    name   = "name"
    values = ["al2023-ami-2023.*-x86_64"]
  }
}

# Scenario 1: Critical Risk EC2 (SSH, DB Ingress, IMDSv1, Public IP, Unencrypted EBS)

# Creating a security group with public SSH and MySQL ingress
resource "aws_security_group" "ec2_critical_london_sg" {
  count       = var.deploy_ec2 ? 1 : 0
  name        = "msc-lab-london-critical-sg"
  description = "CRITICAL: Unrestricted SSH & MySQL exposure"
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

# Deploying an instance with public IP, IMDSv1, and unencrypted root volume
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

# Scenario 2: Compliant Baseline EC2 (Zero Exposure)

# Creating a locked-down security group allowing internal VPC traffic only
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

# Deploying a hardened private instance with IMDSv2 and encrypted storage
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

# Scenario 3: Medium Risk EC2 (Private, IMDSv2, but Unencrypted EBS)

# Restricting ingress to internal port 80 traffic
resource "aws_security_group" "ec2_medium_london_sg" {
  count       = var.deploy_ec2 ? 1 : 0
  name        = "msc-lab-london-medium-sg"
  description = "MEDIUM: Restricted Ingress"
  vpc_id      = data.aws_vpc.london_default.id

  ingress {
    from_port   = 80
    to_port     = 80
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

# Deploying private instance without root volume encryption
resource "aws_instance" "ec2_medium_london" {
  count                       = var.deploy_ec2 ? 1 : 0
  ami                         = data.aws_ami.london_amazon_linux.id
  instance_type               = "t3.micro"
  subnet_id                   = data.aws_subnets.london_default.ids[0]
  vpc_security_group_ids      = [aws_security_group.ec2_medium_london_sg[0].id]
  associate_public_ip_address = false

  metadata_options {
    http_endpoint = "enabled"
    http_tokens   = "required"
  }

  root_block_device {
    encrypted   = false
    volume_type = "gp3"
    volume_size = 8
  }

  tags = {
    Name = "msc-lab-london-medium"
  }
}

# Scenario 4: High Risk EC2 (RDP Exposure & IMDSv1) [us-east-1]

# Creating a security group with public RDP access
resource "aws_security_group" "ec2_high_us_east_1_sg" {
  provider    = aws.us_east_1
  count       = var.deploy_ec2 ? 1 : 0
  name        = "msc-lab-us-east-1-high-sg"
  description = "HIGH: Unrestricted RDP exposure"
  vpc_id      = data.aws_vpc.us_east_1_default.id

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

# Deploying public instance in us-east-1 with IMDSv1 enabled
resource "aws_instance" "ec2_high_us_east_1" {
  provider                    = aws.us_east_1
  count                       = var.deploy_ec2 ? 1 : 0
  ami                         = data.aws_ami.us_east_1_amazon_linux.id
  instance_type               = "t3.micro"
  subnet_id                   = data.aws_subnets.us_east_1_default.ids[0]
  vpc_security_group_ids      = [aws_security_group.ec2_high_us_east_1_sg[0].id]
  associate_public_ip_address = true

  metadata_options {
    http_endpoint = "enabled"
    http_tokens   = "optional"
  }

  root_block_device {
    encrypted   = true
    volume_type = "gp3"
    volume_size = 8
  }

  tags = {
    Name = "msc-lab-us-east-1-high"
  }
}