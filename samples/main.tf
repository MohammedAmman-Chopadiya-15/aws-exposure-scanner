# samples/main.tf

terraform {
  required_version = ">= 1.0"
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 5.0"
    }
    random = {
      source  = "hashicorp/random"
      version = "~> 3.5"
    }
  }
}

# ---------------------------------------------------------------------
# MULTI-REGION PROVIDERS
# ---------------------------------------------------------------------
# Default Provider: London (eu-west-2)
provider "aws" {
  region = "eu-west-2"
}

# Alternate Provider 1: N. Virginia (us-east-1)
provider "aws" {
  alias  = "us_east_1"
  region = "us-east-1"
}

# Alternate Provider 2: Ireland (eu-west-1)
provider "aws" {
  alias  = "eu_west_1"
  region = "eu-west-1"
}

# ---------------------------------------------------------------------
# SERVICE SELECTION TOGGLES
# ---------------------------------------------------------------------
variable "deploy_s3" {
  type        = bool
  default     = false
  description = "Set to true to deploy S3 lab infrastructure"
}

variable "deploy_ec2" {
  type        = bool
  default     = false
  description = "Set to true to deploy EC2 lab infrastructure"
}

variable "deploy_iam" {
  type        = bool
  default     = false
  description = "Set to true to deploy IAM lab infrastructure"
}

variable "deploy_rds" {
  type        = bool
  default     = false
  description = "Set to true to deploy RDS lab infrastructure"
}

variable "deploy_lambda" {
  type        = bool
  default     = false
  description = "Set to true to deploy Lambda lab infrastructure"
}

variable "deploy_apigateway" {
  type        = bool
  default     = false
  description = "Set to true to deploy API Gateway lab infrastructure"
}