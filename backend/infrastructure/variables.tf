variable "aws_region" {
  description = "AWS region to deploy the scanner backend"
  type        = string
  default     = "eu-west-2"
}

variable "app_name" {
  description = "Base prefix for resource naming"
  type        = string
  default     = "exposure-scanner"
}

variable "scanner_api_key" {
  description = "Secret key required to authorize requests to API Gateway"
  type        = string
  sensitive   = true
}