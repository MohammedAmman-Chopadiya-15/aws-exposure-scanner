terraform {
  required_version = ">= 1.5.0"
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 5.0"
    }
    archive = {
      source  = "hashicorp/archive"
      version = "~> 2.4"
    }
  }
}

provider "aws" {
  region = var.aws_region
}

# Creating an IAM execution role shared across all auditor and orchestrator Lambdas
resource "aws_iam_role" "lambda_exec_role" {
  name = "${var.app_name}-exec-role"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Action    = "sts:AssumeRole"
      Effect    = "Allow"
      Principal = { Service = "lambda.amazonaws.com" }
    }]
  })
}

# Attaching AWS SecurityAudit managed policy to grant read-only inspection access
resource "aws_iam_role_policy_attachment" "security_audit_attach" {
  role       = aws_iam_role.lambda_exec_role.name
  policy_arn = "arn:aws:iam::aws:policy/SecurityAudit"
}

# Attaching basic execution permissions for writing CloudWatch logs
resource "aws_iam_role_policy_attachment" "lambda_logs_attach" {
  role       = aws_iam_role.lambda_exec_role.name
  policy_arn = "arn:aws:iam::aws:policy/service-role/AWSLambdaBasicExecutionRole"
}

# Defining an IAM policy allowing the orchestrator function to trigger auditor Lambdas
resource "aws_iam_policy" "lambda_invoke_policy" {
  name        = "${var.app_name}-invoke-policy"
  description = "Allows orchestrator lambda to trigger service auditor lambdas"

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect   = "Allow"
      Action   = "lambda:InvokeFunction"
      Resource = "arn:aws:lambda:${var.aws_region}:*:function:${var.app_name}-*"
    }]
  })
}

# Attaching the Lambda invocation policy to the shared execution role
resource "aws_iam_role_policy_attachment" "invoke_policy_attach" {
  role       = aws_iam_role.lambda_exec_role.name
  policy_arn = aws_iam_policy.lambda_invoke_policy.arn
}

# Provisioning the public HTTP API Gateway endpoint
resource "aws_apigatewayv2_api" "http_api" {
  name          = "${var.app_name}-api"
  protocol_type = "HTTP"

  cors_configuration {
    allow_origins = ["*"]
    allow_methods = ["GET", "OPTIONS"]
    allow_headers = ["*"]
  }
}

# Configuring the default stage with automatic deployment enabled
resource "aws_apigatewayv2_stage" "api_stage" {
  api_id      = aws_apigatewayv2_api.http_api.id
  name        = "$default"
  auto_deploy = true
}

# Updating the frontend .env file with the newly generated API Gateway endpoint URL
resource "null_resource" "update_frontend_env" {
  triggers = {
    api_url = aws_apigatewayv2_stage.api_stage.invoke_url
  }

  provisioner "local-exec" {
    interpreter = ["PowerShell", "-Command"]
    command     = <<-EOT
      $envFile = "${path.module}/../../frontend/.env"
      $newUrl = "VITE_API_URL=${aws_apigatewayv2_stage.api_stage.invoke_url}/api/scan"
      
      if (Test-Path $envFile) {
        $content = Get-Content $envFile
        if ($content -match '^VITE_API_URL=') {
          $content = $content -replace '^VITE_API_URL=.*', $newUrl
        } else {
          $content += $newUrl
        }
        Set-Content -Path $envFile -Value $content
      } else {
        Set-Content -Path $envFile -Value $newUrl
      }
    EOT
  }
}