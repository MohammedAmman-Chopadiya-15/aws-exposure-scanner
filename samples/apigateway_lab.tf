# Scenario 1: Critical Risk HTTP API (Unauthenticated, Wildcard CORS, Default Endpoint)

# Deploying a publicly exposed HTTP API with open CORS
resource "aws_apigatewayv2_api" "critical_http_api" {
  count                        = var.deploy_apigateway ? 1 : 0
  name                         = "msc-lab-critical-http-api"
  protocol_type                = "HTTP"
  disable_execute_api_endpoint = false

  cors_configuration {
    allow_origins = ["*"]
    allow_methods = ["GET", "POST", "OPTIONS"]
    allow_headers = ["*"]
  }

  tags = {
    Name        = "msc-lab-critical-http-api"
    Environment = "MSc-Lab"
  }
}

# Setting up an unauthenticated public route
resource "aws_apigatewayv2_route" "critical_http_route" {
  count              = var.deploy_apigateway ? 1 : 0
  api_id             = aws_apigatewayv2_api.critical_http_api[0].id
  route_key          = "GET /public-data"
  authorization_type = "NONE"
}

# Deploying default stage without access logging
resource "aws_apigatewayv2_stage" "critical_http_stage" {
  count       = var.deploy_apigateway ? 1 : 0
  api_id      = aws_apigatewayv2_api.critical_http_api[0].id
  name        = "$default"
  auto_deploy = true
}

# Scenario 2: High Risk REST API (Missing WAF & Resource Policy)

# Deploying a REST API without a restrictive resource policy
resource "aws_api_gateway_rest_api" "high_risk_rest_api" {
  count       = var.deploy_apigateway ? 1 : 0
  name        = "msc-lab-high-rest-api"
  description = "REST API with missing WAF and resource policy"

  endpoint_configuration {
    types = ["REGIONAL"]
  }
  policy = ""
}

# Adding a secure data resource path
resource "aws_api_gateway_resource" "rest_resource" {
  count       = var.deploy_apigateway ? 1 : 0
  rest_api_id = aws_api_gateway_rest_api.high_risk_rest_api[0].id
  parent_id   = aws_api_gateway_rest_api.high_risk_rest_api[0].root_resource_id
  path_part   = "secure-data"
}

# Securing the GET method with IAM auth
resource "aws_api_gateway_method" "rest_method_iam" {
  count         = var.deploy_apigateway ? 1 : 0
  rest_api_id   = aws_api_gateway_rest_api.high_risk_rest_api[0].id
  resource_id   = aws_api_gateway_resource.rest_resource[0].id
  http_method   = "GET"
  authorization = "AWS_IAM"
}

# Attaching a mock backend integration
resource "aws_api_gateway_integration" "rest_mock_integration" {
  count       = var.deploy_apigateway ? 1 : 0
  rest_api_id = aws_api_gateway_rest_api.high_risk_rest_api[0].id
  resource_id = aws_api_gateway_resource.rest_resource[0].id
  http_method = aws_api_gateway_method.rest_method_iam[0].http_method
  type        = "MOCK"

  request_templates = {
    "application/json" = "{\"statusCode\": 200}"
  }
}

# Triggering deployment on method or integration changes
resource "aws_api_gateway_deployment" "rest_deployment" {
  count       = var.deploy_apigateway ? 1 : 0
  rest_api_id = aws_api_gateway_rest_api.high_risk_rest_api[0].id

  triggers = {
    redeployment = sha1(jsonencode([
      aws_api_gateway_resource.rest_resource[0].id,
      aws_api_gateway_method.rest_method_iam[0].id,
      aws_api_gateway_integration.rest_mock_integration[0].id,
    ]))
  }

  lifecycle {
    create_before_destroy = true
  }

  depends_on = [
    aws_api_gateway_integration.rest_mock_integration
  ]
}

# Deploying dev stage without attaching WAF or execution logging
resource "aws_api_gateway_stage" "rest_stage" {
  count         = var.deploy_apigateway ? 1 : 0
  deployment_id = aws_api_gateway_deployment.rest_deployment[0].id
  rest_api_id   = aws_api_gateway_rest_api.high_risk_rest_api[0].id
  stage_name    = "dev"
}

# Scenario 3: Medium Risk HTTP API (Missing Stage Access Logs)

# Deploying an HTTP API with disabled default endpoint and locked CORS
resource "aws_apigatewayv2_api" "medium_http_api" {
  count                        = var.deploy_apigateway ? 1 : 0
  name                         = "msc-lab-medium-http-api"
  protocol_type                = "HTTP"
  disable_execute_api_endpoint = true

  cors_configuration {
    allow_origins = ["https://app.securelab.internal"]
    allow_methods = ["GET", "OPTIONS"]
    allow_headers = ["Authorization", "Content-Type"]
  }
}

# Protecting user profile route with IAM auth
resource "aws_apigatewayv2_route" "medium_http_route" {
  count              = var.deploy_apigateway ? 1 : 0
  api_id             = aws_apigatewayv2_api.medium_http_api[0].id
  route_key          = "GET /user-profile"
  authorization_type = "AWS_IAM"
}

# Deploying default stage without access logs
resource "aws_apigatewayv2_stage" "medium_http_stage" {
  count       = var.deploy_apigateway ? 1 : 0
  api_id      = aws_apigatewayv2_api.medium_http_api[0].id
  name        = "$default"
  auto_deploy = true
}

# Scenario 4: Compliant Baseline HTTP API (Zero Exposure)

# Creating CloudWatch log group for access logs
resource "aws_cloudwatch_log_group" "compliant_api_logs" {
  count             = var.deploy_apigateway ? 1 : 0
  name              = "/aws/apigateway/msc-lab-compliant-http-api"
  retention_in_days = 7
}

# Deploying fully hardened HTTP API
resource "aws_apigatewayv2_api" "compliant_http_api" {
  count                        = var.deploy_apigateway ? 1 : 0
  name                         = "msc-lab-compliant-http-api"
  protocol_type                = "HTTP"
  disable_execute_api_endpoint = true

  cors_configuration {
    allow_origins = ["https://app.securelab.internal"]
    allow_methods = ["GET", "OPTIONS"]
    allow_headers = ["Authorization", "Content-Type"]
  }
}

# Protecting orders route with IAM auth
resource "aws_apigatewayv2_route" "compliant_orders_route" {
  count              = var.deploy_apigateway ? 1 : 0
  api_id             = aws_apigatewayv2_api.compliant_http_api[0].id
  route_key          = "GET /orders"
  authorization_type = "AWS_IAM"
}

# Permitting unauthenticated OPTIONS preflight route
resource "aws_apigatewayv2_route" "compliant_options_route" {
  count              = var.deploy_apigateway ? 1 : 0
  api_id             = aws_apigatewayv2_api.compliant_http_api[0].id
  route_key          = "OPTIONS /orders"
  authorization_type = "NONE"
}

# Deploying stage with structured CloudWatch logging enabled
resource "aws_apigatewayv2_stage" "compliant_http_stage" {
  count       = var.deploy_apigateway ? 1 : 0
  api_id      = aws_apigatewayv2_api.compliant_http_api[0].id
  name        = "$default"
  auto_deploy = true

  access_log_settings {
    destination_arn = aws_cloudwatch_log_group.compliant_api_logs[0].arn
    format = jsonencode({
      requestId      = "$context.requestId"
      ip             = "$context.identity.sourceIp"
      requestTime    = "$context.requestTime"
      httpMethod     = "$context.httpMethod"
      routeKey       = "$context.routeKey"
      status         = "$context.status"
      responseLength = "$context.responseLength"
    })
  }
}