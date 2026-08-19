# samples/apigateway_lab.tf

# =====================================================================
# SCENARIO 1: CRITICAL RISK HTTP API (API Gateway v2)
# Triggers:
# - APIGW-01: Unauthenticated route (AuthorizationType: NONE) -> CRITICAL (9.5)
# - APIGW-03: Default execute-api endpoint enabled -> HIGH (7.8)
# - APIGW-04: Wildcard CORS origin (*) -> HIGH (7.8)
# - APIGW-06: Stage access logging disabled -> MEDIUM (5.5)
# Overall Severity: CRITICAL (9.5)
# =====================================================================
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

resource "aws_apigatewayv2_route" "critical_http_route" {
  count              = var.deploy_apigateway ? 1 : 0
  api_id             = aws_apigatewayv2_api.critical_http_api[0].id
  route_key          = "GET /public-data"
  authorization_type = "NONE" # Triggers APIGW-01 (CRITICAL: 9.5)
}

resource "aws_apigatewayv2_stage" "critical_http_stage" {
  count       = var.deploy_apigateway ? 1 : 0
  api_id      = aws_apigatewayv2_api.critical_http_api[0].id
  name        = "$default"
  auto_deploy = true # Lacks access logging -> Triggers APIGW-06 (MEDIUM: 5.5)
}

# =====================================================================
# SCENARIO 2: HIGH RISK REST API (API Gateway v1)
# Triggers:
# - APIGW-02: Missing AWS WAF Web ACL on Stage -> HIGH (8.2)
# - APIGW-05: Missing Resource Policy -> HIGH (7.5)
# - APIGW-06: Execution logging disabled -> MEDIUM (5.5)
# (Uses AWS_IAM auth so APIGW-01 is NOT triggered)
# Overall Severity: HIGH (8.2)
# =====================================================================
resource "aws_api_gateway_rest_api" "high_risk_rest_api" {
  count       = var.deploy_apigateway ? 1 : 0
  name        = "msc-lab-high-rest-api"
  description = "REST API with missing WAF and resource policy"

  endpoint_configuration {
    types = ["REGIONAL"]
  }
  policy = "" # Triggers APIGW-05 (HIGH: 7.5)
}

resource "aws_api_gateway_resource" "rest_resource" {
  count       = var.deploy_apigateway ? 1 : 0
  rest_api_id = aws_api_gateway_rest_api.high_risk_rest_api[0].id
  parent_id   = aws_api_gateway_rest_api.high_risk_rest_api[0].root_resource_id
  path_part   = "secure-data"
}

resource "aws_api_gateway_method" "rest_method_iam" {
  count         = var.deploy_apigateway ? 1 : 0
  rest_api_id   = aws_api_gateway_rest_api.high_risk_rest_api[0].id
  resource_id   = aws_api_gateway_resource.rest_resource[0].id
  http_method   = "GET"
  authorization = "AWS_IAM" # Passes APIGW-01
}

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

resource "aws_api_gateway_stage" "rest_stage" {
  count         = var.deploy_apigateway ? 1 : 0
  deployment_id = aws_api_gateway_deployment.rest_deployment[0].id
  rest_api_id   = aws_api_gateway_rest_api.high_risk_rest_api[0].id
  stage_name    = "dev" # Triggers APIGW-02 (HIGH: 8.2) & APIGW-06 (MEDIUM: 5.5)
}


# =====================================================================
# SCENARIO 3: MEDIUM RISK HTTP API (API Gateway v2)
# Triggers:
# - APIGW-06: Stage access logging disabled -> MEDIUM (5.5)
# (Disabled default endpoint, explicit CORS whitelist, AWS_IAM auth)
# Overall Severity: MEDIUM (5.5)
# =====================================================================
resource "aws_apigatewayv2_api" "medium_http_api" {
  count                        = var.deploy_apigateway ? 1 : 0
  name                         = "msc-lab-medium-http-api"
  protocol_type                = "HTTP"
  disable_execute_api_endpoint = true # Passes APIGW-03

  cors_configuration {
    allow_origins = ["https://app.securelab.internal"] # Passes APIGW-04
    allow_methods = ["GET", "OPTIONS"]
    allow_headers = ["Authorization", "Content-Type"]
  }
}

resource "aws_apigatewayv2_route" "medium_http_route" {
  count              = var.deploy_apigateway ? 1 : 0
  api_id             = aws_apigatewayv2_api.medium_http_api[0].id
  route_key          = "GET /user-profile"
  authorization_type = "AWS_IAM" # Passes APIGW-01
}

resource "aws_apigatewayv2_stage" "medium_http_stage" {
  count       = var.deploy_apigateway ? 1 : 0
  api_id      = aws_apigatewayv2_api.medium_http_api[0].id
  name        = "$default"
  auto_deploy = true # Triggers APIGW-06 (MEDIUM: 5.5)
}

# =====================================================================
# SCENARIO 4: COMPLIANT HTTP API (Zero Exposure - ADVISORY: 0.0)
# Controls:
# - Disabled default execute-api endpoint (Passes APIGW-03)
# - Explicit CORS whitelist (Passes APIGW-04)
# - AWS_IAM auth on data route (Passes APIGW-01)
# - OPTIONS route unauthenticated (Exempted by auditor)
# - CloudWatch access logging configured (Passes APIGW-06)
# Overall Severity: ADVISORY (0.0)
# =====================================================================
resource "aws_cloudwatch_log_group" "compliant_api_logs" {
  count             = var.deploy_apigateway ? 1 : 0
  name              = "/aws/apigateway/msc-lab-compliant-http-api"
  retention_in_days = 7
}

resource "aws_apigatewayv2_api" "compliant_http_api" {
  count                        = var.deploy_apigateway ? 1 : 0
  name                         = "msc-lab-compliant-http-api"
  protocol_type                = "HTTP"
  disable_execute_api_endpoint = true # Passes APIGW-03

  cors_configuration {
    allow_origins = ["https://app.securelab.internal"] # Passes APIGW-04
    allow_methods = ["GET", "OPTIONS"]
    allow_headers = ["Authorization", "Content-Type"]
  }
}

resource "aws_apigatewayv2_route" "compliant_orders_route" {
  count              = var.deploy_apigateway ? 1 : 0
  api_id             = aws_apigatewayv2_api.compliant_http_api[0].id
  route_key          = "GET /orders"
  authorization_type = "AWS_IAM" # Passes APIGW-01
}

resource "aws_apigatewayv2_route" "compliant_options_route" {
  count              = var.deploy_apigateway ? 1 : 0
  api_id             = aws_apigatewayv2_api.compliant_http_api[0].id
  route_key          = "OPTIONS /orders"
  authorization_type = "NONE" # OPTIONS preflight route exempted in auditor
}

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