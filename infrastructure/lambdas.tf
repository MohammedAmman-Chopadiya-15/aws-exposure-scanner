# Package Lambda Source Code dynamically into Zips
data "archive_file" "zip_s3" {
  type        = "zip"
  source_dir  = "${path.module}/../lambdas/auditor_s3"
  output_path = "${path.module}/zips/auditor_s3.zip"
}

data "archive_file" "zip_ec2" {
  type        = "zip"
  source_dir  = "${path.module}/../lambdas/auditor_ec2"
  output_path = "${path.module}/zips/auditor_ec2.zip"
}

data "archive_file" "zip_rds" {
  type        = "zip"
  source_dir  = "${path.module}/../lambdas/auditor_rds"
  output_path = "${path.module}/zips/auditor_rds.zip"
}

data "archive_file" "zip_iam" {
  type        = "zip"
  source_dir  = "${path.module}/../lambdas/auditor_iam"
  output_path = "${path.module}/zips/auditor_iam.zip"
}

data "archive_file" "zip_orchestrator" {
  type        = "zip"
  source_dir  = "${path.module}/../lambdas/orchestrator"
  output_path = "${path.module}/zips/orchestrator.zip"
}

# --- 1. AUDITOR LAMBDAS ---
resource "aws_lambda_function" "auditor_s3" {
  function_name    = "${var.app_name}-auditor-s3"
  role             = aws_iam_role.lambda_exec_role.arn
  handler          = "lambda_function.lambda_handler"
  runtime          = "python3.12"
  timeout          = 30
  filename         = data.archive_file.zip_s3.output_path
  source_code_hash = data.archive_file.zip_s3.output_base64sha256
}

resource "aws_lambda_function" "auditor_ec2" {
  function_name    = "${var.app_name}-auditor-ec2"
  role             = aws_iam_role.lambda_exec_role.arn
  handler          = "lambda_function.lambda_handler"
  runtime          = "python3.12"
  timeout          = 30
  filename         = data.archive_file.zip_ec2.output_path
  source_code_hash = data.archive_file.zip_ec2.output_base64sha256
}

resource "aws_lambda_function" "auditor_rds" {
  function_name    = "${var.app_name}-auditor-rds"
  role             = aws_iam_role.lambda_exec_role.arn
  handler          = "lambda_function.lambda_handler"
  runtime          = "python3.12"
  timeout          = 30
  filename         = data.archive_file.zip_rds.output_path
  source_code_hash = data.archive_file.zip_rds.output_base64sha256
}

resource "aws_lambda_function" "auditor_iam" {
  function_name    = "${var.app_name}-auditor-iam"
  role             = aws_iam_role.lambda_exec_role.arn
  handler          = "lambda_function.lambda_handler"
  runtime          = "python3.12"
  timeout          = 30
  filename         = data.archive_file.zip_iam.output_path
  source_code_hash = data.archive_file.zip_iam.output_base64sha256
}

# --- 2. ORCHESTRATOR LAMBDA ---
resource "aws_lambda_function" "orchestrator" {
  function_name    = "${var.app_name}-orchestrator"
  role             = aws_iam_role.lambda_exec_role.arn
  handler          = "lambda_function.lambda_handler"
  runtime          = "python3.12"
  timeout          = 45
  filename         = data.archive_file.zip_orchestrator.output_path
  source_code_hash = data.archive_file.zip_orchestrator.output_base64sha256

  environment {
    variables = {
      SCANNER_API_KEY = var.scanner_api_key
    }
  }
}

# --- 3. API GATEWAY INTEGRATION ---
resource "aws_apigatewayv2_integration" "api_integration" {
  api_id                 = aws_apigatewayv2_api.http_api.id
  integration_type       = "AWS_PROXY"
  integration_uri        = aws_lambda_function.orchestrator.invoke_arn
  payload_format_version = "2.0"
}

resource "aws_apigatewayv2_route" "scan_route" {
  api_id    = aws_apigatewayv2_api.http_api.id
  route_key = "GET /api/scan"
  target    = "integrations/${aws_apigatewayv2_integration.api_integration.id}"
}

resource "aws_lambda_permission" "apigw_permission" {
  statement_id  = "AllowExecutionFromAPIGateway"
  action        = "lambda:InvokeFunction"
  function_name = aws_lambda_function.orchestrator.function_name
  principal     = "apigateway.amazonaws.com"
  source_arn    = "${aws_apigatewayv2_api.http_api.execution_arn}/*/*"
}