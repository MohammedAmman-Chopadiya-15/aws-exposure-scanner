# lambdas.tf

# Discover all subdirectories inside ../lambdas matching "auditor_*"
# -----------------------------------------------------------------------------

locals {
  auditor_dirs = toset(distinct([
    for f in fileset("${path.module}/../lambdas", "auditor_*/*") :
    split("/", f)[0]
  ]))
}


# Dynamic zip generation for all discovered auditor folders

data "archive_file" "dynamic_auditor_zips" {
  for_each    = local.auditor_dirs
  type        = "zip"
  source_dir  = "${path.module}/../lambdas/${each.value}"
  output_path = "${path.module}/zips/${each.value}.zip"
}

# Explicit zip for the orchestrator (since it requires unique env vars & timeout)
data "archive_file" "zip_orchestrator" {
  type        = "zip"
  source_dir  = "${path.module}/../lambdas/orchestrator"
  output_path = "${path.module}/zips/orchestrator.zip"
}

# Automatically provisions a Lambda resource per discovered folder

resource "aws_lambda_function" "dynamic_auditors" {
  for_each         = local.auditor_dirs
  # Converts "auditor_s3" -> "${var.app_name}-auditor-s3"
  function_name    = "${var.app_name}-${replace(each.value, "_", "-")}"
  role             = aws_iam_role.lambda_exec_role.arn
  handler          = "lambda_function.lambda_handler"
  runtime          = "python3.12"
  timeout          = 60
  filename         = data.archive_file.dynamic_auditor_zips[each.value].output_path
  source_code_hash = data.archive_file.dynamic_auditor_zips[each.value].output_base64sha256
}


# ORCHESTRATOR LAMBDA FUNCTION

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


# API GATEWAY INTEGRATION & PERMISSIONS

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