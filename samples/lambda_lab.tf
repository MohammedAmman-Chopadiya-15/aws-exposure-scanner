# Packaging dummy Lambda code inline without external file dependencies
data "archive_file" "lambda_dummy_zip" {
  count       = var.deploy_lambda ? 1 : 0
  type        = "zip"
  output_path = "${path.module}/dummy_lambda.zip"

  source {
    content  = "def lambda_handler(event, context):\n    return {'statusCode': 200, 'body': 'OK'}"
    filename = "index.py"
  }
}

# Creating standard minimal IAM execution role
resource "aws_iam_role" "lambda_basic_role" {
  count = var.deploy_lambda ? 1 : 0
  name  = "msc-lab-lambda-basic-role"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Action    = "sts:AssumeRole"
      Effect    = "Allow"
      Principal = { Service = "lambda.amazonaws.com" }
    }]
  })
}

# Attaching basic execution permissions for CloudWatch logs
resource "aws_iam_role_policy_attachment" "lambda_basic_attach" {
  count      = var.deploy_lambda ? 1 : 0
  role       = aws_iam_role.lambda_basic_role[0].name
  policy_arn = "arn:aws:iam::aws:policy/service-role/AWSLambdaBasicExecutionRole"
}

# Creating an overprivileged IAM admin execution role
resource "aws_iam_role" "lambda_admin_role" {
  count = var.deploy_lambda ? 1 : 0
  name  = "msc-lab-lambda-admin-role"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Action    = "sts:AssumeRole"
      Effect    = "Allow"
      Principal = { Service = "lambda.amazonaws.com" }
    }]
  })
}

# Attaching full AdministratorAccess to the admin role
resource "aws_iam_role_policy_attachment" "lambda_admin_attach" {
  count      = var.deploy_lambda ? 1 : 0
  role       = aws_iam_role.lambda_admin_role[0].name
  policy_arn = "arn:aws:iam::aws:policy/AdministratorAccess"
}

# Scenario 1: Critical Risk Function (Unauthenticated URL & Public Resource Policy)

# Deploying a function exposed via public invoke policies
resource "aws_lambda_function" "critical_lambda" {
  count            = var.deploy_lambda ? 1 : 0
  function_name    = "msc-lab-critical-public-lambda"
  role             = aws_iam_role.lambda_basic_role[0].arn
  handler          = "index.lambda_handler"
  runtime          = "python3.12"
  filename         = data.archive_file.lambda_dummy_zip[0].output_path
  source_code_hash = data.archive_file.lambda_dummy_zip[0].output_base64sha256

  tracing_config {
    mode = "Active"
  }
}

# Creating an unauthenticated public Function URL
resource "aws_lambda_function_url" "critical_url" {
  count              = var.deploy_lambda ? 1 : 0
  function_name      = aws_lambda_function.critical_lambda[0].function_name
  authorization_type = "NONE"
}

# Granting wildcard public invocation permissions
resource "aws_lambda_permission" "critical_public_invoke" {
  count         = var.deploy_lambda ? 1 : 0
  statement_id  = "AllowPublicInvokeWildcard"
  action        = "lambda:InvokeFunction"
  function_name = aws_lambda_function.critical_lambda[0].function_name
  principal     = "*"
}

# Scenario 2: High Risk Function (Administrator Role & Deprecated Runtime)

# Deploying function with full admin privileges on deprecated python3.8 runtime
resource "aws_lambda_function" "high_risk_lambda" {
  count            = var.deploy_lambda ? 1 : 0
  function_name    = "msc-lab-high-deprecated-lambda"
  role             = aws_iam_role.lambda_admin_role[0].arn
  handler          = "index.lambda_handler"
  runtime          = "python3.8"
  filename         = data.archive_file.lambda_dummy_zip[0].output_path
  source_code_hash = data.archive_file.lambda_dummy_zip[0].output_base64sha256

  tracing_config {
    mode = "Active"
  }
}

# Scenario 3: Medium Risk Function (Unencrypted Env Vars & No VPC)

# Deploying function with default AWS KMS key and no VPC isolation
resource "aws_lambda_function" "medium_risk_lambda" {
  count            = var.deploy_lambda ? 1 : 0
  function_name    = "msc-lab-medium-env-novpc-lambda"
  role             = aws_iam_role.lambda_basic_role[0].arn
  handler          = "index.lambda_handler"
  runtime          = "python3.12"
  filename         = data.archive_file.lambda_dummy_zip[0].output_path
  source_code_hash = data.archive_file.lambda_dummy_zip[0].output_base64sha256

  environment {
    variables = {
      STAGE       = "dev"
      DB_ENDPOINT = "mysql.internal.local"
    }
  }

  tracing_config {
    mode = "Active"
  }
}

# Scenario 4: Low Risk Function (X-Ray Tracing Disabled)

# Deploying function with pass-through tracing mode instead of active X-Ray
resource "aws_lambda_function" "low_risk_lambda" {
  count            = var.deploy_lambda ? 1 : 0
  function_name    = "msc-lab-low-notracing-lambda"
  role             = aws_iam_role.lambda_basic_role[0].arn
  handler          = "index.lambda_handler"
  runtime          = "python3.12"
  filename         = data.archive_file.lambda_dummy_zip[0].output_path
  source_code_hash = data.archive_file.lambda_dummy_zip[0].output_base64sha256

  tracing_config {
    mode = "PassThrough"
  }
}

# Scenario 5: Multi-Region High Risk Function [us-east-1]

# Deploying an overprivileged admin Lambda function in us-east-1
resource "aws_lambda_function" "us_east_1_high_lambda" {
  provider         = aws.us_east_1
  count            = var.deploy_lambda ? 1 : 0
  function_name    = "msc-lab-us-east-1-admin-lambda"
  role             = aws_iam_role.lambda_admin_role[0].arn
  handler          = "index.lambda_handler"
  runtime          = "python3.12"
  filename         = data.archive_file.lambda_dummy_zip[0].output_path
  source_code_hash = data.archive_file.lambda_dummy_zip[0].output_base64sha256

  tracing_config {
    mode = "Active"
  }
}