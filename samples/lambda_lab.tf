# samples/lambda_lab.tf

# ---------------------------------------------------------------------
# CODE PACKAGE (Zero external files required)
# ---------------------------------------------------------------------
data "archive_file" "lambda_dummy_zip" {
  count       = var.deploy_lambda ? 1 : 0
  type        = "zip"
  output_path = "${path.module}/dummy_lambda.zip"

  source {
    content  = "def lambda_handler(event, context):\n    return {'statusCode': 200, 'body': 'OK'}"
    filename = "index.py"
  }
}

# ---------------------------------------------------------------------
# SHARED IAM ROLES
# ---------------------------------------------------------------------
# Compliant Minimal Execution Role
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

resource "aws_iam_role_policy_attachment" "lambda_basic_attach" {
  count      = var.deploy_lambda ? 1 : 0
  role       = aws_iam_role.lambda_basic_role[0].name
  policy_arn = "arn:aws:iam::aws:policy/service-role/AWSLambdaBasicExecutionRole"
}

# Overprivileged Admin Role (Triggers Check 3)
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

resource "aws_iam_role_policy_attachment" "lambda_admin_attach" {
  count      = var.deploy_lambda ? 1 : 0
  role       = aws_iam_role.lambda_admin_role[0].name
  policy_arn = "arn:aws:iam::aws:policy/AdministratorAccess"
}

# =====================================================================
# SCENARIO 1: CRITICAL RISK FUNCTION (Unauthenticated Function URL & Public Policy)
# Triggers:
# - Check 1: Public Function URL (AuthType: NONE) -> CRITICAL (9.8)
# - Check 2: Public Resource Policy (Principal: *) -> CRITICAL (9.2)
# =====================================================================
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

# Check 1 Trigger: Public URL (AuthType NONE)
resource "aws_lambda_function_url" "critical_url" {
  count              = var.deploy_lambda ? 1 : 0
  function_name      = aws_lambda_function.critical_lambda[0].function_name
  authorization_type = "NONE"
}

# Check 2 Trigger: Public Resource Policy (* Principal without condition)
resource "aws_lambda_permission" "critical_public_invoke" {
  count         = var.deploy_lambda ? 1 : 0
  statement_id  = "AllowPublicInvokeWildcard"
  action        = "lambda:InvokeFunction"
  function_name = aws_lambda_function.critical_lambda[0].function_name
  principal     = "*"
}

# =====================================================================
# SCENARIO 2: HIGH RISK FUNCTION (Admin Role & Deprecated Runtime)
# Triggers:
# - Check 3: Overprivileged Role (AdministratorAccess) -> HIGH (8.5)
# - Check 4: Deprecated Runtime (python3.8) -> HIGH (7.5)
# =====================================================================
resource "aws_lambda_function" "high_risk_lambda" {
  count            = var.deploy_lambda ? 1 : 0
  function_name    = "msc-lab-high-deprecated-lambda"
  role             = aws_iam_role.lambda_admin_role[0].arn # Check 3: Admin Role
  handler          = "index.lambda_handler"
  runtime          = "python3.8"                          # Check 4: Deprecated Runtime
  filename         = data.archive_file.lambda_dummy_zip[0].output_path
  source_code_hash = data.archive_file.lambda_dummy_zip[0].output_base64sha256

  tracing_config {
    mode = "Active"
  }
}

# =====================================================================
# SCENARIO 3: MEDIUM RISK FUNCTION (Unencrypted Env Vars & No VPC)
# Triggers:
# - Check 5: Env Vars without KMS CMK -> MEDIUM (5.0)
# - Check 6: Function Outside VPC -> MEDIUM (4.2)
# =====================================================================
resource "aws_lambda_function" "medium_risk_lambda" {
  count            = var.deploy_lambda ? 1 : 0
  function_name    = "msc-lab-medium-env-novpc-lambda"
  role             = aws_iam_role.lambda_basic_role[0].arn
  handler          = "index.lambda_handler"
  runtime          = "python3.12"
  filename         = data.archive_file.lambda_dummy_zip[0].output_path
  source_code_hash = data.archive_file.lambda_dummy_zip[0].output_base64sha256

  # Check 5 Trigger: Environment variables without KMS CMK
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

# =====================================================================
# SCENARIO 4: LOW RISK FUNCTION (X-Ray Tracing Disabled)
# Triggers:
# - Check 7: X-Ray Tracing Disabled (PassThrough) -> LOW (2.5)
# =====================================================================
resource "aws_lambda_function" "low_risk_lambda" {
  count            = var.deploy_lambda ? 1 : 0
  function_name    = "msc-lab-low-notracing-lambda"
  role             = aws_iam_role.lambda_basic_role[0].arn
  handler          = "index.lambda_handler"
  runtime          = "python3.12"
  filename         = data.archive_file.lambda_dummy_zip[0].output_path
  source_code_hash = data.archive_file.lambda_dummy_zip[0].output_base64sha256

  # Check 7 Trigger: Tracing mode is PassThrough (Not Active)
  tracing_config {
    mode = "PassThrough"
  }
}

# =====================================================================
# SCENARIO 5: N. VIRGINIA (us-east-1) HIGH RISK MULTI-REGION FUNCTION
# Triggers:
# - Check 3: Overprivileged Role (AdministratorAccess) -> HIGH (8.5)
# =====================================================================
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