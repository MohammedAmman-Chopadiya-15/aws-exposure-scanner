variable "github_repo" {
  description = "GitHub repository formatted as 'username/repo-name'"
  type        = string
  default     = "MohammedAmman-Chopadiya-15/aws-exposure-scanner-backend"
}

# 1. Create the OIDC Identity Provider for GitHub in AWS
resource "aws_iam_openid_connect_provider" "github_oidc" {
  url             = "https://token.actions.githubusercontent.com"
  client_id_list  = ["sts.amazonaws.com"]
  thumbprint_list = ["6938fd4d98bab03faadb97b34396831e3780aea1"]
}

# 2. Create the IAM Role that GitHub Actions will assume
resource "aws_iam_role" "github_actions_role" {
  name = "github-actions-terraform-deployer"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect = "Allow"
        Principal = {
          Federated = aws_iam_openid_connect_provider.github_oidc.arn
        }
        Action = "sts:AssumeRoleWithWebIdentity"
        Condition = {
          StringEquals = {
            "token.actions.githubusercontent.com:aud" = "sts.amazonaws.com"
          }
          StringLike = {
            # STRICT GUARDRAIL: Only allow pushes from YOUR specific repository
            "token.actions.githubusercontent.com:sub" = "repo:${var.github_repo}:*"
          }
        }
      }
    ]
  })
}

# 3. Attach permissions required to deploy the scanner stack
resource "aws_iam_role_policy_attachment" "github_actions_admin_attach" {
  role       = aws_iam_role.github_actions_role.name
  policy_arn = "arn:aws:iam::aws:policy/AdministratorAccess" # Or scoped deployment policy
}

output "github_actions_role_arn" {
  description = "IAM Role ARN to put in GitHub Secrets/Variables"
  value       = aws_iam_role.github_actions_role.arn
}