# iam_lab.tf

# ---------------------------------------------------------------------
# SCENARIO 1: CRITICAL USER (Direct Admin Access)
# ---------------------------------------------------------------------
resource "aws_iam_user" "critical_user" {
  count = var.deploy_iam ? 1 : 0
  name  = "msc-lab-critical-admin-user"
  path  = "/lab/"
}

resource "aws_iam_user_policy_attachment" "critical_admin_attach" {
  count      = var.deploy_iam ? 1 : 0
  user       = aws_iam_user.critical_user[0].name
  policy_arn = "arn:aws:iam::aws:policy/AdministratorAccess"
}

# ---------------------------------------------------------------------
# SCENARIO 2: COMPLIANT READ-ONLY USER
# ---------------------------------------------------------------------
resource "aws_iam_user" "perfect_user" {
  count = var.deploy_iam ? 1 : 0
  name  = "msc-lab-perfect-read-only-user"
  path  = "/lab/"
}

resource "aws_iam_policy" "compliant_policy" {
  count       = var.deploy_iam ? 1 : 0
  name        = "msc-lab-restricted-s3-read-policy"
  description = "Compliant least-privilege policy"

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect   = "Allow"
        Action   = ["s3:ListAllMyBuckets", "s3:GetBucketLocation"]
        Resource = "arn:aws:s3:::*"
      }
    ]
  })
}

resource "aws_iam_user_policy_attachment" "perfect_user_attach" {
  count      = var.deploy_iam ? 1 : 0
  user       = aws_iam_user.perfect_user[0].name
  policy_arn = aws_iam_policy.compliant_policy[0].arn
}

# ---------------------------------------------------------------------
# SCENARIO 3: WEAK ACCOUNT PASSWORD POLICY
# ---------------------------------------------------------------------
resource "aws_iam_account_password_policy" "lab_password_policy" {
  count                          = var.deploy_iam ? 1 : 0
  minimum_password_length        = 8
  require_symbols                = false
  require_numbers                = true
  require_uppercase_characters   = true
  require_lowercase_characters   = true
  allow_users_to_change_password = true
}
