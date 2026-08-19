# iam_lab.tf

# ---------------------------------------------------------------------
# SCENARIO 1: HIGH RISK USER (Direct AdministratorAccess - IAM-03)
# ---------------------------------------------------------------------
resource "aws_iam_user" "high_admin_user" {
  count         = var.deploy_iam ? 1 : 0
  name          = "msc-lab-high-admin-user"
  path          = "/lab/"
  force_destroy = true
}

resource "aws_iam_user_policy_attachment" "high_admin_attach" {
  count      = var.deploy_iam ? 1 : 0
  user       = aws_iam_user.high_admin_user[0].name
  policy_arn = "arn:aws:iam::aws:policy/AdministratorAccess"
}

# ---------------------------------------------------------------------
# SCENARIO 2: MEDIUM RISK USER (Console Password Without MFA - IAM-05)
# ---------------------------------------------------------------------
resource "aws_iam_user" "medium_console_user" {
  count         = var.deploy_iam ? 1 : 0
  name          = "msc-lab-medium-console-user"
  path          = "/lab/"
  force_destroy = true
}

resource "aws_iam_user_login_profile" "medium_console_login" {
  count                   = var.deploy_iam ? 1 : 0
  user                    = aws_iam_user.medium_console_user[0].name
  password_reset_required = false
}

# ---------------------------------------------------------------------
# SCENARIO 3: LOW RISK USER (Multiple Active Access Keys - IAM-08)
# ---------------------------------------------------------------------
resource "aws_iam_user" "low_keys_user" {
  count         = var.deploy_iam ? 1 : 0
  name          = "msc-lab-low-multiple-keys-user"
  path          = "/lab/"
  force_destroy = true
}

resource "aws_iam_access_key" "key_one" {
  count  = var.deploy_iam ? 1 : 0
  user   = aws_iam_user.low_keys_user[0].name
  status = "Active"
}

resource "aws_iam_access_key" "key_two" {
  count  = var.deploy_iam ? 1 : 0
  user   = aws_iam_user.low_keys_user[0].name
  status = "Active"
}

# ---------------------------------------------------------------------
# SCENARIO 4: COMPLIANT / PERFECT USER (Group Inherited - ADVISORY: 0.0)
# ---------------------------------------------------------------------
resource "aws_iam_user" "perfect_user" {
  count         = var.deploy_iam ? 1 : 0
  name          = "msc-lab-perfect-read-only-user"
  path          = "/lab/"
  force_destroy = true
}

resource "aws_iam_group" "compliant_group" {
  count = var.deploy_iam ? 1 : 0
  name  = "msc-lab-readonly-group"
  path  = "/lab/"
}

resource "aws_iam_group_policy_attachment" "compliant_group_attach" {
  count      = var.deploy_iam ? 1 : 0
  group      = aws_iam_group.compliant_group[0].name
  policy_arn = "arn:aws:iam::aws:policy/ReadOnlyAccess"
}

resource "aws_iam_user_group_membership" "perfect_user_membership" {
  count = var.deploy_iam ? 1 : 0
  user  = aws_iam_user.perfect_user[0].name
  groups = [
    aws_iam_group.compliant_group[0].name
  ]
}