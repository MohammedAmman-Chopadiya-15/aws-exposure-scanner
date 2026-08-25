# Scenario 1: High Risk User (Direct AdministratorAccess Policy Attachment)

# Creating an IAM user with direct admin privileges
resource "aws_iam_user" "high_admin_user" {
  count         = var.deploy_iam ? 1 : 0
  name          = "msc-lab-high-admin-user"
  path          = "/lab/"
  force_destroy = true
}

# Attaching AdministratorAccess directly to the user
resource "aws_iam_user_policy_attachment" "high_admin_attach" {
  count      = var.deploy_iam ? 1 : 0
  user       = aws_iam_user.high_admin_user[0].name
  policy_arn = "arn:aws:iam::aws:policy/AdministratorAccess"
}

# Scenario 2: Medium Risk User (Console Password Without MFA Configured)

# Creating a user with console login access
resource "aws_iam_user" "medium_console_user" {
  count         = var.deploy_iam ? 1 : 0
  name          = "msc-lab-medium-console-user"
  path          = "/lab/"
  force_destroy = true
}

# Enabling console password login without enforcing MFA
resource "aws_iam_user_login_profile" "medium_console_login" {
  count                   = var.deploy_iam ? 1 : 0
  user                    = aws_iam_user.medium_console_user[0].name
  password_reset_required = false
}

# Scenario 3: Low Risk User (Multiple Simultaneous Active Access Keys)

# Creating an IAM user with redundant programmatic keys
resource "aws_iam_user" "low_keys_user" {
  count         = var.deploy_iam ? 1 : 0
  name          = "msc-lab-low-multiple-keys-user"
  path          = "/lab/"
  force_destroy = true
}

# Generating primary active access key
resource "aws_iam_access_key" "key_one" {
  count  = var.deploy_iam ? 1 : 0
  user   = aws_iam_user.low_keys_user[0].name
  status = "Active"
}

# Generating secondary active access key
resource "aws_iam_access_key" "key_two" {
  count  = var.deploy_iam ? 1 : 0
  user   = aws_iam_user.low_keys_user[0].name
  status = "Active"
}

# Scenario 4: Compliant Baseline User (Group-Inherited Read-Only Permissions)

# Creating a standard read-only IAM user
resource "aws_iam_user" "perfect_user" {
  count         = var.deploy_iam ? 1 : 0
  name          = "msc-lab-perfect-read-only-user"
  path          = "/lab/"
  force_destroy = true
}

# Creating dedicated IAM group for read-only access
resource "aws_iam_group" "compliant_group" {
  count = var.deploy_iam ? 1 : 0
  name  = "msc-lab-readonly-group"
  path  = "/lab/"
}

# Attaching ReadOnlyAccess policy to the group
resource "aws_iam_group_policy_attachment" "compliant_group_attach" {
  count      = var.deploy_iam ? 1 : 0
  group      = aws_iam_group.compliant_group[0].name
  policy_arn = "arn:aws:iam::aws:policy/ReadOnlyAccess"
}

# Adding the user to the compliant IAM group
resource "aws_iam_user_group_membership" "perfect_user_membership" {
  count = var.deploy_iam ? 1 : 0
  user  = aws_iam_user.perfect_user[0].name
  groups = [
    aws_iam_group.compliant_group[0].name
  ]
}