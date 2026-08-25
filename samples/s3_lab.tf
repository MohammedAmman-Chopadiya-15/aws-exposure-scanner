# Generating a random hex suffix to ensure unique bucket names
resource "random_id" "bucket_suffix" {
  count       = var.deploy_s3 ? 1 : 0
  byte_length = 4
}

# Creating dedicated audit logging destination bucket
resource "aws_s3_bucket" "audit_logs" {
  count         = var.deploy_s3 ? 1 : 0
  bucket        = "msc-lab-${random_id.bucket_suffix[0].hex}-audit-logs"
  force_destroy = true
}

# Enforcing bucket owner permissions on audit logs
resource "aws_s3_bucket_ownership_controls" "audit_logs_ownership" {
  count  = var.deploy_s3 ? 1 : 0
  bucket = aws_s3_bucket.audit_logs[0].id
  rule {
    object_ownership = "BucketOwnerEnforced"
  }
}

# Locking down public access on audit logging bucket
resource "aws_s3_bucket_public_access_block" "audit_logs_bpa" {
  count                   = var.deploy_s3 ? 1 : 0
  bucket                  = aws_s3_bucket.audit_logs[0].id
  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

# Scenario 1: Compliant Baseline Bucket [London] (Zero Exposure)

# Creating fully hardened London S3 bucket
resource "aws_s3_bucket" "perfect" {
  count         = var.deploy_s3 ? 1 : 0
  bucket        = "msc-lab-${random_id.bucket_suffix[0].hex}-perfect"
  force_destroy = true
}

# Disabling legacy ACLs via bucket owner enforcement
resource "aws_s3_bucket_ownership_controls" "perfect_ownership" {
  count  = var.deploy_s3 ? 1 : 0
  bucket = aws_s3_bucket.perfect[0].id
  rule {
    object_ownership = "BucketOwnerEnforced"
  }
}

# Blocking all public access settings
resource "aws_s3_bucket_public_access_block" "perfect_bpa" {
  count                   = var.deploy_s3 ? 1 : 0
  bucket                  = aws_s3_bucket.perfect[0].id
  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

# Enabling default AES-256 server-side encryption
resource "aws_s3_bucket_server_side_encryption_configuration" "perfect_crypto" {
  count  = var.deploy_s3 ? 1 : 0
  bucket = aws_s3_bucket.perfect[0].id
  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm = "AES256"
    }
  }
}

# Enabling bucket object versioning
resource "aws_s3_bucket_versioning" "perfect_versioning" {
  count  = var.deploy_s3 ? 1 : 0
  bucket = aws_s3_bucket.perfect[0].id
  versioning_configuration {
    status = "Enabled"
  }
}

# Forwarding server access logs to the audit destination bucket
resource "aws_s3_bucket_logging" "perfect_logging" {
  count         = var.deploy_s3 ? 1 : 0
  bucket        = aws_s3_bucket.perfect[0].id
  target_bucket = aws_s3_bucket.audit_logs[0].id
  target_prefix = "perfect-logs/"
}

# Configuring lifecycle expiration rules for noncurrent object versions
resource "aws_s3_bucket_lifecycle_configuration" "perfect_lifecycle" {
  count  = var.deploy_s3 ? 1 : 0
  bucket = aws_s3_bucket.perfect[0].id

  rule {
    id     = "expire-noncurrent"
    status = "Enabled"

    filter {}

    noncurrent_version_expiration {
      noncurrent_days = 90
    }
  }
}

# Enforcing TLS encrypted transit across all S3 requests
resource "aws_s3_bucket_policy" "perfect_secure_transport" {
  count  = var.deploy_s3 ? 1 : 0
  bucket = aws_s3_bucket.perfect[0].id
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid       = "EnforceHTTPS"
        Effect    = "Deny"
        Principal = "*"
        Action    = "s3:*"
        Resource = [
          aws_s3_bucket.perfect[0].arn,
          "${aws_s3_bucket.perfect[0].arn}/*"
        ]
        Condition = {
          Bool = {
            "aws:SecureTransport" = "false"
          }
        }
      }
    ]
  })
}

# Scenario 2: Low Risk Bucket [London] (Missing Lifecycle Rules & Access Logging)

# Creating encrypted versioned bucket without access logging
resource "aws_s3_bucket" "low" {
  count         = var.deploy_s3 ? 1 : 0
  bucket        = "msc-lab-${random_id.bucket_suffix[0].hex}-low"
  force_destroy = true
}

# Enforcing bucket ownership controls
resource "aws_s3_bucket_ownership_controls" "low_ownership" {
  count  = var.deploy_s3 ? 1 : 0
  bucket = aws_s3_bucket.low[0].id
  rule {
    object_ownership = "BucketOwnerEnforced"
  }
}

# Blocking all public access permissions
resource "aws_s3_bucket_public_access_block" "low_bpa" {
  count                   = var.deploy_s3 ? 1 : 0
  bucket                  = aws_s3_bucket.low[0].id
  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

# Enabling default encryption at rest
resource "aws_s3_bucket_server_side_encryption_configuration" "low_crypto" {
  count  = var.deploy_s3 ? 1 : 0
  bucket = aws_s3_bucket.low[0].id
  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm = "AES256"
    }
  }
}

# Enabling bucket versioning
resource "aws_s3_bucket_versioning" "low_versioning" {
  count  = var.deploy_s3 ? 1 : 0
  bucket = aws_s3_bucket.low[0].id
  versioning_configuration {
    status = "Enabled"
  }
}

# Attaching HTTPS enforcement policy
resource "aws_s3_bucket_policy" "low_secure_transport" {
  count  = var.deploy_s3 ? 1 : 0
  bucket = aws_s3_bucket.low[0].id
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid       = "EnforceHTTPS"
        Effect    = "Deny"
        Principal = "*"
        Action    = "s3:*"
        Resource  = [aws_s3_bucket.low[0].arn, "${aws_s3_bucket.low[0].arn}/*"]
        Condition = { Bool = { "aws:SecureTransport" = "false" } }
      }
    ]
  })
}

# Scenario 3: Medium Risk Bucket [London] (Versioning Suspended)

# Creating bucket with suspended versioning state
resource "aws_s3_bucket" "medium" {
  count         = var.deploy_s3 ? 1 : 0
  bucket        = "msc-lab-${random_id.bucket_suffix[0].hex}-medium"
  force_destroy = true
}

# Disabling legacy ACL access
resource "aws_s3_bucket_ownership_controls" "medium_ownership" {
  count  = var.deploy_s3 ? 1 : 0
  bucket = aws_s3_bucket.medium[0].id
  rule {
    object_ownership = "BucketOwnerEnforced"
  }
}

# Blocking public access permissions
resource "aws_s3_bucket_public_access_block" "medium_bpa" {
  count                   = var.deploy_s3 ? 1 : 0
  bucket                  = aws_s3_bucket.medium[0].id
  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

# Enabling default encryption at rest
resource "aws_s3_bucket_server_side_encryption_configuration" "medium_crypto" {
  count  = var.deploy_s3 ? 1 : 0
  bucket = aws_s3_bucket.medium[0].id
  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm = "AES256"
    }
  }
}

# Setting bucket versioning to suspended
resource "aws_s3_bucket_versioning" "medium_versioning" {
  count  = var.deploy_s3 ? 1 : 0
  bucket = aws_s3_bucket.medium[0].id
  versioning_configuration {
    status = "Suspended"
  }
}

# Enforcing secure transport over HTTPS
resource "aws_s3_bucket_policy" "medium_secure_transport" {
  count  = var.deploy_s3 ? 1 : 0
  bucket = aws_s3_bucket.medium[0].id
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid       = "EnforceHTTPS"
        Effect    = "Deny"
        Principal = "*"
        Action    = "s3:*"
        Resource  = [aws_s3_bucket.medium[0].arn, "${aws_s3_bucket.medium[0].arn}/*"]
        Condition = { Bool = { "aws:SecureTransport" = "false" } }
      }
    ]
  })
}

# Scenario 4: High Risk Bucket [N. Virginia] (Block Public Access Disabled & Missing TLS Policy)

# Deploying unprotected bucket in us-east-1
resource "aws_s3_bucket" "high" {
  provider      = aws.us_east_1
  count         = var.deploy_s3 ? 1 : 0
  bucket        = "msc-lab-${random_id.bucket_suffix[0].hex}-high"
  force_destroy = true
}

# Disabling all Block Public Access controls
resource "aws_s3_bucket_public_access_block" "high_bpa" {
  provider                = aws.us_east_1
  count                   = var.deploy_s3 ? 1 : 0
  bucket                  = aws_s3_bucket.high[0].id
  block_public_acls       = false
  block_public_policy     = false
  ignore_public_acls      = false
  restrict_public_buckets = false
}

# Scenario 5: Critical Risk Bucket [N. Virginia] (Anonymous Public Read Policy Attached)

# Deploying publicly readable bucket in us-east-1
resource "aws_s3_bucket" "critical" {
  provider      = aws.us_east_1
  count         = var.deploy_s3 ? 1 : 0
  bucket        = "msc-lab-${random_id.bucket_suffix[0].hex}-critical"
  force_destroy = true
}

# Disabling Block Public Access controls to permit public policies
resource "aws_s3_bucket_public_access_block" "critical_bpa" {
  provider                = aws.us_east_1
  count                   = var.deploy_s3 ? 1 : 0
  bucket                  = aws_s3_bucket.critical[0].id
  block_public_acls       = false
  block_public_policy     = false
  ignore_public_acls      = false
  restrict_public_buckets = false
}

# Granting global anonymous read permissions to the public
resource "aws_s3_bucket_policy" "critical_anonymous_policy" {
  provider = aws.us_east_1
  count    = var.deploy_s3 ? 1 : 0
  bucket   = aws_s3_bucket.critical[0].id
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid       = "PublicReadGetObject"
        Effect    = "Allow"
        Principal = "*"
        Action    = "s3:GetObject"
        Resource  = "${aws_s3_bucket.critical[0].arn}/*"
      }
    ]
  })

  depends_on = [aws_s3_bucket_public_access_block.critical_bpa]
}