# s3_lab.tf

resource "random_id" "bucket_suffix" {
  count       = var.deploy_s3 ? 1 : 0
  byte_length = 4
}

# Dedicated audit log destination bucket (Needed for compliant S3 access logging)
resource "aws_s3_bucket" "audit_logs" {
  count         = var.deploy_s3 ? 1 : 0
  bucket        = "msc-lab-${random_id.bucket_suffix[0].hex}-audit-logs"
  force_destroy = true
}

resource "aws_s3_bucket_ownership_controls" "audit_logs_ownership" {
  count  = var.deploy_s3 ? 1 : 0
  bucket = aws_s3_bucket.audit_logs[0].id
  rule {
    object_ownership = "BucketOwnerEnforced"
  }
}

resource "aws_s3_bucket_public_access_block" "audit_logs_bpa" {
  count                   = var.deploy_s3 ? 1 : 0
  bucket                  = aws_s3_bucket.audit_logs[0].id
  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

# =====================================================================
# LONDON REGION (eu-west-2) BUCKETS
# =====================================================================

# ---------------------------------------------------------------------
# BUCKET 1: PERFECT (Completely Compliant - ADVISORY: 0.0) [London]
# ---------------------------------------------------------------------
resource "aws_s3_bucket" "perfect" {
  count         = var.deploy_s3 ? 1 : 0
  bucket        = "msc-lab-${random_id.bucket_suffix[0].hex}-perfect"
  force_destroy = true
}

resource "aws_s3_bucket_ownership_controls" "perfect_ownership" {
  count  = var.deploy_s3 ? 1 : 0
  bucket = aws_s3_bucket.perfect[0].id
  rule {
    object_ownership = "BucketOwnerEnforced"
  }
}

resource "aws_s3_bucket_public_access_block" "perfect_bpa" {
  count                   = var.deploy_s3 ? 1 : 0
  bucket                  = aws_s3_bucket.perfect[0].id
  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

resource "aws_s3_bucket_server_side_encryption_configuration" "perfect_crypto" {
  count  = var.deploy_s3 ? 1 : 0
  bucket = aws_s3_bucket.perfect[0].id
  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm = "AES256"
    }
  }
}

resource "aws_s3_bucket_versioning" "perfect_versioning" {
  count  = var.deploy_s3 ? 1 : 0
  bucket = aws_s3_bucket.perfect[0].id
  versioning_configuration {
    status = "Enabled"
  }
}

resource "aws_s3_bucket_logging" "perfect_logging" {
  count         = var.deploy_s3 ? 1 : 0
  bucket        = aws_s3_bucket.perfect[0].id
  target_bucket = aws_s3_bucket.audit_logs[0].id
  target_prefix = "perfect-logs/"
}

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

# ---------------------------------------------------------------------
# BUCKET 2: LOW SEVERITY (Missing Lifecycle & Logging - Highest: LOW / 3.2) [London]
# ---------------------------------------------------------------------
resource "aws_s3_bucket" "low" {
  count         = var.deploy_s3 ? 1 : 0
  bucket        = "msc-lab-${random_id.bucket_suffix[0].hex}-low"
  force_destroy = true
}

resource "aws_s3_bucket_ownership_controls" "low_ownership" {
  count  = var.deploy_s3 ? 1 : 0
  bucket = aws_s3_bucket.low[0].id
  rule {
    object_ownership = "BucketOwnerEnforced"
  }
}

resource "aws_s3_bucket_public_access_block" "low_bpa" {
  count                   = var.deploy_s3 ? 1 : 0
  bucket                  = aws_s3_bucket.low[0].id
  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

resource "aws_s3_bucket_server_side_encryption_configuration" "low_crypto" {
  count  = var.deploy_s3 ? 1 : 0
  bucket = aws_s3_bucket.low[0].id
  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm = "AES256"
    }
  }
}

resource "aws_s3_bucket_versioning" "low_versioning" {
  count  = var.deploy_s3 ? 1 : 0
  bucket = aws_s3_bucket.low[0].id
  versioning_configuration {
    status = "Enabled"
  }
}

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

# ---------------------------------------------------------------------
# BUCKET 3: MEDIUM SEVERITY (Versioning Suspended - Highest: MEDIUM / 4.8) [London]
# ---------------------------------------------------------------------
resource "aws_s3_bucket" "medium" {
  count         = var.deploy_s3 ? 1 : 0
  bucket        = "msc-lab-${random_id.bucket_suffix[0].hex}-medium"
  force_destroy = true
}

resource "aws_s3_bucket_ownership_controls" "medium_ownership" {
  count  = var.deploy_s3 ? 1 : 0
  bucket = aws_s3_bucket.medium[0].id
  rule {
    object_ownership = "BucketOwnerEnforced"
  }
}

resource "aws_s3_bucket_public_access_block" "medium_bpa" {
  count                   = var.deploy_s3 ? 1 : 0
  bucket                  = aws_s3_bucket.medium[0].id
  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

resource "aws_s3_bucket_server_side_encryption_configuration" "medium_crypto" {
  count  = var.deploy_s3 ? 1 : 0
  bucket = aws_s3_bucket.medium[0].id
  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm = "AES256"
    }
  }
}

resource "aws_s3_bucket_versioning" "medium_versioning" {
  count  = var.deploy_s3 ? 1 : 0
  bucket = aws_s3_bucket.medium[0].id
  versioning_configuration {
    status = "Suspended"
  }
}

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


# =====================================================================
# N. VIRGINIA REGION (us-east-1) BUCKETS
# =====================================================================

# ---------------------------------------------------------------------
# BUCKET 4: HIGH SEVERITY (BPA Disabled, Legacy ACLs, No TLS Policy - Highest: HIGH / 8.2) [N. Virginia]
# ---------------------------------------------------------------------
resource "aws_s3_bucket" "high" {
  provider      = aws.us_east_1
  count         = var.deploy_s3 ? 1 : 0
  bucket        = "msc-lab-${random_id.bucket_suffix[0].hex}-high"
  force_destroy = true
}

resource "aws_s3_bucket_public_access_block" "high_bpa" {
  provider                = aws.us_east_1
  count                   = var.deploy_s3 ? 1 : 0
  bucket                  = aws_s3_bucket.high[0].id
  block_public_acls       = false
  block_public_policy     = false
  ignore_public_acls      = false
  restrict_public_buckets = false
}

# ---------------------------------------------------------------------
# BUCKET 5: CRITICAL SEVERITY (Anonymous Public Read Policy - Highest: CRITICAL / 9.8) [N. Virginia]
# ---------------------------------------------------------------------
resource "aws_s3_bucket" "critical" {
  provider      = aws.us_east_1
  count         = var.deploy_s3 ? 1 : 0
  bucket        = "msc-lab-${random_id.bucket_suffix[0].hex}-critical"
  force_destroy = true
}

resource "aws_s3_bucket_public_access_block" "critical_bpa" {
  provider                = aws.us_east_1
  count                   = var.deploy_s3 ? 1 : 0
  bucket                  = aws_s3_bucket.critical[0].id
  block_public_acls       = false
  block_public_policy     = false
  ignore_public_acls      = false
  restrict_public_buckets = false
}

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