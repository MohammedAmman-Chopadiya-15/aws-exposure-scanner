# s3_lab.tf

resource "random_id" "bucket_suffix" {
  count       = var.deploy_s3 ? 1 : 0
  byte_length = 4
}

# =====================================================================
# LONDON REGION (eu-west-2) BUCKETS
# =====================================================================

# BUCKET 1: PERFECT (Completely Compliant - Should have 0 flaws) [London]
resource "aws_s3_bucket" "perfect" {
  count  = var.deploy_s3 ? 1 : 0
  bucket = "msc-lab-${random_id.bucket_suffix[0].hex}-perfect"
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
    status     = "Enabled"
    mfa_delete = "Disabled"
  }
}

resource "aws_s3_bucket_logging" "perfect_logging" {
  count         = var.deploy_s3 ? 1 : 0
  bucket        = aws_s3_bucket.perfect[0].id
  target_bucket = aws_s3_bucket.perfect[0].id
  target_prefix = "logs/"
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
        Resource  = [
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

# BUCKET 2: LOW SEVERITY (Only Missing Logging - Highest: LOW) [London]
resource "aws_s3_bucket" "low" {
  count  = var.deploy_s3 ? 1 : 0
  bucket = "msc-lab-${random_id.bucket_suffix[0].hex}-low"
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

# BUCKET 3: MEDIUM SEVERITY (Missing Logging & Encryption - Highest: MEDIUM) [London]
resource "aws_s3_bucket" "medium" {
  count  = var.deploy_s3 ? 1 : 0
  bucket = "msc-lab-${random_id.bucket_suffix[0].hex}-medium"
}

resource "aws_s3_bucket_public_access_block" "medium_bpa" {
  count                   = var.deploy_s3 ? 1 : 0
  bucket                  = aws_s3_bucket.medium[0].id
  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
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

# BUCKET 4: HIGH SEVERITY (Missing Logging, Encryption, & BPA) [N. Virginia]
resource "aws_s3_bucket" "high" {
  provider = aws.us_east_1
  count    = var.deploy_s3 ? 1 : 0
  bucket   = "msc-lab-${random_id.bucket_suffix[0].hex}-high"
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

# BUCKET 5: CRITICAL SEVERITY (Missing All Protection + Open Policy) [N. Virginia]
resource "aws_s3_bucket" "critical" {
  provider = aws.us_east_1
  count    = var.deploy_s3 ? 1 : 0
  bucket   = "msc-lab-${random_id.bucket_suffix[0].hex}-critical"
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
