# samples/cloudfront_lab.tf

# ---------------------------------------------------------------------
# DEDICATED RANDOM ID FOR CLOUDFRONT LAB
# ---------------------------------------------------------------------
resource "random_id" "cf_suffix" {
  count       = var.deploy_cloudfront ? 1 : 0
  byte_length = 4
}

# ---------------------------------------------------------------------
# SHARED ORIGIN S3 BUCKET & LOG BUCKET
# ---------------------------------------------------------------------
resource "aws_s3_bucket" "cf_origin_bucket" {
  count         = var.deploy_cloudfront ? 1 : 0
  bucket        = "msc-lab-${random_id.cf_suffix[0].hex}-cf-origin"
  force_destroy = true
}

resource "aws_s3_bucket_public_access_block" "cf_origin_bpa" {
  count                   = var.deploy_cloudfront ? 1 : 0
  bucket                  = aws_s3_bucket.cf_origin_bucket[0].id
  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

# Dedicated Logging Bucket for CloudFront Standard Access Logs
resource "aws_s3_bucket" "cf_logs_bucket" {
  count         = var.deploy_cloudfront ? 1 : 0
  bucket        = "msc-lab-${random_id.cf_suffix[0].hex}-cf-logs"
  force_destroy = true
}

resource "aws_s3_bucket_ownership_controls" "cf_logs_ownership" {
  count  = var.deploy_cloudfront ? 1 : 0
  bucket = aws_s3_bucket.cf_logs_bucket[0].id
  rule {
    object_ownership = "BucketOwnerPreferred"
  }
}

resource "aws_s3_bucket_acl" "cf_logs_acl" {
  count      = var.deploy_cloudfront ? 1 : 0
  bucket     = aws_s3_bucket.cf_logs_bucket[0].id
  acl        = "log-delivery-write"
  depends_on = [aws_s3_bucket_ownership_controls.cf_logs_ownership]
}

# ---------------------------------------------------------------------
# ORIGIN ACCESS CONTROL (OAC) & WAF PREREQUISITES
# ---------------------------------------------------------------------
resource "aws_cloudfront_origin_access_control" "lab_oac" {
  count                             = var.deploy_cloudfront ? 1 : 0
  name                              = "msc-lab-origin-access-control"
  description                       = "Origin Access Control for secure S3 integration"
  origin_access_control_origin_type = "s3"
  signing_behavior                  = "always"
  signing_protocol                  = "sigv4"
}

# AWS WAFv2 Web ACL for CloudFront (Must be scoped to CLOUDFRONT in us-east-1)
resource "aws_wafv2_web_acl" "cf_waf" {
  provider    = aws.us_east_1
  count       = var.deploy_cloudfront ? 1 : 0
  name        = "msc-lab-cf-waf-acl"
  description = "Compliant AWS WAF Web ACL for CloudFront"
  scope       = "CLOUDFRONT"

  default_action {
    allow {}
  }

  visibility_config {
    cloudwatch_metrics_enabled = false
    metric_name                = "mscLabCfWafMetric"
    sampled_requests_enabled   = false
  }
}

# =====================================================================
# SCENARIO 1: CRITICAL RISK CLOUDFRONT DISTRIBUTION
# Triggers:
# - CF-01 (CRITICAL: 9.5): S3 origin lacking OAC / OAI
# - CF-02 (HIGH: 8.5): ViewerProtocolPolicy set to allow-all (HTTP unencrypted)
# - CF-03 (HIGH: 8.2): Missing AWS WAF Web ACL
# - CF-05 (MEDIUM: 5.5): Access logging disabled
# Overall Severity: CRITICAL (9.5)
# =====================================================================
resource "aws_cloudfront_distribution" "critical_distribution" {
  count   = var.deploy_cloudfront ? 1 : 0
  enabled = true
  comment = "msc-lab-critical-distribution"

  # CF-01 Trigger: S3 origin configured with NO OAC or OAI
  origin {
    domain_name = aws_s3_bucket.cf_origin_bucket[0].bucket_regional_domain_name
    origin_id   = "S3Origin-Critical"
  }

  # CF-02 Trigger: Insecure viewer protocol (allow-all HTTP)
  default_cache_behavior {
    allowed_methods        = ["GET", "HEAD"]
    cached_methods         = ["GET", "HEAD"]
    target_origin_id       = "S3Origin-Critical"
    viewer_protocol_policy = "allow-all"

    forwarded_values {
      query_string = false
      cookies {
        forward = "none"
      }
    }
  }

  restrictions {
    geo_restriction {
      restriction_type = "none"
    }
  }

  viewer_certificate {
    cloudfront_default_certificate = true
  }

  tags = {
    Name        = "msc-lab-critical-distribution"
    Environment = "MSc-Lab"
  }
}

# =====================================================================
# SCENARIO 2: HIGH RISK CLOUDFRONT DISTRIBUTION
# Triggers:
# - CF-02 (HIGH: 8.5): ViewerProtocolPolicy set to allow-all
# - CF-03 (HIGH: 8.2): Missing AWS WAF Web ACL
# - CF-05 (MEDIUM: 5.5): Access logging disabled
# (OAC is attached, so CF-01 CRITICAL is avoided)
# Overall Severity: HIGH (8.5)
# =====================================================================
resource "aws_cloudfront_distribution" "high_distribution" {
  count   = var.deploy_cloudfront ? 1 : 0
  enabled = true
  comment = "msc-lab-high-distribution"

  origin {
    domain_name              = aws_s3_bucket.cf_origin_bucket[0].bucket_regional_domain_name
    origin_id                = "S3Origin-High"
    origin_access_control_id = aws_cloudfront_origin_access_control.lab_oac[0].id # Passes CF-01
  }

  # CF-02 Trigger: allow-all HTTP
  default_cache_behavior {
    allowed_methods        = ["GET", "HEAD"]
    cached_methods         = ["GET", "HEAD"]
    target_origin_id       = "S3Origin-High"
    viewer_protocol_policy = "allow-all"

    forwarded_values {
      query_string = false
      cookies {
        forward = "none"
      }
    }
  }

  restrictions {
    geo_restriction {
      restriction_type = "none"
    }
  }

  viewer_certificate {
    cloudfront_default_certificate = true
  }

  tags = {
    Name        = "msc-lab-high-distribution"
    Environment = "MSc-Lab"
  }
}

# =====================================================================
# SCENARIO 3: MEDIUM RISK CLOUDFRONT DISTRIBUTION
# Triggers:
# - CF-05 (MEDIUM: 5.5): Access logging disabled
# (OAC attached, HTTPS enforced, WAF Web ACL attached)
# Overall Severity: MEDIUM (5.5)
# =====================================================================
resource "aws_cloudfront_distribution" "medium_distribution" {
  count       = var.deploy_cloudfront ? 1 : 0
  enabled     = true
  comment     = "msc-lab-medium-distribution"
  web_acl_id = aws_wafv2_web_acl.cf_waf[0].arn # Passes CF-03

  origin {
    domain_name              = aws_s3_bucket.cf_origin_bucket[0].bucket_regional_domain_name
    origin_id                = "S3Origin-Medium"
    origin_access_control_id = aws_cloudfront_origin_access_control.lab_oac[0].id # Passes CF-01
  }

  default_cache_behavior {
    allowed_methods        = ["GET", "HEAD"]
    cached_methods         = ["GET", "HEAD"]
    target_origin_id       = "S3Origin-Medium"
    viewer_protocol_policy = "redirect-to-https" # Passes CF-02

    forwarded_values {
      query_string = false
      cookies {
        forward = "none"
      }
    }
  }

  restrictions {
    geo_restriction {
      restriction_type = "none"
    }
  }

  viewer_certificate {
    cloudfront_default_certificate = true
  }

  tags = {
    Name        = "msc-lab-medium-distribution"
    Environment = "MSc-Lab"
  }
}

# =====================================================================
# SCENARIO 4: COMPLIANT CLOUDFRONT DISTRIBUTION (ADVISORY: 0.0)
# Controls:
# - S3 Origin protected by Origin Access Control (Passes CF-01)
# - Viewer Protocol Policy set to redirect-to-https (Passes CF-02)
# - AWS WAF Web ACL attached (Passes CF-03)
# - TLS 1.2+ default certificate configuration (Passes CF-04)
# - Standard S3 access logging enabled (Passes CF-05)
# Overall Severity: ADVISORY (0.0)
# =====================================================================
resource "aws_cloudfront_distribution" "compliant_distribution" {
  count       = var.deploy_cloudfront ? 1 : 0
  enabled     = true
  comment     = "msc-lab-compliant-distribution"
  web_acl_id = aws_wafv2_web_acl.cf_waf[0].arn

  origin {
    domain_name              = aws_s3_bucket.cf_origin_bucket[0].bucket_regional_domain_name
    origin_id                = "S3Origin-Compliant"
    origin_access_control_id = aws_cloudfront_origin_access_control.lab_oac[0].id
  }

  default_cache_behavior {
    allowed_methods        = ["GET", "HEAD"]
    cached_methods         = ["GET", "HEAD"]
    target_origin_id       = "S3Origin-Compliant"
    viewer_protocol_policy = "redirect-to-https"

    forwarded_values {
      query_string = false
      cookies {
        forward = "none"
      }
    }
  }

  logging_config {
    include_cookies = false
    bucket          = aws_s3_bucket.cf_logs_bucket[0].bucket_domain_name
    prefix          = "cf-logs/"
  }

  restrictions {
    geo_restriction {
      restriction_type = "none"
    }
  }

  viewer_certificate {
    cloudfront_default_certificate = true
  }

  depends_on = [
    aws_s3_bucket_acl.cf_logs_acl
  ]

  tags = {
    Name        = "msc-lab-compliant-distribution"
    Environment = "MSc-Lab"
  }
}