# Dedicated random suffix for naming lab S3 buckets uniquely
resource "random_id" "cf_suffix" {
  count       = var.deploy_cloudfront ? 1 : 0
  byte_length = 4
}

# Creating origin S3 bucket to serve CloudFront content
resource "aws_s3_bucket" "cf_origin_bucket" {
  count         = var.deploy_cloudfront ? 1 : 0
  bucket        = "msc-lab-${random_id.cf_suffix[0].hex}-cf-origin"
  force_destroy = true
}

# Enforcing Block Public Access on the origin S3 bucket
resource "aws_s3_bucket_public_access_block" "cf_origin_bpa" {
  count                   = var.deploy_cloudfront ? 1 : 0
  bucket                  = aws_s3_bucket.cf_origin_bucket[0].id
  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

# Creating dedicated log bucket for CloudFront access logs
resource "aws_s3_bucket" "cf_logs_bucket" {
  count         = var.deploy_cloudfront ? 1 : 0
  bucket        = "msc-lab-${random_id.cf_suffix[0].hex}-cf-logs"
  force_destroy = true
}

# Setting bucket ownership controls for log delivery
resource "aws_s3_bucket_ownership_controls" "cf_logs_ownership" {
  count  = var.deploy_cloudfront ? 1 : 0
  bucket = aws_s3_bucket.cf_logs_bucket[0].id
  rule {
    object_ownership = "BucketOwnerPreferred"
  }
}

# Granting log-delivery write permissions on the logs bucket
resource "aws_s3_bucket_acl" "cf_logs_acl" {
  count      = var.deploy_cloudfront ? 1 : 0
  bucket     = aws_s3_bucket.cf_logs_bucket[0].id
  acl        = "log-delivery-write"
  depends_on = [aws_s3_bucket_ownership_controls.cf_logs_ownership]
}

# Creating Origin Access Control (OAC) for secure S3 origin integration
resource "aws_cloudfront_origin_access_control" "lab_oac" {
  count                             = var.deploy_cloudfront ? 1 : 0
  name                              = "msc-lab-origin-access-control"
  description                       = "Origin Access Control for secure S3 integration"
  origin_access_control_origin_type = "s3"
  signing_behavior                  = "always"
  signing_protocol                  = "sigv4"
}

# Provisioning an AWS WAFv2 Web ACL in us-east-1 for CloudFront distributions
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

# Scenario 1: Critical Risk Distribution (Missing OAC/OAI, Insecure HTTP, Missing WAF, Logging Disabled)

# Deploying a CloudFront distribution with direct S3 origin exposure and unencrypted HTTP access
resource "aws_cloudfront_distribution" "critical_distribution" {
  count   = var.deploy_cloudfront ? 1 : 0
  enabled = true
  comment = "msc-lab-critical-distribution"

  origin {
    domain_name = aws_s3_bucket.cf_origin_bucket[0].bucket_regional_domain_name
    origin_id   = "S3Origin-Critical"
  }

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

# Scenario 2: High Risk Distribution (Insecure HTTP, Missing WAF, Logging Disabled)

# Deploying a distribution with OAC secured origin but open HTTP access and no WAF
resource "aws_cloudfront_distribution" "high_distribution" {
  count   = var.deploy_cloudfront ? 1 : 0
  enabled = true
  comment = "msc-lab-high-distribution"

  origin {
    domain_name              = aws_s3_bucket.cf_origin_bucket[0].bucket_regional_domain_name
    origin_id                = "S3Origin-High"
    origin_access_control_id = aws_cloudfront_origin_access_control.lab_oac[0].id
  }

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

# Scenario 3: Medium Risk Distribution (Missing Access Logging)

# Deploying a distribution with OAC, HTTPS redirect, and WAF attached but missing logging
resource "aws_cloudfront_distribution" "medium_distribution" {
  count       = var.deploy_cloudfront ? 1 : 0
  enabled     = true
  comment     = "msc-lab-medium-distribution"
  web_acl_id = aws_wafv2_web_acl.cf_waf[0].arn

  origin {
    domain_name              = aws_s3_bucket.cf_origin_bucket[0].bucket_regional_domain_name
    origin_id                = "S3Origin-Medium"
    origin_access_control_id = aws_cloudfront_origin_access_control.lab_oac[0].id
  }

  default_cache_behavior {
    allowed_methods        = ["GET", "HEAD"]
    cached_methods         = ["GET", "HEAD"]
    target_origin_id       = "S3Origin-Medium"
    viewer_protocol_policy = "redirect-to-https"

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

# Scenario 4: Compliant Baseline Distribution (Zero Exposure)

# Deploying a fully hardened distribution with OAC, HTTPS redirect, WAF, and S3 access logging
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