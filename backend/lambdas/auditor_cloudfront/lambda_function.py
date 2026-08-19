# lambdas/auditor_cloudfront/lambda_function.py
import json
import boto3
from botocore.config import Config
from botocore.exceptions import ClientError

FAST_AWS_CONFIG = Config(
    connect_timeout=2,
    read_timeout=4,
    retries={'max_attempts': 1}
)

# Known insecure and outdated viewer certificate security policies
LEGACY_TLS_POLICIES = {
    "SSLv3",
    "TLSv1",
    "TLSv1_2016",
    "TLSv1.1_2016"
}

def run_cloudfront_scan():
    """
    Audits Amazon CloudFront Distributions against AWS security baselines.
    Returns flat finding dictionaries mapped to orchestrator schema.
    """
    # CloudFront control plane is global and routed via us-east-1
    cf_client = boto3.client('cloudfront', region_name='us-east-1', config=FAST_AWS_CONFIG)
    findings = []
    region = "global"

    try:
        paginator = cf_client.get_paginator('list_distributions')
        for page in paginator.paginate():
            dist_list = page.get('DistributionList', {})
            for dist in dist_list.get('Items', []):
                dist_id = dist['Id']
                domain_name = dist.get('DomainName', dist_id)
                aliases = dist.get('Aliases', {}).get('Items', [])
                display_name = f"{aliases[0]} ({dist_id})" if aliases else f"{domain_name} ({dist_id})"
                dist_findings = []

                # -------------------------------------------------------------
                # CF-01: S3 ORIGIN WITHOUT OAC / OAI
                # -------------------------------------------------------------
                origins = dist.get('Origins', {}).get('Items', [])
                for origin in origins:
                    domain = origin.get('DomainName', '')
                    s3_origin_config = origin.get('S3OriginConfig')
                    oac_id = origin.get('OriginAccessControlId')

                    # Detect if target is an S3 bucket origin
                    if 's3.amazonaws.com' in domain or 's3.' in domain or s3_origin_config is not None:
                        has_oai = bool(s3_origin_config and s3_origin_config.get('OriginAccessIdentity'))
                        has_oac = bool(oac_id)

                        if not has_oac and not has_oai:
                            dist_findings.append({
                                "resource_name": display_name,
                                "service": "CLOUDFRONT",
                                "region": region,
                                "vulnerability_description": f"[{region}] CloudFront Distribution '{dist_id}' S3 origin '{domain}' lacks Origin Access Control (OAC). Direct S3 exposure risk.",
                                "severity_level": "CRITICAL",
                                "risk_score": 9.5,
                                "remediation_suggestion": f"Associate an Origin Access Control (OAC) with origin '{origin.get('Id')}' and restrict S3 bucket policy."
                            })

                # -------------------------------------------------------------
                # CF-02: INSECURE VIEWER PROTOCOL (ALLOW-ALL HTTP)
                # -------------------------------------------------------------
                default_cache = dist.get('DefaultCacheBehavior', {})
                viewer_protocol = default_cache.get('ViewerProtocolPolicy', 'allow-all')

                if viewer_protocol == 'allow-all':
                    dist_findings.append({
                        "resource_name": display_name,
                        "service": "CLOUDFRONT",
                        "region": region,
                        "vulnerability_description": f"[{region}] CloudFront Distribution '{dist_id}' default cache behavior permits unencrypted HTTP traffic (ViewerProtocolPolicy: allow-all).",
                        "severity_level": "HIGH",
                        "risk_score": 8.5,
                        "remediation_suggestion": f"Update ViewerProtocolPolicy to 'redirect-to-https' or 'https-only' for distribution '{dist_id}'."
                    })

                # Check custom cache behaviors
                custom_cache_behaviors = dist.get('CacheBehaviors', {}).get('Items', [])
                for cb in custom_cache_behaviors:
                    cb_protocol = cb.get('ViewerProtocolPolicy', 'allow-all')
                    path_pattern = cb.get('PathPattern', 'unknown')
                    if cb_protocol == 'allow-all':
                        dist_findings.append({
                            "resource_name": display_name,
                            "service": "CLOUDFRONT",
                            "region": region,
                            "vulnerability_description": f"[{region}] CloudFront Distribution '{dist_id}' cache behavior path '{path_pattern}' permits unencrypted HTTP traffic.",
                            "severity_level": "HIGH",
                            "risk_score": 8.5,
                            "remediation_suggestion": f"Update path pattern '{path_pattern}' ViewerProtocolPolicy to 'redirect-to-https'."
                        })

                # -------------------------------------------------------------
                # CF-03: MISSING WAF WEB ACL
                # -------------------------------------------------------------
                web_acl_id = dist.get('WebACLId', '')
                if not web_acl_id:
                    dist_findings.append({
                        "resource_name": display_name,
                        "service": "CLOUDFRONT",
                        "region": region,
                        "vulnerability_description": f"[{region}] CloudFront Distribution '{dist_id}' is not protected by an AWS WAF Web ACL.",
                        "severity_level": "HIGH",
                        "risk_score": 8.2,
                        "remediation_suggestion": f"Associate an AWS WAFv2 Web ACL (CLOUDFRONT scope) with distribution '{dist_id}'."
                    })

                # -------------------------------------------------------------
                # CF-04: OUTDATED VIEWER TLS PROTOCOL
                # -------------------------------------------------------------
                viewer_cert = dist.get('ViewerCertificate', {})
                min_protocol_version = viewer_cert.get('MinimumProtocolVersion', 'TLSv1')

                if min_protocol_version in LEGACY_TLS_POLICIES:
                    dist_findings.append({
                        "resource_name": display_name,
                        "service": "CLOUDFRONT",
                        "region": region,
                        "vulnerability_description": f"[{region}] CloudFront Distribution '{dist_id}' uses legacy minimum TLS version '{min_protocol_version}' instead of TLSv1.2_2021.",
                        "severity_level": "HIGH",
                        "risk_score": 7.5,
                        "remediation_suggestion": f"Update ViewerCertificate MinimumProtocolVersion to 'TLSv1.2_2021' for distribution '{dist_id}'."
                    })

                # -------------------------------------------------------------
                # CF-05: STANDARD ACCESS LOGGING DISABLED
                # -------------------------------------------------------------
                logging_config = dist.get('Logging', {})
                if not logging_config.get('Enabled', False):
                    dist_findings.append({
                        "resource_name": display_name,
                        "service": "CLOUDFRONT",
                        "region": region,
                        "vulnerability_description": f"[{region}] CloudFront Distribution '{dist_id}' does not have standard access logging enabled.",
                        "severity_level": "MEDIUM",
                        "risk_score": 5.5,
                        "remediation_suggestion": f"Enable standard access logging targeting a designated logging S3 bucket for distribution '{dist_id}'."
                    })

                # -------------------------------------------------------------
                # CF-06: BASELINE COMPLIANT RECORD
                # -------------------------------------------------------------
                if not dist_findings:
                    dist_findings.append({
                        "resource_name": display_name,
                        "service": "CLOUDFRONT",
                        "region": region,
                        "vulnerability_description": f"[{region}] CloudFront Distribution '{dist_id}' audited and compliant.",
                        "severity_level": "ADVISORY",
                        "risk_score": 0.0,
                        "remediation_suggestion": "Distribution meets baseline encryption, access control, and logging standards."
                    })

                findings.extend(dist_findings)

    except ClientError as e:
        if "UnauthorizedOperation" not in str(e):
            print(f"[ERROR] Auditing CloudFront: {e}")

    return findings

def lambda_handler(event, context):
    """
    Entry point for the AWS CloudFront auditor Lambda.
    """
    return run_cloudfront_scan()

if __name__ == "__main__":
    print(json.dumps(lambda_handler({}, None), indent=2))