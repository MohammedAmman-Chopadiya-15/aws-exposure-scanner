import json
import logging
import boto3
from botocore.exceptions import ClientError

logger = logging.getLogger(__name__)
logger.setLevel(logging.INFO)


def run_s3_scan():
    s3_client = boto3.client('s3')
    findings = []

    # Fetching all existing S3 buckets across the account
    try:
        response = s3_client.list_buckets()
        buckets = response.get('Buckets', [])
    except ClientError as e:
        logger.error(f"Failed listing S3 buckets: {e}")
        return findings

    # Iterating through each bucket to run individual security checks
    for bucket in buckets:
        bucket_name = bucket['Name']
        bucket_findings = []

        # Checking if the bucket policy allows public read or write access
        try:
            policy_status = s3_client.get_bucket_policy_status(Bucket=bucket_name)
            if policy_status.get('PolicyStatus', {}).get('IsPublic', False):
                bucket_findings.append({
                    "resource_name": bucket_name,
                    "service": "S3",
                    "region": "global",
                    "severity_level": "CRITICAL",
                    "risk_score": 9.8,
                    "vulnerability_description": "Active Bucket Policy allows public read or write access globally.",
                    "remediation_suggestion": f"aws s3api delete-bucket-policy --bucket {bucket_name}"
                })
        except ClientError:
            pass

        # Verifying whether Object Ownership is enforced to disable legacy ACLs
        try:
            ownership = s3_client.get_bucket_ownership_controls(Bucket=bucket_name)
            rules = ownership.get('OwnershipControls', {}).get('Rules', [])
            if not any(rule.get('ObjectOwnership') == 'BucketOwnerEnforced' for rule in rules):
                bucket_findings.append({
                    "resource_name": bucket_name,
                    "service": "S3",
                    "region": "global",
                    "severity_level": "HIGH",
                    "risk_score": 8.2,
                    "vulnerability_description": "Object Ownership set to 'ACLs Enabled', allowing legacy permissions.",
                    "remediation_suggestion": f"aws s3api put-bucket-ownership-controls --bucket {bucket_name} --ownership-controls Rules=[{{ObjectOwnership=BucketOwnerEnforced}}]"
                })
        except ClientError:
            bucket_findings.append({
                "resource_name": bucket_name,
                "service": "S3",
                "region": "global",
                "severity_level": "HIGH",
                "risk_score": 8.2,
                "vulnerability_description": "Lacks Object Ownership Controls, reverting to legacy ACL models.",
                "remediation_suggestion": f"aws s3api put-bucket-ownership-controls --bucket {bucket_name} --ownership-controls Rules=[{{ObjectOwnership=BucketOwnerEnforced}}]"
            })

        # Checking for an explicit policy statement enforcing HTTPS in transit
        has_secure_transport_policy = False
        try:
            policy_resp = s3_client.get_bucket_policy(Bucket=bucket_name)
            policy_json = json.loads(policy_resp.get('Policy', '{}'))
            for stmt in policy_json.get('Statement', []):
                condition = stmt.get('Condition', {})
                if stmt.get('Effect') == 'Deny':
                    bool_cond = condition.get('Bool', {})
                    if bool_cond.get('aws:SecureTransport') in ['false', False]:
                        has_secure_transport_policy = True
                        break
        except ClientError:
            has_secure_transport_policy = False

        if not has_secure_transport_policy:
            bucket_findings.append({
                "resource_name": bucket_name,
                "service": "S3",
                "region": "global",
                "severity_level": "HIGH",
                "risk_score": 7.8,
                "vulnerability_description": "Bucket policy does not enforce TLS in transit (allows insecure HTTP requests).",
                "remediation_suggestion": f"Attach a Deny policy with Condition: {{'Bool': {{'aws:SecureTransport': 'false'}}}} to bucket '{bucket_name}'."
            })

        # Confirming all four Block Public Access settings are turned on
        is_public_blocked = False
        try:
            pab = s3_client.get_public_access_block(Bucket=bucket_name)
            config = pab.get('PublicAccessBlockConfiguration', {})
            if all([config.get('BlockPublicAcls'), config.get('IgnorePublicAcls'), 
                    config.get('BlockPublicPolicy'), config.get('RestrictPublicBuckets')]):
                is_public_blocked = True
        except ClientError:
            is_public_blocked = False

        if not is_public_blocked:
            bucket_findings.append({
                "resource_name": bucket_name,
                "service": "S3",
                "region": "global",
                "severity_level": "HIGH",
                "risk_score": 7.5,
                "vulnerability_description": "Block Public Access configuration is either disabled or incomplete.",
                "remediation_suggestion": f"aws s3api put-public-access-block --bucket {bucket_name} --public-access-block-configuration BlockPublicAcls=true,IgnorePublicAcls=true,BlockPublicPolicy=true,RestrictPublicBuckets=true"
            })

        # Ensuring default server-side encryption at rest is configured
        try:
            s3_client.get_bucket_encryption(Bucket=bucket_name)
        except ClientError as e:
            if e.response['Error']['Code'] == 'ServerSideEncryptionConfigurationNotFoundError':
                bucket_findings.append({
                    "resource_name": bucket_name,
                    "service": "S3",
                    "region": "global",
                    "severity_level": "MEDIUM",
                    "risk_score": 5.5,
                    "vulnerability_description": "Default server-side encryption is disabled on this bucket.",
                    "remediation_suggestion": f"aws s3api put-bucket-encryption --bucket {bucket_name} --server-side-encryption-configuration '{{\"Rules\": [{{\"ApplyServerSideEncryptionByDefault\": {{\"SSEAlgorithm\": \"AES256\"}}}}]}}'"
                })

        # Checking if versioning is active to protect against accidental deletions
        try:
            version_resp = s3_client.get_bucket_versioning(Bucket=bucket_name)
            if version_resp.get('Status') != 'Enabled':
                bucket_findings.append({
                    "resource_name": bucket_name,
                    "service": "S3",
                    "region": "global",
                    "severity_level": "MEDIUM",
                    "risk_score": 4.8,
                    "vulnerability_description": "Bucket versioning is disabled.",
                    "remediation_suggestion": f"aws s3api put-bucket-versioning --bucket {bucket_name} --versioning-configuration Status=Enabled"
                })
        except ClientError:
            pass

        # Verifying whether server access logging is enabled for audit trails
        try:
            logging_resp = s3_client.get_bucket_logging(Bucket=bucket_name)
            if not logging_resp.get('LoggingEnabled'):
                bucket_findings.append({
                    "resource_name": bucket_name,
                    "service": "S3",
                    "region": "global",
                    "severity_level": "LOW",
                    "risk_score": 3.2,
                    "vulnerability_description": "S3 Server Access Logging is disabled on this bucket.",
                    "remediation_suggestion": f"aws s3api put-bucket-logging --bucket {bucket_name} --bucket-logging-status '{{\"LoggingEnabled\": {{\"TargetBucket\": \"<AUDIT_LOG_BUCKET>\", \"TargetPrefix\": \"{bucket_name}/\"}}}}'"
                })
        except ClientError:
            pass

        # Checking if lifecycle rules exist to manage object retention
        try:
            lifecycle_resp = s3_client.get_bucket_lifecycle_configuration(Bucket=bucket_name)
            if not lifecycle_resp.get('Rules'):
                bucket_findings.append({
                    "resource_name": bucket_name,
                    "service": "S3",
                    "region": "global",
                    "severity_level": "LOW",
                    "risk_score": 2.0,
                    "vulnerability_description": "No S3 Lifecycle rules configured to manage object version retention.",
                    "remediation_suggestion": f"aws s3api put-bucket-lifecycle-configuration --bucket {bucket_name} --lifecycle-configuration file://lifecycle.json"
                })
        except ClientError as e:
            if e.response['Error']['Code'] == 'NoSuchLifecycleConfiguration':
                bucket_findings.append({
                    "resource_name": bucket_name,
                    "service": "S3",
                    "region": "global",
                    "severity_level": "LOW",
                    "risk_score": 2.0,
                    "vulnerability_description": "No S3 Lifecycle rules configured to manage object version retention.",
                    "remediation_suggestion": f"aws s3api put-bucket-lifecycle-configuration --bucket {bucket_name} --lifecycle-configuration file://lifecycle.json"
                })

        # Marking the bucket compliant if no vulnerabilities were detected
        if not bucket_findings:
            bucket_findings.append({
                "resource_name": bucket_name,
                "service": "S3",
                "region": "global",
                "severity_level": "ADVISORY",
                "risk_score": 0.0,
                "vulnerability_description": "Bucket fully complies with baseline security policies.",
                "remediation_suggestion": "No action required."
            })

        findings.extend(bucket_findings)

    return findings


def lambda_handler(event, context):
    return run_s3_scan()


if __name__ == "__main__":
    print(json.dumps(lambda_handler({}, None), indent=2))