import json
import boto3
from botocore.exceptions import ClientError

def run_s3_scan():
    s3_client = boto3.client('s3')
    findings = []

    try:
        response = s3_client.list_buckets()
        buckets = response.get('Buckets', [])
    except ClientError as e:
        print(f"Permissions Error listing S3 buckets: {e}")
        return findings

    for bucket in buckets:
        bucket_name = bucket['Name']
        
        # 1. Public Access Block
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
            findings.append({
                "resource_name": bucket_name,
                "service": "S3",
                "region": "global",
                "severity_level": "HIGH",
                "risk_score": 7.5,
                "vulnerability_description": "Block Public Access configuration is either disabled or incomplete.",
                "remediation_suggestion": f"aws s3api put-public-access-block --bucket {bucket_name} --public-access-block-configuration BlockPublicAcls=true,IgnorePublicAcls=true,BlockPublicPolicy=true,RestrictPublicBuckets=true"
            })

        # 2. Public Policy Check
        try:
            policy_status = s3_client.get_bucket_policy_status(Bucket=bucket_name)
            if policy_status.get('PolicyStatus', {}).get('IsPublic', False):
                findings.append({
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

        # 3. Object Ownership / ACL Check
        try:
            ownership = s3_client.get_bucket_ownership_controls(Bucket=bucket_name)
            rules = ownership.get('OwnershipControls', {}).get('Rules', [])
            if not any(rule.get('ObjectOwnership') == 'BucketOwnerEnforced' for rule in rules):
                findings.append({
                    "resource_name": bucket_name,
                    "service": "S3",
                    "region": "global",
                    "severity_level": "HIGH",
                    "risk_score": 8.2,
                    "vulnerability_description": "Object Ownership set to 'ACLs Enabled', allowing legacy permissions.",
                    "remediation_suggestion": f"aws s3api put-bucket-ownership-controls --bucket {bucket_name} --ownership-controls Rules=[{{ObjectOwnership=BucketOwnerEnforced}}]"
                })
        except ClientError:
            findings.append({
                "resource_name": bucket_name,
                "service": "S3",
                "region": "global",
                "severity_level": "HIGH",
                "risk_score": 8.2,
                "vulnerability_description": "Lacks Object Ownership Controls, reverting to legacy ACL models.",
                "remediation_suggestion": f"aws s3api put-bucket-ownership-controls --bucket {bucket_name} --ownership-controls Rules=[{{ObjectOwnership=BucketOwnerEnforced}}]"
            })

        # 4. Default Encryption Check
        try:
            s3_client.get_bucket_encryption(Bucket=bucket_name)
        except ClientError as e:
            if e.response['Error']['Code'] == 'ServerSideEncryptionConfigurationNotFoundError':
                findings.append({
                    "resource_name": bucket_name,
                    "service": "S3",
                    "region": "global",
                    "severity_level": "MEDIUM",
                    "risk_score": 5.5,
                    "vulnerability_description": "Default server-side encryption is disabled on this bucket.",
                    "remediation_suggestion": f"aws s3api put-bucket-encryption --bucket {bucket_name} --server-side-encryption-configuration '{{\"Rules\": [{{\"ApplyServerSideEncryptionByDefault\": {{\"SSEAlgorithm\": \"AES256\"}}}}]}}'"
                })

        # 5. Versioning Check
        try:
            version_resp = s3_client.get_bucket_versioning(Bucket=bucket_name)
            if version_resp.get('Status') != 'Enabled':
                findings.append({
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

    return findings

def lambda_handler(event, context):
    return run_s3_scan()