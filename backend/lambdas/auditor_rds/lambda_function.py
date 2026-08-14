import boto3
from botocore.exceptions import ClientError
from regions import get_enabled_regions

def run_rds_scan_region(region):
    rds = boto3.client('rds', region_name=region)
    findings = []

    try:
        response = rds.describe_db_instances()
        for db in response.get('DBInstances', []):
            db_id = db.get('DBInstanceIdentifier', 'Unknown-RDS-Instance')
            engine = db.get('Engine', 'unknown')
            instance_findings = []

            if db.get('PubliclyAccessible', False):
                instance_findings.append({
                    "resource_name": db_id,
                    "service": "RDS",
                    "region": region,
                    "vulnerability_description": f"[{region}] RDS Instance '{db_id}' ({engine}) is Publicly Accessible.",
                    "severity_level": "CRITICAL",
                    "risk_score": 9.6,
                    "remediation_suggestion": f"aws rds modify-db-instance --db-instance-identifier {db_id} --no-publicly-accessible --region {region}"
                })

            if not db.get('StorageEncrypted', False):
                instance_findings.append({
                    "resource_name": db_id,
                    "service": "RDS",
                    "region": region,
                    "vulnerability_description": f"[{region}] RDS Instance '{db_id}' ({engine}) storage encryption is disabled.",
                    "severity_level": "HIGH",
                    "risk_score": 7.5,
                    "remediation_suggestion": f"Create an encrypted snapshot of '{db_id}' in region {region}."
                })

            # IF COMPLIANT: Append baseline ADVISORY entry so zero-exposure databases appear
            if not instance_findings:
                instance_findings.append({
                    "resource_name": db_id,
                    "service": "RDS",
                    "region": region,
                    "vulnerability_description": f"[{region}] RDS Instance '{db_id}' ({engine}) audited and compliant.",
                    "severity_level": "ADVISORY",
                    "risk_score": 0.0,
                    "remediation_suggestion": "Database meets baseline security standards."
                })

            findings.extend(instance_findings)
    except ClientError:
        pass

    return findings

def lambda_handler(event, context):
    regions = get_enabled_regions()
    all_findings = []
    for r in regions:
        all_findings.extend(run_rds_scan_region(r))
    return all_findings