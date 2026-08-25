import json
import logging
import boto3
from concurrent.futures import ThreadPoolExecutor
from botocore.config import Config
from botocore.exceptions import ClientError
from regions import get_enabled_regions

logger = logging.getLogger(__name__)
logger.setLevel(logging.INFO)

# Setting aggressive timeouts to prevent slow regional endpoints from stalling the scan
FAST_AWS_CONFIG = Config(
    connect_timeout=2,
    read_timeout=4,
    retries={'max_attempts': 1}
)


def run_rds_scan_region(region):
    rds = boto3.client('rds', region_name=region, config=FAST_AWS_CONFIG)
    findings = []

    # Querying all active RDS database instances in the target region
    try:
        response = rds.describe_db_instances()
        for db in response.get('DBInstances', []):
            db_id = db.get('DBInstanceIdentifier', 'Unknown-RDS-Instance')
            engine = db.get('Engine', 'unknown')
            instance_findings = []

            # Checking if the database is exposed directly to the public internet
            if db.get('PubliclyAccessible', False):
                instance_findings.append({
                    "resource_name": db_id,
                    "service": "RDS",
                    "region": region,
                    "vulnerability_description": f"[{region}] RDS Instance '{db_id}' ({engine}) is Publicly Accessible to the internet.",
                    "severity_level": "CRITICAL",
                    "risk_score": 9.6,
                    "remediation_suggestion": f"aws rds modify-db-instance --db-instance-identifier {db_id} --no-publicly-accessible --region {region}"
                })

            # Checking if storage-level encryption at rest is enabled
            if not db.get('StorageEncrypted', False):
                instance_findings.append({
                    "resource_name": db_id,
                    "service": "RDS",
                    "region": region,
                    "vulnerability_description": f"[{region}] RDS Instance '{db_id}' ({engine}) storage encryption at rest is disabled.",
                    "severity_level": "HIGH",
                    "risk_score": 7.8,
                    "remediation_suggestion": f"Create an encrypted snapshot of '{db_id}' and restore to a new encrypted instance in region {region}."
                })

            # Verifying that automated backup retention is not set to zero days
            backup_retention = db.get('BackupRetentionPeriod', 0)
            if backup_retention == 0:
                instance_findings.append({
                    "resource_name": db_id,
                    "service": "RDS",
                    "region": region,
                    "vulnerability_description": f"[{region}] RDS Instance '{db_id}' ({engine}) has automated backups disabled (retention period: 0 days).",
                    "severity_level": "HIGH",
                    "risk_score": 7.2,
                    "remediation_suggestion": f"aws rds modify-db-instance --db-instance-identifier {db_id} --backup-retention-period 7 --apply-immediately --region {region}"
                })

            # Evaluating whether Multi-AZ deployment is active for high availability
            if not db.get('MultiAZ', False):
                instance_findings.append({
                    "resource_name": db_id,
                    "service": "RDS",
                    "region": region,
                    "vulnerability_description": f"[{region}] RDS Instance '{db_id}' ({engine}) is deployed as Single-AZ without automated Multi-AZ failover redundancy.",
                    "severity_level": "MEDIUM",
                    "risk_score": 5.8,
                    "remediation_suggestion": f"aws rds modify-db-instance --db-instance-identifier {db_id} --multi-az --apply-immediately --region {region}"
                })

            # Checking if automatic minor version patching is turned on
            if not db.get('AutoMinorVersionUpgrade', False):
                instance_findings.append({
                    "resource_name": db_id,
                    "service": "RDS",
                    "region": region,
                    "vulnerability_description": f"[{region}] RDS Instance '{db_id}' ({engine}) has automatic minor version security upgrades disabled.",
                    "severity_level": "MEDIUM",
                    "risk_score": 5.0,
                    "remediation_suggestion": f"aws rds modify-db-instance --db-instance-identifier {db_id} --auto-minor-version-upgrade --apply-immediately --region {region}"
                })

            # Adding a baseline advisory record if all security checks passed
            if not instance_findings:
                instance_findings.append({
                    "resource_name": db_id,
                    "service": "RDS",
                    "region": region,
                    "vulnerability_description": f"[{region}] RDS Instance '{db_id}' ({engine}) audited and compliant.",
                    "severity_level": "ADVISORY",
                    "risk_score": 0.0,
                    "remediation_suggestion": "Database meets baseline security and availability standards."
                })

            findings.extend(instance_findings)

    except ClientError as e:
        # Ignoring expected authorization errors while logging unexpected regional failures
        if "UnauthorizedOperation" not in str(e):
            logger.error(f"Auditing RDS instances in region '{region}' failed: {e}")

    return findings


def lambda_handler(event, context):
    # Fetching all active regions and auditing them in parallel
    regions = get_enabled_regions()
    all_findings = []

    with ThreadPoolExecutor(max_workers=len(regions) or 1) as executor:
        for res in executor.map(run_rds_scan_region, regions):
            all_findings.extend(res)

    return all_findings


if __name__ == "__main__":
    print(json.dumps(lambda_handler({}, None), indent=2))