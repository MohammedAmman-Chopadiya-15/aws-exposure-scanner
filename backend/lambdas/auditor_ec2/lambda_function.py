# lambdas/auditor_ec2/lambda_function.py
import json
import boto3
from concurrent.futures import ThreadPoolExecutor
from botocore.config import Config
from botocore.exceptions import ClientError
from regions import get_enabled_regions

FAST_AWS_CONFIG = Config(
    connect_timeout=2,
    read_timeout=4,
    retries={'max_attempts': 1}
)

DATABASE_PORTS = {3306, 5432, 1433, 1521, 27017, 6379, 9200}

def get_instance_name(instance):
    for tag in instance.get('Tags', []):
        if tag.get('Key') == 'Name':
            return tag.get('Value')
    return instance['InstanceId']

def run_ec2_scan_region(region):
    ec2 = boto3.client('ec2', region_name=region, config=FAST_AWS_CONFIG)
    findings = []
    active_attached_sg_ids = set()

    # Track active attached security groups and instances
    instances_list = []
    try:
        instance_response = ec2.describe_instances()
        for reservation in instance_response.get('Reservations', []):
            for instance in reservation.get('Instances', []):
                if instance.get('State', {}).get('Name') == 'terminated':
                    continue
                instances_list.append(instance)
                for sg in instance.get('SecurityGroups', []):
                    active_attached_sg_ids.add(sg['GroupId'])
    except ClientError as e:
        print(f"[ERROR] Describing instances in {region}: {e}")
        return findings

    # -------------------------------------------------------------------------
    # 1. AUDIT SECURITY GROUPS (EC2-01, EC2-02, EC2-03)
    # -------------------------------------------------------------------------
    try:
        sg_response = ec2.describe_security_groups()
        for sg in sg_response.get('SecurityGroups', []):
            sg_id = sg['GroupId']
            sg_name = sg['GroupName']
            
            # Skip unattached default security groups
            if sg_name == 'default' and sg_id not in active_attached_sg_ids:
                continue

            resource_display_name = sg_name if sg_name != 'default' else f"SecurityGroup-{sg_id}"
            sg_findings = []

            for rule in sg.get('IpPermissions', []):
                from_port = rule.get('FromPort')
                to_port = rule.get('ToPort')
                ip_protocol = rule.get('IpProtocol')
                is_global = any(ip_range.get('CidrIp') == '0.0.0.0/0' for ip_range in rule.get('IpRanges', []))

                if is_global:
                    # EC2-03: All traffic open
                    if ip_protocol == '-1' or (from_port == 0 and to_port == 65535):
                        sg_findings.append({
                            "resource_name": resource_display_name,
                            "service": "EC2",
                            "region": region,
                            "vulnerability_description": f"[{region}] Security Group '{sg_name}' ({sg_id}) allows unrestricted inbound access (0.0.0.0/0) across all ports.",
                            "severity_level": "CRITICAL",
                            "risk_score": 9.2,
                            "remediation_suggestion": f"aws ec2 revoke-security-group-ingress --group-id {sg_id} --protocol all --cidr 0.0.0.0/0 --region {region}"
                        })

                    # EC2-01: Admin Ports (SSH: 22, RDP: 3389)
                    if from_port is not None and to_port is not None:
                        if (from_port <= 22 <= to_port) or (from_port <= 3389 <= to_port):
                            sg_findings.append({
                                "resource_name": resource_display_name,
                                "service": "EC2",
                                "region": region,
                                "vulnerability_description": f"[{region}] Security Group '{sg_name}' ({sg_id}) exposes remote administrative ports (SSH/RDP) to the public internet (0.0.0.0/0).",
                                "severity_level": "CRITICAL",
                                "risk_score": 9.5,
                                "remediation_suggestion": f"aws ec2 revoke-security-group-ingress --group-id {sg_id} --protocol tcp --port 22 --cidr 0.0.0.0/0 --region {region}"
                            })

                        # EC2-02: Database Ports
                        if any(from_port <= db_port <= to_port for db_port in DATABASE_PORTS):
                            sg_findings.append({
                                "resource_name": resource_display_name,
                                "service": "EC2",
                                "region": region,
                                "vulnerability_description": f"[{region}] Security Group '{sg_name}' ({sg_id}) exposes database listener ports directly to the public internet (0.0.0.0/0).",
                                "severity_level": "CRITICAL",
                                "risk_score": 9.0,
                                "remediation_suggestion": f"aws ec2 revoke-security-group-ingress --group-id {sg_id} --protocol tcp --port {from_port} --cidr 0.0.0.0/0 --region {region}"
                            })

            if not sg_findings:
                sg_findings.append({
                    "resource_name": resource_display_name,
                    "service": "EC2",
                    "region": region,
                    "vulnerability_description": f"[{region}] Security Group '{sg_name}' ({sg_id}) audited and compliant.",
                    "severity_level": "ADVISORY",
                    "risk_score": 0.0,
                    "remediation_suggestion": "Security Group rule definitions meet baseline policy."
                })

            findings.extend(sg_findings)
    except ClientError as e:
        print(f"[ERROR] Describing security groups in {region}: {e}")

    # -------------------------------------------------------------------------
    # 2. AUDIT EC2 INSTANCES & ATTACHED VOLUMES (EC2-04, EC2-05, EC2-06)
    # -------------------------------------------------------------------------
    for instance in instances_list:
        instance_id = instance['InstanceId']
        display_name = get_instance_name(instance)
        inst_findings = []

        # EC2-04: IMDSv1 Check
        metadata_options = instance.get('MetadataOptions', {})
        if metadata_options.get('HttpTokens') != 'required':
            inst_findings.append({
                "resource_name": display_name,
                "service": "EC2",
                "region": region,
                "vulnerability_description": f"[{region}] Instance '{display_name}' ({instance_id}) has legacy IMDSv1 enabled (vulnerable to SSRF credential exfiltration).",
                "severity_level": "HIGH",
                "risk_score": 7.8,
                "remediation_suggestion": f"aws ec2 modify-instance-metadata-options --instance-id {instance_id} --http-tokens required --http-endpoint enabled --region {region}"
            })

        # EC2-05: Public IPv4 Address Assigned
        if instance.get('PublicIpAddress'):
            inst_findings.append({
                "resource_name": display_name,
                "service": "EC2",
                "region": region,
                "vulnerability_description": f"[{region}] Instance '{display_name}' ({instance_id}) has a direct public IPv4 address ({instance.get('PublicIpAddress')}) assigned.",
                "severity_level": "HIGH",
                "risk_score": 7.2,
                "remediation_suggestion": f"Relocate instance '{instance_id}' to a private subnet behind a NAT Gateway or load balancer."
            })

        # EC2-06: Unencrypted Attached EBS Volumes
        for bdm in instance.get('BlockDeviceMappings', []):
            ebs_info = bdm.get('Ebs', {})
            volume_id = ebs_info.get('VolumeId')
            if volume_id:
                try:
                    vol_resp = ec2.describe_volumes(VolumeIds=[volume_id])
                    for vol in vol_resp.get('Volumes', []):
                        if not vol.get('Encrypted', False):
                            inst_findings.append({
                                "resource_name": display_name,
                                "service": "EC2",
                                "region": region,
                                "vulnerability_description": f"[{region}] Instance '{display_name}' ({instance_id}) has unencrypted attached EBS volume '{volume_id}'.",
                                "severity_level": "MEDIUM",
                                "risk_score": 5.8,
                                "remediation_suggestion": f"Enable EBS default encryption and migrate volume '{volume_id}' to an encrypted volume snapshot."
                            })
                except ClientError:
                    pass

        # Baseline Compliant Record
        if not inst_findings:
            inst_findings.append({
                "resource_name": display_name,
                "service": "EC2",
                "region": region,
                "vulnerability_description": f"[{region}] EC2 Instance '{display_name}' ({instance_id}) audited and compliant.",
                "severity_level": "ADVISORY",
                "risk_score": 0.0,
                "remediation_suggestion": "Instance meets baseline configuration policy."
            })

        findings.extend(inst_findings)

    return findings

def lambda_handler(event, context):
    regions = get_enabled_regions()
    all_findings = []
    
    with ThreadPoolExecutor(max_workers=len(regions) or 1) as executor:
        results = executor.map(run_ec2_scan_region, regions)
        for res in results:
            all_findings.extend(res)

    return all_findings

if __name__ == "__main__":
    print(json.dumps(lambda_handler({}, None), indent=2))