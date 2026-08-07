import boto3
from botocore.exceptions import ClientError
from regions import get_enabled_regions

def get_instance_name(instance):
    for tag in instance.get('Tags', []):
        if tag.get('Key') == 'Name':
            return tag.get('Value')
    return instance['InstanceId']

def run_ec2_scan_region(region):
    ec2 = boto3.client('ec2', region_name=region)
    findings = []
    active_attached_sg_ids = set()

    try:
        instance_response = ec2.describe_instances()
        for reservation in instance_response.get('Reservations', []):
            for instance in reservation.get('Instances', []):
                if instance.get('State', {}).get('Name') == 'terminated':
                    continue
                for sg in instance.get('SecurityGroups', []):
                    active_attached_sg_ids.add(sg['GroupId'])
    except ClientError:
        pass

    try:
        sg_response = ec2.describe_security_groups()
        for sg in sg_response.get('SecurityGroups', []):
            sg_id = sg['GroupId']
            sg_name = sg['GroupName']
            if sg_name == 'default' and sg_id not in active_attached_sg_ids:
                continue

            resource_display_name = sg_name if sg_name != 'default' else f"SecurityGroup-{sg_id}"

            for rule in sg.get('IpPermissions', []):
                from_port = rule.get('FromPort')
                to_port = rule.get('ToPort')
                ip_protocol = rule.get('IpProtocol')
                is_global = any(ip_range.get('CidrIp') == '0.0.0.0/0' for ip_range in rule.get('IpRanges', []))

                if is_global and from_port is not None and to_port is not None:
                    if (from_port <= 22 <= to_port) or (from_port <= 3389 <= to_port) or ip_protocol == '-1':
                        findings.append({
                            "resource_name": resource_display_name,
                            "service": "EC2",
                            "region": region,
                            "vulnerability_description": f"[{region}] Security Group '{sg_name}' ({sg_id}) permits global internet access (0.0.0.0/0) to remote administration ports (SSH/RDP).",
                            "severity_level": "CRITICAL",
                            "risk_score": 9.5,
                            "remediation_suggestion": f"aws ec2 revoke-security-group-ingress --group-id {sg_id} --protocol tcp --port 22 --cidr 0.0.0.0/0 --region {region}"
                        })
    except ClientError:
        pass

    try:
        instance_response = ec2.describe_instances()
        for reservation in instance_response.get('Reservations', []):
            for instance in reservation.get('Instances', []):
                if instance.get('State', {}).get('Name') == 'terminated':
                    continue
                instance_id = instance['InstanceId']
                display_name = get_instance_name(instance)

                findings.append({
                    "resource_name": display_name,
                    "service": "EC2",
                    "region": region,
                    "vulnerability_description": f"[{region}] EC2 Instance '{display_name}' ({instance_id}) audited.",
                    "severity_level": "ADVISORY",
                    "risk_score": 0.0,
                    "remediation_suggestion": "Instance baseline checked."
                })

                metadata_options = instance.get('MetadataOptions', {})
                if metadata_options.get('HttpTokens') != 'required':
                    findings.append({
                        "resource_name": display_name,
                        "service": "EC2",
                        "region": region,
                        "vulnerability_description": f"[{region}] Instance '{display_name}' ({instance_id}) has legacy IMDSv1 enabled.",
                        "severity_level": "HIGH",
                        "risk_score": 7.8,
                        "remediation_suggestion": f"aws ec2 modify-instance-metadata-options --instance-id {instance_id} --http-tokens required --http-endpoint enabled --region {region}"
                    })
    except ClientError:
        pass

    return findings

def lambda_handler(event, context):
    regions = get_enabled_regions()
    all_findings = []
    for r in regions:
        all_findings.extend(run_ec2_scan_region(r))
    return all_findings