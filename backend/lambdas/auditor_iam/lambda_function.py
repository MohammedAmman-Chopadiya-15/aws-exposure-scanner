import boto3
from botocore.exceptions import ClientError

def run_iam_scan():
    iam = boto3.client('iam')
    findings = []
    region = "global"

    # 1. Audit Root Account
    try:
        summary_resp = iam.get_account_summary()
        summary = summary_resp.get('SummaryMap', {})
        root_findings = []

        if summary.get('AccountMFAEnabled', 0) == 0:
            root_findings.append({
                "resource_name": "Root-Account",
                "service": "IAM",
                "region": region,
                "vulnerability_description": "[global] Root account lacks Multi-Factor Authentication (MFA).",
                "severity_level": "CRITICAL",
                "risk_score": 9.8,
                "remediation_suggestion": "Enable virtual or hardware MFA on root account via AWS Console."
            })

        if not root_findings:
            root_findings.append({
                "resource_name": "Root-Account",
                "service": "IAM",
                "region": region,
                "vulnerability_description": "[global] AWS Root Account baseline audited and compliant.",
                "severity_level": "ADVISORY",
                "risk_score": 0.0,
                "remediation_suggestion": "Root account meets baseline MFA standards."
            })

        findings.extend(root_findings)
    except ClientError:
        pass

    # 2. Audit IAM Users
    try:
        paginator = iam.get_paginator('list_users')
        for page in paginator.paginate():
            for u in page.get('Users', []):
                u_name = u['UserName']
                resource_id = f"User-{u_name}"
                user_findings = []

                attached = iam.list_attached_user_policies(UserName=u_name).get('AttachedPolicies', [])
                for pol in attached:
                    if pol['PolicyName'] == 'AdministratorAccess':
                        user_findings.append({
                            "resource_name": resource_id,
                            "service": "IAM",
                            "region": region,
                            "vulnerability_description": f"[global] IAM User '{u_name}' is directly attached to 'AdministratorAccess'.",
                            "severity_level": "HIGH",
                            "risk_score": 8.0,
                            "remediation_suggestion": f"aws iam detach-user-policy --user-name {u_name} --policy-arn {pol['PolicyArn']}"
                        })

                if not user_findings:
                    user_findings.append({
                        "resource_name": resource_id,
                        "service": "IAM",
                        "region": region,
                        "vulnerability_description": f"[global] IAM User '{u_name}' identified and audited.",
                        "severity_level": "ADVISORY",
                        "risk_score": 0.0,
                        "remediation_suggestion": "User complies with baseline identity standards."
                    })

                findings.extend(user_findings)
    except ClientError:
        pass

    return findings

def lambda_handler(event, context):
    return run_iam_scan()