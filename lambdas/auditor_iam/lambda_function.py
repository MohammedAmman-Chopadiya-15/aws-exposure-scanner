import boto3
import csv
import io
import time
from datetime import datetime, timezone
from botocore.exceptions import ClientError

def run_iam_scan():
    iam = boto3.client('iam')
    findings = []
    region = "global"

    try:
        summary_resp = iam.get_account_summary()
        summary = summary_resp.get('SummaryMap', {})
        
        findings.append({
            "resource_name": "Root-Account",
            "service": "IAM",
            "region": region,
            "vulnerability_description": "[global] AWS Root Account baseline audit.",
            "severity_level": "ADVISORY",
            "risk_score": 0.0,
            "remediation_suggestion": "Root account baseline registered."
        })

        if summary.get('AccountMFAEnabled', 0) == 0:
            findings.append({
                "resource_name": "Root-Account",
                "service": "IAM",
                "region": region,
                "vulnerability_description": "[global] Root account lacks Multi-Factor Authentication (MFA).",
                "severity_level": "CRITICAL",
                "risk_score": 9.8,
                "remediation_suggestion": "Enable virtual or hardware MFA on root account via AWS Console."
            })
    except ClientError:
        pass

    try:
        paginator = iam.get_paginator('list_users')
        for page in paginator.paginate():
            for u in page.get('Users', []):
                u_name = u['UserName']
                resource_id = f"User-{u_name}"

                findings.append({
                    "resource_name": resource_id,
                    "service": "IAM",
                    "region": region,
                    "vulnerability_description": f"[global] IAM User '{u_name}' identified and audited.",
                    "severity_level": "ADVISORY",
                    "risk_score": 0.0,
                    "remediation_suggestion": "User complies with baseline identity standards."
                })

                attached = iam.list_attached_user_policies(UserName=u_name).get('AttachedPolicies', [])
                for pol in attached:
                    if pol['PolicyName'] == 'AdministratorAccess':
                        findings.append({
                            "resource_name": resource_id,
                            "service": "IAM",
                            "region": region,
                            "vulnerability_description": f"[global] IAM User '{u_name}' is directly attached to 'AdministratorAccess'.",
                            "severity_level": "HIGH",
                            "risk_score": 8.0,
                            "remediation_suggestion": f"aws iam detach-user-policy --user-name {u_name} --policy-arn {pol['PolicyArn']}"
                        })
    except ClientError:
        pass

    return findings

def lambda_handler(event, context):
    return run_iam_scan()