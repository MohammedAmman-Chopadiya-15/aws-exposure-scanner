import json
import logging
import boto3
from datetime import datetime, timezone
from botocore.exceptions import ClientError

logger = logging.getLogger(__name__)
logger.setLevel(logging.INFO)


def run_iam_scan():
    iam = boto3.client('iam')
    findings = []
    region = "global"
    now = datetime.now(timezone.utc)

    # Auditing root account credentials and MFA configuration
    try:
        summary_resp = iam.get_account_summary()
        summary = summary_resp.get('SummaryMap', {})
        root_findings = []

        # Checking if MFA is enabled on the root account
        if summary.get('AccountMFAEnabled', 0) == 0:
            root_findings.append({
                "resource_name": "Root-Account",
                "service": "IAM",
                "region": region,
                "vulnerability_description": "[global] Root account lacks Multi-Factor Authentication (MFA).",
                "severity_level": "CRITICAL",
                "risk_score": 9.8,
                "remediation_suggestion": "Enable virtual or hardware MFA on the root account via the AWS Management Console."
            })

        # Checking if active programmatic access keys exist for the root user
        if summary.get('AccountAccessKeysPresent', 0) > 0:
            root_findings.append({
                "resource_name": "Root-Account",
                "service": "IAM",
                "region": region,
                "vulnerability_description": "[global] Root account has active access keys generated. Root credentials should never possess programmatic keys.",
                "severity_level": "CRITICAL",
                "risk_score": 9.5,
                "remediation_suggestion": "Delete root access keys immediately via IAM Security Credentials."
            })

        # Adding a baseline advisory record if root security checks pass
        if not root_findings:
            root_findings.append({
                "resource_name": "Root-Account",
                "service": "IAM",
                "region": region,
                "vulnerability_description": "[global] AWS Root Account baseline audited and compliant.",
                "severity_level": "ADVISORY",
                "risk_score": 0.0,
                "remediation_suggestion": "Root account meets baseline MFA and credential standards."
            })

        findings.extend(root_findings)
    except ClientError as e:
        logger.error(f"Auditing root account failed: {e}")

    # Paginating through all IAM users across the account
    try:
        paginator = iam.get_paginator('list_users')
        for page in paginator.paginate():
            for u in page.get('Users', []):
                u_name = u['UserName']
                resource_id = f"User-{u_name}"
                user_findings = []

                # Checking if console password access exists and whether MFA is registered
                has_console_password = False
                try:
                    iam.get_login_profile(UserName=u_name)
                    has_console_password = True
                except ClientError as e:
                    if e.response['Error']['Code'] != 'NoSuchEntity':
                        pass

                if has_console_password:
                    try:
                        mfa_devices = iam.list_mfa_devices(UserName=u_name).get('MFADevices', [])
                        if len(mfa_devices) == 0:
                            user_findings.append({
                                "resource_name": resource_id,
                                "service": "IAM",
                                "region": region,
                                "vulnerability_description": f"[global] IAM User '{u_name}' has console password access enabled without MFA configured.",
                                "severity_level": "MEDIUM",
                                "risk_score": 5.8,
                                "remediation_suggestion": f"Enforce MFA registration for user '{u_name}' before console login is permitted."
                            })
                    except ClientError:
                        pass

                # Checking if AdministratorAccess is directly attached to the user
                attached_policies = []
                try:
                    attached_policies = iam.list_attached_user_policies(UserName=u_name).get('AttachedPolicies', [])
                    for pol in attached_policies:
                        if pol['PolicyName'] == 'AdministratorAccess':
                            user_findings.append({
                                "resource_name": resource_id,
                                "service": "IAM",
                                "region": region,
                                "vulnerability_description": f"[global] IAM User '{u_name}' is directly attached to 'AdministratorAccess' (Full *:*).",
                                "severity_level": "HIGH",
                                "risk_score": 8.0,
                                "remediation_suggestion": f"aws iam detach-user-policy --user-name {u_name} --policy-arn {pol['PolicyArn']}"
                            })
                except ClientError:
                    pass

                # Flagging inline policies and non-admin direct attachments in favor of group inheritance
                inline_policies = []
                try:
                    inline_policies = iam.list_user_policies(UserName=u_name).get('PolicyNames', [])
                except ClientError:
                    pass

                if inline_policies or (len(attached_policies) > 0 and not any(p['PolicyName'] == 'AdministratorAccess' for p in attached_policies)):
                    user_findings.append({
                        "resource_name": resource_id,
                        "service": "IAM",
                        "region": region,
                        "vulnerability_description": f"[global] IAM User '{u_name}' has direct user-level policies attached rather than inheriting from IAM Groups.",
                        "severity_level": "LOW",
                        "risk_score": 3.2,
                        "remediation_suggestion": f"Migrate permissions for '{u_name}' into dedicated IAM Groups and assign group membership."
                    })

                # Evaluating access key rotation, dormancy, and overall count
                try:
                    access_keys = iam.list_access_keys(UserName=u_name).get('AccessKeyMetadata', [])
                    active_keys = [k for k in access_keys if k.get('Status') == 'Active']

                    # Checking for multiple simultaneous active access keys
                    if len(active_keys) > 1:
                        user_findings.append({
                            "resource_name": resource_id,
                            "service": "IAM",
                            "region": region,
                            "vulnerability_description": f"[global] IAM User '{u_name}' has {len(active_keys)} active access keys simultaneously.",
                            "severity_level": "LOW",
                            "risk_score": 2.8,
                            "remediation_suggestion": f"Delete redundant access keys for '{u_name}' leaving a single active key."
                        })

                    # Inspecting the creation age and last used timestamp for each active key
                    for key in active_keys:
                        key_id = key['AccessKeyId']
                        create_date = key['CreateDate']
                        age_days = (now - create_date).days

                        # Checking if the access key is older than the 90-day rotation limit
                        if age_days > 90:
                            user_findings.append({
                                "resource_name": resource_id,
                                "service": "IAM",
                                "region": region,
                                "vulnerability_description": f"[global] IAM User '{u_name}' access key '{key_id}' has not been rotated for {age_days} days (>90 days).",
                                "severity_level": "HIGH",
                                "risk_score": 7.5,
                                "remediation_suggestion": f"Rotate access key '{key_id}' for user '{u_name}' and deactivate the older key."
                            })

                        # Checking for dormant access keys unused for more than 90 days
                        try:
                            last_used_resp = iam.get_access_key_last_used(AccessKeyId=key_id)
                            last_used_date = last_used_resp.get('AccessKeyLastUsed', {}).get('LastUsedDate')
                            if last_used_date:
                                inactive_days = (now - last_used_date).days
                                if inactive_days > 90:
                                    user_findings.append({
                                        "resource_name": resource_id,
                                        "service": "IAM",
                                        "region": region,
                                        "vulnerability_description": f"[global] IAM User '{u_name}' access key '{key_id}' has been inactive for {inactive_days} days.",
                                        "severity_level": "MEDIUM",
                                        "risk_score": 4.8,
                                        "remediation_suggestion": f"aws iam update-access-key --access-key-id {key_id} --status Inactive --user-name {u_name}"
                                    })
                            elif age_days > 30:
                                # Flagging keys created over 30 days ago that have never been used
                                user_findings.append({
                                    "resource_name": resource_id,
                                    "service": "IAM",
                                    "region": region,
                                    "vulnerability_description": f"[global] IAM User '{u_name}' access key '{key_id}' was created {age_days} days ago and never used.",
                                    "severity_level": "MEDIUM",
                                    "risk_score": 4.8,
                                    "remediation_suggestion": f"aws iam delete-access-key --access-key-id {key_id} --user-name {u_name}"
                                })
                        except ClientError:
                            pass

                except ClientError:
                    pass

                # Adding a baseline advisory record if no user-level vulnerabilities were detected
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

    except ClientError as e:
        logger.error(f"Auditing IAM users failed: {e}")

    return findings


def lambda_handler(event, context):
    return run_iam_scan()


if __name__ == "__main__":
    print(json.dumps(lambda_handler({}, None), indent=2))