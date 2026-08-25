import json
import logging
import boto3
from botocore.exceptions import ClientError
from regions import get_enabled_regions

logger = logging.getLogger(__name__)
logger.setLevel(logging.INFO)

# Tracking runtimes that have reached end-of-life or deprecation
DEPRECATED_RUNTIMES = {
    "python2.7", "python3.6", "python3.7", "python3.8", "python3.9",
    "nodejs10.x", "nodejs12.x", "nodejs14.x", "nodejs16.x", "nodejs18.x",
    "ruby2.5", "ruby2.7",
    "java8", "java8.al2", "java11",
    "dotnetcore1.0", "dotnetcore2.0", "dotnetcore2.1", "dotnetcore3.1", "dotnet6", "dotnet7",
    "go1.x"
}


def run_lambda_scan_region(region):
    lambda_client = boto3.client('lambda', region_name=region)
    iam_client = boto3.client('iam')
    findings = []

    # Paginating through all Lambda functions in the target region
    try:
        paginator = lambda_client.get_paginator('list_functions')
        for page in paginator.paginate():
            for fn in page.get('Functions', []):
                fn_name = fn['FunctionName']
                fn_arn = fn['FunctionArn']
                runtime = fn.get('Runtime', 'unknown')
                role_arn = fn.get('Role', '')
                func_findings = []

                # Checking for unauthenticated public Function URLs
                try:
                    url_configs = lambda_client.list_function_url_configs(FunctionName=fn_name)
                    for cfg in url_configs.get('FunctionUrlConfigs', []):
                        if cfg.get('AuthType') == 'NONE':
                            func_findings.append({
                                "resource_name": fn_name,
                                "service": "LAMBDA",
                                "region": region,
                                "vulnerability_description": f"[{region}] Function '{fn_name}' has an unauthenticated Public Function URL (AuthType: NONE).",
                                "severity_level": "CRITICAL",
                                "risk_score": 9.8,
                                "remediation_suggestion": f"aws lambda update-function-url-config --function-name {fn_name} --auth-type AWS_IAM --region {region}"
                            })
                except ClientError:
                    pass

                # Inspecting the resource policy for unrestricted wildcard access
                try:
                    policy_resp = lambda_client.get_policy(FunctionName=fn_name)
                    policy_doc = json.loads(policy_resp.get('Policy', '{}'))
                    for stmt in policy_doc.get('Statement', []):
                        principal = stmt.get('Principal')
                        effect = stmt.get('Effect')
                        is_wildcard = (
                            principal == '*' or
                            principal == {'AWS': '*'} or
                            (isinstance(principal, dict) and principal.get('AWS') == '*')
                        )
                        has_condition = 'Condition' in stmt

                        if effect == 'Allow' and is_wildcard and not has_condition:
                            sid = stmt.get('Sid', 'UnknownStatement')
                            func_findings.append({
                                "resource_name": fn_name,
                                "service": "LAMBDA",
                                "region": region,
                                "vulnerability_description": f"[{region}] Function '{fn_name}' resource policy permits unrestricted public invocation (Principal: *).",
                                "severity_level": "CRITICAL",
                                "risk_score": 9.2,
                                "remediation_suggestion": f"aws lambda remove-permission --function-name {fn_name} --statement-id {sid} --region {region}"
                            })
                except ClientError as e:
                    # Catching cases where no resource policy is attached
                    if e.response['Error']['Code'] != 'ResourceNotFoundException':
                        pass

                # Checking if the function execution role has AdministratorAccess attached
                if role_arn:
                    role_name = role_arn.split('/')[-1]
                    try:
                        attached_policies = iam_client.list_attached_role_policies(RoleName=role_name).get('AttachedPolicies', [])
                        for pol in attached_policies:
                            if pol['PolicyName'] == 'AdministratorAccess':
                                func_findings.append({
                                    "resource_name": fn_name,
                                    "service": "LAMBDA",
                                    "region": region,
                                    "vulnerability_description": f"[{region}] Function '{fn_name}' execution role '{role_name}' has full AdministratorAccess attached.",
                                    "severity_level": "HIGH",
                                    "risk_score": 8.5,
                                    "remediation_suggestion": f"aws iam detach-role-policy --role-name {role_name} --policy-arn {pol['PolicyArn']}"
                                })
                    except ClientError:
                        pass

                # Flagging functions running on deprecated or unsupported runtimes
                if runtime in DEPRECATED_RUNTIMES:
                    func_findings.append({
                        "resource_name": fn_name,
                        "service": "LAMBDA",
                        "region": region,
                        "vulnerability_description": f"[{region}] Function '{fn_name}' runs on deprecated runtime '{runtime}'.",
                        "severity_level": "HIGH",
                        "risk_score": 7.5,
                        "remediation_suggestion": f"aws lambda update-function-configuration --function-name {fn_name} --runtime python3.12 --region {region}"
                    })

                # Checking if environment variables rely on the default KMS key instead of a CMK
                env_vars = fn.get('Environment', {}).get('Variables', {})
                kms_key = fn.get('KMSKeyArn')
                if env_vars and not kms_key:
                    func_findings.append({
                        "resource_name": fn_name,
                        "service": "LAMBDA",
                        "region": region,
                        "vulnerability_description": f"[{region}] Function '{fn_name}' stores environment variables using default AWS-managed KMS key rather than a CMK.",
                        "severity_level": "MEDIUM",
                        "risk_score": 5.0,
                        "remediation_suggestion": f"aws lambda update-function-configuration --function-name {fn_name} --kms-key-arn <CUSTOMER_MANAGED_KEY_ARN> --region {region}"
                    })

                # Verifying whether the function is deployed inside a VPC
                vpc_config = fn.get('VpcConfig', {})
                subnet_ids = vpc_config.get('SubnetIds', [])
                if not subnet_ids:
                    func_findings.append({
                        "resource_name": fn_name,
                        "service": "LAMBDA",
                        "region": region,
                        "vulnerability_description": f"[{region}] Function '{fn_name}' is not configured with VPC isolation.",
                        "severity_level": "MEDIUM",
                        "risk_score": 4.2,
                        "remediation_suggestion": f"aws lambda update-function-configuration --function-name {fn_name} --vpc-config SubnetIds=<SUBNET_IDS>,SecurityGroupIds=<SG_ID> --region {region}"
                    })

                # Checking if active AWS X-Ray tracing is enabled
                tracing_mode = fn.get('TracingConfig', {}).get('Mode')
                if tracing_mode != 'Active':
                    func_findings.append({
                        "resource_name": fn_name,
                        "service": "LAMBDA",
                        "region": region,
                        "vulnerability_description": f"[{region}] Function '{fn_name}' active X-Ray tracing is disabled (Mode: '{tracing_mode}').",
                        "severity_level": "LOW",
                        "risk_score": 2.5,
                        "remediation_suggestion": f"aws lambda update-function-configuration --function-name {fn_name} --tracing-config Mode=Active --region {region}"
                    })

                # Adding a baseline advisory record if no issues were identified
                if not func_findings:
                    func_findings.append({
                        "resource_name": fn_name,
                        "service": "LAMBDA",
                        "region": region,
                        "vulnerability_description": f"[{region}] Lambda Function '{fn_name}' audited and compliant.",
                        "severity_level": "ADVISORY",
                        "risk_score": 0.0,
                        "remediation_suggestion": "Function configuration meets baseline security standards."
                    })

                findings.extend(func_findings)

    except ClientError as e:
        # Logging unexpected errors while skipping expected permission issues
        if "UnauthorizedOperation" not in str(e):
            logger.error(f"Auditing Lambda in region '{region}' failed: {e}")

    return findings


def lambda_handler(event, context):
    # Discovering enabled regions and aggregating audit findings across all of them
    regions = get_enabled_regions()
    all_findings = []
    for r in regions:
        all_findings.extend(run_lambda_scan_region(r))
    return all_findings


if __name__ == "__main__":
    print(json.dumps(lambda_handler({}, None), indent=2))