import json
import logging
import boto3
from concurrent.futures import ThreadPoolExecutor
from botocore.config import Config
from botocore.exceptions import ClientError
from regions import get_enabled_regions

logger = logging.getLogger(__name__)
logger.setLevel(logging.INFO)

# Setting aggressive timeouts to prevent slow API calls from stalling execution
FAST_AWS_CONFIG = Config(
    connect_timeout=2,
    read_timeout=4,
    retries={'max_attempts': 1}
)


def scan_apigw_v2_region(apigwv2_client, region):
    findings = []
    
    # Querying all HTTP and WebSocket APIs in the target region
    try:
        apis_resp = apigwv2_client.get_apis()
        for api in apis_resp.get('Items', []):
            api_id = api['ApiId']
            api_name = api.get('Name', api_id)

            # Skipping the scanner's own API Gateway to avoid self-auditing
            if api_name.startswith("exposure-scanner-"):
                continue

            disable_execute_api = api.get('DisableExecuteApiEndpoint', False)
            api_findings = []

            # Checking if the default execute-api endpoint is left enabled
            if not disable_execute_api:
                api_findings.append({
                    "resource_name": f"{api_name} ({api_id})",
                    "service": "APIGATEWAY",
                    "region": region,
                    "vulnerability_description": f"[{region}] API '{api_name}' ({api_id}) has default execute-api endpoint enabled.",
                    "severity_level": "HIGH",
                    "risk_score": 7.8,
                    "remediation_suggestion": f"aws apigatewayv2 update-api --api-id {api_id} --disable-execute-api-endpoint --region {region}"
                })

            # Checking for overly permissive wildcard origins in CORS settings
            cors_config = api.get('CorsConfiguration', {})
            allow_origins = cors_config.get('AllowOrigins', [])
            if '*' in allow_origins:
                api_findings.append({
                    "resource_name": f"{api_name} ({api_id})",
                    "service": "APIGATEWAY",
                    "region": region,
                    "vulnerability_description": f"[{region}] API '{api_name}' ({api_id}) allows wildcard origin ('*') in CORS configuration.",
                    "severity_level": "HIGH",
                    "risk_score": 7.8,
                    "remediation_suggestion": f"aws apigatewayv2 update-api --api-id {api_id} --cors-configuration AllowOrigins='[\"https://yourdomain.com\"]' --region {region}"
                })

            # Inspecting individual routes for unauthenticated access
            try:
                routes_resp = apigwv2_client.get_routes(ApiId=api_id)
                for route in routes_resp.get('Items', []):
                    route_key = route.get('RouteKey', '')
                    auth_type = route.get('AuthorizationType', 'NONE')
                    route_id = route.get('RouteId', '')

                    # Skipping CORS OPTIONS preflight routes
                    if not route_key.startswith('OPTIONS ') and auth_type == 'NONE':
                        api_findings.append({
                            "resource_name": f"{api_name} ({api_id})",
                            "service": "APIGATEWAY",
                            "region": region,
                            "vulnerability_description": f"[{region}] API '{api_name}' route '{route_key}' allows unauthenticated access (AuthorizationType: NONE).",
                            "severity_level": "CRITICAL",
                            "risk_score": 9.5,
                            "remediation_suggestion": f"aws apigatewayv2 update-route --api-id {api_id} --route-id {route_id} --authorization-type JWT --authorizer-id <AUTHORIZER_ID> --region {region}"
                        })
            except ClientError:
                pass

            # Verifying whether CloudWatch access logging is configured on active stages
            try:
                stages_resp = apigwv2_client.get_stages(ApiId=api_id)
                for stage in stages_resp.get('Items', []):
                    stage_name = stage.get('StageName', '$default')
                    access_logs = stage.get('AccessLogSettings', {})
                    if not access_logs.get('DestinationArn'):
                        api_findings.append({
                            "resource_name": f"{api_name} ({api_id})",
                            "service": "APIGATEWAY",
                            "region": region,
                            "vulnerability_description": f"[{region}] API '{api_name}' stage '{stage_name}' has CloudWatch access logging disabled.",
                            "severity_level": "MEDIUM",
                            "risk_score": 5.5,
                            "remediation_suggestion": f"aws apigatewayv2 update-stage --api-id {api_id} --stage-name '{stage_name}' --access-log-settings DestinationArn=<CW_LOG_GROUP_ARN>,Format='$context.identity.sourceIp $context.routeKey' --region {region}"
                        })
            except ClientError:
                pass

            # Adding a baseline advisory record if the API Gateway v2 checks pass
            if not api_findings:
                api_findings.append({
                    "resource_name": f"{api_name} ({api_id})",
                    "service": "APIGATEWAY",
                    "region": region,
                    "vulnerability_description": f"[{region}] API Gateway v2 '{api_name}' ({api_id}) audited and compliant.",
                    "severity_level": "ADVISORY",
                    "risk_score": 0.0,
                    "remediation_suggestion": "API configuration meets established baseline security standards."
                })

            findings.extend(api_findings)

    except ClientError as e:
        if "UnauthorizedOperation" not in str(e):
            logger.error(f"Auditing API Gateway v2 failed in region '{region}': {e}")

    return findings


def scan_apigw_v1_region(apigw_client, region):
    findings = []
    
    # Querying all REST APIs in the target region
    try:
        apis_resp = apigw_client.get_rest_apis()
        for api in apis_resp.get('items', []):
            api_id = api['id']
            api_name = api.get('name', api_id)

            # Skipping the scanner's own REST API to prevent recursive auditing
            if api_name.startswith("exposure-scanner-"):
                continue

            endpoint_config = api.get('endpointConfiguration', {})
            types = endpoint_config.get('types', ['REGIONAL'])
            policy = api.get('policy')
            api_findings = []

            # Checking if public EDGE or REGIONAL endpoints lack restrictive resource policies
            if ('EDGE' in types or 'REGIONAL' in types) and not policy:
                api_findings.append({
                    "resource_name": f"{api_name} ({api_id})",
                    "service": "APIGATEWAY",
                    "region": region,
                    "vulnerability_description": f"[{region}] REST API '{api_name}' ({'/'.join(types)}) lacks an IP/VPC restrictive Resource Policy.",
                    "severity_level": "HIGH",
                    "risk_score": 7.5,
                    "remediation_suggestion": f"aws apigateway update-rest-api --rest-api-id {api_id} --patch-operations op=replace,path=/policy,value='<RESTRICTIVE_POLICY_JSON>' --region {region}"
                })

            # Inspecting each resource method for missing authorization controls
            try:
                resources_resp = apigw_client.get_resources(restApiId=api_id, embed=['methods'])
                for res in resources_resp.get('items', []):
                    res_path = res.get('path', '/')
                    res_id = res.get('id')
                    res_methods = res.get('resourceMethods', {})
                    for http_method, method_props in res_methods.items():
                        if http_method == 'OPTIONS':
                            continue
                        auth_type = method_props.get('authorizationType', 'NONE')
                        if auth_type == 'NONE':
                            api_findings.append({
                                "resource_name": f"{api_name} ({api_id})",
                                "service": "APIGATEWAY",
                                "region": region,
                                "vulnerability_description": f"[{region}] REST API '{api_name}' method {http_method} {res_path} allows unauthenticated access (authorizationType: NONE).",
                                "severity_level": "CRITICAL",
                                "risk_score": 9.5,
                                "remediation_suggestion": f"aws apigateway update-method --rest-api-id {api_id} --resource-id {res_id} --http-method {http_method} --patch-operations op=replace,path=/authorizationType,value=COGNITO_USER_POOLS --region {region}"
                            })
            except ClientError:
                pass

            # Auditing deployment stages for WAF protection and CloudWatch logging
            try:
                stages_resp = apigw_client.get_stages(restApiId=api_id)
                for stage in stages_resp.get('item', []):
                    stage_name = stage.get('stageName', 'prod')

                    # Checking if an AWS WAF Web ACL is attached to the stage
                    if not stage.get('webAclArn'):
                        api_findings.append({
                            "resource_name": f"{api_name} ({api_id})",
                            "service": "APIGATEWAY",
                            "region": region,
                            "vulnerability_description": f"[{region}] REST API '{api_name}' stage '{stage_name}' is not protected by an AWS WAF Web ACL.",
                            "severity_level": "HIGH",
                            "risk_score": 8.2,
                            "remediation_suggestion": f"aws wafv2 associate-web-acl --web-acl-arn <WAF_WEB_ACL_ARN> --resource-arn <STAGE_ARN> --region {region}"
                        })

                    # Checking if CloudWatch execution logging is enabled
                    method_settings = stage.get('methodSettings', {})
                    root_settings = method_settings.get('*/*', {})
                    logging_level = root_settings.get('loggingLevel', 'OFF')
                    if logging_level == 'OFF':
                        api_findings.append({
                            "resource_name": f"{api_name} ({api_id})",
                            "service": "APIGATEWAY",
                            "region": region,
                            "vulnerability_description": f"[{region}] REST API '{api_name}' stage '{stage_name}' has CloudWatch execution logging disabled (loggingLevel: OFF).",
                            "severity_level": "MEDIUM",
                            "risk_score": 5.5,
                            "remediation_suggestion": f"aws apigateway update-stage --rest-api-id {api_id} --stage-name '{stage_name}' --patch-operations op=replace,path=/*/*/logging/loglevel,value=INFO --region {region}"
                        })
            except ClientError:
                pass

            # Adding a baseline advisory record if REST API configuration is safe
            if not api_findings:
                api_findings.append({
                    "resource_name": f"{api_name} ({api_id})",
                    "service": "APIGATEWAY",
                    "region": region,
                    "vulnerability_description": f"[{region}] REST API '{api_name}' ({api_id}) audited and compliant.",
                    "severity_level": "ADVISORY",
                    "risk_score": 0.0,
                    "remediation_suggestion": "REST API configuration meets baseline security standards."
                })

            findings.extend(api_findings)

    except ClientError as e:
        if "UnauthorizedOperation" not in str(e):
            logger.error(f"Auditing REST APIs failed in region '{region}': {e}")

    return findings


def scan_custom_domains_region(region):
    findings = []
    apigwv2 = boto3.client('apigatewayv2', region_name=region, config=FAST_AWS_CONFIG)
    
    # Querying all configured custom domain names in the region
    try:
        domains_resp = apigwv2.get_domain_names()
        for dom in domains_resp.get('Items', []):
            domain_name = dom.get('DomainName', '')
            domain_configs = dom.get('DomainNameConfigurations', [])
            dom_findings = []
            
            # Checking if Mutual TLS (mTLS) authentication is enforced
            mtls_config = dom.get('MutualTlsAuthentication')
            if not mtls_config or not mtls_config.get('TruststoreUri'):
                dom_findings.append({
                    "resource_name": f"Domain-{domain_name}",
                    "service": "APIGATEWAY",
                    "region": region,
                    "vulnerability_description": f"[{region}] Custom Domain '{domain_name}' does not enforce Mutual TLS (mTLS) authentication.",
                    "severity_level": "MEDIUM",
                    "risk_score": 5.0,
                    "remediation_suggestion": f"aws apigatewayv2 update-domain-name --domain-name {domain_name} --mutual-tls-authentication TruststoreUri=s3://<BUCKET>/truststore.pem --region {region}"
                })

            # Checking for legacy TLS security policies (TLS 1.0 or 1.1)
            for cfg in domain_configs:
                sec_policy = cfg.get('SecurityPolicy', '')
                if sec_policy in ['TLS_1_0', 'TLS_1_1']:
                    dom_findings.append({
                        "resource_name": f"Domain-{domain_name}",
                        "service": "APIGATEWAY",
                        "region": region,
                        "vulnerability_description": f"[{region}] Custom Domain '{domain_name}' uses legacy TLS policy '{sec_policy}' instead of TLS_1_2.",
                        "severity_level": "MEDIUM",
                        "risk_score": 5.0,
                        "remediation_suggestion": f"aws apigatewayv2 update-domain-name --domain-name {domain_name} --domain-name-configurations SecurityPolicy=TLS_1_2 --region {region}"
                    })

            # Adding a baseline advisory record if custom domain configuration is compliant
            if not dom_findings:
                dom_findings.append({
                    "resource_name": f"Domain-{domain_name}",
                    "service": "APIGATEWAY",
                    "region": region,
                    "vulnerability_description": f"[{region}] Custom Domain '{domain_name}' audited and compliant.",
                    "severity_level": "ADVISORY",
                    "risk_score": 0.0,
                    "remediation_suggestion": "Custom Domain meets baseline TLS and mTLS policy standards."
                })

            findings.extend(dom_findings)
    except ClientError as e:
        if "UnauthorizedOperation" not in str(e):
            logger.error(f"Auditing custom domains failed in region '{region}': {e}")

    return findings


def run_apigw_scan_region(region):
    apigwv2 = boto3.client('apigatewayv2', region_name=region, config=FAST_AWS_CONFIG)
    apigwv1 = boto3.client('apigateway', region_name=region, config=FAST_AWS_CONFIG)

    findings = []
    findings.extend(scan_apigw_v2_region(apigwv2, region))
    findings.extend(scan_apigw_v1_region(apigwv1, region))
    findings.extend(scan_custom_domains_region(region))
    return findings


def lambda_handler(event, context):
    # Fetching active regions and auditing API Gateway resources in parallel
    regions = get_enabled_regions()
    all_findings = []
    
    with ThreadPoolExecutor(max_workers=len(regions) or 1) as executor:
        for res in executor.map(run_apigw_scan_region, regions):
            all_findings.extend(res)

    return all_findings


if __name__ == "__main__":
    print(json.dumps(lambda_handler({}, None), indent=2))