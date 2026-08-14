import os
import json
import boto3
from concurrent.futures import ThreadPoolExecutor

lambda_client = boto3.client('lambda')

# Reads the secret token injected by Terraform environment variables
SECRET_TOKEN = os.environ.get("SCANNER_API_KEY")

AUDITOR_FUNCTIONS = [
    "exposure-scanner-auditor-s3",
    "exposure-scanner-auditor-ec2",
    "exposure-scanner-auditor-rds",
    "exposure-scanner-auditor-iam"
]

def consolidate_and_score(raw_findings):
    consolidated_resources = {}
    severity_order = {"ADVISORY": 0, "LOW": 1, "MEDIUM": 2, "HIGH": 3, "CRITICAL": 4}

    for finding in raw_findings:
        res_name = finding['resource_name']
        region = finding.get('region', 'global')
        
        if res_name not in consolidated_resources:
            consolidated_resources[res_name] = {
                "resource_name": res_name,
                "service": finding['service'],
                "region": region,
                "total_vulnerabilities_found": 0,
                "highest_severity_level": "ADVISORY",
                "final_risk_score": 0.0,
                "individual_problems": []
            }
            
        consolidated_resources[res_name]["individual_problems"].append({
            "vulnerability_description": finding['vulnerability_description'],
            "severity": finding['severity_level'],
            "risk_score": finding['risk_score'],
            "remediation_suggestion": finding['remediation_suggestion']
        })

    for res_name, data in consolidated_resources.items():
        problems = data["individual_problems"]
        data["total_vulnerabilities_found"] = len(problems)
        
        individual_scores = [p["risk_score"] for p in problems]
        individual_severities = [p["severity"] for p in problems]
        
        data["highest_severity_level"] = max(individual_severities, key=lambda s: severity_order.get(s, 0))
        active_scores = [s for s in individual_scores if s > 0.0]
        
        if active_scores:
            max_base_score = max(active_scores)
            active_count = len(active_scores)
            aggregated_score = max_base_score + ((active_count - 1) * 0.15)
            data["final_risk_score"] = round(min(10.0, aggregated_score), 2)
        else:
            data["final_risk_score"] = 0.0

    return list(consolidated_resources.values())

def invoke_auditor(function_name):
    try:
        response = lambda_client.invoke(
            FunctionName=function_name,
            InvocationType='RequestResponse'
        )
        payload = json.loads(response['Payload'].read().decode('utf-8'))
        return payload if isinstance(payload, list) else []
    except Exception as e:
        print(f"Failed invoking {function_name}: {e}")
        return []

def lambda_handler(event, context):
    headers = event.get("headers", {}) or {}
    
    # API Gateway lowercases incoming header names
    incoming_token = headers.get("x-api-token") or headers.get("X-Api-Token")

    # 1. SECURITY AUTHORIZATION CHECK
    if not SECRET_TOKEN or incoming_token != SECRET_TOKEN:
        return {
            "statusCode": 401,
            "headers": {
                "Content-Type": "application/json",
                "Access-Control-Allow-Origin": "*",
                "Access-Control-Allow-Methods": "GET, OPTIONS",
                "Access-Control-Allow-Headers": "Content-Type, Authorization, x-api-token"
            },
            "body": json.dumps({"error": "Unauthorized: Invalid or missing x-api-token header"})
        }

    # 2. PARALLEL EXECUTION ACROSS WORKER THREADS
    raw_findings = []
    with ThreadPoolExecutor(max_workers=len(AUDITOR_FUNCTIONS)) as executor:
        results = executor.map(invoke_auditor, AUDITOR_FUNCTIONS)
        for res in results:
            raw_findings.extend(res)

    consolidated = consolidate_and_score(raw_findings)

    return {
        "statusCode": 200,
        "headers": {
            "Content-Type": "application/json",
            "Access-Control-Allow-Origin": "*",
            "Access-Control-Allow-Methods": "GET, OPTIONS",
            "Access-Control-Allow-Headers": "Content-Type, Authorization, x-api-token"
        },
        "body": json.dumps({"findings": consolidated})
    }