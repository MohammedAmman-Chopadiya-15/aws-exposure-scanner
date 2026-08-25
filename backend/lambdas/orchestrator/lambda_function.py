import os
import json
import logging
from collections import defaultdict
from concurrent.futures import ThreadPoolExecutor
import boto3

logger = logging.getLogger(__name__)
logger.setLevel(logging.INFO)

lambda_client = boto3.client('lambda')

# Grab the secret key configured in environment variables
API_KEY = os.environ.get("SCANNER_API_KEY")

# List of all the auditor Lambda functions we want to trigger
AUDITOR_FUNCTIONS = [
    "exposure-scanner-auditor-s3",
    "exposure-scanner-auditor-ec2",
    "exposure-scanner-auditor-rds",
    "exposure-scanner-auditor-iam",
    "exposure-scanner-auditor-lambda",
    "exposure-scanner-auditor-apigateway",
    "exposure-scanner-auditor-cloudfront"
]

# Numeric ranking to easily find the worst severity for a resource
SEVERITY_WEIGHTS = {
    "ADVISORY": 0,
    "LOW": 1,
    "MEDIUM": 2,
    "HIGH": 3,
    "CRITICAL": 4
}

# Standard CORS headers
RESPONSE_HEADERS = {
    "Content-Type": "application/json",
    "Access-Control-Allow-Origin": "*",
    "Access-Control-Allow-Methods": "GET, OPTIONS",
    "Access-Control-Allow-Headers": "Content-Type, Authorization, x-api-token"
}


def consolidate_and_score(raw_findings):
    """
    Groups raw findings by resource name and calculates
    an aggregated risk score and the highest severity.
    """
    grouped = defaultdict(lambda: {
        "service": "UNKNOWN",
        "region": "global",
        "problems": []
    })

    # Grouping all findings under their respective resource name
    for finding in raw_findings:
        name = finding['resource_name']
        grouped[name]["service"] = finding.get('service', 'UNKNOWN')
        grouped[name]["region"] = finding.get('region', 'global')
        grouped[name]["problems"].append({
            "vulnerability_description": finding.get('vulnerability_description', ''),
            "severity": finding.get('severity_level', 'ADVISORY'),
            "risk_score": float(finding.get('risk_score', 0.0)),
            "remediation_suggestion": finding.get('remediation_suggestion', '')
        })

    consolidated = []
    for res_name, data in grouped.items():
        problems = data["problems"]
        severities = [p["severity"] for p in problems]
        active_scores = [p["risk_score"] for p in problems if p["risk_score"] > 0]

        # Picking the highest severity among all findings for this resource
        highest_severity = max(severities, key=lambda s: SEVERITY_WEIGHTS.get(s, 0)) if severities else "ADVISORY"

        # Calculating final risk score:
        # Highest individual score + 0.15 for every extra issue found
        if active_scores:
            base_score = max(active_scores)
            compounding_factor = (len(active_scores) - 1) * 0.15
            final_score = round(min(10.0, base_score + compounding_factor), 2)
        else:
            final_score = 0.0

        consolidated.append({
            "resource_name": res_name,
            "service": data["service"],
            "region": data["region"],
            "total_vulnerabilities_found": len(problems),
            "highest_severity_level": highest_severity,
            "final_risk_score": final_score,
            "individual_problems": problems
        })

    return consolidated


def invoke_auditor(function_name):

    try:
        response = lambda_client.invoke(
            FunctionName=function_name,
            InvocationType='RequestResponse'
        )
        payload = json.loads(response['Payload'].read().decode('utf-8'))
        return payload if isinstance(payload, list) else []
    except Exception as e:
        # Log the failure but don't crash the whole scan
        logger.error(f"Failed invoking {function_name}: {e}")
        return []


def lambda_handler(event, context):
    # Normalize headers to lowercase so we don't worry about casing differences
    headers = {k.lower(): v for k, v in (event.get("headers") or {}).items()}
    token = headers.get("x-api-token")

    # Simple auth check before doing any work
    if not API_KEY or token != API_KEY:
        return {
            "statusCode": 401,
            "headers": RESPONSE_HEADERS,
            "body": json.dumps({"error": "Unauthorized: Invalid or missing x-api-token header"})
        }

    # Running all auditor Lambdas in parallel to keep scan time fast
    raw_findings = []
    with ThreadPoolExecutor(max_workers=len(AUDITOR_FUNCTIONS)) as executor:
        for result in executor.map(invoke_auditor, AUDITOR_FUNCTIONS):
            raw_findings.extend(result)

    # Combine findings and score them
    findings = consolidate_and_score(raw_findings)

    return {
        "statusCode": 200,
        "headers": RESPONSE_HEADERS,
        "body": json.dumps({"findings": findings})
    }