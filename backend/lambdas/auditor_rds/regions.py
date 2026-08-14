# local_app/regions.py
import boto3
from botocore.exceptions import ClientError

def get_enabled_regions():
    """
    Fetches all enabled AWS regions for the active account using ec2.describe_regions.
    Falls back to a standard default list if permissions are restricted.
    """
    try:
        ec2 = boto3.client('ec2', region_name='us-east-1')
        response = ec2.describe_regions(AllRegions=False)
        regions = [r['RegionName'] for r in response.get('Regions', [])]
        print(f"🌍 Discovered {len(regions)} active AWS regions: {regions}")
        return regions
    except ClientError as e:
        print(f"⚠️ Unable to query enabled regions ({e}). Falling back to primary region list.")
        return ["eu-west-2", "us-east-1", "us-west-2"]