# local_app/regions.py
import boto3
from botocore.exceptions import ClientError

def get_enabled_regions():
    """
    Fetches all enabled AWS regions for the active account using ec2.describe_regions.
    Falls back to primary regions if permissions are restricted.
    """
    fallback_regions = ["eu-west-2", "us-east-1", "eu-west-1"]
    try:
        ec2 = boto3.client('ec2', region_name='eu-west-2')
        response = ec2.describe_regions(AllRegions=False)
        regions = [r['RegionName'] for r in response.get('Regions', [])]
        print(f"[INFO] Discovered {len(regions)} active AWS regions: {regions}")
        return regions
    except ClientError as e:
        print(f"[WARNING] Unable to query enabled regions ({e}). Falling back to default list.")
        return fallback_regions
    except Exception as e:
        print(f"[WARNING] Unexpected error resolving regions ({e}). Falling back to default list.")
        return fallback_regions

if __name__ == "__main__":
    print(get_enabled_regions())