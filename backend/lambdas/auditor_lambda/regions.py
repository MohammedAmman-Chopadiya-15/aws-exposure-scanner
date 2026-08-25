import logging
import boto3
from botocore.exceptions import ClientError

logger = logging.getLogger(__name__)
logger.setLevel(logging.INFO)


def get_enabled_regions():
    # Defining fallback regions in case regional discovery permissions are missing
    fallback_regions = ["eu-west-2", "us-east-1", "eu-west-1"]

    # Querying all active AWS regions enabled on the account
    try:
        ec2 = boto3.client('ec2', region_name='eu-west-2')
        response = ec2.describe_regions(AllRegions=False)
        regions = [r['RegionName'] for r in response.get('Regions', [])]
        logger.info(f"Discovered {len(regions)} active AWS regions: {regions}")
        return regions
    except ClientError as e:
        # Falling back to primary default regions when describe_regions fails
        logger.warning(f"Unable to query enabled regions ({e}), falling back to default list.")
        return fallback_regions
    except Exception as e:
        logger.warning(f"Unexpected error resolving regions ({e}), falling back to default list.")
        return fallback_regions


if __name__ == "__main__":
    print(get_enabled_regions())