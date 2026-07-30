#==========================================================================
#
# File : awsAuditSession.py
# Project : AWS-secure-configuration-auditor
# Description : Handles the AWS Client / Resource / etc sessions
#
#==========================================================================
import boto3

class AWSAuditSession:
    def __init__(self, profile):

        self.audit_session = boto3.Session(profile_name=profile)

        self.iam_client = self.audit_session.client("iam")
        self.ec2_client = self.audit_session.client("ec2")
        self.s3_client = self.audit_session.client("s3")
        self.s3_resource = self.audit_session.resource("s3")

        # Gather active regions
        self.regions = self.gather_active_regions(self.ec2_client)

    #---------------------
    # Helper Function
    #---------------------
    def gather_active_regions(self, ec2_client):
        active_regions = []

        # Gather all available regions
        all_regions = [region['RegionName'] for region in ec2_client.describe_regions()['Regions']]

        # Iterate through regions and gather regions with resources
        for ret_region in all_regions:
            region_ec2_client = boto3.client('resourcegroupstaggingapi', region_name=ret_region)
            reg_resources = region_ec2_client.get_resources(ResourcesPerPage=1)

            # If there are resources in the region, it is considered an active region
            if reg_resources['ResourceTagMappingList']:
                active_regions.append(ret_region)

        return active_regions
