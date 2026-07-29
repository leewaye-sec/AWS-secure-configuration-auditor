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

        self.regions = [region['RegionName'] for region in self.ec2_client.describe_regions()['Regions']]


