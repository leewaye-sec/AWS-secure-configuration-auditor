#==========================================================================
#
# File : s3_audit_collector.py
# Project : AWS-secure-configuration-auditor
# Description : Class definitions for S3 Collectors
#
#==========================================================================
# Import base detector
import boto3
from botocore.exceptions import ClientError
from .baseCollector import BaseCollector
from ..AWSStandardizedDataStructures import S3Inventory

#------------------------
# Class Definition : S3Collector
#------------------------
class S3Collector(BaseCollector):
    # Define the collection checks
    def collect(self, session):
        s3_inventory = S3Inventory()

        # Gather S3 client / resources
        s3_client = session.client('s3')
        s3_resources = session.resource('s3')

        # Begin collection
        s3_inventory.buckets = self.collect_buckets(s3_resources)
        s3_inventory.bucket_policies = self.collect_bucket_policies(s3_resources, s3_client)
        s3_inventory.acls = self.collect_acls(s3_resources, s3_client)
        s3_inventory.public_access_block = self.collect_public_access_block(s3_resources, s3_client)
        s3_inventory.encryption = self.collect_encryption(s3_resources, s3_client)
        s3_inventory.versioning = self.collect_versioning(s3_resources)
        s3_inventory.logging = self.collect_logging(s3_resources, s3_client)

        return s3_inventory

    # Helper Functions
    def collect_buckets(self, resource):
        return resource.buckets.all()

    # Return list of dictionaries
    def collect_bucket_policies(self, resource, client):
        # Gather buckets
        buckets = resource.buckets.all()
        collected_policies = []
        # Loop through and grab bucket name and policies
        for bucket in buckets:
            name = bucket.name
            try:
                # Gather policies associated with bucket
                policy_response = client.get_bucket_policy(Bucket=name)
                # Add to policy dict
                bucket_policy = {
                    "bucket_name": name,
                    "bucket_policy": policy_response
                }
                collected_policies.append(bucket_policy)
            except ClientError as e:
                # Add empty policy dict
                bucket_policy = {
                    "bucket_name": name,
                    "bucket_policy": None
                }
                collected_policies.append(bucket_policy)

        return collected_policies

    def collect_acls(self, resource, client):
        # Gather buckets
        buckets = resource.buckets.all()
        collected_acls = []
        # Loop through and grab bucket name and acl policies
        #   If no policy associated, save none
        for bucket in buckets:
            name = bucket.name
            # Grab acl policy
            try:
                bucket_acl = client.get_bucket_acl(Bucket=name)
                acl = {
                    "bucket_name": name,
                    "bucket_acl": bucket_acl
                }
                collected_acls.append(acl)
            except ClientError as e:
                acl = {
                    "bucket_name": name,
                    "bucket_acl": None
                }
                collected_acls.append(acl)

        return collected_acls

    def collect_public_access_block(self, resource, client):
        # Gather buckets
        buckets = resource.buckets.all()

        collected_pabs = []
        # Iterate through the buckets and use client to get public access block
        for bucket in buckets:
            name = bucket.name

            try:
                bucket_pab = client.get_public_access_block(Bucket=name)
                pab = {
                    "bucket_name": name,
                    "bucket_pab": bucket_pab
                }
                collected_pabs.append(pab)
            except ClientError as e:
                pab = {
                    "bucket_name" : name,
                    "bucket_pab" : None
                }
                collected_pabs.append(pab)

        return collected_pabs

    def collect_encryption(self, resource, client):
        # Gather buckets
        buckets = resource.buckets.all()

        collected_encryption_blocks = []
        for bucket in buckets:
            name = bucket.name

            try:
                enc_block = client.get_bucket_encryption(Bucket=name)
                encryption_block = {
                    "name": name,
                    "bucket_encryption": enc_block
                }
                collected_encryption_blocks.append(encryption_block)

            except ClientError as e:
                encryption_block = {
                    "name": name,
                    "bucket_encryption": None
                }
                collected_encryption_blocks.append(encryption_block)

        return collected_encryption_blocks


    def collect_versioning(self, resource):
        # Gather buckets
        buckets = resource.buckets.all()

        collected_versioning = []
        for bucket in buckets:
            name = bucket.name
            version = resource.BucketVersioning(name)

            if version:
                bucket_version = {
                    "name": name,
                    "bucket_versioning": version
                }
                collected_versioning.append(bucket_version)
            else:
                bucket_version = {
                    "name": name,
                    "bucket_versioning": None
                }
                collected_versioning.append(bucket_version)

        return collected_versioning

    def collect_logging(self, resource, client):
        # Gather buckets
        buckets = resource.buckets.all()

        collected_versioning = []
        for bucket in buckets:
            name = bucket.name
            logging = client.get_bucket_logging(Bucket=name)

            if logging:
                bucket_logging = {
                    "name": name,
                    "bucket_logging": logging
                }
                collected_versioning.append(bucket_logging)
            else:
                bucket_logging = {
                    "name": name,
                    "bucket_logging": None
                }
                collected_versioning.append(bucket_logging)

        return collected_versioning

