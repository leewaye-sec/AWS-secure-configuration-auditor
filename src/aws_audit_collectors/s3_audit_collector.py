#==========================================================================
#
# File : s3_audit_collector.py
# Project : AWS-secure-configuration-auditor
# Description : Class definitions for S3 Collectors
#
#==========================================================================
# Import base detector
from .baseCollector import BaseCollector
from ..AWSStandardizedDataStructures import S3Inventory

#------------------------
# Class Definition : S3Collector
#------------------------
class S3Collector(BaseCollector):
    # Define the collection checks
    def collect(self):
        s3_inventory = S3Inventory()

        # Begin collection
        s3_inventory.buckets = self.collect_buckets()
        s3_inventory.bucket_policies = self.collect_bucket_policies()
        s3_inventory.acls = self.collect_acls()
        s3_inventory.public_access_block = self.collect_public_access_block()
        s3_inventory.encryption = self.collect_encryption()
        s3_inventory.versioning = self.collect_versioning()
        s3_inventory.logging = self.collect_logging()

        return s3_inventory

    # Helper Functions
    def collect_buckets(self):
        pass

    def collect_bucket_policies(self):
        pass

    def collect_acls(self):
        pass

    def collect_public_access_block(self):
        pass

    def collect_encryption(self):
        pass

    def collect_versioning(self):
        pass

    def collect_logging(self):
        pass

