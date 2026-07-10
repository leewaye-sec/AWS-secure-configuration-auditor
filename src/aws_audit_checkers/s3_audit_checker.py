#==========================================================================
#
# File : s3_audit_checker.py
# Project : AWS-secure-configuration-auditor
# Description : Class definitions for S3 Checks
#
#==========================================================================
# Import base detector
from .baseChecker import BaseChecker
from ..AWSStandardizedDataStructures import AuditFinding
from ..AWSStandardizedDataStructures import S3Inventory

#------------------------
# Class Definition : PublicBucketCheck
#------------------------
class PublicBucketCheck(BaseChecker):
    def process(self, inventory: S3Inventory):
        pass
    # Notes:
    #   try:
    #       pab_configuration = bucket_pab.get('PublicAccessBlockConfiguration')
    #   except ClientError as e:
    #       if e.response["Error"]["Code"] == "NoSuchPublicAccessBlockConfiguration":
    #           Unconfigured / disabled

#------------------------
# Class Definition : BucketEncryptionCheck
#------------------------
class BucketEncryptionCheck(BaseChecker):
    def process(self, inventory: S3Inventory):
        pass
    # Notes:
    #   Encryption rule and defaults:
    #   try:
    #       encryption_rule = bucket_encryption["ServerSideEncryptionConfiguration"]["Rules"][0]
    #       encryption_defaults = encryption_rule.get("ApplyServerSideEncryptionByDefault", {})
    #   except ClientError as e:
    #       if e.response["Error"]["Code"] == "ServerSideEncryptionConfigurationNotFoundError":
    #           # Encryption is disabled/default

#------------------------
# Class Definition : BucketVersioningCheck
#------------------------
class BucketVersioningCheck(BaseChecker):
    def process(self, inventory: S3Inventory):
        pass
    # Notes: bucket.Versioning().status

#------------------------
# Class Definition : BucketLoggingCheck
#------------------------
class BucketLoggingCheck(BaseChecker):
    def process(self, inventory: S3Inventory):
        pass
    # Notes:
    #   Checks:
    #       - Logging configuration removed or missing  (logging == None)
    #       - Logging disabled
    #           try:
    #               bucket_logging.load()
    #               if bucket_logging.logging_enabled:
    #               ...

#------------------------
# Class Definition : BucketACLCheck
#------------------------
class BucketACLCheck(BaseChecker):
    def process(self, inventory: S3Inventory):
        pass

#------------------------
# Class Definition : BucketOwnershipCheck
#------------------------
class BucketOwnershipCheck(BaseChecker):
    def process(self, inventory: S3Inventory):
        pass

