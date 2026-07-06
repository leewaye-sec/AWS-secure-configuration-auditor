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

#------------------------
# Class Definition : PublicBucketCheck
#------------------------
class PublicBucketCheck(BaseChecker):
    def process(self, inventory):
        pass

#------------------------
# Class Definition : BucketEncryptionCheck
#------------------------
class BucketEncryptionCheck(BaseChecker):
    def process(self, inventory):
        pass

#------------------------
# Class Definition : BucketVersioningCheck
#------------------------
class BucketVersioningCheck(BaseChecker):
    def process(self, inventory):
        pass

#------------------------
# Class Definition : BucketLoggingCheck
#------------------------
class BucketLoggingCheck(BaseChecker):
    def process(self, inventory):
        pass

#------------------------
# Class Definition : BucketACLCheck
#------------------------
class BucketACLCheck(BaseChecker):
    def process(self, inventory):
        pass

#------------------------
# Class Definition : BucketOwnershipCheck
#------------------------
class BucketOwnershipCheck(BaseChecker):
    def process(self, inventory):
        pass

