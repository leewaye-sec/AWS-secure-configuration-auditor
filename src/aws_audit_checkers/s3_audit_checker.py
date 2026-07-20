#==========================================================================
#
# File : s3_audit_checker.py
# Project : AWS-secure-configuration-auditor
# Description : Class definitions for S3 Checks
#
#==========================================================================
# Import base detector
from .baseChecker import BaseChecker
from collections.abc import Callable
from ..AWSStandardizedDataStructures import AuditFinding
from ..AWSStandardizedDataStructures import S3Inventory

#------------------------
# Class Definition : IAMAuditEngine()
#------------------------
class S3AuditEngine(BaseChecker):
    # Initial Class Definition to include class functions
    def __init__(self):
        self.s3_audit_checks: list[Callable[[S3Inventory], list]] = [
            self.public_bucket_check,
            self.bucket_encryption_check,
            self.bucket_versioning_check,
            self.bucket_logging_check,
            self.bucket_acl_check,
            self.bucket_ownership_check
        ]

    #--------------------------
    # Main driver function
    #--------------------------
    def audit(self, inventory: S3Inventory):
        # Array to hold findings
        audit_findings = []

        # Work through the checks
        for audit_check in self.s3_audit_checks:
            audit_findings.extend(audit_check(inventory))

        return audit_findings

    #------------------------
    # Helper functions
    #------------------------
    def public_bucket_check(self, inventory: S3Inventory) -> list[AuditFinding]:
        # Notes:
        #   try:
        #       pab_configuration = bucket_pab.get('PublicAccessBlockConfiguration')
        #   except ClientError as e:
        #       if e.response["Error"]["Code"] == "NoSuchPublicAccessBlockConfiguration":
        #           Unconfigured / disabled
        return []

    def bucket_encryption_check(self, inventory: S3Inventory) -> list[AuditFinding]:
        # Notes:
        #   Encryption rule and defaults:
        #   try:
        #       encryption_rule = bucket_encryption["ServerSideEncryptionConfiguration"]["Rules"][0]
        #       encryption_defaults = encryption_rule.get("ApplyServerSideEncryptionByDefault", {})
        #   except ClientError as e:
        #       if e.response["Error"]["Code"] == "ServerSideEncryptionConfigurationNotFoundError":
        #           # Encryption is disabled/default
        return []

    def bucket_versioning_check(self, inventory: S3Inventory) -> list[AuditFinding]:
        # Notes: bucket.Versioning().status
        return []

    def bucket_logging_check(self, inventory: S3Inventory) -> list[AuditFinding]:
        # Notes:
        #   Checks:
        #       - Logging configuration removed or missing  (logging == None)
        #       - Logging disabled
        #           try:
        #               bucket_logging.load()
        #               if bucket_logging.logging_enabled:
        #               ...
        return []

    def bucket_acl_check(self, inventory: S3Inventory) -> list[AuditFinding]:
        return []

    def bucket_ownership_check(self, inventory: S3Inventory) -> list[AuditFinding]:
        return []

