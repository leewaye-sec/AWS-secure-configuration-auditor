#==========================================================================
#
# File : s3_audit_checker.py
# Project : AWS-secure-configuration-auditor
# Description : Class definitions for S3 Checks
#
#==========================================================================
# Import base detector
from aws_audit_checkers.baseChecker import BaseChecker
from collections.abc import Callable
from AWSStandardizedDataStructures import AuditFinding
from AWSStandardizedDataStructures import S3Inventory

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
        public_bucket_findings = []
        #------------
        # Check Public Access Block
        #------------
        for pab in inventory.public_access_block:
            bucket_name = pab['bucket_name']
            # Make sure it's there
            #   If not -- report
            #   If yes -- further checks
            if pab['bucket_pab']:
                pab_config = pab['bucket_pab']['PublicAccessBlockConfiguration']

                if not pab_config['BlockPublicAcls']:
                    public_bucket_findings.append(AuditFinding(
                        severity_level="HIGH",
                        service="S3",
                        resource_type="Bucket",
                        resource_name=f"{bucket_name}",
                        finding_name="PUBLIC_BUCKET",
                        finding_description=f"Bucket allows public access - Public Access Block [ BlockPublicAcls ]",
                        recommendation="Disable public access or confirm setting"
                    ))
                if not pab_config['BlockPublicPolicy']:
                    public_bucket_findings.append(AuditFinding(
                        severity_level="HIGH",
                        service="S3",
                        resource_type="Bucket",
                        resource_name=f"{bucket_name}",
                        finding_name="PUBLIC_BUCKET",
                        finding_description=f"Bucket allows public access - Public Access Block [ BlockPublicAcls ]",
                        recommendation="Disable public access or confirm setting"
                    ))
            else:
                public_bucket_findings.append(AuditFinding(
                    severity_level="HIGH",
                    service="S3",
                    resource_type="Bucket",
                    resource_name=f"{bucket_name}",
                    finding_name="PUBLIC_ACCESS_BLOCK_DISABLED",
                    finding_description=f"Public Access Block is not enabled",
                    recommendation="Enable Public Access Block settings"
                ))

        #------------
        # Check Bucket Policy Status
        #------------
        for status in inventory.bucket_policy_statuses:
            bucket_status_name = status['bucket_name']

            if status['bucket_policy_status']:
                if status['bucket_policy_status']['PolicyStatus']['IsPublic']:
                    public_bucket_findings.append(AuditFinding(
                        severity_level="HIGH",
                        service="S3",
                        resource_type="Bucket",
                        resource_name=f"{bucket_status_name}",
                        finding_name="PUBLIC_BUCKET",
                        finding_description=f"Bucket allows public access - Bucket Policy Status [ PolicyStatus = IsPublic ]",
                        recommendation="Disable public access or confirm setting"
                    ))

        #------------
        # Check ACL Status
        #------------
        public_groups = ["http://acs.amazonaws.com/groups/global/AllUsers", "http://amazonaws.com"]
        for bucket_acl in inventory.acls:
            acl_bucket_name = bucket_acl['bucket_name']

            # Check for public group uri's
            #   Isolate the buckets' acl
            for acl_grant in bucket_acl['bucket_acl'].get('Grants', []):
                acl_granted = acl_grant.get('Grantee', {})
                # Check ACL configuration against public groups
                if acl_granted.get('Type') == 'Group' and acl_granted.get('URI') in public_groups:
                    public_bucket_findings.append(AuditFinding(
                        severity_level="HIGH",
                        service="S3",
                        resource_type="Bucket",
                        resource_name=f"{acl_bucket_name}",
                        finding_name="PUBLIC_BUCKET",
                        finding_description=f"Bucket allows public access - Bucket ACL",
                        recommendation="Disable public access or confirm setting"
                    ))

        return public_bucket_findings

    def bucket_encryption_check(self, inventory: S3Inventory) -> list[AuditFinding]:
        encryption_findings = []
        # Iterate through buckets and review encryption configurations
        for bucket_enc_info in inventory.encryption:
            enc_bucket_name = bucket_enc_info['bucket_name']

            # If now encryption block / configuration, report finding
            if bucket_enc_info['bucket_encryption']['ServerSideEncryptionConfiguration']['Rules']:
                encryption_findings.append(AuditFinding(
                    severity_level="HIGH",
                    service="S3",
                    resource_type="Bucket",
                    resource_name=f"{enc_bucket_name}",
                    finding_name="ENCRYPTION_DISABLED",
                    finding_description=f"Bucket encryption is not configured and/or enabled",
                    recommendation="Enable server-side encryption"
                ))

        return encryption_findings

    def bucket_versioning_check(self, inventory: S3Inventory) -> list[AuditFinding]:
        versioning_findings = []

        # Iterate through the buckets and their versioning information
        #   Report finding if versioning is not enabled
        for bucket_ver in inventory.versioning:
            bucket_ver_name = bucket_ver['bucket_name']
            if bucket_ver['bucket_versioning']:
                ver_status = bucket_ver['bucket_versioning'].get('Status')
                if ver_status != 'Enabled':
                    versioning_findings.append(AuditFinding(
                        severity_level="MEDIUM",
                        service="S3",
                        resource_type="Bucket",
                        resource_name=f"{bucket_ver_name}",
                        finding_name="VERSIONING_DISABLED",
                        finding_description=f"Bucket versioning is not enabled",
                        recommendation="Enable bucket versioning"
                    ))
            else:
                versioning_findings.append(AuditFinding(
                    severity_level="MEDIUM",
                    service="S3",
                    resource_type="Bucket",
                    resource_name=f"{bucket_ver_name}",
                    finding_name="VERSIONING_DISABLED",
                    finding_description=f"Bucket versioning is not enabled",
                    recommendation="Enable bucket versioning"
                ))

        return versioning_findings

    def bucket_logging_check(self, inventory: S3Inventory) -> list[AuditFinding]:
        logging_findings = []
        # Work through bucket / logging info
        for bucket_logging in inventory.logging:
            bucket_logging_name = bucket_logging['bucket_name']
            # Make sure logging information was present
            #   If not there, then also report
            if bucket_logging['bucket_logging']:
                if 'LoggingEnabled' not in bucket_logging['bucket_logging']:
                    logging_findings.append(AuditFinding(
                        severity_level="MEDIUM",
                        service="S3",
                        resource_type="Bucket",
                        resource_name=f"{bucket_logging_name}",
                        finding_name="LOGGING_DISABLED",
                        finding_description=f"Bucket logging is not enabled",
                        recommendation="Enable bucket logging"
                    ))
            else:
                logging_findings.append(AuditFinding(
                    severity_level="MEDIUM",
                    service="S3",
                    resource_type="Bucket",
                    resource_name=f"{bucket_logging_name}",
                    finding_name="LOGGING_DISABLED",
                    finding_description=f"Bucket logging is not enabled",
                    recommendation="Enable bucket logging"
                ))

        return logging_findings

    def bucket_ownership_check(self, inventory: S3Inventory) -> list[AuditFinding]:
        ownership_findings = []

        # Iterate bucket info and check for ownership
        for bucket_owner_info in inventory.ownership:
            bucket_owner_name = bucket_owner_info['bucket_name']
            # If ownership not found or not configured
            if not bucket_owner_info['bucket_ownership'] or not bucket_owner_info['bucket_ownership'].get('OwnershipControls',{}).get('Rules',[]):
                ownership_findings.append(AuditFinding(
                    severity_level="LOW",
                    service="S3",
                    resource_type="Bucket",
                    resource_name=f"{bucket_owner_name}",
                    finding_name="OWNERSHIP_CONTROL_MISSING",
                    finding_description=f"Bucket Ownership enforcement is not configured",
                    recommendation="Enable bucket ownership enforcement controls"
                ))


        return ownership_findings

