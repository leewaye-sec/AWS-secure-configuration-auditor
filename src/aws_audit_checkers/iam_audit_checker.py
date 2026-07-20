#==========================================================================
#
# File : iam_audit_checker.py
# Project : AWS-secure-configuration-auditor
# Description : Class definitions for IAM Checks
#
#==========================================================================
# Import base detector
from baseChecker import BaseChecker
from collections.abc import Callable
from ..AWSStandardizedDataStructures import IAMInventory
from ..AWSStandardizedDataStructures import AuditFinding

#------------------------
# Class Definition : IAMAuditEngine()
#------------------------
class IAMAuditEngine(BaseChecker):
    # Initial Class Definition to include class functions
    def __init__(self):
        self.iam_audit_checks: list[Callable[[IAMInventory], list]] = [
            self.adminstrator_access_check,
            self.mfa_enabled_check,
            self.old_access_key_check,
            self.inactive_access_key_check,
            self.wild_card_policy_check,
            self.root_access_key_check,
            self.console_access_check,
            self.unused_user_check
        ]

    #--------------------------
    # Main driver function
    #--------------------------
    def audit(self, inventory: IAMInventory):
        # Array to hold findings
        audit_findings = []

        # Work through the checks
        for audit_check in self.iam_audit_checks:
            audit_findings.extend(audit_check(inventory))

        return audit_findings

    #--------------------------
    # Helper functions
    #--------------------------
    def adminstrator_access_check(self, inventory: IAMInventory) -> list[AuditFinding]:
            return[]

    def mfa_enabled_check(self, inventory: IAMInventory) -> list[AuditFinding]:
        return[]

    def old_access_key_check(self, inventory: IAMInventory) -> list[AuditFinding]:
        return[]

    def inactive_access_key_check(self, inventory: IAMInventory) -> list[AuditFinding]:
        return[]

    def wild_card_policy_check(self, inventory: IAMInventory) -> list[AuditFinding]:
        return[]

    def root_access_key_check(self, inventory: IAMInventory) -> list[AuditFinding]:
        return[]

    def console_access_check(self, inventory: IAMInventory) -> list[AuditFinding]:
        return[]

    def unused_user_check(self, inventory: IAMInventory) -> list[AuditFinding]:
        return[]

