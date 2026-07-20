#==========================================================================
#
# File : ec2_audit_checker.py
# Project : AWS-secure-configuration-auditor
# Description : Class definitions for EC2 Checks
#
#==========================================================================
# Import base detector
from .baseChecker import BaseChecker
from collections.abc import Callable
from ..AWSStandardizedDataStructures import EC2Inventory
from ..AWSStandardizedDataStructures import AuditFinding

#------------------------
# Class Definition : EC2AuditEngine()
#------------------------
class EC2AuditEngine(BaseChecker):
    # Initial Class Definition to include class functions
    def __init__(self):
        self.ec2_audit_checks: list[Callable[[EC2Inventory], list]] = [
            self.open_ssh_check,
            self.open_rdp_check,
            self.open_database_check,
            self.imdsv2_check,
            self.ebs_encryption_check,
            self.public_ip_check
        ]

    #--------------------------
    # Main driver function
    #--------------------------
    def audit(self, inventory: EC2Inventory):
        # Array to hold findings
        audit_findings = []

        # Work through the checks
        for audit_check in self.ec2_audit_checks:
            audit_findings.extend(audit_check(inventory))

        return audit_findings

    #--------------------------
    # Helper function
    #--------------------------
    def open_ssh_check(self, inventory: EC2Inventory) -> list[AuditFinding]:
        return []

    def open_rdp_check(self, inventory: EC2Inventory) -> list[AuditFinding]:
        return []

    def open_database_check(self, inventory: EC2Inventory) -> list[AuditFinding]:
        return []

    def imdsv2_check(self, inventory: EC2Inventory) -> list[AuditFinding]:
        return []

    def ebs_encryption_check(self, inventory: EC2Inventory) -> list[AuditFinding]:
        return []

    def public_ip_check(self, inventory: EC2Inventory) -> list[AuditFinding]:
        return []

