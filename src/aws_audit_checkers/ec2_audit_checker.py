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
        ssh_findings = []

        # Iterate through security group dictionaries
        for sec_group in inventory.security_group_details:
            group_id = sec_group['sec_group_id']
            group_name = sec_group['sec_group_name']

            sg_details = sec_group['sec_group_details']

            # Permission Checks: exposed port 22, public access IPv4, IPv6 public access
            #   If port 22 is exposed, further checks
            for details in sg_details['SecurityGroups']:
                for permission in details.get('IpPermissions', []):
                    if (permission.get('IpProtocol') == 'tcp' and permission.get('FromPort', 0) <= 22 and permission.get('ToPort', 0) >= 22):
                        # Check ipv4
                        for ipv4_range in permission.get('IpRanges', []):
                            if ipv4_range.get('CidrIp') == '0.0.0.0/0':
                                ssh_findings.append(AuditFinding(
                                    severity_level="HIGH",
                                    service="EC2",
                                    resource_type="Security Group",
                                    resource_name=f"{group_name}",
                                    finding_name="PUBLICLY_ACCESSIBLE_SSH",
                                    finding_description=f"Inbound SSH allowed from the internet [ IPv4 ]",
                                    recommendation="Restrict SSH access to trusted IP ranges"
                                ))

                        # Check ipv6
                        for ipv6_range in permission.get('Ipv6Ranges', []):
                            if ipv6_range.get('CidrIpv6') == '::/0':
                                ssh_findings.append(AuditFinding(
                                    severity_level="HIGH",
                                    service="EC2",
                                    resource_type="Security Group",
                                    resource_name=f"{group_name}",
                                    finding_name="PUBLICLY_ACCESSIBLE_SSH",
                                    finding_description=f"Inbound SSH allowed from the internet [ IPv6 ]",
                                    recommendation="Restrict SSH access to trusted IP ranges"
                                ))

            return ssh_findings

    def open_rdp_check(self, inventory: EC2Inventory) -> list[AuditFinding]:
        rdp_findings = []

        # Iterate through security group dictionaries
        for sec_group in inventory.security_group_details:
            group_name = sec_group['sec_group_name']
            sg_details = sec_group['sec_group_details']

            for details in sg_details['SecurityGroups']:
                for permission in details.get('IpPermissions', []):
                    ingress_port = permission.get('FromPort', 0)
                    egress_port = permission.get('ToPort', 0)
                    ip_protocol = permission.get('IpProtocol', '')

                    #if ip_protocol == '-1'

        return rdp_findings

    def open_database_check(self, inventory: EC2Inventory) -> list[AuditFinding]:
        return []

    def imdsv2_check(self, inventory: EC2Inventory) -> list[AuditFinding]:
        return []

    def ebs_encryption_check(self, inventory: EC2Inventory) -> list[AuditFinding]:
        return []

    def public_ip_check(self, inventory: EC2Inventory) -> list[AuditFinding]:
        return []

