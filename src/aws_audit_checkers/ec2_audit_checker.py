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
            self.public_ip_check,
            self.associated_iam_role_check
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

            # Isolate variables from the inventory
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

                    # Check if RDP is being used
                    if ip_protocol == '-1' or (ip_protocol == 'tcp' and ingress_port <= 3389 and egress_port > 3389):
                        # Determine if unrestricted
                        for ip_range in permission.get('IpRanges', []):
                            # If RDP is unrestricted, report finding
                            if ip_range.get('CidrIp') == '0.0.0.0/0':
                                rdp_findings.append(AuditFinding(
                                    severity_level="HIGH",
                                    service="EC2",
                                    resource_type="Security Group",
                                    resource_name=f"{group_name}",
                                    finding_name="PUBLICLY_ACCESSIBLE_RDP",
                                    finding_description=f"Inbound RDP allowed from unrestricted sources",
                                    recommendation="Restrict RDP access to trusted IP ranges"
                                ))

        return rdp_findings

    def open_database_check(self, inventory: EC2Inventory) -> list[AuditFinding]:
        open_db_findings = []
        # Common db ports
        db_ports = [3306, 6432, 27017, 1433]

        for db_info in inventory.database_services:
            db_resource = db_info['db_resource']
            db_id = db_info['db_identifier']
            db_instance = db_info['db_instance']
            db_instance_details = db_info['db_instance_details']

            if db_resource == "RDS":
                # Check resource for publicly accessible flag
                if db_instance.get('PubliclyAccessible'):
                    open_db_findings.append(AuditFinding(
                        severity_level="HIGH",
                        service="EC2",
                        resource_type="RDS",
                        resource_name=f"{db_id}",
                        finding_name="PUBLICLY_ACCESSIBLE_DATABASE",
                        finding_description=f"Database access [ RDS ] allowed from unrestricted sources",
                        recommendation="Restrict Database access to trusted IP ranges"
                    ))
            elif db_resource == "EC2":
                for rule in db_instance_details.get('SecurityGroupRules', []):
                    if not rule.get('IsEgress', False):
                        rule_cidr = rule.get('CidrIpv4')
                        ingress_port = rule.get('FromPort')
                        egress_port = rule.get('ToPort')

                        # If rule allows open access, check if db ports
                        if rule_cidr == '0.0.0.0/0' and ingress_port is not None:
                            for port in db_ports:
                                if ingress_port <= port <= egress_port:
                                    open_db_findings.append(AuditFinding(
                                        severity_level="HIGH",
                                        service="EC2",
                                        resource_type="SECURITY_GROUP",
                                        resource_name=f"{db_id}",
                                        finding_name="PUBLICLY_ACCESSIBLE_DATABASE",
                                        finding_description=f"Database access [ EC2 ] allowed from unrestricted sources",
                                        recommendation="Restrict Database access to trusted IP ranges"
                                    ))

        return open_db_findings

    def imdsv2_check(self, inventory: EC2Inventory) -> list[AuditFinding]:
        imdsv2_findings = []

        # Iterate through metadata information
        for metadata in inventory.metadata_options:

            instance_name = metadata.get("instance_name")
            instance_id = metadata.get("instance_id")
            metadata_options = metadata.get('instance_metadata')

            # Gather metadata for imdsv2 information
            http_tokens = metadata_options.get('HttpTokens')
            http_endpoint = metadata_options.get('HttpEndpoint')

            if http_tokens == 'optional':
                imdsv2_findings.append(AuditFinding(
                    severity_level="MEDIUM",
                    service="EC2",
                    resource_type="INSTANCE",
                    resource_name=f"{instance_name}",
                    finding_name="IMDSV2_DISABLED",
                    finding_description=f"No Instance Metadata Service Version 2 required by instance",
                    recommendation="Require IMDSv2 for instances"
                ))

            if http_endpoint == 'disabled':
                imdsv2_findings.append(AuditFinding(
                    severity_level="MEDIUM",
                    service="EC2",
                    resource_type="INSTANCE",
                    resource_name=f"{instance_name}",
                    finding_name="METADATA_ENDPOINT_DISABLED",
                    finding_description=f"No Metadata Endpoint enabled for instance",
                    recommendation="Require endpoint for instances"
                ))

        return imdsv2_findings

    def ebs_encryption_check(self, inventory: EC2Inventory) -> list[AuditFinding]:
        ebs_encryption_findings = []

        # Work through inventory of ebs volumes and check encryption
        for ebs_inventory in inventory.ebs_volumes:
            for volume in ebs_inventory['volumes']:
                volume_id = volume['VolumeId']
                volume_encrypted = volume['Encrypted']

                if not volume_encrypted:
                    ebs_encryption_findings.append(AuditFinding(
                        severity_level="HIGH",
                        service="EC2",
                        resource_type="EBS_VOLUME",
                        resource_name=f"{ebs_inventory['instance_name']} - {volume_id}",
                        finding_name="UNENCRYPTED_EBS_VOLUME",
                        finding_description=f"EBS volume is not encrypted",
                        recommendation="Enable encryption on EBS volumes"
                    ))

        return ebs_encryption_findings

    def public_ip_check(self, inventory: EC2Inventory) -> list[AuditFinding]:
        public_ip_findings = []

        for instance_info in inventory.instances:
            instance = instance_info['instances']
            public_ip_addr = instance.get('PublicIpAddress', 'N/A')

            if public_ip_addr != 'N/A':
                public_ip_findings.append(AuditFinding(
                    severity_level="HIGH",
                    service="EC2",
                    resource_type="EC2_INSTANCE",
                    resource_name=f"{instance['instance_name']}",
                    finding_name="PUBLIC_MANAGEMENT_INTERFACE",
                    finding_description=f"Instance has public IP and exposes management services",
                    recommendation="Restrict access or remove public IP"
                ))

        return public_ip_findings

    def associated_iam_role_check(self, inventory: EC2Inventory) -> list[AuditFinding]:
        iam_role_findings =[]

        # Iterate through instances and check for
        for instance_dict in inventory.instances:
            name = instance_dict['instance_name']
            instance = instance_dict['instances']

            # Get Profile if present
            if not instance.get('IamInstanceProfile'):
                iam_role_findings.append(AuditFinding(
                    severity_level="LOW",
                    service="EC2",
                    resource_type="EC2_INSTANCE",
                    resource_name=f"{name}",
                    finding_name="MISSING_IAM_ROLE",
                    finding_description=f"Instance missing IAM role",
                    recommendation="Attach IAM role of least-privilege if AWS API access required"
                ))

        return iam_role_findings
