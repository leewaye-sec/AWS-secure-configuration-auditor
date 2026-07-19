#==========================================================================
#
# File : ec2_audit_collector.py
# Project : AWS-secure-configuration-auditor
# Description : Class definitions for EC2 Collectors
#
#==========================================================================
# Import base detector
from .baseCollector import BaseCollector
from ..AWSStandardizedDataStructures import EC2Inventory
from ..awsAuditSession import AWSAuditSession

#------------------------
# Class Definition : EC2Collector
#------------------------
class EC2Collector(BaseCollector):
    # Define the collection checks
    def collect(self, session: AWSAuditSession):

        # Define inventory
        ec2_inventory = EC2Inventory()

        # Begin collection
        ec2_inventory.instances = self.collect_instances(session.ec2_client)
        ec2_inventory.security_groups = self.collect_security_groups(session.ec2_client)
        ec2_inventory.network_interfaces = self.collect_network_interfaces(session.ec2_client)
        ec2_inventory.ebs_volumes = self.collect_ebs_volumes(session.ec2_client)
        #ec2_inventory.metadata_options = self.collect_metadata_options(session.ec2_client)
        ec2_inventory.key_pairs = self.collect_key_pairs(session.ec2_client)

        return ec2_inventory

    #-------------------------
    # Helper functions
    #-------------------------
    def collect_instances(self, ec2_client):
        # Gather and return instances
        ec2_instances = ec2_client.describe_instances()
        return ec2_instances

    def collect_security_groups(self, ec2_client):
        # Gather and return security groups
        security_groups = ec2_client.describe_security_groups()
        return security_groups

    def collect_network_interfaces(self, ec2_client):
        # Gather and return security groups
        net_int = ec2_client.describe_network_interfaces()
        return net_int

    def collect_ebs_volumes(self, ec2_client):
        # Gather and return ebs volumes
        ebs_vols = ec2_client.describe_volumes()
        return ebs_vols

    #def collect_metadata_options(self, ec2_client):
    #    # Gather and return metadata
    #    metadata = ec2_client.describe_instances()
    #    return metadata

    def collect_key_pairs(self, ec2_client):
        # Gather and return key pairs
        key_pairs = ec2_client.describe_key_pairs()
        return key_pairs
