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

#------------------------
# Class Definition : EC2Collector
#------------------------
class EC2Collector(BaseCollector):
    # Define the collection checks
    def collect(self):
        ec2_inventory = EC2Inventory()

        # Begin collection
        ec2_inventory.instances = self.collect_instances()
        ec2_inventory.security_groups = self.collect_security_groups()
        ec2_inventory.network_interfaces = self.collect_network_interfaces()
        ec2_inventory.ebs_volumes = self.collect_ebs_volumes()
        ec2_inventory.metadata_options = self.collect_metadata_options()
        ec2_inventory.key_pairs = self.collect_key_pairs()

        return ec2_inventory

    # Helper functions
    def collect_instances(self):
        pass

    def collect_security_groups(self):
        pass

    def collect_network_interfaces(self):
        pass

    def collect_ebs_volumes(self):
        pass

    def collect_metadata_options(self):
        pass

    def collect_key_pairs(self):
        pass
