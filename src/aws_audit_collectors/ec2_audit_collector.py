#==========================================================================
#
# File : ec2_audit_collector.py
# Project : AWS-secure-configuration-auditor
# Description : Class definitions for EC2 Collectors
#
#==========================================================================
# Import base detector
import boto3

from .baseCollector import BaseCollector
from ..AWSStandardizedDataStructures import EC2Inventory

#------------------------
# Class Definition : EC2Collector
#------------------------
class EC2Collector(BaseCollector):
    # Define the collection checks
    def collect(self, session):
        ec2_inventory = EC2Inventory()

        # Initialize the EC2 client and resource
        ec2_resource = session.resource('ec2', region_name='us-east''1')
        ec2_client = session.client('ec2', region_name='us-east''1')

        # Begin collection
        ec2_inventory.instances = self.collect_instances(ec2_resource)
        ec2_inventory.security_groups = self.collect_security_groups(ec2_client)
        ec2_inventory.network_interfaces = self.collect_network_interfaces(ec2_resource)
        ec2_inventory.ebs_volumes = self.collect_ebs_volumes(ec2_resource)
        ec2_inventory.metadata_options = self.collect_metadata_options(ec2_client)
        ec2_inventory.key_pairs = self.collect_key_pairs(ec2_client)

        return ec2_inventory

    #-------------------------
    # Helper functions
    #-------------------------
    def collect_instances(self, ec2_resource):
        # Gather and return instances
        ec2_instances = ec2_resource.instance.all()
        return ec2_instances

    def collect_security_groups(self, ec2_client):
        # Gather and return security groups
        security_groups = ec2_client.descript_security_groups()
        return security_groups

    def collect_network_interfaces(self, ec2_resource):
        # Gather and return security groups
        net_int = ec2_resource.network_interfaces.all()
        return net_int

    def collect_ebs_volumes(self, ec2_resource):
        # Gather and return ebs volumes
        ebs_vols = ec2_resource.volumes.all()
        return ebs_vols

    def collect_metadata_options(self, ec2_client):
        # Gather and return metadata
        metadata = ec2_client.describe_instances()
        return metadata

    def collect_key_pairs(self, ec2_client):
        # Gather and return key pairs
        key_pairs = ec2_client.describe_key_pairs()
        return key_pairs
