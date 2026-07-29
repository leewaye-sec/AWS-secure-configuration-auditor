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
        ec2_inventory.instances = self.collect_instances(session.audit_session, session.regions)
        ec2_inventory.security_groups = self.collect_security_groups(session.ec2_client)
        ec2_inventory.security_group_details = self.collect_security_group_details(session.audit_session, session.regions)
        ec2_inventory.network_interfaces = self.collect_network_interfaces(session.ec2_client)
        ec2_inventory.ebs_volumes = self.collect_ebs_volumes(session.ec2_client)
        #ec2_inventory.metadata_options = self.collect_metadata_options(session.ec2_client)
        ec2_inventory.key_pairs = self.collect_key_pairs(session.ec2_client)

        return ec2_inventory

    #-------------------------
    # Helper functions
    #-------------------------
    def collect_instances(self, audit_session, regions):

        ec2_instances = []
        # Gather and return instances
        for region in regions:
            regional_client = audit_session.client('ec2', region_name=region)
            instances = regional_client.describe_instances()

            # Check that something was returned
            if len(instances.get('Reservations', [])) > 0:
                instance_info = {
                    "region" : region,
                    "instances": instances
                }
                ec2_instances.append(instance_info)

        return ec2_instances

    def collect_security_groups(self, ec2_client):
        # Gather and return security groups
        security_groups = ec2_client.describe_security_groups()
        return security_groups

    def collect_security_group_details(self, audit_session, regions):
        security_group_details = []
        # Work through regions --> instances --> security groups --> details
        for region in regions:
            regional_client = audit_session.client('ec2', region_name=region)
            instances = regional_client.describe_instances()

            # Check that something was returned
            if len(instances.get('Reservations', [])) > 0:

                # Gather and return security groups
                security_group_details = []

                # Iterate through nested instances and gather details
                for reservation in instances.get('Reservations', []):
                    for instance in reservation.get('Instances', []):
                        #---------------------
                        # Gather Details
                        #---------------------
                        # instance id
                        instance_id = instance.get('InstanceId')

                        # Instance State
                        state = instance.get('State', {}).get('Name')

                        # Isolate name
                        name = "No Name"
                        for tag in instance.get('Tags', []):
                            if tag['Key'] == "Name":
                                name = tag['Value']

                        #---------------------
                        # Gather Security Group Details
                        #---------------------
                        sec_group_list = instance['SecurityGroups']

                        for sg_info in sec_group_list:
                            group_id = sg_info['GroupId']
                            group_name = sg_info['GroupName']
                            sg_details = regional_client.describe_security_groups(GroupIds=[sg_info])

                            sec_group_details = {
                                "region": region,
                                "instance_id": instance_id,
                                "instance_state": state,
                                "instance_name": name,
                                "sec_group_id": group_id,
                                "sec_group_name": group_name,
                                "sec_group_details": sg_details
                            }
                            security_group_details.append(sec_group_details)

        return security_group_details

    def collect_network_interfaces(self, ec2_client):
        # Gather and return network interfaces
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
