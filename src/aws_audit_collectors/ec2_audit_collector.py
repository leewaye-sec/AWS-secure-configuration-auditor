#==========================================================================
#
# File : ec2_audit_collector.py
# Project : AWS-secure-configuration-auditor
# Description : Class definitions for EC2 Collectors
#
#==========================================================================
# Import base detector
from aws_audit_collectors.baseCollector import BaseCollector
from AWSStandardizedDataStructures import EC2Inventory
from awsAuditSession import AWSAuditSession

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
        ec2_inventory.database_services = self.collect_database_details(session.audit_session, session.regions)
        ec2_inventory.network_interfaces = self.collect_network_interfaces(session.ec2_client)
        ec2_inventory.ebs_volumes = self.collect_ebs_volumes(session.audit_session, session.regions)
        ec2_inventory.metadata_options = self.collect_metadata_options(session.audit_session, session.regions)
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
                for reservation in instances.get('Reservations', []):
                    for instance in reservation.get('Instances', []):
                        # ---------------------
                        # Gather Details
                        # ---------------------
                        # instance id
                        instance_id = instance.get('InstanceId')

                        # Instance State
                        state = instance.get('State', {}).get('Name')

                        # Isolate name
                        name = "No Name"
                        for tag in instance.get('Tags', []):
                            if tag['Key'] == "Name":
                                name = tag['Value']

                        instance_info = {
                            "region" : region,
                            "instance_id": instance_id,
                            "instance_name": name,
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
                            sg_details = regional_client.describe_security_groups(GroupIds=[group_id])

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

    def collect_database_details(self, audit_session, regions):

        database_details = []

        # Iterate through regions and gather database service information
        for region in regions:
            regional_rds_client = audit_session.client('rds', region_name=region)
            regional_ec2_client = audit_session.client('ec2', region_name=region)

            #------------------
            # Handle RDS Services
            #------------------
            database_instances = regional_rds_client.describe_db_instances()

            # Only process instances with databases
            for db_instance in database_instances.get('DBInstances', []):
                if db_instance:
                    # Gather db identifier
                    db_identifier = db_instance['DBInstanceIdentifier']

                    # Record the data
                    db_instance_details = {
                        "db_resource": "RDS",
                        "db_identifier": db_identifier,
                        "db_instance": db_instance,
                        "db_instance_details": db_instance
                    }
                    database_details.append(db_instance_details)

            # ------------------
            # Handle EC2 Databases
            # ------------------
            instances = regional_ec2_client.describe_instances()

            # Check that something was returned
            if len(instances.get('Reservations', [])) > 0:

                # Gather and return security groups
                security_group_details = []

                # Iterate through nested instances and gather details
                for reservation in instances.get('Reservations', []):
                    for instance in reservation.get('Instances', []):
                        # ---------------------
                        # Gather Details
                        # ---------------------
                        # instance id
                        instance_id = instance.get('InstanceId')

                        # Instance State
                        state = instance.get('State', {}).get('Name')

                        # Isolate name
                        name = "No Name"
                        for tag in instance.get('Tags', []):
                            if tag['Key'] == "Name":
                                name = tag['Value']

                        # ---------------------
                        # Gather Security Group Details
                        # ---------------------
                        sec_group_list = instance['SecurityGroups']

                        # Iterate through security groups
                        for sg_info in sec_group_list:
                            group_id = sg_info['GroupId']
                            group_name = sg_info['GroupName']
                            #sg_rules_details = regional_ec2_client.describe_security_group_rules(GroupIds=[group_id])
                            sg_rules_details = regional_ec2_client.describe_security_group_rules(Filters=[{'Name':'group-id', 'Values':[group_id]}])

                            # Record the data
                            db_instance_details = {
                                "db_resource": "EC2",
                                "db_identifier": name,
                                "db_instance": instance,
                                "db_instance_details": sg_rules_details
                            }
                            database_details.append(db_instance_details)

        return database_details

    def collect_network_interfaces(self, ec2_client):
        # Gather and return network interfaces
        net_int = ec2_client.describe_network_interfaces()
        return net_int

    def collect_ebs_volumes(self, audit_session, regions):
        ebs_volume_details = []
        # Gather and return ebs volumes
        for region in regions:
            regional_client = audit_session.client('ec2', region_name=region)
            regional_instances = regional_client.describe_instances()

            # Check that something was returned
            if len(regional_instances.get('Reservations', [])) > 0:
                for reservation in regional_instances.get('Reservations', []):
                    for instance in reservation.get('Instances', []):
                        # ---------------------
                        # Gather Details
                        # ---------------------
                        # instance id
                        instance_id = instance.get('InstanceId')

                        # Isolate name
                        name = "No Name"
                        for tag in instance.get('Tags', []):
                            if tag['Key'] == "Name":
                                name = tag['Value']

                        # Iterate through volume blocks
                        volume_ids = []
                        for blocks in instance.get('BlockDeviceMappings', []):
                            volume_ids.append(blocks['Ebs']['VolumeId'])

                        # Check volume IDs
                        if volume_ids:
                            volume_info = regional_client.describe_volumes(VolumeIds=volume_ids)

                            # Create dictionary
                            ebs_volume = {
                                'instance_id': instance,
                                'instance_name': name,
                                'volumes': volume_info
                            }


        return ebs_volume_details

    def collect_metadata_options(self, audit_session, regions):
        metadata = []
        # Gather and return metadata
        for region in regions:
            regional_client = audit_session.client('ec2', region_name=region)
            regional_instance = regional_client.describe_instances()

            # Check that something was returned
            if len(regional_instance.get('Reservations', [])) > 0:
                for reservation in regional_instance.get('Reservations', []):
                    for instance in reservation.get('Instances', []):
                        # ---------------------
                        # Gather Details
                        # ---------------------
                        # instance id
                        instance_id = instance.get('InstanceId')

                        # Isolate name
                        name = "No Name"
                        for tag in instance.get('Tags', []):
                            if tag['Key'] == "Name":
                                name = tag['Value']

                        # Gather Metadata
                        metadata_options = instance.get('MetadataOptions', {})

                        # Create dictionary
                        metadata_dict = {
                            "instance_id" : instance_id,
                            "instance_name": name,
                            "instance_region": region,
                            "instance_metadata": metadata_options
                        }
                        metadata.append(metadata_dict)

        return metadata

    def collect_key_pairs(self, ec2_client):
        # Gather and return key pairs
        key_pairs = ec2_client.describe_key_pairs()
        return key_pairs
