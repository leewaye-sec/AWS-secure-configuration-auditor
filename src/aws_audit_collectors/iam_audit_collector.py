#==========================================================================
#
# File : iam_audit_collector.py
# Project : AWS-secure-configuration-auditor
# Description : Class definitions for IAM Collectors
#
#==========================================================================
# Import base detector
import boto3
from .baseCollector import BaseCollector
from ..AWSStandardizedDataStructures import IAMInventory
from ..awsAuditSession import AWSAuditSession

#------------------------
# Class Definition : IAMCollector
#------------------------
class IAMCollector(BaseCollector):
    # Define the collection checks
    def collect(self, session: AWSAuditSession):

        # Define inventory
        iam_inventory = IAMInventory()

        # Begin collection
        iam_inventory.users = self.collect_users(session.iam_client)
        iam_inventory.groups = self.collect_groups(session.iam_client)
        iam_inventory.roles = self.collect_roles(session.iam_client)
        iam_inventory.policies = self.collect_policies(session.iam_client)
        iam_inventory.access_keys = self.collect_access_keys(session.iam_client)
        iam_inventory.login_profiles = self.collect_login_profiles(session.iam_client)
        iam_inventory.mfa_devices = self.collect_mfa_devices(session.iam_client)

        return iam_inventory

    #========================================
    # Helper functions
    #========================================
    #--------------------
    # Collect Users : returns list
    #--------------------
    def collect_users(self, client):
        return client.list_users()['Users']

    #--------------------
    # Collect Groups : returns list
    #--------------------
    def collect_groups(self, client):
        return client.list_groups()['Groups']

    #--------------------
    # Collect Roles : returns list
    #--------------------
    def collect_roles(self, client):
        return client.list_roles()['Roles']

    #--------------------
    # Collect Policies : returns list
    #--------------------
    def collect_policies(self, client):
        return client.list_policies()['Policies']

    #--------------------
    # Collect Access Keys : returns list
    #--------------------
    def collect_access_keys(self, client):
        return client.list_access_keys()['AccessKeyMetadata']

    #--------------------
    # Collect Login Profiles : returns list of dictionaries
    #--------------------
    def collect_login_profiles(self, client):
        login_profiles = []
        users = client.list_users()['Users']
        for user in users:
            try:
                login_profile_dict = {}
                username = user['UserName']
                login_profile = client.get_login_profile(UserName=username)['LoginProfile']

                # Add to dictionary, then append to list
                login_profile_dict['username'] = username
                login_profile_dict['login_profile'] = login_profile
                login_profiles.append(login_profile_dict)
            except:
                pass

        return login_profiles

    #--------------------
    # Collect MFA Devices : returns list of dictionaries
    #--------------------
    def collect_mfa_devices(self, client):
        mfa_devices = []
        users = client.list_users()['Users']
        for user in users:
            mfa_device_dict = {}
            username = user['UserName']
            user_devices = client.list_mfa_devices(UserName=username)
            mfa_device_dict['username'] = username
            mfa_device_dict['mfa_devices'] = user_devices

        return mfa_devices