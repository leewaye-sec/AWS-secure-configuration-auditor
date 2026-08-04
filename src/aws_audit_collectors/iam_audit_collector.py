#==========================================================================
#
# File : iam_audit_collector.py
# Project : AWS-secure-configuration-auditor
# Description : Class definitions for IAM Collectors
#
#==========================================================================
# Import base detector
import json

import boto3
from aws_audit_collectors.baseCollector import BaseCollector
from AWSStandardizedDataStructures import IAMInventory
from awsAuditSession import AWSAuditSession

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
        iam_inventory.account_summary = self.collect_summary(session.iam_client)

        return iam_inventory

    #========================================
    # Helper functions
    #========================================
    #--------------------
    # Collect Users / User Info: returns list of dictionaries
    #--------------------
    def collect_users(self, client):
        #------------------------
        # Gather users
        #------------------------
        user_information = []
        users_present = client.list_users()['Users']

        #------------------------
        # Gather user information
        #------------------------
        for user in users_present:
            username = user['UserName']

            # User Attached Policies
            user_attached_policies = client.list_attached_user_policies(UserName=username)

            # User Inline Policies
            user_inline_policies = []
            user_inline_policy = client.list_user_policies(UserName=username)
            for user_inline_policy in user_inline_policy.get('PolicyNames', []):
                user_policy = client.get_user_policy(UserName=username, PolicyName=user_inline_policy)
                user_inline_policies.append(user_policy)

            # User Group Membership
            user_groups = None
            try:
                user_groups = client.list_groups_for_user(UserName=username)
            except:
                user_groups = None

            # Gather console access
            user_console_access = False
            try:
                client.get_login_profile(UserName=username)
                user_console_access = True
            except:
                pass

            # Update user information
            user_policy_def = {
                "username": username,
                "user_info": user,
                "user_attached_policies": user_attached_policies,
                "user_inline_policies": user_inline_policies,
                "user_groups": user_groups,
                "console_access": user_console_access
            }
            user_information.append(user_policy_def)

        return user_information

    #--------------------
    # Collect Groups : returns list of
    #--------------------
    def collect_groups(self, client):
        #------------------------
        # Gather groups
        #------------------------
        groups_present = client.list_groups()['Groups']
        groups_information = []

        #------------------------
        # Gather Group Policies
        #------------------------
        for group in groups_present:
            group_name = group['GroupName']

            # Gather group attached policies
            group_attached_policies = client.list_attached_group_policies(GroupName=group_name).get('AttachedPolicies', [])

            # Gather group inline policies
            group_inline_policies = []
            group_policy = client.list_attached_group_policies(GroupName=group_name)
            for policy_name in group_policy.get("PolicyNames", []):
                inline_policy = client.get_group_policy(GroupName=group_name, PolicyName=policy_name)
                group_inline_policies.append(inline_policy["PolicyDocument"])

            group_info = {
                "group_name": group_name,
                "group_info": group,
                "group_policies": group_inline_policies,
                "group_attached_policies": group_attached_policies
            }
            groups_information.append(group_info)

        return groups_information

    #--------------------
    # Collect Roles : returns list
    #--------------------
    def collect_roles(self, client):
        return client.list_roles()['Roles']

    #--------------------
    # Collect Policies : returns list of dictionaries
    #--------------------
    def collect_policies(self, client):
        #------------------------
        # Gather Policies
        #------------------------
        policies_present = client.list_policies()['Policies']
        policies_info = []

        for policy in policies_present:
            policy_name = policy['PolicyName']
            policy_arn = policy['Arn']

            # Get policy details
            policy_info = client.get_policy(PolicyArn=policy_arn)
            policy_default_verions = policy_info['Policy']['DefaultVersionId']

            # Get json for policy
            policy_version = client.get_policy_version(PolicyArn=policy_arn, VersionId=policy_default_verions)
            policy_doc = policy_version['PolicyVersion']['Document']
            policy_doc_json = None
            if isinstance(policy_doc, str):
                policy_doc_json = json.loads(policy_doc)

            # Create dictionary to hold info
            policy_info_dict = {
                "policy_name": policy_name,
                "policy_arn": policy_arn,
                "policy_doc": policy_doc_json
            }
            policies_info.append(policy_info_dict)

        return policies_info

    #--------------------
    # Collect Access Keys : returns list
    #--------------------
    def collect_access_keys(self, client):
        #return client.list_access_keys()['AccessKeyMetadata']
        #------------------------
        # Gather users
        #------------------------
        users_access_keys = []
        users_present = client.list_users()['Users']

        for user in users_present:
            username = user["UserName"]

            # Gather keys
            user_keys = client.list_access_keys(UserName=username)["AccessKeyMetadata"]

            # Gather last used key
            user_keys_info = []
            for key in user_keys:
                key_id = key["AccessKeyId"]
                key_status = key["Status"]
                key_create_date = key["CreateDate"]
                last_used = client.get_access_key_last_used(AccessKeyId=key_id)["AccessKeyLastUsed"]
                last_used_date = last_used.get("LastUsedDate")

                user_key_info = {
                    "key_id": key_id,
                    "key": key,
                    "key_create_date": key_create_date,
                    "key_status": key_status,
                    "key_last_used": last_used,
                    "key_last_used_date": last_used_date
                }
                user_keys_info.append(user_key_info)

            # Gather last password used

            # Create user dictionary
            user_access_key = {
                "username": username,
                "user_info": user,
                "access_keys": user_keys_info
            }
            users_access_keys.append(user_access_key)

        return users_access_keys

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
            username = user['UserName']
            user_devices = client.list_mfa_devices(UserName=username)
            mfa_device_dict = {
                'username': username,
                'mfa_devices': user_devices
            }
            mfa_devices.append(mfa_device_dict)

        return mfa_devices

    # --------------------
    # Collect Account Summary
    # --------------------
    def collect_summary(self, client):
        return client.get_account_summary()