#==========================================================================
#
# File : iam_audit_collector.py
# Project : AWS-secure-configuration-auditor
# Description : Class definitions for IAM Collectors
#
#==========================================================================
# Import base detector
from .baseCollector import BaseCollector
from ..AWSStandardizedDataStructures import IAMInventory

#------------------------
# Class Definition : IAMCollector
#------------------------
class IAMCollector(BaseCollector):
    # Define the collection checks
    def collect(self):
        iam_inventory = IAMInventory()

        # Begin collection
        iam_inventory.users = self.collect_users()
        iam_inventory.groups = self.collect_groups()
        iam_inventory.roles = self.collect_roles()
        iam_inventory.policies = self.collect_policies()
        iam_inventory.access_keys = self.collect_access_keys()
        iam_inventory.mfa_devices = self.collect_mfa_devices()

        return iam_inventory

    # Helper functions
    def collect_users(self):
        pass

    def collect_groups(self):
        pass

    def collect_roles(self):
        pass

    def collect_policies(self):
        pass

    def collect_access_keys(self):
        pass

    def collect_mfa_devices(self):
        pass