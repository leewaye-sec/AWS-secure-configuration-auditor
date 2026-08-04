#==========================================================================
#
# File : iam_audit_checker.py
# Project : AWS-secure-configuration-auditor
# Description : Class definitions for IAM Checks
#
#==========================================================================
# Import base detector
from datetime import datetime, timezone
from aws_audit_checkers.baseChecker import BaseChecker
from collections.abc import Callable
from AWSStandardizedDataStructures import IAMInventory
from AWSStandardizedDataStructures import AuditFinding

#------------------------
# Class Definition : IAMAuditEngine()
#------------------------
class IAMAuditEngine(BaseChecker):
    # Initial Class Definition to include class functions
    def __init__(self):
        self.iam_audit_checks: list[Callable[[IAMInventory], list]] = [
            self.adminstrator_access_check,
            self.mfa_enabled_check,
            self.old_access_key_check,
            self.inactive_access_key_check,
            self.wild_card_policy_check,
            self.root_access_key_check,
            self.console_access_check,
            self.unused_user_check
        ]

    #--------------------------
    # Main driver function
    #--------------------------
    def audit(self, inventory: IAMInventory):
        # Array to hold findings
        audit_findings = []

        # Work through the checks
        for audit_check in self.iam_audit_checks:
            audit_findings.extend(audit_check(inventory))

        return audit_findings

    #--------------------------
    # Helper functions
    #--------------------------
    def adminstrator_access_check(self, inventory: IAMInventory) -> list[AuditFinding]:
        administrator_access_findings = []
        # Check user for admin
        #   - Also grab group membership
        # Iterate through groups and determine policies (Admin Access)
        #---------------------
        # Group Checks
        #---------------------
        admin_groups = []
        for group in inventory.groups:
            group_name = group['group_name']

            # Attached Policies
            for policy in group['group_attached_policies']:
                if "AdministratorAccess" in policy['PolicyArn']:
                    administrator_access_findings.append(AuditFinding(
                        severity_level="HIGH",
                        service="IAM",
                        resource_type="Group",
                        resource_name=f"{group_name}",
                        finding_name="ADMINISTRATOR_ACCESS",
                        finding_description=f"Group has administrative permissions",
                        recommendation="Review admin privileges and adjust where appropriate"
                    ))
                    # Add group to admin list
                    #admin_groups.append(group)
                    admin_groups.append(group_name)

            # Inline Policy Check
            for inline in group['group_policies']:
                policy_statement = inline.get('Statement', [])

                # Normalize
                if isinstance(policy_statement, dict):
                    policy_statement = [policy_statement]

                # Iterate through and further normalize to simplify checks
                for statement in policy_statement:
                    if statement.get("Effect") == "Allow":
                        policy_action = statement.get("Action", [])
                        policy_resource = statement.get("Resource", [])

                        # Get into lists if applicable
                        if isinstance(policy_action, str):
                            policy_actions = [policy_action]
                        else:
                            policy_actions = policy_action

                        if isinstance(policy_resource, str):
                            policy_resources = [policy_resource]
                        else:
                            policy_resources = policy_resource

                        # Check for wildcard permissions
                        if "*" in policy_actions and "*" in policy_resources:
                            administrator_access_findings.append(AuditFinding(
                                severity_level="HIGH",
                                service="IAM",
                                resource_type="Group",
                                resource_name=f"{group_name}",
                                finding_name="ADMINISTRATOR_ACCESS",
                                finding_description=f"Group has administrative permissions",
                                recommendation="Review admin privileges and adjust where appropriate"
                            ))

        #---------------------
        # User Checks
        #---------------------
        # First check user policies
        for user in inventory.users:
            username = user['username']

            # Check attached policies
            for a_policy in user['user_attached_policies'].get('AttachedPolicies', []):
                if "AdministratorAccess" in a_policy['PolicyName']:
                    administrator_access_findings.append(AuditFinding(
                        severity_level="HIGH",
                        service="IAM",
                        resource_type="User",
                        resource_name=f"{username}",
                        finding_name="ADMINISTRATOR_ACCESS",
                        finding_description=f"IAM user has administrative permissions",
                        recommendation="Review user admin privileges and adjust where appropriate"
                    ))

            # Check inline policies
            for i_policy in user['user_inline_policies']:
                i_policy_statements = i_policy.get('PolicyDocument', {}).get('Statement', [])
                for i_statement in i_policy_statements:
                    if i_statement.get('Action') == "*" and i_statement.get('Effect') == 'Allow':
                        administrator_access_findings.append(AuditFinding(
                            severity_level="HIGH",
                            service="IAM",
                            resource_type="User",
                            resource_name=f"{username}",
                            finding_name="ADMINISTRATOR_ACCESS",
                            finding_description=f"IAM user has administrative permissions",
                            recommendation="Review user admin privileges and adjust where appropriate"
                        ))

            # Check if user is in group with admin policies (from above)
            # Gather users' groups / group names
            user_groups = user['user_groups']
            user_group_names = [group['GroupName'] for group in user_groups.get('Groups', [])]
            for group_name in user_group_names:
                if group_name in admin_groups:
            #for u_group in user['user_groups']:
            #    group_name = u_group['group_name']
            #    if u_group in admin_groups:
                    administrator_access_findings.append(AuditFinding(
                        severity_level="HIGH",
                        service="IAM",
                        resource_type="User",
                        resource_name=f"{username} - {group_name}",
                        finding_name="ADMINISTRATOR_ACCESS",
                        finding_description=f"IAM user membership in group with administrative permissions",
                        recommendation="Review user group membership/admin privileges and adjust where appropriate"
                    ))

        return administrator_access_findings

    def mfa_enabled_check(self, inventory: IAMInventory) -> list[AuditFinding]:
        mfa_disabled_findings = []

        # Iterate through user / MFA
        for user_mfa in inventory.mfa_devices:
            username = user_mfa['username']
            # No MFA Devices
            if len(user_mfa['mfa_devices']) == 0:
                mfa_disabled_findings.append(AuditFinding(
                    severity_level="HIGH",
                    service="IAM",
                    resource_type="User",
                    resource_name=f"{username}",
                    finding_name="MFA_DISABLED",
                    finding_description=f"MFA not enabled for IAM user",
                    recommendation="Enable MFA for user"
                ))

        return mfa_disabled_findings

    def old_access_key_check(self, inventory: IAMInventory) -> list[AuditFinding]:
        old_access_key_findings = []
        #--------------------
        # Define inactivity variables
        #--------------------
        key_age = 90
        time_now = datetime.now(timezone.utc)

        # Iterate through access keys
        aws_access_keys = inventory.access_keys

        # Iterate through the users and their access keys
        for aws_key_account in aws_access_keys:
            username = aws_key_account['username']

            for key in aws_key_account['access_keys']:
                key_last_used = key['key_last_used_date']

                if key_last_used:
                    # Time comparison
                    key_inactivity = (time_now - key_last_used).days
                    if key_inactivity >= key_age:
                        old_access_key_findings.append(AuditFinding(
                            severity_level = "MEDIUM",
                            service = "IAM",
                            resource_type = "Access Key",
                            resource_name = f"{username}",
                            finding_name = "OLD_ACCESS_KEY",
                            finding_description = f"IAM access key exceeds age period of {key_age} days",
                            recommendation = "Rotate or remove old access key"
                        ))
                else:
                    old_access_key_findings.append(AuditFinding(
                        severity_level="MEDIUM",
                        service="IAM",
                        resource_type="Access Key",
                        resource_name=f"{username}",
                        finding_name="UNUSED_ACCESS_KEY",
                        finding_description=f"IAM access key is unused",
                        recommendation="Rotate or remove old access key"
                    ))

        return old_access_key_findings

    def inactive_access_key_check(self, inventory: IAMInventory) -> list[AuditFinding]:
        inactive_access_key_findings = []

        # Work through user keys and check status
        for user_key_info in inventory.access_keys:
            username = user_key_info['username']
            # Work through reported keys
            for key in user_key_info['access_keys']:
                if key['key_status'] != "Active":
                    inactive_access_key_findings.append(AuditFinding(
                        severity_level="LOW",
                        service="IAM",
                        resource_type="Access Key",
                        resource_name=f"{username}",
                        finding_name="INACTIVE_ACCESS_KEY",
                        finding_description=f"IAM access key marked as inactive",
                        recommendation="Remove or disable inactive access keys"
                    ))
        return inactive_access_key_findings

    def wild_card_policy_check(self, inventory: IAMInventory) -> list[AuditFinding]:
        wildcard_policy_findings = []

        # Work through policies and not if policy contains wildcard
        for policy in inventory.policies:
            policy_name = policy['policy_name']
            policy_doc = policy['policy_doc']

            # Isolate policy statements from policy doc and put into list
            if policy_doc:
                policy_statements = policy_doc.get('Statement', [])
                if isinstance(policy_statements, dict):
                    policy_statements = [policy_statements]

                    # Work through each statement and report wildcards
                    #for i, statement in enumerate(policy_statements):
                    for statement in policy_statements:
                        statement_actions = statement.get('Action', [])
                        statement_resources = statement.get('Resource', [])

                        # Ensure proper format for iteration
                        if isinstance(statement_actions, str): statement_actions = [statement_actions]
                        if isinstance(statement_resources, str): statement_resources = [statement_resources]

                        # Search for wildcard
                        if "*" in statement_actions:
                            wildcard_policy_findings.append(AuditFinding(
                                severity_level="HIGH",
                                service="IAM",
                                resource_type="IAM Policy Action",
                                resource_name=f"{policy_name}",
                                finding_name="WILDCARD_POLICY",
                                finding_description=f"Wildcard permissions found in IAM Policy Action",
                                recommendation="Update permissions for least privilege"
                            ))
                        if "*" in statement_resources:
                            wildcard_policy_findings.append(AuditFinding(
                                severity_level="HIGH",
                                service="IAM",
                                resource_type="IAM Policy Resource",
                                resource_name=f"{policy_name}",
                                finding_name="WILDCARD_POLICY",
                                finding_description=f"Wildcard permissions found in IAM Policy Resource",
                                recommendation="Update permissions for least privilege"
                            ))


        return wildcard_policy_findings

    def root_access_key_check(self, inventory: IAMInventory) -> list[AuditFinding]:
        root_access_key_findings = []
        #--------------------
        # Gather account information
        #--------------------
        summary_map = inventory.account_summary['SummaryMap']

        # Determine if root keys are present
        root_access_key_present = summary_map.get('AccountAccessKeyPresent', 0)

        if root_access_key_present > 0:
            root_access_key_findings.append(AuditFinding(
                severity_level="CRITICAL",
                service="IAM",
                resource_type="Root Account",
                resource_name= "Root Account",
                finding_name="ROOT_ACCESS_KEY",
                finding_description=f"Active access keys for root account",
                recommendation="Remove root access keys"
            ))

        return root_access_key_findings

    def console_access_check(self, inventory: IAMInventory) -> list[AuditFinding]:
        console_access_findings = []
        #--------------------
        # Iterate through user inventory
        #--------------------
        for user in inventory.users:
            username = user['username']
            # If they have console access, report it
            if user['console_access']:
                console_access_findings.append(AuditFinding(
                    severity_level="LOW",
                    service="IAM",
                    resource_type="User",
                    resource_name= username,
                    finding_name="CONSOLE_ACCESS_ENABLED",
                    finding_description=f"IAM user has Console Access enabled",
                    recommendation="Console access review and possible removal"
                ))
        return console_access_findings

    def unused_user_check(self, inventory: IAMInventory) -> list[AuditFinding]:

        unused_user_findings = []
        #--------------------
        # Check creation date and compare to last key date and last password
        #--------------------
        # Iterate through access keys
        aws_access_keys = inventory.access_keys

        # Iterate through the users and their access keys
        for aws_key_account in aws_access_keys:
            activity_tracker = []
            username = aws_key_account['username']
            user_creation = aws_key_account['user_info']['CreateDate']

            # Password date comparison
            #if aws_key_account['user_info']['PasswordLastUsed']:
            if aws_key_account['user_info'].get("PasswordLastUsed"):
                activity_tracker.append(aws_key_account['user_info']['PasswordLastUsed'])

            # Key date comparison
            for key in aws_key_account['access_keys']:
                key_last_used = key['key_last_used_date']
                if key['key_last_used_date']:
                    activity_tracker.append(key['key_last_used_date'])

            # Compare the gathered account activity times and compare to creation
            for activity in activity_tracker:
                #   If no activity, unused account
                if activity <= user_creation:
                    unused_user_findings.append(AuditFinding(
                        severity_level = "LOW",
                        service = "IAM",
                        resource_type = "User",
                        resource_name = f"{username}",
                        finding_name = "UNUSED_USER",
                        finding_description = f"Inactive IAM user likely",
                        recommendation = "Review account and remove if necessary"
                    ))

        return unused_user_findings

