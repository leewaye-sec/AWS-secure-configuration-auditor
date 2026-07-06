#==========================================================================
#
# File : iam_audit_checker.py
# Project : AWS-secure-configuration-auditor
# Description : Class definitions for IAM Checks
#
#==========================================================================
# Import base detector
from .baseChecker import BaseChecker
from ..AWSStandardizedDataStructures import AuditFinding

#------------------------
# Class Definition : AdminstratorAccessCheck
#------------------------
class AdminstratorAccessCheck(BaseChecker):
    def process(self, inventory):
        pass

#------------------------
# Class Definition : MFAEnabledCheck
#------------------------
class MFAEnabledCheck(BaseChecker):
    def process(self, inventory):
        pass

#------------------------
# Class Definition : OldAccessKeyCheck
#------------------------
class OldAccessKeyCheck(BaseChecker):
    def process(self, inventory):
        pass

#------------------------
# Class Definition : InactiveAccessKeyCheck
#------------------------
class InactiveAccessKeyCheck(BaseChecker):
    def process(self, inventory):
        pass

#------------------------
# Class Definition : WildcardPolicyCheck
#------------------------
class WildcardPolicyCheck(BaseChecker):
    def process(self, inventory):
        pass

#------------------------
# Class Definition : RootAccessKeyCheck
#------------------------
class RootAccessKeyCheck(BaseChecker):
    def process(self, inventory):
        pass

#------------------------
# Class Definition : ConsoleAccessCheck
#------------------------
class ConsoleAccessCheck(BaseChecker):
    def process(self, inventory):
        pass

#------------------------
# Class Definition : UnusedUserCheck
#------------------------
class ConsoleAccessCheck(BaseChecker):
    def process(self, inventory):
        pass

