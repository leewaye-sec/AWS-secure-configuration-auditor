#==========================================================================
#
# File : ec2_audit_checker.py
# Project : AWS-secure-configuration-auditor
# Description : Class definitions for EC2 Checks
#
#==========================================================================
# Import base detector
from .baseChecker import BaseChecker
from ..AWSStandardizedDataStructures import AuditFinding

#------------------------
# Class Definition : OpenSSHCheck
#------------------------
class OpenSSHCheck(BaseChecker):
    def process(self, inventory):
        pass

#------------------------
# Class Definition : OpenRDPCheck
#------------------------
class OpenRDPCheck(BaseChecker):
    def process(self, inventory):
        pass

#------------------------
# Class Definition : OpenDatabaseCheck
#------------------------
class OpenDatabaseCheck(BaseChecker):
    def process(self, inventory):
        pass

#------------------------
# Class Definition : IMDSv2Check
#------------------------
class IMDSv2Check(BaseChecker):
    def process(self, inventory):
        pass

#------------------------
# Class Definition : EBSEncryptionCheck
#------------------------
class EBSEncryptionCheck(BaseChecker):
    def process(self, inventory):
        pass

#------------------------
# Class Definition : PublicIPCheck
#------------------------
class PublicIPCheck(BaseChecker):
    def process(self, inventory):
        pass

