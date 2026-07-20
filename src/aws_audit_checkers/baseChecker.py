#==========================================================================
#
#           File : baseChecker.py
#        Project : AWS-secure-configuration-auditor
#    Description : Prototype / Base Definition for BaseCheck class definitions
#                  Utilizes ABC to ensure audit-checker classes are not instantiated directly
#                  Utilizes abstractmethod to ensure 'process' method implemented for all subclasses
#
#==========================================================================
from abc import ABC, abstractmethod

#=====================================
# Base Class : BaseCheck
#=====================================
class BaseChecker(ABC):
    @abstractmethod
    def audit(self, inventory):
            pass