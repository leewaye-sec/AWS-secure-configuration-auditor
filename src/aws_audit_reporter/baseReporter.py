#==========================================================================
#
#           File : baseReporter.py
#        Project : AWS-secure-configuration-auditor
#    Description : Prototype / Base Definition for BaseReporter class definitions
#                  Utilizes ABC to ensure audit-reporter classes are not instantiated directly
#                  Utilizes abstractmethod to ensure 'generate' method implemented for all subclasses
#
#==========================================================================
from abc import ABC, abstractmethod

#=====================================
# Base Class : BaseReporter
#=====================================
class BaseReporter(ABC):
    @abstractmethod
    def generate(self, aws_findings):
        pass
