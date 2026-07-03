#==========================================================================
#
#           File : baseCollector.py
#        Project : AWS-secure-configuration-auditor
#    Description : Prototype / Base Definition for BaseCollector class definitions
#                  Utilizes ABC to ensure audit-collector classes are not instantiated directly
#                  Utilizes abstractmethod to ensure 'collect' method implemented for all subclasses
#
#==========================================================================
from abc import ABC, abstractmethod

#=====================================
# Base Class : BaseCollector
#=====================================
class BaseCollector(ABC):
    @abstractmethod
    def collect(self):
        pass
