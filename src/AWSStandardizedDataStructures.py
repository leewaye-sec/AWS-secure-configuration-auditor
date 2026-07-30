#==========================================================================
#
#           File : AWSStandardizedDataStructures.py
#        Project : AWS-secure-configuration-auditor
#    Description : Holds the data class structures for several SIEM components
#                  Use for normalization of ingested data
#
#==========================================================================
from dataclasses import dataclass, field

#------------------------
# Data Class Definition : IAMInventory
#   Use : Standardize and normalize IAM collections
#------------------------
@dataclass
class IAMInventory:
    users: list = field(default_factory=list)
    groups: list = field(default_factory=list)
    roles: list = field(default_factory=list)
    policies: list = field(default_factory=list)
    access_keys: list = field(default_factory=list)
    login_profiles: list = field(default_factory=list)
    mfa_devices: list = field(default_factory=list)
    account_summary: dict = field(default_factory=dict)

#------------------------
# Data Class Definition : S3Inventory
#   Use : Standardize and normalize S3 collections
#------------------------
@dataclass
class S3Inventory:
    buckets: list = field(default_factory=list)
    bucket_policies: list = field(default_factory=list)
    bucket_policy_statuses: list = field(default_factory=list)
    acls: list = field(default_factory=list)
    public_access_block: list = field(default_factory=list)
    encryption: list = field(default_factory=list)
    versioning: list = field(default_factory=list)
    ownership: list = field(default_factory=list)
    logging: list = field(default_factory=list)

#------------------------
# Data Class Definition : EC2Inventory
#   Use : Standardize and normalize EC2 collections
#------------------------
@dataclass
class EC2Inventory:
    instances: list = field(default_factory=list)
    security_groups: list = field(default_factory=list)
    security_group_details: list = field(default_factory=list)
    database_services: list = field(default_factory=list)
    network_interfaces: list = field(default_factory=list)
    ebs_volumes: list = field(default_factory=list)
    metadata_options: list = field(default_factory=list)
    key_pairs: list = field(default_factory=list)

#------------------------
# Data Class Definition : VPCInventory
#   Use : Standardize and normalize VPC collections
#   * Future use
#------------------------
@dataclass
class VPCInventory:
    vpcs: list = field(default_factory=list)
    subnets: list = field(default_factory=list)
    route_tables: list = field(default_factory=list)
    internet_gateways: list = field(default_factory=list)
    nat_gateways: list = field(default_factory=list)
    network_acls: list = field(default_factory=list)

#------------------------
# Data Class Definition : CloudTrailInventory
#   Use : Standardize and normalize CloudTrail collections
#   * Future use
#------------------------
@dataclass
class CloudTrailInventory:
    trails: list = field(default_factory=list)
    multi_region_status: list = field(default_factory=list)
    log_validation: list = field(default_factory=list)
    s3_destination: list = field(default_factory=list)
    cloud_Watch_integration: list = field(default_factory=list)

#------------------------
# Data Class Definition : AWSConfigInventory
#   Use : Standardize and normalize AWSConfig collections
#   * Future use
#------------------------
@dataclass
class AWSConfigInventory:
    configuration_recorder: list = field(default_factory=list)
    delivery_channel: list = field(default_factory=list)
    recording_scope: list = field(default_factory=list)

#------------------------
# Data Class Definition : GuardDutyInventory
#   Use : Standardize and normalize GuardDuty collections
#   * Future use
#------------------------
@dataclass
class GuardDutyInventory:
    detectors: list = field(default_factory=list)
    publishing_configuration: list = field(default_factory=list)

#------------------------
# Data Class Definition : AuditFinding
#   Use : Standardize and normalize Checks / Audit Findings
#------------------------
@dataclass
class AuditFinding:
    severity_level: str
    finding_name: str
    finding_description: str
    service: str
    resource_name: str
    resource_type: str
    recommendation: str
