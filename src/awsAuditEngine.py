#==========================================================================
#
# File : awsAuditEngine.py
# Project : AWS-secure-configuration-auditor
# Description : AWS Audit Wrapper Class
#
#==========================================================================
from aws_audit_checkers.iam_audit_checker import IAMAuditEngine
from aws_audit_checkers.ec2_audit_checker import EC2AuditEngine
from aws_audit_checkers.s3_audit_checker import S3AuditEngine

#------------------------
# Class Definition : awsAuditEngine
#------------------------
class AWSAuditEngine:
    def audit(self, inventory_list):
        # Array to catch findings
        aws_audit_findings = []

        # Handle the AWS Audit Checks
        aws_audit_findings.extend(IAMAuditEngine().audit(inventory_list['iam']))
        aws_audit_findings.extend(EC2AuditEngine().audit(inventory_list['ec2']))
        aws_audit_findings.extend(S3AuditEngine().audit(inventory_list['s3']))

        return aws_audit_findings
