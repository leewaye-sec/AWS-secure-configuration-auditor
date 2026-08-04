#==========================================================================
#
# File : awsCollector.py
# Project : AWS-secure-configuration-auditor
# Description : Collector Wrapper Class
#
#==========================================================================
from aws_audit_collectors.iam_audit_collector import IAMCollector
from aws_audit_collectors.ec2_audit_collector import EC2Collector
from aws_audit_collectors.s3_audit_collector import S3Collector

#------------------------
# Class Definition : awsCollector
#------------------------
class AWSCollectors:
    def collect(self, session):
        return {
            "iam": IAMCollector().collect(session),
            "ec2": EC2Collector().collect(session),
            "s3": S3Collector().collect(session)
        }