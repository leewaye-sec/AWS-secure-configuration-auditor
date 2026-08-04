#!/usr/local/bin/python3
#==========================================================================
#
#           File : awsSecurConfigurationAuditor.py
#        Project : AWS Auditor
#    Description : Audits an AWS environment for common security 
#                  misconfigurations and produces a audit report
#
#==========================================================================
#--------------------
# Imports
#--------------------
import sys
import os
import argparse
import logging
import boto3
from botocore.exceptions import ProfileNotFound, NoCredentialsError, ClientError
from pathlib import Path
import textwrap
from datetime import datetime

#--------------------
# Class Imports
#--------------------
from awsAuditSession import AWSAuditSession
from awsCollector import AWSCollectors
from awsAuditEngine import AWSAuditEngine
from aws_audit_reporter.awsReportGenerator import awsReportGenerator

#--------------------
# Global Variables
#--------------------
# Timestamp
global TIMESTAMP
timestamp_dirty = datetime.now()
TIMESTAMP = timestamp_dirty.strftime("%Y%m%d_%H%M%S")

# Path Definitions
global CWD
CWD = os.path.abspath(os.getcwd())
CWD = CWD + "/"

#--------------------------------------------------------------------------
# Functions
#--------------------------------------------------------------------------
#==================
# Wrapper function to hold audit collection/checking/results
#==================
def awsSecurityAuditWrapper(aws_profile):

    #--------------------------
    # Session Creation
    #--------------------------
    try:
        logging.info(f"Creating session connection with passed profile [ {aws_profile} ]")

        #--------------------------
        # Create AWS Session
        #--------------------------
        audit_session = AWSAuditSession(aws_profile)

        #--------------------------
        # Create inventories via AWSCollectors
        #--------------------------
        logging.info("Begin Collection")
        collector_engine = AWSCollectors()
        collected_inventories = collector_engine.collect(audit_session)
        logging.info("\tCollection Complete")

        #--------------------------
        # Work through checks
        #--------------------------
        logging.info("Begin Checks")
        aws_auditor_findings = AWSAuditEngine().audit(collected_inventories)
        logging.info("\tChecks Complete")

        #--------------------------
        # Generate Report
        #--------------------------
        logging.info("Begin Report Generation")
        aws_findings_report = awsReportGenerator()
        aws_findings_report.generate(aws_auditor_findings, OUTPUT, PRINT)

    except ProfileNotFound:
        logging.exception(f"Passed profile does not exist [ {aws_profile} ]")
        logging.exception(f"Run 'aws configure list-profiles' for valid profiles")

    except NoCredentialsError:
        logging.error(f"Profile has no valid AWS credentials [ {aws_profile} ]")
        logging.error(f"Run 'aws configure --profile {aws_profile}' to configure")

    except ClientError as e:
        logging.exception(f"AWS API Error encountered [ {e.response['Error']['Message']} ]")


#==========================================================================
# Main
#==========================================================================
def main():

    # Grab the script version
    script_version = sys.argv[0]

    # Initial Help Menu Output
    parser = argparse.ArgumentParser(
        prog = script_version,
        description = "AWS Secure Configuration Auditor",
        formatter_class = argparse.RawDescriptionHelpFormatter,
        epilog = textwrap.dedent(f'''
            Examples:
                Show options associated with script
                    => python3 {script_version} -h
                
            '''))

    # Start considering logging
    global verbose_logging
    verbose_logging = False

    # Set some 'global' options
    parser.add_argument("-a", "--aws_profile", required=True, help="AWS Profile used for connection")
    parser.add_argument("-v", "--verbose", action="store_true", help="Logging output will be verbose")
    parser.add_argument('-p', '--print', action='store_true', help='Print results to STDOUT only')
    parser.add_argument('-o', '--output', help='Specify audit report path/name')

    #========================
    # Process Passed Arguments
    #========================
    args = parser.parse_args()

    # Set logging levels
    if args.verbose:
        logging.basicConfig(level=logging.DEBUG, format='%(asctime)s \t[[ %(levelname)s ]] \t%(message)s',datefmt='%Y-%m-%d %I:%M:%S %p')
    else:
        logging.basicConfig(level=logging.INFO, format='%(asctime)s \t[[ %(levelname)s ]] \t%(message)s',datefmt='%Y-%m-%d %I:%M:%S %p')

    # Handle some global variables
    global OUTPUT
    global PRINT

    # Determine output name (even if stdout only)
    output_filename = f"{CWD}{TIMESTAMP}_AWS_Findings.json"
    OUTPUT = args.output if args.output else output_filename

    # Determine print
    PRINT = args.print

    #========================
    # Begin Processing
    #========================
    awsSecurityAuditWrapper(args.aws_profile)


if __name__ == "__main__":
    main()
