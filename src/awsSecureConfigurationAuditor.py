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

from pathlib import Path
import textwrap
from datetime import datetime

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
    parser.add_argument("-a", "--aws", action="store_true", help="AWS environment to be audited")
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

if __name__ == "__main__":
    main()
