#!/usr/local/bin/python3
#==========================================================================
#
#           File : awsReportGenerator.py
#        Project : AWS-secure-configuration-auditor
#    Description : Converts the findings provided into dictionaries to be output in to json
#
#==========================================================================
#----------------
# Imports
#----------------
import logging
import os.path
import json
import sys
from .baseReporter import BaseReporter

class awsReportGenerator(BaseReporter):
    # Generate json report, if stdout-only else write to file
    def generate(self, passed_findings, output_file, stdout_only):
        report = {
            "summary": {
                "critical": 0,
                "high": 0,
                "medium": 0,
                "low": 0,
                "info": 0,
                "total_findings": 0
            },
            "findings": []
        }

        # Work through the returned findings
        for finding in passed_findings:

            # Add the dataclass converted to a dict to the findings array
            report["findings"].append(finding.convert_to_dict())

            # Update counts
            if finding.severity_level == "CRITICAL":
                report["summary"]["critical"] += 1
                report["summary"]["total_findings"] += 1
            elif finding.severity_level == "HIGH":
                report["summary"]["high"] += 1
                report["summary"]["total_findings"] += 1
            elif finding.severity_level == "MEDIUM":
                report["summary"]["medium"] += 1
                report["summary"]["total_findings"] += 1
            elif finding.severity_level == "LOW":
                report["summary"]["low"] += 1
                report["summary"]["total_findings"] += 1
            elif finding.severity_level == "INFO":
                report["summary"]["info"] += 1
                report["summary"]["total_findings"] += 1

        # After working through the findings, add the summary to the array
        report["findings"].insert(0, report["summary"])

        # Create json output
        findings_summary_json = json.dumps(report["findings"], indent=4, sort_keys=False)

        logging.info(f'Analysis Complete [ Events: {report["summary"]["total_findings"]} | Critical: {report["summary"]["critical"]} | High: {report["summary"]["high"]} | Medium: {report["summary"]["medium"]} | Low: {report["summary"]["low"]} | Info: {report["summary"]["info"]} ]')
        logging.info(f"Generating findings report")

        # Output based on specifications passed
        if stdout_only:
            print(findings_summary_json)
        else:
            output_basename = os.path.basename(output_file)
            try:
                with open(output_file, "w") as file:
                    file.write(findings_summary_json)
                logging.info(f"Report written to [ {output_basename} ]")
            except PermissionError:
                logging.exception(f"Failed to write output file [ {output_basename} ] - Permission Error")
                print(findings_summary_json)
            except IOError as e:
                logging.exception(f"Failed to write output file [ {output_basename} ] - I/O Error : {e}")
                print(findings_summary_json)
            except Exception as ee:
                logging.exception(f"Failed to write output file [ {output_basename} ] - Unexpected error {ee}")
                print(findings_summary_json)
