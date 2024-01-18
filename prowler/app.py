#flask
from flask import Flask, render_template, request

import os
import sys

from prowler.lib.check.check import (
    bulk_load_checks_metadata,
    bulk_load_compliance_frameworks,
    execute_checks,

)
from prowler.lib.check.checks_loader import load_checks_to_execute
from prowler.lib.check.compliance import update_checks_metadata_with_compliance
from prowler.lib.cli.parser import ProwlerArgumentParser
from prowler.lib.logger import logger, set_logging_config
from prowler.lib.outputs.compliance import display_compliance_table
from prowler.lib.outputs.html import add_html_footer, fill_html_overview_statistics
from prowler.lib.outputs.json import close_json
from prowler.lib.outputs.outputs import extract_findings_statistics
from prowler.lib.outputs.summary_table import display_summary_table

from prowler.providers.common.allowlist import set_provider_allowlist
from prowler.providers.common.audit_info import (
    set_provider_audit_info,

)
from prowler.providers.common.outputs import set_provider_output_options


app = Flask(__name__)

dict_compliance={1: 'aws_audit_manager_control_tower_guardrails_aws', 2: 'aws_foundational_security_best_practices_aws', 3: 'aws_well_architected_framework_reliability_pillar_aws', 4: 'aws_well_architected_framework_security_pillar_aws', 5: 'cisa_aws', 6: 'cis_1.4_aws', 7: 'cis_1.5_aws', 8: 'cis_2.0_aws', 9: 'ens_rd2022_aws', 10: 'fedramp_low_revision_4_aws', 11: 'fedramp_moderate_revision_4_aws', 12: 'ffiec_aws', 13: 'gdpr_aws', 14: 'gxp_21_cfr_part_11_aws', 15: 'gxp_eu_annex_11_aws', 16: 'hipaa_aws', 17: 'iso27001_2013_aws', 18: 'mitre_attack_aws', 19: 'nist_800_171_revision_2_aws', 20: 'nist_800_53_revision_4_aws', 21: 'nist_800_53_revision_5_aws', 22: 'nist_csf_1.1_aws', 23: 'pci_3.2.1_aws', 24: 'rbi_cyber_security_framework_aws', 25: 'soc2_aws', 26: 'cis_2.0_gcp'}

@app.route('/')
def home():
    return render_template('index.html',dict_compliance=dict_compliance)

@app.route('/scan', methods=['POST'])
def scan_compliance():
    ans=int(request.form['compliance'])
    selected_compliance=dict_compliance[ans]
    print(f"selected_compliance-> {selected_compliance}")
    result = perform_prowler_scan(selected_compliance)
    return result

def perform_prowler_scan(selected_compliance):
    try:
        # Parse Arguments
        parser = ProwlerArgumentParser()
        args = parser.parse()

        # Save Arguments
        provider = args.provider
        checks = args.checks
        services = args.services
        categories = args.categories
        checks_file = args.checks_file
        severities = args.severity

        compliance_framework = selected_compliance
        # We treat the compliance framework as another output format
        if compliance_framework:
            args.output_modes.extend(compliance_framework)

        # Set Logger configuration
        set_logging_config(args.log_level, args.log_file, args.only_logs)

        # Load checks metadata
        logger.debug("Loading checks metadata from .metadata.json files")
        bulk_checks_metadata = bulk_load_checks_metadata(provider)

        bulk_compliance_frameworks = {}
        # Load compliance frameworks
        logger.debug("Loading compliance frameworks from .json files")

        bulk_compliance_frameworks = bulk_load_compliance_frameworks(provider)
        # Complete checks metadata with the compliance framework specification
        bulk_checks_metadata = update_checks_metadata_with_compliance(
            bulk_compliance_frameworks, bulk_checks_metadata
        )

        # Update checks metadata if the --custom-checks-metadata-file is present
        custom_checks_metadata = None

        # Load checks to execute
        checks_to_execute = load_checks_to_execute(
            bulk_checks_metadata,
            bulk_compliance_frameworks,
            checks_file,
            checks,
            services,
            severities,
            compliance_framework,
            categories,
            provider,
        )

        # Set the audit info based on the selected provider
        audit_info = set_provider_audit_info(provider, args.__dict__)

        # Sort final check list
        checks_to_execute = sorted(checks_to_execute)

        # Parse Allowlist
        allowlist_file = set_provider_allowlist(provider, audit_info, args)

        # Set output options based on the selected provider
        audit_output_options = set_provider_output_options(
            provider, args, audit_info, allowlist_file, bulk_checks_metadata
        )

        # Execute checks
        findings = []
        if len(checks_to_execute):
            findings = execute_checks(
                checks_to_execute,
                provider,
                audit_info,
                audit_output_options,
                custom_checks_metadata,
            )
        else:
            logger.error(
                "There are no checks to execute. Please, check your input arguments"
            )

        # Extract findings stats
        stats = extract_findings_statistics(findings)

        if args.output_modes:
            for mode in args.output_modes:
                # Close json file if exists
                if "json" in mode:
                    close_json(
                        audit_output_options.output_filename, args.output_directory, mode
                    )
                if mode == "html":
                    add_html_footer(
                        audit_output_options.output_filename, args.output_directory
                    )
                    fill_html_overview_statistics(
                        stats, audit_output_options.output_filename, args.output_directory
                    )

        # Display summary table
        if not args.only_logs:
            display_summary_table(
                findings,
                audit_info,
                audit_output_options,
                provider,
            )

            if compliance_framework and findings:
                for compliance in compliance_framework:
                    # Display compliance table
                    display_compliance_table(
                        findings,
                        bulk_checks_metadata,
                        compliance,
                        audit_output_options.output_filename,
                        audit_output_options.output_directory,
                    )

        # If there are failed findings exit code 3, except if -z is input
        if not args.ignore_exit_code_3 and stats["total_fail"] > 0:
            # sys.exit(3)
            return "prowler Scan failed\n"
        else:
            return "prowler Scan sucessfull\n"

    except Exception as e:
        logger.error(f"An error occured: {str(e)}")
        return "An error occured during the scan."


# app.py
if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000, debug=True)





