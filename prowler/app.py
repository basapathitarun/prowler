#flask
from flask import Flask, render_template, request
import os
from prowler.lib.check.check import (
    bulk_load_checks_metadata,
    bulk_load_compliance_frameworks,
    execute_checks,
)
from prowler.lib.check.checks_loader import load_checks_to_execute
from prowler.lib.check.compliance import update_checks_metadata_with_compliance
from prowler.lib.cli.parser import ProwlerArgumentParser
from prowler.lib.logger import  set_logging_config
from prowler.lib.outputs.compliance import display_compliance_table
# from prowler.lib.logger import logger
# from prowler.lib.outputs.outputs import extract_findings_statistics

from prowler.providers.common.audit_info import (
    set_provider_audit_info,

)
from prowler.providers.common.outputs import set_provider_output_options

from database.insertdb import mongo_conn
from database.insertdb import upload_file
import gridfs

app = Flask(__name__)

dict_compliance={1: 'aws_audit_manager_control_tower_guardrails_aws', 2: 'aws_foundational_security_best_practices_aws', 3: 'aws_well_architected_framework_reliability_pillar_aws', 4: 'aws_well_architected_framework_security_pillar_aws', 5: 'cisa_aws', 6: 'cis_1.4_aws', 7: 'cis_1.5_aws', 8: 'cis_2.0_aws', 9: 'ens_rd2022_aws', 10: 'fedramp_low_revision_4_aws', 11: 'fedramp_moderate_revision_4_aws', 12: 'ffiec_aws', 13: 'gdpr_aws', 14: 'gxp_21_cfr_part_11_aws', 15: 'gxp_eu_annex_11_aws', 16: 'hipaa_aws', 17: 'iso27001_2013_aws', 18: 'mitre_attack_aws', 19: 'nist_800_171_revision_2_aws', 20: 'nist_800_53_revision_4_aws', 21: 'nist_800_53_revision_5_aws', 22: 'nist_csf_1.1_aws', 23: 'pci_3.2.1_aws', 24: 'rbi_cyber_security_framework_aws', 25: 'soc2_aws', 26: 'cis_2.0_gcp'}

@app.route('/')
def home():
    return render_template('index.html',dict_compliance=dict_compliance)

@app.route('/scan', methods=['POST'])
def scan_compliance():
    ans=int(request.form['compliance'])
    print(f"ans -> {ans}\n")
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
        services = None
        categories = []
        checks_file = None
        checks_folder = None
        severities = args.severity

        compliance_framework = [selected_compliance]
        # We treat the compliance framework as another output format
        if compliance_framework:
            args.output_modes.extend(compliance_framework)

        # Set Logger configuration
        set_logging_config(args.log_level, args.only_logs)

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
        # custom_checks_metadata = None

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
        allowlist_file = None

        # Set output options based on the selected provider
        audit_output_options = set_provider_output_options(
            provider, args, audit_info, allowlist_file, bulk_checks_metadata
        )

        # Execute checks
        findings = []

        custom_checks_metadata = None

        # changes -> file_descriptors.py
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

        # Display summary table
        if compliance_framework and findings:
            for compliance in compliance_framework:
                # Display compliance table
                compliance_table=display_compliance_table(
                    findings,
                    bulk_checks_metadata,
                    compliance,
                    audit_output_options.output_filename,
                    audit_output_options.output_directory,
                )

            print(f"compliance_table->{compliance_table}\n")
            file_loc = os.path.join(audit_output_options.output_directory, audit_output_options.output_filename,
                                    f"{compliance_framework[0]}.csv")

            print(f" -output-> CSV: {file_loc}\n")
                # adding to database
            file_name = f"{compliance_framework[0]}.csv"
            db = mongo_conn()
            fs = gridfs.GridFS(db, collection="output")
                # upload file
            upload_file(file_loc=file_loc, file_name=file_name, fs=fs)

        return render_template('output.html',compliance_table=compliance_table,file=file_name)


    except Exception as e:
        print(f"n error occured: {str(e)}\n")
        logger.error(f"An error occured: {str(e)}")
        return "An error occured during the scan."




#testing purpose
import sys


from colorama import Fore, Style
from tabulate import tabulate

from prowler.config.config import orange_color
from prowler.lib.logger import logger


@app.route('/output')
def display_compliance_table(
        findings: list,
        bulk_checks_metadata: dict,
        compliance_framework: str,
        output_filename: str,
        output_directory: str,
):
    try:
        if "ens_rd2022_aws" == compliance_framework:
            marcos = {}
            compliance_table = {
                "Proveedor": [],
                "Marco/Categoria": [],
                "Estado": [],
                "Alto": [],
                "Medio": [],
                "Bajo": [],
                "Opcional": [],

            }
            pass_count = fail_count = 0
            for finding in findings:
                check = bulk_checks_metadata[finding.check_metadata.CheckID]
                check_compliances = check.Compliance
                for compliance in check_compliances:
                    if (
                            compliance.Framework == "ENS"
                            and compliance.Provider == "AWS"
                            and compliance.Version == "RD2022"
                    ):
                        compliance_version = compliance.Version
                        compliance_fm = compliance.Framework
                        compliance_provider = compliance.Provider
                        for requirement in compliance.Requirements:
                            for attribute in requirement.Attributes:
                                marco_categoria = (
                                    f"{attribute.Marco}/{attribute.Categoria}"
                                )
                                # Check if Marco/Categoria exists
                                if marco_categoria not in marcos:
                                    marcos[marco_categoria] = {
                                        "Estado": f"{Fore.GREEN}CUMPLE{Style.RESET_ALL}",
                                        "Opcional": 0,
                                        "Alto": 0,
                                        "Medio": 0,
                                        "Bajo": 0,
                                    }
                                if finding.status == "FAIL":
                                    if attribute.Tipo != "recomendacion":
                                        fail_count += 1
                                    marcos[marco_categoria][
                                        "Estado"
                                    ] = f"{Fore.RED}NO CUMPLE{Style.RESET_ALL}"
                                elif finding.status == "PASS":
                                    pass_count += 1
                                if attribute.Nivel == "opcional":
                                    marcos[marco_categoria]["Opcional"] += 1
                                elif attribute.Nivel == "alto":
                                    marcos[marco_categoria]["Alto"] += 1
                                elif attribute.Nivel == "medio":
                                    marcos[marco_categoria]["Medio"] += 1
                                elif attribute.Nivel == "bajo":
                                    marcos[marco_categoria]["Bajo"] += 1

            # Add results to table
            for marco in sorted(marcos):
                compliance_table["Proveedor"].append(compliance.Provider)
                compliance_table["Marco/Categoria"].append(marco)
                compliance_table["Estado"].append(marcos[marco]["Estado"])
                compliance_table["Opcional"].append(
                    f"{Fore.BLUE}{marcos[marco]['Opcional']}{Style.RESET_ALL}"
                )
                compliance_table["Alto"].append(
                    f"{Fore.LIGHTRED_EX}{marcos[marco]['Alto']}{Style.RESET_ALL}"
                )
                compliance_table["Medio"].append(
                    f"{orange_color}{marcos[marco]['Medio']}{Style.RESET_ALL}"
                )
                compliance_table["Bajo"].append(
                    f"{Fore.YELLOW}{marcos[marco]['Bajo']}{Style.RESET_ALL}"
                )

            if fail_count + pass_count < 0:
                print(
                    f"\n {Style.BRIGHT}There are no resources for {Fore.YELLOW}{compliance_fm} {compliance_version} - {compliance_provider}{Style.RESET_ALL}.\n"
                )
            else:
                print(
                    f"\nEstado de Cumplimiento de {Fore.YELLOW}{compliance_fm} {compliance_version} - {compliance_provider}{Style.RESET_ALL}:"
                )
                overview_table = [
                    [
                        f"{Fore.RED}{round(fail_count / (fail_count + pass_count) * 100, 2)}% ({fail_count}) NO CUMPLE{Style.RESET_ALL}",
                        f"{Fore.GREEN}{round(pass_count / (fail_count + pass_count) * 100, 2)}% ({pass_count}) CUMPLE{Style.RESET_ALL}",
                    ]
                ]
                print(tabulate(overview_table, tablefmt="rounded_grid"))
                print(
                    f"\nResultados de {Fore.YELLOW}{compliance_fm} {compliance_version} - {compliance_provider}{Style.RESET_ALL}:"
                )
                print(
                    tabulate(
                        compliance_table, headers="keys", tablefmt="rounded_grid"
                    )
                )
                print(
                    f"{Style.BRIGHT}* Solo aparece el Marco/Categoria que contiene resultados.{Style.RESET_ALL}"
                )
                print(f"\nResultados detallados de {compliance_fm} en:")
                print(
                    f" -output-> CSV: {output_directory}/{output_filename}_{compliance_framework}.csv\n"
                )

                return compliance_table

        elif "cis_" in compliance_framework:
            sections = {}
            compliance_table = {
                "Provider": [],
                "Section": [],
                "Level 1": [],
                "Level 2": [],
            }
            pass_count = fail_count = 0
            for finding in findings:
                check = bulk_checks_metadata[finding.check_metadata.CheckID]
                check_compliances = check.Compliance
                for compliance in check_compliances:
                    if (
                            compliance.Framework == "CIS"
                            and compliance.Version in compliance_framework
                    ):
                        compliance_version = compliance.Version
                        compliance_fm = compliance.Framework
                        for requirement in compliance.Requirements:
                            for attribute in requirement.Attributes:
                                section = attribute.Section
                                # Check if Section exists
                                if section not in sections:
                                    sections[section] = {
                                        "Status": f"{Fore.GREEN}PASS{Style.RESET_ALL}",
                                        "Level 1": {"FAIL": 0, "PASS": 0},
                                        "Level 2": {"FAIL": 0, "PASS": 0},
                                    }
                                if finding.status == "FAIL":
                                    fail_count += 1
                                elif finding.status == "PASS":
                                    pass_count += 1
                                if attribute.Profile == "Level 1":
                                    if finding.status == "FAIL":
                                        sections[section]["Level 1"]["FAIL"] += 1
                                    else:
                                        sections[section]["Level 1"]["PASS"] += 1
                                elif attribute.Profile == "Level 2":
                                    if finding.status == "FAIL":
                                        sections[section]["Level 2"]["FAIL"] += 1
                                    else:
                                        sections[section]["Level 2"]["PASS"] += 1

            # Add results to table
            sections = dict(sorted(sections.items()))
            for section in sections:
                compliance_table["Provider"].append(compliance.Provider)
                compliance_table["Section"].append(section)
                if sections[section]["Level 1"]["FAIL"] > 0:
                    compliance_table["Level 1"].append(
                        f"{Fore.RED}FAIL({sections[section]['Level 1']['FAIL']}){Style.RESET_ALL}"
                    )
                else:
                    compliance_table["Level 1"].append(
                        f"{Fore.GREEN}PASS({sections[section]['Level 1']['PASS']}){Style.RESET_ALL}"
                    )
                if sections[section]["Level 2"]["FAIL"] > 0:
                    compliance_table["Level 2"].append(
                        f"{Fore.RED}FAIL({sections[section]['Level 2']['FAIL']}){Style.RESET_ALL}"
                    )
                else:
                    compliance_table["Level 2"].append(
                        f"{Fore.GREEN}PASS({sections[section]['Level 2']['PASS']}){Style.RESET_ALL}"
                    )


            if fail_count + pass_count < 1:
                print(
                    f"\n {Style.BRIGHT}There are no resources for {Fore.YELLOW}{compliance_fm}-{compliance_version}{Style.RESET_ALL}.\n"
                )
            else:
                print(
                    f"\nCompliance Status of {Fore.YELLOW}{compliance_fm}-{compliance_version}{Style.RESET_ALL} Framework:"
                )
                overview_table = [
                    [
                        f"{Fore.RED}{round(fail_count / (fail_count + pass_count) * 100, 2)}% ({fail_count}) FAIL{Style.RESET_ALL}",
                        f"{Fore.GREEN}{round(pass_count / (fail_count + pass_count) * 100, 2)}% ({pass_count}) PASS{Style.RESET_ALL}",
                    ]
                ]
                print(tabulate(overview_table, tablefmt="rounded_grid"))
                print(
                    f"\nFramework {Fore.YELLOW}{compliance_fm}-{compliance_version}{Style.RESET_ALL} Results:"
                )
                print(
                    tabulate(
                        compliance_table, headers="keys", tablefmt="rounded_grid"
                    )
                )
                print(
                    f"{Style.BRIGHT}* Only sections containing results appear.{Style.RESET_ALL}"
                )
                print(f"\nDetailed results of {compliance_fm} are in:")
                print(
                    f" -output-> CSV: {output_directory}/{output_filename}_{compliance_framework}.csv\n"

                )
                return compliance_table
        elif "mitre_attack" in compliance_framework:
            tactics = {}
            compliance_table = {
                "Provider": [],
                "Tactic": [],
                "Status": [],
            }
            pass_count = fail_count = 0
            for finding in findings:
                check = bulk_checks_metadata[finding.check_metadata.CheckID]
                check_compliances = check.Compliance
                for compliance in check_compliances:
                    if (
                            "MITRE-ATTACK" in compliance.Framework
                            and compliance.Version in compliance_framework
                    ):
                        compliance_fm = compliance.Framework
                        for requirement in compliance.Requirements:
                            for tactic in requirement.Tactics:
                                if tactic not in tactics:
                                    tactics[tactic] = {"FAIL": 0, "PASS": 0}
                                if finding.status == "FAIL":
                                    fail_count += 1
                                    tactics[tactic]["FAIL"] += 1
                                elif finding.status == "PASS":
                                    pass_count += 1
                                    tactics[tactic]["PASS"] += 1

            # Add results to table
            tactics = dict(sorted(tactics.items()))
            for tactic in tactics:
                compliance_table["Provider"].append(compliance.Provider)
                compliance_table["Tactic"].append(tactic)
                if tactics[tactic]["FAIL"] > 0:
                    compliance_table["Status"].append(
                        f"{Fore.RED}FAIL({tactics[tactic]['FAIL']}){Style.RESET_ALL}"
                    )
                else:
                    compliance_table["Status"].append(
                        f"{Fore.GREEN}PASS({tactics[tactic]['PASS']}){Style.RESET_ALL}"
                    )

            if fail_count + pass_count < 1:
                print(
                    f"\n {Style.BRIGHT}There are no resources for {Fore.YELLOW}{compliance_fm}{Style.RESET_ALL}.\n"
                )
            else:
                print(
                    f"\nCompliance Status of {Fore.YELLOW}{compliance_fm}{Style.RESET_ALL} Framework:"
                )
                overview_table = [
                    [
                        f"{Fore.RED}{round(fail_count / (fail_count + pass_count) * 100, 2)}% ({fail_count}) FAIL{Style.RESET_ALL}",
                        f"{Fore.GREEN}{round(pass_count / (fail_count + pass_count) * 100, 2)}% ({pass_count}) PASS{Style.RESET_ALL}",
                    ]
                ]
                print(tabulate(overview_table, tablefmt="rounded_grid"))
                print(
                    f"\nFramework {Fore.YELLOW}{compliance_fm}{Style.RESET_ALL} Results:"
                )
                print(
                    tabulate(
                        compliance_table, headers="keys", tablefmt="rounded_grid"
                    )
                )
                print(
                    f"{Style.BRIGHT}* Only sections containing results appear.{Style.RESET_ALL}"
                )
                print(f"\nDetailed results of {compliance_fm} are in:")
                print(
                    f" -output-> CSV: {output_directory}/{output_filename}_{compliance_framework}.csv\n"
                )
                return compliance_table
        else:
            print(f"\nDetailed results of {compliance_framework.upper()} are in:")
            print(
                f" -output-> CSV: {output_directory}/{output_filename}_{compliance_framework}.csv\n"
            )


    except Exception as error:
        logger.critical(
            f"{error.__class__.__name__}:{error.__traceback__.tb_lineno} -- {error}"
        )
        sys.exit(1)




# app.py
if __name__ == "__main__":
    app.run(host='0.0.0.0',port=8000)




