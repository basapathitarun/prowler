#!/usr/bin/env python3

import sys

from prowler.__main__ import prowler

if __name__ == "__main__":
    sys.exit(prowler())

# from flask import Flask, render_template, request
#
# from prowler.__main__ import prowler
#
# app = Flask(__name__)
#
# compliance = ['aws_audit_manager_control_tower_guardrails_aws', 'aws_foundational_security_best_practices_aws', 'aws_well_architected_framework_reliability_pillar_aws', 'aws_well_architected_framework_security_pillar_aws', 'cisa_aws', 'cis_1.4_aws', 'cis_1.5_aws', 'cis_2.0_aws', 'ens_rd2022_aws', 'fedramp_low_revision_4_aws', 'fedramp_moderate_revision_4_aws', 'ffiec_aws', 'gdpr_aws', 'gxp_21_cfr_part_11_aws', 'gxp_eu_annex_11_aws', 'hipaa_aws', 'iso27001_2013_aws', 'mitre_attack_aws', 'nist_800_171_revision_2_aws', 'nist_800_53_revision_4_aws', 'nist_800_53_revision_5_aws', 'nist_csf_1.1_aws', 'pci_3.2.1_aws', 'rbi_cyber_security_framework_aws', 'soc2_aws', 'cis_2.0_gcp']
#
# dict_compliance = {}
# i = 1
# for each in compliance:
#     dict_compliance[i]=each
#     i+=1
#
# @app.route('/')
# def home():
#     return render_template('index.html',dict_compliance=dict_compliance)
#
# @app.route('/scan', methods=['POST'])
# def scan_compliance():
#     ans=int(request.form['compliance'])
#     selected_complinace = dict_compliance[ans]
#     return prowler(selected_complinace)
#
# if __name__ == '__main__':
#     app.run(debug=True)