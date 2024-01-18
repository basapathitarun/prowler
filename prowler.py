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
# dict_compliance={1: 'aws_audit_manager_control_tower_guardrails_aws', 2: 'aws_foundational_security_best_practices_aws', 3: 'aws_well_architected_framework_reliability_pillar_aws', 4: 'aws_well_architected_framework_security_pillar_aws', 5: 'cisa_aws', 6: 'cis_1.4_aws', 7: 'cis_1.5_aws', 8: 'cis_2.0_aws', 9: 'ens_rd2022_aws', 10: 'fedramp_low_revision_4_aws', 11: 'fedramp_moderate_revision_4_aws', 12: 'ffiec_aws', 13: 'gdpr_aws', 14: 'gxp_21_cfr_part_11_aws', 15: 'gxp_eu_annex_11_aws', 16: 'hipaa_aws', 17: 'iso27001_2013_aws', 18: 'mitre_attack_aws', 19: 'nist_800_171_revision_2_aws', 20: 'nist_800_53_revision_4_aws', 21: 'nist_800_53_revision_5_aws', 22: 'nist_csf_1.1_aws', 23: 'pci_3.2.1_aws', 24: 'rbi_cyber_security_framework_aws', 25: 'soc2_aws', 26: 'cis_2.0_gcp'}

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