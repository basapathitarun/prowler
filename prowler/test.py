from prowler.providers.common.audit_info import set_provider_audit_info
provider ='aws'
args={'version': False, 'provider': 'aws', 'quiet': False, 'output_modes': ['csv', 'json', 'html', 'json-ocsf', 'cis_1.4_aws'], 'output_filename': None, 'output_directory': '/home/cloudshell-user/prowler/prowler/output', 'verbose': False, 'ignore_exit_code_3': False, 'no_banner': False, 'slack': False, 'unix_timestamp': False, 'log_level': 'CRITICAL', 'log_file': None, 'only_logs': False, 'checks': None, 'checks_file': None, 'services': None, 'severity': None, 'compliance': None, 'categories': [], 'checks_folder': None, 'excluded_checks': None, 'excluded_services': None, 'list_checks': False, 'list_checks_json': False, 'list_services': False, 'list_compliance': False, 'list_compliance_requirements': None, 'list_categories': False, 'config_file': '/home/cloudshell-user/.local/lib/python3.9/site-packages/prowler/config/config.yaml', 'custom_checks_metadata_file': None, 'profile': None, 'role': None, 'role_session_name': 'ProwlerAssessmentSession', 'sts_endpoint_region': None, 'mfa': False, 'session_duration': 3600, 'external_id': None, 'region': None, 'organizations_role': None, 'security_hub': False, 'skip_sh_update': False, 'send_sh_only_fails': False, 'quick_inventory': False, 'output_bucket': None, 'output_bucket_no_assume': None, 'shodan': None, 'allowlist_file': None, 'resource_tags': None, 'resource_arn': None, 'aws_retries_max_attempts': None, 'ignore_unused_services': False}
set_provider_audit_info(provider, args.__dict__)