import sys

from botocore.config import Config
from colorama import Fore, Style

from prowler.config.config import load_and_validate_config_file
from prowler.lib.logger import logger
from prowler.providers.aws.aws_provider import (
    AWS_Provider,
    assume_role,
    get_aws_enabled_regions,
    get_checks_from_input_arn,
    get_regions_from_audit_resources,
)
from prowler.providers.aws.lib.arn.arn import parse_iam_credentials_arn
from prowler.providers.aws.lib.audit_info.audit_info import current_audit_info
from prowler.providers.aws.lib.audit_info.models import AWS_Audit_Info, AWS_Credentials
from prowler.providers.aws.lib.credentials.credentials import (
    print_aws_credentials,
    validate_aws_credentials,
)
from prowler.providers.aws.lib.organizations.organizations import (
    get_organizations_metadata,
)
from prowler.providers.aws.lib.resource_api_tagging.resource_api_tagging import (
    get_tagged_resources,
)
from prowler.providers.azure.azure_provider import Azure_Provider
from prowler.providers.azure.lib.audit_info.audit_info import azure_audit_info
from prowler.providers.azure.lib.audit_info.models import (
    Azure_Audit_Info,
    Azure_Region_Config,
)
from prowler.providers.azure.lib.exception.exception import AzureException
from prowler.providers.gcp.gcp_provider import GCP_Provider
from prowler.providers.gcp.lib.audit_info.audit_info import gcp_audit_info
from prowler.providers.gcp.lib.audit_info.models import GCP_Audit_Info



class Audit_Info:
    def __init__(self):
        logger.info("Setting Audit Info ...")
    def set_aws_audit_info(self, arguments) -> AWS_Audit_Info:
        """
        set_aws_audit_info returns the AWS_Audit_Info
        """
        logger.info("Setting AWS session ...")

        # Assume Role Options
        input_role = arguments.get("role")
        current_audit_info.assumed_role_info.role_arn = input_role
        input_session_duration = arguments.get("session_duration")
        input_external_id = arguments.get("external_id")
        input_role_session_name = arguments.get("role_session_name")

        # STS Endpoint Region
        sts_endpoint_region = arguments.get("sts_endpoint_region")

        # MFA Configuration (false by default)
        input_mfa = arguments.get("mfa")
        current_audit_info.mfa_enabled = input_mfa

        input_profile = arguments.get("profile")
        input_regions = arguments.get("region")
        organizations_role_arn = arguments.get("organizations_role")

        # Assumed AWS session
        assumed_session = None

        # Set the maximum retries for the standard retrier config
        aws_retries_max_attempts = arguments.get("aws_retries_max_attempts")
        if aws_retries_max_attempts:
            # Create the new config
            config = Config(
                retries={
                    "max_attempts": aws_retries_max_attempts,
                    "mode": "standard",
                },
            )
            # Merge the new configuration
            new_boto3_config = current_audit_info.session_config.merge(config)
            current_audit_info.session_config = new_boto3_config

        # Set ignore unused services argument
        current_audit_info.ignore_unused_services = arguments.get(
            "ignore_unused_services"
        )

        # Setting session
        current_audit_info.profile = input_profile
        current_audit_info.audited_regions = input_regions

        logger.info("Generating original session ...")
        # Create an global original session using only profile/basic credentials info
        aws_provider = AWS_Provider(current_audit_info)
        current_audit_info.original_session = aws_provider.aws_session
        logger.info("Validating credentials ...")
        # Verificate if we have valid credentials
        caller_identity = validate_aws_credentials(
            current_audit_info.original_session, input_regions, sts_endpoint_region
        )

        logger.info("Credentials validated")
        logger.info(f"Original caller identity UserId: {caller_identity['UserId']}")
        logger.info(f"Original caller identity ARN: {caller_identity['Arn']}")

        current_audit_info.audited_account = caller_identity["Account"]
        current_audit_info.audited_identity_arn = caller_identity["Arn"]
        current_audit_info.audited_user_id = caller_identity["UserId"]
        current_audit_info.audited_partition = parse_iam_credentials_arn(
            caller_identity["Arn"]
        ).partition
        current_audit_info.audited_account_arn = f"arn:{current_audit_info.audited_partition}:iam::{current_audit_info.audited_account}:root"

        logger.info("Checking if role assumption is needed ...")
        if input_role:
            current_audit_info.assumed_role_info.role_arn = input_role
            current_audit_info.assumed_role_info.session_duration = (
                input_session_duration
            )
            current_audit_info.assumed_role_info.external_id = input_external_id
            current_audit_info.assumed_role_info.mfa_enabled = input_mfa
            current_audit_info.assumed_role_info.role_session_name = (
                input_role_session_name
            )

            # Check if role arn is valid
            try:
                # this returns the arn already parsed into a dict to be used when it is needed to access its fields
                role_arn_parsed = parse_iam_credentials_arn(
                    current_audit_info.assumed_role_info.role_arn
                )

            except Exception as error:
                logger.critical(f"{error.__class__.__name__} -- {error}")
                sys.exit(1)

            else:
                logger.info(
                    f"Assuming role {current_audit_info.assumed_role_info.role_arn}"
                )
                # Assume the role
                assumed_role_response = assume_role(
                    aws_provider.aws_session,
                    aws_provider.role_info,
                    sts_endpoint_region,
                )
                logger.info("Role assumed")
                # Set the info needed to create a session with an assumed role
                current_audit_info.credentials = AWS_Credentials(
                    aws_access_key_id=assumed_role_response["Credentials"][
                        "AccessKeyId"
                    ],
                    aws_session_token=assumed_role_response["Credentials"][
                        "SessionToken"
                    ],
                    aws_secret_access_key=assumed_role_response["Credentials"][
                        "SecretAccessKey"
                    ],
                    expiration=assumed_role_response["Credentials"]["Expiration"],
                )
                # new session is needed
                assumed_session = aws_provider.set_session(current_audit_info)

        if assumed_session:
            logger.info("Audit session is the new session created assuming role")
            current_audit_info.audit_session = assumed_session
            current_audit_info.audited_account = role_arn_parsed.account_id
            current_audit_info.audited_partition = role_arn_parsed.partition
            current_audit_info.audited_account_arn = f"arn:{current_audit_info.audited_partition}:iam::{current_audit_info.audited_account}:root"
        else:
            logger.info("Audit session is the original one")
            current_audit_info.audit_session = current_audit_info.original_session

        logger.info("Checking if organizations role assumption is needed ...")
        if organizations_role_arn:
            current_audit_info.assumed_role_info.role_arn = organizations_role_arn
            current_audit_info.assumed_role_info.session_duration = (
                input_session_duration
            )
            current_audit_info.assumed_role_info.external_id = input_external_id
            current_audit_info.assumed_role_info.mfa_enabled = input_mfa

            # Check if role arn is valid
            try:
                # this returns the arn already parsed into a dict to be used when it is needed to access its fields
                role_arn_parsed = parse_iam_credentials_arn(
                    current_audit_info.assumed_role_info.role_arn
                )

            except Exception as error:
                logger.critical(f"{error.__class__.__name__} -- {error}")
                sys.exit(1)

            else:
                logger.info(
                    f"Getting organizations metadata for account {organizations_role_arn}"
                )
                assumed_credentials = assume_role(
                    aws_provider.aws_session,
                    aws_provider.role_info,
                    sts_endpoint_region,
                )
                current_audit_info.organizations_metadata = get_organizations_metadata(
                    current_audit_info.audited_account, assumed_credentials
                )
                logger.info("Organizations metadata retrieved")

        # Setting default region of session
        if current_audit_info.audit_session.region_name:
            current_audit_info.profile_region = (
                current_audit_info.audit_session.region_name
            )
        else:
            current_audit_info.profile_region = "us-east-1"

        if not arguments.get("only_logs"):
            print_aws_credentials(current_audit_info)

        # Parse Scan Tags
        if arguments.get("resource_tags"):
            input_resource_tags = arguments.get("resource_tags")
            current_audit_info.audit_resources = get_tagged_resources(
                input_resource_tags, current_audit_info
            )

        # Parse Input Resource ARNs
        if arguments.get("resource_arn"):
            current_audit_info.audit_resources = arguments.get("resource_arn")

        # Get Enabled Regions
        current_audit_info.enabled_regions = get_aws_enabled_regions(current_audit_info)

        return current_audit_info

    def set_aws_execution_parameters(self, provider, audit_info) -> list[str]:
        # Once the audit_info is set and we have the eventual checks from arn, it is time to exclude the others
        try:
            if audit_info.audit_resources:
                audit_info.audited_regions = get_regions_from_audit_resources(
                    audit_info.audit_resources
                )
                return get_checks_from_input_arn(audit_info.audit_resources, provider)
        except Exception as error:
            logger.critical(
                f"{error.__class__.__name__}[{error.__traceback__.tb_lineno}]: {error}"
            )
            sys.exit(1)




def set_provider_audit_info(provider: str, arguments: dict):
    """
    set_provider_audit_info configures automatically the audit session based on the selected provider and returns the audit_info object.
    """
    try:
        provider_set_audit_info = f"set_{provider}_audit_info"
        provider_audit_info = getattr(Audit_Info(), provider_set_audit_info)(arguments)

        # Set the audit configuration from the config file
        provider_audit_info.audit_config = load_and_validate_config_file(
            provider, arguments["config_file"]
        )
    except Exception as error:
        logger.critical(
            f"{error.__class__.__name__}[{error.__traceback__.tb_lineno}]: {error}"
        )
        sys.exit(1)
    else:
        return provider_audit_info

