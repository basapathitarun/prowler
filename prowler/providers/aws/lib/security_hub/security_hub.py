from boto3 import session

from prowler.config.config import timestamp_utc
from prowler.lib.logger import logger
from prowler.lib.outputs.json import fill_json_asff
from prowler.lib.outputs.models import Check_Output_JSON_ASFF
from prowler.providers.aws.lib.audit_info.models import AWS_Audit_Info

SECURITY_HUB_INTEGRATION_NAME = "prowler/prowler"
SECURITY_HUB_MAX_BATCH = 100


def __send_findings_to_security_hub__(
    findings: [dict], region: str, security_hub_client
):
    """Private function send_findings_to_security_hub chunks the findings in groups of 100 findings and send them to AWS Security Hub. It returns the number of sent findings."""
    success_count = 0
    try:
        list_chunked = [
            findings[i : i + SECURITY_HUB_MAX_BATCH]
            for i in range(0, len(findings), SECURITY_HUB_MAX_BATCH)
        ]

        for findings in list_chunked:
            batch_import = security_hub_client.batch_import_findings(Findings=findings)
            if batch_import["FailedCount"] > 0:
                failed_import = batch_import["FailedFindings"][0]
                logger.error(
                    f"Failed to send findings to AWS Security Hub -- {failed_import['ErrorCode']} -- {failed_import['ErrorMessage']}"
                )
            success_count += batch_import["SuccessCount"]

    except Exception as error:
        logger.error(
            f"{error.__class__.__name__} -- [{error.__traceback__.tb_lineno}]:{error} in region {region}"
        )
    finally:
        return success_count
