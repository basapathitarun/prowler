from prowler.config.config import (
    csv_file_suffix,
    html_file_suffix,
    json_asff_file_suffix,
    json_file_suffix,
    json_ocsf_file_suffix,
)
from prowler.lib.logger import logger



def get_s3_object_path(output_directory: str) -> str:
    bucket_remote_dir = output_directory
    if "prowler/" in bucket_remote_dir:  # Check if it is not a custom directory
        bucket_remote_dir = bucket_remote_dir.partition("prowler/")[-1]

    return bucket_remote_dir
