import boto3
from dataclasses import dataclass, field
from botocore.config import Config
from datetime import datetime
from typing import Any, Optional

@dataclass
class AWS_Credentials:
    aws_access_key_id: str
    aws_secret_access_key: str
    expiration: datetime

@dataclass
class AWS_Audit_Info:
    original_session: boto3.Session
    audit_session: boto3.Session
    session_config: Config
    audited_account: int
    audited_account_arn: str
    audited_identity_arn: str
    audited_user_id: str
    audited_partition: str
    profile: str
    profile_region: str
    credentials: AWS_Credentials
    mfa_enabled: bool
    assumed_role_info: dict  # Assuming you don't have AWS_Assume_Role class, using dict for simplicity
    audited_regions: list
    audit_resources: list
    organizations_metadata: dict  # Assuming you don't have AWS_Organizations_Info class, using dict for simplicity
    audit_metadata: Optional[Any] = None
    audit_config: Optional[dict] = None
    ignore_unused_services: bool = False
    enabled_regions: set = field(default_factory=set)

# Replace 'your_access_key' and 'your_secret_key' with your actual AWS access key ID and secret access key
aws_access_key_id = 'AKIA2PK2EMSNKZJ22XSS'
aws_secret_access_key = 'Fe8iit/mVaQPH6SLBH77u9ml117vVPHFJuFexKHw'

# Create Boto3 session using the provided credentials
boto3_session = boto3.Session(
    aws_access_key_id=aws_access_key_id,
    aws_secret_access_key=aws_secret_access_key,
)

# Additional information
original_session = boto3_session
audit_session = boto3_session
session_config = Config()

# Populate other data (replace placeholders with actual values)
audited_account = 1234567890
audited_account_arn = "audited_account_arn"
audited_identity_arn = "audited_identity_arn"
audited_user_id = "audited_user_id"
audited_partition = "audited_partition"
profile = "your_profile"
profile_region = "your_profile_region"
mfa_enabled = False  # Assuming MFA is not enabled for simplicity
assumed_role_info = {}  # Assuming you don't have AWS_Assume_Role class, using dict for simplicity
audited_regions = ["us-east-1", "us-west-2"]
audit_resources = ["resource1", "resource2"]
organizations_metadata = {}  # Assuming you don't have AWS_Organizations_Info class, using dict for simplicity

# Create an instance of AWS_Audit_Info
aws_audit_info = AWS_Audit_Info(
    original_session=original_session,
    audit_session=audit_session,
    session_config=session_config,
    audited_account=audited_account,
    audited_account_arn=audited_account_arn,
    audited_identity_arn=audited_identity_arn,
    audited_user_id=audited_user_id,
    audited_partition=audited_partition,
    profile=profile,
    profile_region=profile_region,
    credentials=AWS_Credentials(
        aws_access_key_id=aws_access_key_id,
        aws_secret_access_key=aws_secret_access_key,
        expiration=datetime.now()
    ),
    mfa_enabled=mfa_enabled,
    assumed_role_info=assumed_role_info,
    audited_regions=audited_regions,
    audit_resources=audit_resources,
    organizations_metadata=organizations_metadata
)

# Now you can access the values of the variables as needed
print(aws_audit_info.audited_account)  # Output: 1234567890
print(aws_audit_info.credentials.aws_access_key_id)  # Output: your_access_key
# Access other attributes similarly
