import boto3
from datetime import datetime
from dataclasses import dataclass, field
from botocore.config import Config

@dataclass
class AWS_Credentials:
    aws_access_key_id: str
    aws_session_token: str
    aws_secret_access_key: str
    expiration: datetime

@dataclass
class AWS_Organizations_Info:
    account_details_email: str
    account_details_name: str
    account_details_arn: str
    account_details_org: str
    account_details_tags: str

# Assuming you have AWS credentials configured, you can create a session using Boto3
session = boto3.Session()

# Use the STS service to get the account ID
sts_client = session.client('sts')
response = sts_client.get_caller_identity()

# Extract the account ID from the response
account_id = response['Account']

# Print the account ID
print("AWS Account ID:", account_id)
