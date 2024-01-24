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

# Use the Organizations service to retrieve account details
org_client = session.client('organizations')

# Replace 'your_account_id' with the actual AWS account ID
account_id = '720132924570'
account_details = org_client.describe_account(AccountId=account_id)['Account']

# Create an instance of AWS_Organizations_Info with retrieved values
aws_organizations_info = AWS_Organizations_Info(
    account_details_email=account_details['Email'],
    account_details_name=account_details['Name'],
    account_details_arn=account_details['Arn'],
    account_details_org=account_details['JoinedMethod'],
    account_details_tags=str(account_details['Tags'])
)

# Print or use the retrieved information
print(aws_organizations_info)
