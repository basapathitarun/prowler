# import boto3
# import subprocess
#
# # Create a session using the default credential chain
# session = boto3.Session()
#
# # Retrieve the current session credentials
# credentials = session.get_credentials()
#
# # Access Key ID
# access_key_id = credentials.access_key
#
# # Secret Access Key
# secret_access_key = credentials.secret_key
#
#
# # Create an AWS session
# session = boto3.Session(
#     aws_access_key_id=access_key_id,
#     aws_secret_access_key=secret_access_key,
# )
# print(access_key_id)
# print(secret_access_key)
# # Configure the AWS CLI with the provided credentials and region
# subprocess.run(['aws', 'configure', 'set', 'aws_access_key_id', access_key_id])
# subprocess.run(['aws', 'configure', 'set', 'aws_secret_access_key', secret_access_key])
#

compliance_framework = 'cis_1.5_aws'
file_loc = "prowler-output-906113748440-20240205110446"
file_loc = file_loc +"_"+compliance_framework+'.csv'

print(file_loc)