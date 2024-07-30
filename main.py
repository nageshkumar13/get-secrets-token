
import argparse
import json
import requests
import google.auth.transport.requests

from google.oauth2 import service_account
import json
import boto3
from botocore.exceptions import ClientError

def get_secret(secret_name):
    # Create a Secrets Manager client
    session = boto3.Session(profile_name='dd-sol',region_name="ap-south-1")
    client = session.client('secretsmanager')
    try:
        # Attempt to retrieve the secret value
        get_secret_value_response = client.get_secret_value(SecretId=secret_name)
    except ClientError as e:
        # Handle the exception if the secret can't be retrieved
        raise e

    # If there's no exception, process the retrieved secret
    if 'SecretString' in get_secret_value_response:
        secret = get_secret_value_response['SecretString']
    else:
        # For binary secrets, decode them before using
        secret = get_secret_value_response['SecretBinary'].decode('utf-8')
    return secret

# Example usage
secret_name = 'gcp-firebase-secret'
secret_value = get_secret(secret_name)
print(secret_value)

secret_dict = json.loads(secret_value)

# Convert dictionary to JSON string and write to a file
with open('secret.json', 'w') as json_file:
    json.dump(secret_dict, json_file)

SCOPES = ['https://www.googleapis.com/auth/firebase.messaging']
def _get_access_token():
  """Retrieve a valid access token that can be used to authorize requests.

  :return: Access token.
  """
  credentials = service_account.Credentials.from_service_account_file(
    'secret.json', scopes=SCOPES)
  request = google.auth.transport.requests.Request()
  credentials.refresh(request)
  return credentials.token
# [END retrieve_access_token]    

token = _get_access_token()
print('token : ',token)
