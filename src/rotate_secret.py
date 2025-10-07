from datetime import datetime, timedelta, UTC
from azure.identity import ClientSecretCredential
import requests

# TODO: Add the values from your Application Registration here:
TENANT_ID = ""
APPLICATION_CLIENT_ID = ""
APPLICATION_OBJECT_ID = ""
APPLICATION_SECRET = ""
# Don't hardcode secrets in production. Instead, fetch it from an Azure Key Vault.

# Using the existing credentials to authenticate to Entra ID and getting an authentication token
credentials = ClientSecretCredential(
    tenant_id=TENANT_ID,
    client_id=APPLICATION_CLIENT_ID,
    client_secret=APPLICATION_SECRET,
)
graph_token = credentials.get_token("https://graph.microsoft.com/.default").token

# Preparing the headers for our request
headers = {
    "Authorization": f"Bearer {graph_token}",
    "Content-Type": "application/json",
}

# Preparing the body for our request, were we define a new secret with an expiry date of 3 days
expiry_time = datetime.now(UTC) + timedelta(days=3)
body = {
    "passwordCredential": {
        "displayName": "AddedViaPython",
        "endDateTime": expiry_time.strftime("%Y-%m-%dT%H:%M:%SZ"),
    }
}

# The url to which we'll make our call
patch_url = (
    f"https://graph.microsoft.com/v1.0/applications/{APPLICATION_OBJECT_ID}/addPassword"
)

# Making the call and checking the result
response = requests.post(
    patch_url,
    headers=headers,
    json=body,
    timeout=15,
)
if response.status_code == 200:
    print("Added secret to app")
    print(f"New secret value: {response.json()['secretText']}")
else:
    print("something went wrong:")
    print(response.text)