import base64
from datetime import datetime, UTC
from azure.identity import DefaultAzureCredential, ClientSecretCredential
from azure.keyvault.certificates import (
    CertificateClient,
    CertificatePolicy,
    CertificateContentType,
)
import requests

# -------------------- Configuration --------------------
TENANT_ID = ""
APPLICATION_CLIENT_ID = ""
APPLICATION_OBJECT_ID = ""
APPLICATION_SECRET = ""
VAULT_NAME = ""
CERTIFICATE_NAME = ""
CERTIFICATE_EXPIRY_MONTHS = 1

# Generating the vault URL based on your vault name.
VAULT_URL = f"https://{VAULT_NAME}.vault.azure.net/"

def generate_certificate() -> tuple[str, datetime]:
    """
    Created a new certificate inside the Azure Keyvault.

    Returns a base64 version of the public key of the certificate and the expiry date.
    """
    credential = DefaultAzureCredential()
    cert_client = CertificateClient(vault_url=VAULT_URL, credential=credential)
    policy = CertificatePolicy(
        issuer_name="Self",
        subject="CN=AppCert",
        validity_in_months=CERTIFICATE_EXPIRY_MONTHS,
        content_type=CertificateContentType.pem,
        exportable=False,
        reuse_key=False,
        key_type="RSA",
        key_size=2048,
    )
    operation = cert_client.begin_create_certificate(
        certificate_name=CERTIFICATE_NAME, policy=policy
    )
    return base64.b64encode(operation.result().cer).decode(
        "utf-8"
    ), operation.result().properties.expires_on


def add_certificate(certificate: str, expiry_date: datetime):
    """
    Adds a new certificate to the Application Registration. Note that
    this removes any existing certificates associated with the Application
    Registration.
    """
    credentials = ClientSecretCredential(
        tenant_id=TENANT_ID,
        client_id=APPLICATION_CLIENT_ID,
        client_secret=APPLICATION_SECRET,
    )
    graph_token = credentials.get_token("https://graph.microsoft.com/.default").token

    headers = {
        "Authorization": f"Bearer {graph_token}",
        "Content-Type": "application/json",
    }
    new_cert_payload = {
        "keyCredentials": [
            {
                "type": "AsymmetricX509Cert",
                "usage": "Verify",
                "key": certificate,
                "displayName": CERTIFICATE_NAME,
                "startDateTime": datetime.now(UTC).isoformat() + "Z",
                "endDateTime": expiry_date.isoformat() + "Z",
            }
        ]
    }
    patch_url = f"https://graph.microsoft.com/v1.0/applications/{APPLICATION_OBJECT_ID }"
    response = requests.patch(
        patch_url, headers=headers, json=new_cert_payload, timeout=15
    )
    if response.status_code == 204:
        print("Added Certificate to app.")
    else:
        print(f"Something went wrong: {response.text}")


def main():
    """
    Main logic.
    """
    cert, expiry_date = generate_certificate()
    add_certificate(cert, expiry_date)

if __name__ == "__main__":
    main()
