import base64
import hashlib
import json
import uuid
import time
from datetime import UTC, datetime

import requests
from azure.identity import (
    ChainedTokenCredential,
    ClientAssertionCredential,
    DefaultAzureCredential,
)
from azure.keyvault.certificates import (
    CertificateClient,
    CertificatePolicy,
    CertificateContentType,
    KeyVaultCertificate,
)
from azure.keyvault.keys.crypto import CryptographyClient, SignatureAlgorithm


# -------------------- Configuration --------------------

# TODO: Add your values here:
TENANT_ID = ""
APPLICATION_CLIENT_ID = ""
APPLICATION_OBJECT_ID = ""
VAULT_NAME = ""
CERTIFICATE_NAME = ""
CERTIFICATE_EXPIRY_MONTHS = 1

# Generating the vault URL based on your vault name.
VAULT_URL = f"https://{VAULT_NAME}.vault.azure.net/"


# -------------------- Classes --------------------

class AssertionTokenMixin:
    """
    Mixin class providing methods for generating signed JWTs and Proof of Possession (PoP) tokens
    using certificates stored in Azure Key Vault.

    This class is intended to be used alongside credential classes such as ClientAssertionCredential
    to support advanced authentication scenarios, including certificate-based access and secure
    key rotation workflows.
    """

    def _get_signed_jwt(self) -> str:
        """
        Creates a signed JWT, without retrieving the private key from the azure keyvault.

        Returns:
            str: A signed JWT string suitable for use with Entra ID token endpoints
        """
        crypto_client = CryptographyClient(self.certificate.key_id, self.credential)
        header = {
            "alg": "RS256",
            "typ": "JWT",
            "x5t": self._base64url_encode(self.certificate.properties.x509_thumbprint),
        }
        now = int(time.time())
        payload = {
            "aud": f"https://login.microsoftonline.com/{self.tenant_id}/oauth2/v2.0/token",
            "iss": self.client_id,
            "sub": self.client_id,
            "jti": str(uuid.uuid4()),
            "nbf": now,
            "exp": now + 600,
        }
        encoded_header = self._base64url_encode(json.dumps(header).encode())
        encoded_payload = self._base64url_encode(json.dumps(payload).encode())
        unsigned_jwt = f"{encoded_header}.{encoded_payload}"
        digest = hashlib.sha256(unsigned_jwt.encode()).digest()
        signature = crypto_client.sign(SignatureAlgorithm.rs256, digest).signature
        encoded_signature = self._base64url_encode(signature)
        return f"{unsigned_jwt}.{encoded_signature}"

    def get_pop_token(self) -> str:
        """

        Generates a Proof of Possession (PoP) token to demonstrate ownership of the private key
        associated with a certificate stored in Azure Key Vault.

        This token is typically required when performing sensitive operations such as rotating
        application credentials via Microsoft Graph (e.g., `addKey` API).

        Args:
            audience (str): The intended audience for the PoP token, typically the Graph API
            endpoint.

        Returns:
            str: A signed PoP token containing a `cnf` claim and other required fields.
        """

        windows_azure_active_directory_appication_id = (
            "00000002-0000-0000-c000-000000000000"
        )
        crypto_client = CryptographyClient(self.certificate.key_id, self.credential)
        x5c_chain = [self._base64url_encode(self.certificate.cer)]
        header = {
            "alg": "RS256",
            "typ": "JWT",
            "x5c": x5c_chain,
        }
        now = int(time.time())
        payload = {
            "aud": windows_azure_active_directory_appication_id,
            "iss": self.object_id,
            "sub": self.object_id,
            "jti": str(uuid.uuid4()),
            "nbf": now,
            "exp": now + 600,
        }
        encoded_header = self._base64url_encode(json.dumps(header).encode())
        encoded_payload = self._base64url_encode(json.dumps(payload).encode())
        unsigned_jwt = f"{encoded_header}.{encoded_payload}"
        digest = hashlib.sha256(unsigned_jwt.encode()).digest()
        signature = crypto_client.sign(SignatureAlgorithm.rs256, digest).signature
        encoded_signature = self._base64url_encode(signature)
        return f"{unsigned_jwt}.{encoded_signature}"

    @staticmethod
    def _base64url_encode(data: bytes) -> str:
        """
        Encodes bytes into a URL-safe Base64 string without padding.
        """
        return base64.urlsafe_b64encode(data).decode().rstrip("=")


class CustomAssertionCredential(ClientAssertionCredential, AssertionTokenMixin):
    """
    Custom wrapper around the ClientAssertionCredential class, allowing for seamles
    integration with Azure Key Vault and generation of PoP (Proof of Possesion)
    tokens.
    """

    def __init__(
        self,
        credential: ChainedTokenCredential,
        vault_name: str,
        tenant_id: str,
        client_id: str,
        object_id: str,
        certificate_name: str,
    ):
        """
        Creates a CustomAssertionCredential.
        """
        self.credential = credential
        self.vault_name = vault_name
        self.tenant_id = tenant_id
        self.client_id = client_id
        self.object_id = object_id
        self.certificate_name = certificate_name

        self.certificate: KeyVaultCertificate = CertificateClient(
            vault_url=f"https://{self.vault_name}.vault.azure.net/",
            credential=self.credential,
        ).get_certificate(self.certificate_name)

        super().__init__(
            tenant_id=self.tenant_id,
            client_id=self.client_id,
            func=self._get_signed_jwt,
        )


# -------------------- Execution --------------------


def generate_certificate(
    credential: ChainedTokenCredential,
) -> tuple[str, datetime]:
    """
    Created a new certificate inside the Azure Keyvault.

    Returns a base64 version of the public key of the certificate.
    """
    cert_client = CertificateClient(vault_url=VAULT_URL, credential=credential)
    policy = CertificatePolicy(
        issuer_name="Self",
        subject=f"CN={CERTIFICATE_NAME}",
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
    print("Generated certificate in keyvault")
    return base64.b64encode(operation.result().cer).decode(
        "utf-8"
    ), operation.result().properties.expires_on


def add_certificate_to_app(
    credential: CustomAssertionCredential,
    new_cert: str,
    expiry_date: datetime,
):
    """
    Adds a new certificate to the Application registration, leaving the old certificate intact.
    """
    headers = {
        "Authorization": f"Bearer {credential.get_token('https://graph.microsoft.com/.default').token}",
        "Content-Type": "application/json",
    }
    new_cert_payload = {
        "keyCredential": {
            "type": "AsymmetricX509Cert",
            "usage": "Verify",
            "key": new_cert,
            "displayName": "AddedViaPython",
            "startDateTime": datetime.now(UTC).isoformat() + "Z",
            "endDateTime": expiry_date.isoformat() + "Z",
        },
        "proof": credential.get_pop_token(),
    }
    patch_url = (
        f"https://graph.microsoft.com/v1.0/applications/{APPLICATION_OBJECT_ID}/addKey"
    )
    response = requests.post(
        patch_url, headers=headers, json=new_cert_payload, timeout=15
    )
    if response.status_code == 200:
        print("Added certificate to app")
    else:
        print(f"Something went wrong: {response.text}")


def main():
    """
    Main logic
    """
    credential = CustomAssertionCredential(
        credential=DefaultAzureCredential(),
        vault_name=VAULT_NAME,
        tenant_id=TENANT_ID,
        client_id=APPLICATION_CLIENT_ID,
        object_id=APPLICATION_OBJECT_ID,
        certificate_name=CERTIFICATE_NAME,
    )
    cert, expiry = generate_certificate(
        credential=credential,
    )
    add_certificate_to_app(
        credential=credential,
        new_cert=cert,
        expiry_date=expiry,
    )


if __name__ == "__main__":
    main()
