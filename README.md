# Application Registration Secret Demo
A demo repository, containing scripts to automatically rotate Entra ID Application Registration secrets and certificates.
The project is described in these two blogs:
- [Secrets](https://medium.com/@TimGroothuis/application-registration-secrets-fire-forget-c447d4905698)
- [Certificates]()

# Required roles and permissions
### Graph permissions
For rotating credentials, the Application Registrations need the `Graph Application.ReadWrite.OwnedBy` permission and needs to be assigned
as an owner on itself. See the Secrets blog mentioned at the top of this Readme for details on how to do so.

### Keyvault permissions
Aside from Graph permissions, the **workload identity** running the script will need access to the Keyvault to create and use certificates.

| Script                | Required roles                 | 
|-----------------------|--------------------------------|
| rotate_secret         | None                           |
| secret_to_certificate | Key Vault Certificates Officer |
| rotate_certificate    | Key Vault Certificates Officer |

# Usage
- Set up a virtual environment
- Install the dependencies: `pip install -r requirements.txt`
- Fill out the constants at the top of the script you want to use.
- Authenticate to Azure locally (`Connect-AzaAccount` for Powershell, `az login` for CLI) or ensure you're running from a context that has a user or system assinged identity available
- Run the script of your choice: `python .\src\<scriptname>.py`
