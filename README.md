# HelloID-Conn-SA-Full-Exchange-Online-DistributionGroupCreate

| :information_source: Information                                                                                                                                                                                                                                                                            |
| :---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| This repository contains the connector and configuration code only. The implementer is responsible for acquiring the connection details such as organization name, application ID, certificate, etc. You might need to coordinate with the client's application manager before implementing this connector. |

## Description
HelloID-Conn-SA-Full-Exchange-Online-DistributionGroupCreate is a template designed for use with HelloID Service Automation (SA) Delegated Forms. It can be imported into HelloID and customized according to your requirements.

By using this delegated form, you can create a Distribution Group (or a Mail-enabled Security Group) in Exchange Online using app-only authentication. The form workflow includes:
1. Select Distribution Group or Mail-enabled Security Group
2. Enter the group name and alias
   > Name and alias are validated for uniqueness in Entra ID
3. Select the mail domain for the group's email address
   > Email address is generated from the group name and selected domain
4. Optionally provide an alias (mailNickname) for the group
   > Alias is validated for uniqueness in Entra ID
5. Select members for the distribution group
   > Members are selected from a searchable list of Entra ID users
6. Select owners for the distribution group
   > Owners are selected from a searchable list of Entra ID users
7. Create the distribution group or mail-enabled security group
   > The distribution group or mail-enabled security group is created in Exchange Online with the specified name, alias, owners, and members.

## Getting started
### Requirements

#### App Registration & Certificate Setup

Before implementing this connector, configure a Microsoft Entra ID App Registration for Exchange Online app-only authentication and set up certificate-based auth. During setup, create a new App Registration, upload a certificate, and ensure appropriate Exchange Online RBAC permissions for app-only operations.

Follow the official Microsoft documentation for creating an App Registration and setting up certificate-based authentication:
- [App-only authentication with certificate (Exchange Online)](https://learn.microsoft.com/en-us/powershell/exchange/app-only-auth-powershell-v2?view=exchange-ps#set-up-app-only-authentication)

#### HelloID-specific configuration

Once you have completed the Microsoft setup and followed their best practices, configure the following HelloID-specific requirements.

- **Exchange Online RBAC:**
  - Assign an appropriate Exchange Online role (e.g., **Exchange Recipient Administrator**) to the App Registration for app-only access.
- **Certificate:**
  - Upload the public key file (.cer) in Entra ID.
  - Provide the certificate as a Base64 string in HelloID. For instructions on creating the certificate and obtaining the base64 string, refer to our forum post: [Setting up a certificate for Microsoft Graph API in HelloID connectors](https://forum.helloid.com/forum/helloid-provisioning/5338-instruction-setting-up-a-certificate-for-microsoft-graph-api-in-helloid-connectors#post5338)

### Connection settings

The following user-defined variables are used by the connector.

| Setting                               | Description                                                         | Mandatory |
| ------------------------------------- | ------------------------------------------------------------------- | --------- |
| EntraIdOrganization                   | Exchange Online organization/tenant (e.g., contoso.onmicrosoft.com) | Yes       |
| EntraIdAppId                          | Entra application (client) ID                                       | Yes       |
| EntraIdCertificateBase64String        | Entra certificate as Base64 string                                  | Yes       |
| EntraIdCertificatePassword            | Entra certificate password                                          | Yes       |
| ExchangeOnlineDistributionGroupDomain | Mail domain suffix for group addresses (e.g., contoso.com)          | Yes       |

## Remarks

- **Validation data source**:
  - The form includes a validation field that checks group availability using Exchange Online cmdlets.
  - It verifies `Name`, `DisplayName`, `PrimarySmtpAddress`, and `Alias` using `Get-DistributionGroup`.
- **Owners and members**:
  - Owner and member pickers are populated from Exchange Online via `Get-User` and return `UserPrincipalName` values.
- **Group creation**:
  - Groups are created with `New-DistributionGroup`; the template supports both Distribution Groups and Mail-enabled Security Groups.
- **Module and authentication**:
  - Uses the `ExchangeOnlineManagement` module and certificate-based app-only `Connect-ExchangeOnline` with `Organization`, `AppId`, and `Certificate`.
- **Performance notes**:
  - Retrieval/validation typically completes in ~10 seconds; actual times may vary.
- **Duplicate import**:
  - When importing a duplicate form, resource names can be suffixed automatically, as configured in the script.

## Development resources

### API endpoints

This connector uses Exchange Online PowerShell (EXO) cmdlets via the `ExchangeOnlineManagement` module:

| Cmdlet/Operation          | Description                                              |
| ------------------------- | -------------------------------------------------------- |
| Connect-ExchangeOnline    | Establish EXO session using app-only auth                |
| Get-DistributionGroup     | Check group existence/availability                       |
| Get-User                  | List users for owner/member selection                    |
| New-DistributionGroup     | Create Distribution Group or Mail-enabled Security Group |
| Disconnect-ExchangeOnline | Close EXO session                                        |

### API documentation

- Exchange Online PowerShell overview: https://learn.microsoft.com/powershell/exchange/exchange-online-powershell
- Connect-ExchangeOnline: https://learn.microsoft.com/powershell/module/exchange/connect-exchangeonline
- Get-DistributionGroup: https://learn.microsoft.com/powershell/module/exchange/get-distributiongroup
- Get-User: https://learn.microsoft.com/powershell/module/exchange/get-user
- New-DistributionGroup: https://learn.microsoft.com/powershell/module/exchange/new-distributiongroup
- Disconnect-ExchangeOnline: https://learn.microsoft.com/powershell/module/exchange/disconnect-exchangeonline

## Getting help
> :bulb: **Tip:**  
> For more information on Delegated Forms, please refer to our documentation pages: https://docs.helloid.com/en/service-automation/delegated-forms.html

## HelloID docs
The official HelloID documentation can be found at: https://docs.helloid.com/
