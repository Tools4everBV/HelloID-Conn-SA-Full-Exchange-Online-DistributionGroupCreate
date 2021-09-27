<!-- Requirements -->
## Requirements
This HelloID Service Automation Delegated Form uses the [Exchange Online PowerShell V2 module](https://docs.microsoft.com/en-us/powershell/exchange/exchange-online-powershell-v2?view=exchange-ps)

<!-- Description -->
## Description
This HelloID Service Automation Delegated Form provides Exchange Online (Office365) distribution group functionality. The following steps will be performed:
 1. Give a name for a new distribution group to create
 2. Select the owner(s)
 3. Select the member(s)
 4. Create the distribution group

<!-- TABLE OF CONTENTS -->
## Table of Contents
- [Requirements](#requirements)
- [Description](#description)
- [Table of Contents](#table-of-contents)
- [All-in-one PowerShell setup script](#all-in-one-powershell-setup-script)
  - [Getting started](#getting-started)
- [Post-setup configuration](#post-setup-configuration)
- [Manual resources](#manual-resources)
  - [Powershell data source Exchange-online-Distribution-Group-Create-check-names'](#powershell-data-source-exchange-online-distribution-group-create-check-names)
  - [Powershell data source 'Exchange-online-Distribution-Group-Create-owners-generate-table'](#powershell-data-source-exchange-online-distribution-group-create-owners-generate-table)
  - [Powershell data source 'Exchange-online-Distribution-Group-Create-members-generate-table'](#powershell-data-source-exchange-online-distribution-group-create-members-generate-table)
  - [Delegated form task 'Exchange-online-Distribution-Group-Create'](#delegated-form-task-exchange-online-distribution-group-create)
- [Getting help](#getting-help)
- [HelloID Docs](#helloid-docs)


## All-in-one PowerShell setup script
The PowerShell script "createform.ps1" contains a complete PowerShell script using the HelloID API to create the complete Form including user defined variables, tasks and data sources.

 _Please note that this script asumes none of the required resources do exists within HelloID. The script does not contain versioning or source control_


### Getting started
Please follow the documentation steps on [HelloID Docs](https://docs.helloid.com/hc/en-us/articles/360017556559-Service-automation-GitHub-resources) in order to setup and run the All-in one Powershell Script in your own environment.

 
## Post-setup configuration
After the all-in-one PowerShell script has run and created all the required resources. The following items need to be configured according to your own environment
 1. Update the following [user defined variables](https://docs.helloid.com/hc/en-us/articles/360014169933-How-to-Create-and-Manage-User-Defined-Variables)

| Variable name                             | Description                                   | Example value     |
| ----------------------------------------- | --------------------------------------------- | ----------------- |
| ExchangeOnlineAdminUsername               | Exchange admin account                        | user@domain.com   |
| ExchangeOnlineAdminPassword               | Exchange admin password                       | ********          |
| ExchangeOnlineDistributionGroupDomain     | Exchange Distribution group Domain suffix     | domain.com        |


## Manual resources
This Delegated Form uses the following resources in order to run

### Powershell data source Exchange-online-Distribution-Group-Create-check-names'
This Powershell data source checks the available names.

### Powershell data source 'Exchange-online-Distribution-Group-Create-owners-generate-table'
This Powershell data source queries and returns the users in exchange.

### Powershell data source 'Exchange-online-Distribution-Group-Create-members-generate-table'
This Powershell data source queries and returns the users in exchange.

### Delegated form task 'Exchange-online-Distribution-Group-Create'
This delegated form task will create the distribution group in Exchange.


## Getting help
> _For more information on how to configure a HelloID PowerShell connector, please refer to our [documentation](https://docs.helloid.com/hc/en-us/articles/360012518799-How-to-add-a-target-system) pages_

> _If you need help, feel free to ask questions on our [forum](https://forum.helloid.com)_

## HelloID Docs
The official HelloID documentation can be found at: https://docs.helloid.com/