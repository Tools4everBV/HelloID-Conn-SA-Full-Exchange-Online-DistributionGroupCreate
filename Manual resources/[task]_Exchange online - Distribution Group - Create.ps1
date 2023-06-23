$GroupType = "Distribution Group" # "Mail-enabled Security Group" or "Distribution Group"

# Connect to Office 365
try{
    write-information  "Connecting to Office 365.."

    $module = Import-Module ExchangeOnlineManagement

    # Connect to Exchange Online in an unattended scripting scenario using user credentials (MFA not supported).
    $securePassword = ConvertTo-SecureString $ExchangeOnlineAdminPassword -AsPlainText -Force
    $credential = [System.Management.Automation.PSCredential]::new($ExchangeOnlineAdminUsername,$securePassword)
    $exchangeSession = Connect-ExchangeOnline -Credential $credential -ShowBanner:$false -ShowProgress:$false -ErrorAction Stop

    write-information  "Successfully connected to Office 365"
}catch{
    Write-Error "Error connecting to Exchange Online. Error: $($_.Exception.Message)"
   $Log = @{
           Action            = "CreateResource" # optional. ENUM (undefined = default) 
           System            = "Exchange Online" # optional (free format text) 
           Message           = "Failed to connect to Exchange Online" # required (free format text) 
           IsError           = $true # optional. Elastic reporting purposes only. (default = $false. $true = Executed action returned an error) 
           TargetDisplayName = "Exchange Online" # optional (free format text) 
           
       }
   #send result back  
   Write-Information -Tags "Audit" -MessageData $log
}


# Create Mail-enabled Security Group
try{   
    $OwnersToAdd = ($Owners | ConvertFrom-Json).userPrincipalName
    $MembersToAdd = ($Members | ConvertFrom-Json).userPrincipalName

    $groupParams = @{
        Name                =   $form.naming.name
        DisplayName         =   $form.naming.displayName
        PrimarySmtpAddress  =   $form.naming.primarySmtpAddress
        Alias               =   $form.naming.alias
        ManagedBy           =   $form.multiselectOwners.toJsonString
        Members             =   $form.multiselectMembers.toJsonString
        CopyOwnerToMember   =   $true
    }
    
    Switch($GroupType){
        'Mail-enabled Security Group' {
            $mailEnabledSecurityGroup = New-DistributionGroup -Type security @groupParams -ErrorAction Stop
        }

        'Distribution Group' {
            $mailEnabledSecurityGroup = New-DistributionGroup @groupParams -ErrorAction Stop
        }
    }
    
    $Log = @{
        Action            = "CreateResource" # optional. ENUM (undefined = default) 
        System            = "Exchange Online" # optional (free format text) 
        Message           = "Created Mailbox  $($mailEnabledSecurityGroup.displayName)" # required (free format text) 
        IsError           = $false # optional. Elastic reporting purposes only. (default = $false. $true = Executed action returned an error) 
        TargetDisplayName = $($mailEnabledSecurityGroup.displayName) # optional (free format text) 
        TargetIdentifier  = $([string]$mailEnabledSecurityGroup.Guid)  # optional (free format text) 
    }
    #send result back  

    Write-Information -Tags "Audit" -MessageData $log
  
} catch {
   
    $Log = @{
        Action            = "CreateResource" # optional. ENUM (undefined = default) 
        System            = "Exchange Online" # optional (free format text) 
        Message           = "Error creating $GroupType [$($groupParams.Name)]. Error: $($_.Exception.Message)" # required (free format text) 
        IsError           = $true # optional. Elastic reporting purposes only. (default = $false. $true = Executed action returned an error) 
        TargetDisplayName = $($groupParams.displayName) # optional (free format text) 
        
    }
#send result back  
Write-Information -Tags "Audit" -MessageData $log
  
} finally {
   
    $exchangeSessionEnd = Disconnect-ExchangeOnline -Confirm:$false -Verbose:$false -ErrorAction Stop
    write-information -Event Success -Message "Successfully disconnected from Office 365"
}
