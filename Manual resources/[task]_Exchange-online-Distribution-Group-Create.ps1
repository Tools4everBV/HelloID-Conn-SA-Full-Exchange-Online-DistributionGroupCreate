$GroupType = "Distribution Group" # "Mail-enabled Security Group" or "Distribution Group"

# Connect to Office 365
try{
    HID-Write-Status -Event Information -Message "Connecting to Office 365.."

    $module = Import-Module ExchangeOnlineManagement

    # Connect to Exchange Online in an unattended scripting scenario using user credentials (MFA not supported).
    $securePassword = ConvertTo-SecureString $ExchangeOnlineAdminPassword -AsPlainText -Force
    $credential = New-Object System.Management.Automation.PSCredential ($ExchangeOnlineAdminUsername, $securePassword)
    $exchangeSession = Connect-ExchangeOnline -Credential $credential -ShowBanner:$false -ShowProgress:$false -ErrorAction Stop

    HID-Write-Status -Event Success -Message "Successfully connected to Office 365"
}catch{
    throw "Could not connect to Exchange Online, error: $_"
}

# Create Mail-enabled Security Group
try{   
    $OwnersToAdd = ($Owners | ConvertFrom-Json).userPrincipalName
    $MembersToAdd = ($Members | ConvertFrom-Json).userPrincipalName

    $groupParams = @{
        Name                =   $Name
        DisplayName         =   $DisplayName
        PrimarySmtpAddress  =   $PrimarySmtpAddress
        Alias               =   $Alias
        ManagedBy           =   $OwnersToAdd
        Members             =   $MembersToAdd
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
     
    Hid-Write-Status -Event Success -Message "$GroupType [$($groupParams.Name)] created successfully"
    HID-Write-Summary -Event Success -Message "$GroupType [$($groupParams.Name)] created successfully"
} catch {
    HID-Write-Status -Event Error -Message "Error creating $GroupType [$($groupParams.Name)]. Error: $($_.Exception.Message)"
    HID-Write-Summary -Event Failed -Message "Error creating $GroupType [$($groupParams.Name)]"
} finally {
    HID-Write-Status -Event Information -Message "Disconnecting from Office 365.."
    $exchangeSessionEnd = Disconnect-ExchangeOnline -Confirm:$false -Verbose:$false -ErrorAction Stop
    HID-Write-Status -Event Success -Message "Successfully disconnected from Office 365"
}
