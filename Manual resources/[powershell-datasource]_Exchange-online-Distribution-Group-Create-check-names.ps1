$Mailsuffix = $ExchangeOnlineDistributionGroupDomain

# Connect to Office 365
try{
    Write-Verbose -Verbose "Connecting to Office 365.."

    $module = Import-Module ExchangeOnlineManagement

    # Connect to Exchange Online in an unattended scripting scenario using user credentials (MFA not supported).
    $securePassword = ConvertTo-SecureString $ExchangeOnlineAdminPassword -AsPlainText -Force
    $credential = [System.Management.Automation.PSCredential]::new($ExchangeOnlineAdminUsername,$securePassword)
    $exchangeSession = Connect-ExchangeOnline -Credential $credential -ShowBanner:$false -ShowProgress:$false -ErrorAction Stop

    Write-Verbose -Verbose "Successfully connected to Office 365"
}catch{
    throw "Could not connect to Exchange Online, error: $_"
}

try {
    $iterationMax = 10
    $iterationStart = 1;
        
    for($i = $iterationStart; $i -lt $iterationMax; $i++) {
        if($i -eq $iterationStart) {
            $tempName = $datasource.name
            $DisplayName =  $tempName
    
            $Name =   $tempName.Replace(" ","")

            $PrimarySmtpAddress =   $tempName.Replace(" ","") + "@" + $Mailsuffix
            
            $Alias =   $tempName.Replace(" ","")
         } else {
            $tempName = $datasource.name
            $DisplayName =  $tempName + "$i"
    
            $Name =   ($tempName + "$i").Replace(" ","")

            $PrimarySmtpAddress =   ($tempName + "$i").Replace(" ","") + "@" + $Mailsuffix 
            
            $Alias =   ($tempName + "$i").Replace(" ","")
        }
        
        Write-Information -Message "Searching for Distribution Group Name=$Name or DisplayName=$DisplayName or EmailAddresses=$PrimarySmtpAddress or Alias=$Alias"

        $found = Get-DistributionGroup -Filter "Name -eq '$Name' -or DisplayName -eq '$DisplayName' -or EmailAddresses -eq '$PrimarySmtpAddress' -or Alias -eq '$Alias'"

        if(@($found).count -eq 0) {
            $returnObject = @{
                name=$Name;
                displayName=$DisplayName;
                primarySmtpAddress=$PrimarySmtpAddress;
                alias=$Alias;
                samAccountName=$SamAccountName
            }
            Write-Information -Message "Distribution Group Name=$Name or DisplayName=$DisplayName or EmailAddresses=$PrimarySmtpAddress or Alias=$Alias not found"
            break;
        } else {
            Write-Warning -Message "Distribution Group Name=$Name or DisplayName=$DisplayName or EmailAddresses=$PrimarySmtpAddress or Alias=$Alias found"
        }
    }
    
    Write-Output $returnObject

} catch {
    Write-Error "Error generating names. Error: $_"
} finally {
    Write-Verbose -Verbose "Disconnecting from Office 365.."
    $exchangeSessionEnd = Disconnect-ExchangeOnline -Confirm:$false -Verbose:$false -ErrorAction Stop
    Write-Verbose -Verbose "Successfully disconnected from Office 365"
}
