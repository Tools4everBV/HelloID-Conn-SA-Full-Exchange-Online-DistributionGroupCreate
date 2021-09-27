# Connect to Office 365
try{
    Write-Verbose -Verbose "Connecting to Office 365.."

    $module = Import-Module ExchangeOnlineManagement

    # Connect to Exchange Online in an unattended scripting scenario using user credentials (MFA not supported).
    $securePassword = ConvertTo-SecureString $ExchangeOnlineAdminPassword -AsPlainText -Force
    $credential = New-Object System.Management.Automation.PSCredential ($ExchangeOnlineAdminUsername, $securePassword)
    $exchangeSession = Connect-ExchangeOnline -Credential $credential -ShowBanner:$false -ShowProgress:$false -ErrorAction Stop

    Write-Verbose -Verbose "Successfully connected to Office 365"
}catch{
    throw "Could not connect to Exchange Online, error: $_"
}

try {
    Write-Information -Message "Searching for Exchange Online users.."
        
    $exchangeOnlineUsers = Get-User -ResultSize unlimited

    $users = $exchangeOnlineUsers
    $resultCount = @($users).Count
     
    Write-Information -Message "Result count: $resultCount"
    if($resultCount -gt 0){
        foreach($user in $users){
            $displayValue = $user.displayName + " [" + $user.UserPrincipalName + "]"
            $returnObject = @{
                UserPrincipalName="$($user.UserPrincipalName)";
                name=$displayValue;
                id="$($user.id)";
            }
     
            Write-Output $returnObject
        }
    }
} catch {
    Write-Error "Error getting users. Error: $_"
} finally {
    Write-Verbose -Verbose "Disconnecting from Office 365.."
    $exchangeSessionEnd = Disconnect-ExchangeOnline -Confirm:$false -Verbose:$false -ErrorAction Stop
    Write-Verbose -Verbose "Successfully disconnected from Office 365"
}
