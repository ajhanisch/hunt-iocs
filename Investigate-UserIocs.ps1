<#
.Synopsis
Script to perform searching for IOC users passed in from -IocsUsers on hosts passed in from -LiveHosts.

.Description
Currently this script utilizes Get-LocalUser on the remote hosts to identify users.
Future versions will include ability to utilize other methods.

.Example
.\Investigate-FileIocs.ps1 -LiveHosts .\hosts.txt -UserCredentials Administrator -IocsUsers .\users.txt
Look for user based IOCs passed in from -IocsUsers on remote machines passed in from -LiveHosts.

.Parameter LiveHosts
File containing line separated list of IP addresses you wish to investigate.

.Parameter UserCredentials
Secure credential object created via following method:
$UserPassSecure = ConvertTo-SecureString $UserPass -AsPlainText -Force
$UserCredentials = New-Object -TypeName System.Management.Automation.PSCredential $UserName,$UserPassSecure
This object is what the parent script (Hunt-Iocs.ps1) uses when it calls this script automatically. 
If you wish to use this script on its own, pass a username and you will be prompted for a password.

.Parameter IocsUsers
File containing line separated list of known IOC user names to look for on hosts passed in from -LiveHosts. 

.Inputs
Mandatory inputs are -LiveHosts, -UserCredentials, -IocsUsers.

.Outputs
Script currently outputs a users_based_iocs.csv file containing the results found on all remote hosts passed in from -LiveHosts.

.Notes
Author: Ashton J. Hanisch
Version: 0.1
#>

[cmdletbinding()]
Param (
    [Parameter(Mandatory=$true)]
    $LiveHosts,
    [Parameter(Mandatory=$true)]
    $UserCredentials,
    [Parameter(Mandatory=$true)]
    $IocsUsers
)

$Users = Get-Content -Path $IocsUsers
$UsersTotal = $Users.Length
$RemoteServers = @(Get-Content -Path $LiveHosts)
$ServersInvestigated = 0
$ServersTotal = $RemoteServers.Length
$UsersResultsOutput = "$(Get-Location | Select-Object -ExpandProperty Path)\InvestigationResults\users_based_iocs.csv"

foreach($RemoteServer in $RemoteServers)
{
    $ServersInvestigated += 1
    Write-Host "Investigating [${UsersTotal}] user based IOCs on [${RemoteServer}] [${ServersInvestigated}/${ServersTotal}]" -ForegroundColor Cyan

    $ServerResults = Invoke-Command -ComputerName $RemoteServer -Credential $UserCredentials -ScriptBlock {
        Get-LocalUser
        Write-Output $ServerResults
    }

    foreach($User in $Users)
    {
        if($User -in $ServerResults.Name)
        {
            Write-Host "Found user based IOC [${User}] on [${RemoteServer}]" -ForegroundColor Red
            Write-Host "Adding user based IOC result [${User}] to [${UsersResultsOutput}]" -ForegroundColor Yellow
            $ServerResults | ? { $_.Name -eq $User } | Export-Csv -Path $UsersResultsOutput -NoTypeInformation -Append -Force
        }
    }

    Write-Host "Finished investigating [${UsersTotal}] user based IOCs on [${RemoteServer}] [${ServersInvestigated}/${ServersTotal}]" -ForegroundColor Cyan
}