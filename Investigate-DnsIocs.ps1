<#
.Synopsis
Script to perform searching for IOC domains passed in from -IocsDns on hosts passed in from -LiveHosts.

.Description
Currently this script utilizes Get-NetTCPConnection on the remote hosts to look for connections to known IOC IP addresses. 
Future versions will include ability to utilize other methods.

.Example
.\Investigate-DnsIocs.ps1 -LiveHosts .\hosts.txt -UserCredentials Administrator -IocsDns .\dns.txt
Look for dns based IOCs passed in from -IocsDns on remote machines passed in from -LiveHosts.

.Parameter LiveHosts
File containing line separated list of IP addresses you wish to investigate.

.Parameter UserCredentials
Secure credential object created via following method:
$UserPassSecure = ConvertTo-SecureString $UserPass -AsPlainText -Force
$UserCredentials = New-Object -TypeName System.Management.Automation.PSCredential $UserName,$UserPassSecure
This object is what the parent script (Hunt-Iocs.ps1) uses when it calls this script automatically. 
If you wish to use this script on its own, pass a username and you will be prompted for a password.

.Parameter IocsDns
File containing line separated list of known IOC domain names to look for on hosts passed in from -LiveHosts.

.Inputs
Mandatory inputs are -LiveHosts, -UserCredentials, -IocsDns.

.Outputs
Script currently outputs a dns_based_iocs.csv file containing the results found on all remote hosts passed in from -LiveHosts.

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
    $IocsDns
)

$DnsEntries = Get-Content -Path $IocsDns
$DnsEntriesTotal = $DnsEntries.Length
$RemoteServers = @(Get-Content -Path $LiveHosts)
$ServersInvestigated = 0
$ServersTotal = $RemoteServers.Length
$DnsResultsOutput = "$(Get-Location | Select-Object -ExpandProperty Path)\InvestigationResults\dns_based_iocs.csv"

foreach($RemoteServer in $RemoteServers)
{
    $ServersInvestigated += 1
    Write-Host "Investigating [${DnsEntriesTotal}] dns based IOCs on [${RemoteServer}] [${ServersInvestigated}/${ServersTotal}]" -ForegroundColor Cyan

    $ServerResults = Invoke-Command -ComputerName $RemoteServer -Credential $UserCredentials -ScriptBlock {
        Get-DnsClientCache
        Write-Output $ServerResults
    }   

    foreach($DnsEntry in $DnsEntries)
    {
        if($DnsEntry -in $ServerResults.Entry)
        {
            Write-Host "Found ${DnsEntry} on [${RemoteServer}]" -ForegroundColor Red
            Write-Host "Adding dns based IOC result [${DnsEntry}] to [${DnsResultsOutput}]" -ForegroundColor Yellow
            $ServerResults | ? { $_.Entry -eq $DnsEntry } | Export-Csv -Path $DnsResultsOutput -NoTypeInformation -Append -Force

        }
    }

    Write-Host "Finished investigating [${DnsEntriesTotal}] dns based IOCs on [${RemoteServer}] [${ServersInvestigated}/${ServersTotal}]" -ForegroundColor Cyan
}