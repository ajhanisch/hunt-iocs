<#
.Synopsis
Script to perform searching for IOC IP addresses passed in from -IocsIps on hosts passed in from -LiveHosts.

.Description
Currently this script utilizes Get-NetTCPConnection on the remote hosts to look for connections to known IOC IP addresses. 
Future versions will include ability to utilize other methods.

.Example
.\Investigate-IpIocs.ps1 -LiveHosts .\hosts.txt -UserCredentials Administrator -IpIocs .\ip.txt
Look for IP based IOCs passed in from -IocsIps on remote machines passed in from -LiveHosts.

.Parameter LiveHosts
File containing line separated list of IP addresses you wish to investigate.

.Parameter UserCredentials
Secure credential object created via following method:
$UserPassSecure = ConvertTo-SecureString $UserPass -AsPlainText -Force
$UserCredentials = New-Object -TypeName System.Management.Automation.PSCredential $UserName,$UserPassSecure
This object is what the parent script (Hunt-Iocs.ps1) uses when it calls this script automatically. 
If you wish to use this script on its own, pass a username and you will be prompted for a password.

.Parameter IocsIps
File containing line separated list of known IOC IP addresses to look for on hosts passed in from -LiveHosts.

.Inputs
Mandatory inputs are -LiveHosts, -UserCredentials, -IocsIps.

.Outputs
Script currently outputs a ips_based_iocs.csv file containing the results found on all remote hosts passed in from -LiveHosts.
Currently output is unfinished.

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
    $IocsIps
)

$Ips = Get-Content -Path $IocsIps
$IpsTotal = $Ips.Length
$RemoteServers = @(Get-Content -Path $LiveHosts)
$ServersInvestigated = 0
$ServersTotal = $RemoteServers.Length
$IpsResultsOutput = "$(Get-Location | Select-Object -ExpandProperty Path)\InvestigationResults\ips_based_iocs.csv"

foreach($RemoteServer in $RemoteServers)
{
    $ServersInvestigated += 1
    Write-Host "Investigating [${IpsTotal}] IP based IOCs on [${RemoteServer}] [${ServersInvestigated}/${ServersTotal}]" -ForegroundColor Cyan

    $ServerResults = Invoke-Command -ComputerName $RemoteServer -Credential $UserCredentials -ScriptBlock {
        Get-NetTCPConnection
        Write-Output $ServerResults
    }
  
    foreach($Ip in $Ips)
    {
        if($ServerResults.RemoteAddress -eq $Ip)
        {
            Write-Host "Found IP based IOC [${Ip}] on [${RemoteServer}]" -ForegroundColor Red
            $IpsFinding = New-Object System.Object
            $IpsFinding | Add-Member -MemberType NoteProperty -Name "Host" -Value $RemoteServer
            $IpsFinding | Add-Member -MemberType NoteProperty -Name "Ip" -Value $Ip
            Write-Host "Adding IP based IOC results [${Ip}] to [${IpsResultsOutput}]" -ForegroundColor Yellow
            $IpsFinding | Export-Csv -Path $IpsResultsOutput -NoTypeInformation -Append -Force            
        }
    }

    Write-Host "Finished investigating [${IpsTotal}] IP based IOCs on [${RemoteServer}] [${ServersInvestigated}/${ServersTotal}]" -ForegroundColor Cyan
}