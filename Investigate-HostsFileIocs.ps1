<#
.Synopsis
Script to perform searching for host file entries passed in from -IocsHostsFile on remote hosts passed in from -LiveHosts.

.Description
Currently this script only looks within the C:\ drive. Future versions will include ability to look within multiple drive paths.

.Example
.\Investigate-FileIocs.ps1 -LiveHosts .\hosts.txt -UserCredentials Administrator -IocsHostsFile .\files.txt
Look for file based IOCs passed in from -IocsHostsFile on remote machines passed in from -LiveHosts.

.Parameter LiveHosts
File containing line separated list of IP addresses you wish to investigate.

.Parameter UserCredentials
Secure credential object created via following method:
$UserPassSecure = ConvertTo-SecureString $UserPass -AsPlainText -Force
$UserCredentials = New-Object -TypeName System.Management.Automation.PSCredential $UserName,$UserPassSecure
This object is what the parent script (Hunt-Iocs.ps1) uses when it calls this script automatically. 
If you wish to use this script on its own, pass a username and you will be prompted for a password.

.Parameter IocsHostsFile
File containing line separated list of known IOC host file entries to look for on hosts passed in from -LiveHosts. 

.Inputs
Mandatory inputs are -LiveHosts, -UserCredentials, -IocsHostsFile.

.Outputs
Script currently outputs a hosts_file_based_iocs.csv file containing the results found on all remote hosts passed in from -LiveHosts.

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
    $IocsHostsFile
)

$RemoteServers = @(Get-Content -Path $LiveHosts)
$HostsFiles = Get-Content -Path $IocsHostsFile
$HostsFilesTotal = $HostsFiles.Length
$ServersInvestigated = 0
$ServersTotal = $RemoteServers.Length
$HostsFilesResultsOutput = "$(Get-Location | Select-Object -ExpandProperty Path)\InvestigationResults\hosts_file_based_iocs.csv"

foreach($RemoteServer in $RemoteServers)
{
    $ServersInvestigated += 1
    Write-Host "Investigating [${HostsFilesTotal}] hosts file based IOCs on [${RemoteServer}] [${ServersInvestigated}/${ServersTotal}]" -ForegroundColor Cyan

    $ServerResults = Invoke-Command -ComputerName $RemoteServer -Credential $UserCredentials -ScriptBlock {
        Get-Content -Path C:\Windows\System32\drivers\etc\hosts
        Write-Output $ServerResults
    }
  
    foreach($HostsFile in $HostsFiles)
    {
        if($ServerResults | Select-String -SimpleMatch $HostsFile)
        {
            Write-Host "Found hosts file based IOC [${HostsFile}] on [${RemoteServer}]" -ForegroundColor Red
            $HostsFileFinding = New-Object System.Object
            $HostsFileFinding | Add-Member -MemberType NoteProperty -Name "Host" -Value $RemoteServer
            $HostsFileFinding | Add-Member -MemberType NoteProperty -Name "Entry" -Value $HostsFile
            Write-Host "Adding hosts file based IOC results [${HostsFile}] to [${HostsFilesResultsOutput}]" -ForegroundColor Yellow
            $HostsFileFinding | Export-Csv -Path $HostsFilesResultsOutput -NoTypeInformation -Append -Force            
        }
    }

    Write-Host "Finished investigating [${HostsFilesTotal}] hosts file based IOCs on [${RemoteServer}] [${ServersInvestigated}/${ServersTotal}]" -ForegroundColor Cyan
}