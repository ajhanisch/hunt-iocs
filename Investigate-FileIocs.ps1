<#
.Synopsis
Script to perform searching for IOC files passed in from -IocsFiles on remote hosts passed in from -LiveHosts.

.Description
Currently this script only looks within the C:\ drive. Future versions will include ability to look within multiple drive paths.

.Example
.\Investigate-FileIocs.ps1 -LiveHosts .\hosts.txt -UserCredentials Administrator -IocsFiles .\files.txt
Look for file based IOCs passed in from -IocsFiles on remote machines passed in from -LiveHosts.

.Parameter LiveHosts
File containing line separated list of IP addresses you wish to investigate.

.Parameter UserCredentials
Secure credential object created via following method:
$UserPassSecure = ConvertTo-SecureString $UserPass -AsPlainText -Force
$UserCredentials = New-Object -TypeName System.Management.Automation.PSCredential $UserName,$UserPassSecure
This object is what the parent script (Hunt-Iocs.ps1) uses when it calls this script automatically. 
If you wish to use this script on its own, pass a username and you will be prompted for a password.

.Parameter IocsFiles
File containing line separated list of known IOC file names (including extension) to look for on hosts passed in from -LiveHosts. 
Currently this script only looks within the C:\ drive. Future versions will include ability to look within multiple drive paths.

.Inputs
Mandatory inputs are -LiveHosts, -UserCredentials, -IocsFiles.

.Outputs
Script currently outputs a file_based_iocs.csv file containing the results found on all remote hosts passed in from -LiveHosts.

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
    $IocsFiles
)

$RemoteServers = @(Get-Content -Path $LiveHosts)
$Files = Get-Content -Path $IocsFiles
$FilesTotal = $Files.Length
$ServersInvestigated = 0
$ServersTotal = $RemoteServers.Length
$FileResultsOutput = "$(Get-Location | Select-Object -ExpandProperty Path)\InvestigationResults\file_based_iocs.csv"

foreach($RemoteServer in $RemoteServers)
{
    $ServersInvestigated += 1
    Write-Host "Investigating [${FilesTotal}] file based IOCs on [${RemoteServer}] [${ServersInvestigated}/${ServersTotal}]" -ForegroundColor Cyan

    $ServerResults = Invoke-Command -ComputerName $RemoteServer -Credential $UserCredentials -ScriptBlock {
        Get-ChildItem -Path C:\ -Include $using:Files -Recurse -Force -ErrorAction SilentlyContinue | 
        Select-Object -Property Name,FullName,Length,CreationTime,CreationTimeUtc,LastAccessTime,LastAccessTimeUtc,LastWriteTime,LastWriteTimeUtc,PSComputerName
    }
     
    $ServerResultsCount = $ServerResults.Length 
    if($ServerResultsCount -gt 0)
    {
        Write-Host "[${RemoteServer}] has [${ServerResultsCount}] file based IOCs!" -ForegroundColor Red
        foreach($Result in $ServerResults)
        {
            Write-Host "Adding file based IOC result [$($Result.FullName)] to [${FileResultsOutput}]" -ForegroundColor Yellow
            Export-Csv -InputObject $Result -Path $FileResultsOutput -NoTypeInformation -Append
        }
    }
    else
    {
        Write-Host "Did not find any file based IOCs on [${RemoteServer}]" -ForegroundColor Green
    }

    Write-Host "Finished investigating [${FilesTotal}] file based IOCs on [${RemoteServer}] [${ServersInvestigated}/${ServersTotal}]" -ForegroundColor Cyan
}