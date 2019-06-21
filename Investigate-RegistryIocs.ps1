<#
.Synopsis
Script to perform searching for IOC registry keys passed in from -IocsRegkeys on hosts passed in from -LiveHosts.

.Description
Currently this script only looks within the following registry paths:
HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run
HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce
HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run
HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce
Future version will include ability to look within other registry paths.

.Example
.\Investigate-RegistryIocs.ps1 -LiveHosts .\hosts.txt -UserCredentials Administrator -IocsRegkeys .\reg.txt
Look for registry based IOCs passed in from -IocsRegkeys on remote machines passed in from -LiveHosts.

.Parameter LiveHosts
File containing line separated list of IP addresses you wish to investigate.

.Parameter UserCredentials
Secure credential object created via following method:
$UserPassSecure = ConvertTo-SecureString $UserPass -AsPlainText -Force
$UserCredentials = New-Object -TypeName System.Management.Automation.PSCredential $UserName,$UserPassSecure
This object is what the parent script (Hunt-Iocs.ps1) uses when it calls this script automatically. 
If you wish to use this script on its own, pass a username and you will be prompted for a password.

.Parameter IocsRegkeys
File containing line separated list of known IOC registry keys to look for on hosts passed in from -LiveHosts.

.Inputs
Mandatory inputs are -LiveHosts, -UserCredentials, -IocsRegkeys.

.Outputs
Script currently outputs a registry_based_iocs.csv file containing the results found on all remote hosts passed in from -LiveHosts.

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
    $IocsRegkeys
)

$RegKeys = Get-Content -Path $IocsRegkeys 
$RegKeysTotal = $RegKeys.Length
$RemoteServers = @(Get-Content -Path $LiveHosts)
$ServersInvestigated = 0
$ServersTotal = $RemoteServers.Length
$RegKeysResultsOutput = "$(Get-Location | Select-Object -ExpandProperty Path)\InvestigationResults\registry_based_iocs.csv"

foreach($RemoteServer in $RemoteServers)
{
    $ServersInvestigated += 1
    Write-Host "Investigating [${RegKeysTotal}] registry based IOCs on [${RemoteServer}] [${ServersInvestigated}/${ServersTotal}]" -ForegroundColor Cyan

    $ServerResults = Invoke-Command -ComputerName $RemoteServer -Credential $UserCredentials -ScriptBlock {
        (Get-ItemProperty HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run -ErrorAction SilentlyContinue).PSObject.Properties | Select-Object -Property Name,Value,PSComputerName,@{Name="HiveKey"; Expression={"HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run"}};
        (Get-ItemProperty HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce -ErrorAction SilentlyContinue).PSObject.Properties | Select-Object -Property Name,Value,PSComputerName,@{Name="HiveKey"; Expression={"HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce"}};
        (Get-ItemProperty HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run -ErrorAction SilentlyContinue).PSObject.Properties | Select-Object -Property Name,Value,PSComputerName,@{Name="HiveKey"; Expression={"HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run"}}
        (Get-ItemProperty HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce -ErrorAction SilentlyContinue).PSObject.Properties | Select-Object -Property Name,Value,PSComputerName,@{Name="HiveKey"; Expression={"HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce"}};
        Write-Output $ServerResults
    }

    foreach($RegKey in $RegKeys)
    {
        foreach($Result in $ServerResults)
        {
            if($Result.Value -match $RegKey -or $Result.Name -match $RegKey)
            {
                Write-Host "Found registry key based IOC [${RegKey}] on [${RemoteServer}]" -ForegroundColor Red
                Write-Host "Adding registry based IOC result [${RegKey}] to [${RegKeysResultsOutput}]" -ForegroundColor Yellow
                Export-Csv -InputObject $Result -Path $RegKeysResultsOutput -NoTypeInformation -Append
            }
        }
    }

    Write-Host "Finished investigating [${RegKeysTotal}] registry based IOCs on [${RemoteServer}] [${ServersInvestigated}/${ServersTotal}]" -ForegroundColor Cyan
}