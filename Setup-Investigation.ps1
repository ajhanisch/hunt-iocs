<#
.Synopsis
Script to perform required tasks prior to starting investigations.

.Description
Script is designed to add the address passed in from -Subnet to WSMan:\localhost\Client\TrustedHosts as well as create the required working directories within the same directory as the script.

.Example
.\Setup-Investigation.ps1 -Subnet 192.168.1.*
Add a /24 to TrustedHosts on local machine.

.Example
.\Setup-Investigation.ps1 -Subnet 192.168.1.15
Add a specific host to TrustedHosts on local machine.

.Example
.\Setup-Investigation.ps1 -Subnet 192.168.*.*
Add a /16 to TrustedHosts on local machine.

.Parameter Subnet
Ipv4 address to add to WSMan:\localhost\Client\TrustedHosts on the host machine used to run Hunt-Iocs.ps1 to allow for connections to hosts passed in from -LiveHosts.

.Inputs
Mandatory input is -Subnet. 
Mandatory input is a string of the IPv4 address/es you wish to add to TrustedHosts on local machine.

.Outputs
Script currently modifies WSMan:\localhost\Client\TrustedHosts and creates InvestigationResults directory in same directory as script.

.Notes
Author: Ashton J. Hanisch
Version: 0.1
#>


[cmdletbinding()]
Param (
    [Parameter(Mandatory=$true)]
    [string]$Subnet
)

if((Get-Item -Path WSMan:\localhost\Client\TrustedHosts).Value -ne $Subnet) 
{ 
    Write-Host "Adding [${Subnet}] to [WSMan:\localhost\Client\TrustedHosts]" -ForegroundColor Yellow
    Set-Item WSMan:\localhost\Client\TrustedHosts -Value $Subnet -Force 
}

$InvestigationOutput = "$(Get-Location | Select-Object -ExpandProperty Path)\InvestigationResults"
if(!(Test-Path -Path $InvestigationOutput))
{
    Write-Host "Creating investigation results directory [$InvestigationOutput]" -ForegroundColor Yellow
    New-Item -Path $InvestigationOutput -ItemType Directory -Force | Out-Null
}