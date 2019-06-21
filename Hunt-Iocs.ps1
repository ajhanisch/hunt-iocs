<#
.Synopsis
Script to help automate hunting for known indicators of compromise on a list of local and/or remote hosts.

.Description
Script is designed to take lists of known IOCs and allow the investigator to look for them on any amount of remote machines, saving large amounts of time during the initial phases of investigations.

.Example
.\Hunt-Iocs.ps1 -UserName Administrator -UserPass Password -Subnet 172.16.8.* -LiveHosts .\IOCs\hosts.txt -IocsFiles .\IOCs\files.txt
Search for only file based IOCs.

.Example
.\Hunt-Iocs.ps1 -UserName Administrator -UserPass Password -Subnet 172.16.8.* -LiveHosts .\IOCs\hosts.txt -IocsRegkeys .\IOCs\reg.txt
Search for only registry based IOCs.

.Example
.\Hunt-Iocs.ps1 -UserName Administrator -UserPass Password -Subnet 172.16.8.* -LiveHosts  .\IOCs\hosts.txt -IocsIps .\IOCs\ips.txt
Search for only ip based IOCs.

.Example
.\Hunt-Iocs.ps1 -UserName Administrator -UserPass Password -Subnet 172.16.8.* -LiveHosts  .\IOCs\hosts.txt -IocsDns .\IOCs\dns.txt
Search for only dns based IOCs.

.Example 
.\Hunt-Iocs.ps1 -UserName Administrator -UserPass Password -Subnet 172.16.8.* -LiveHosts  .\IOCs\hosts.txt -IocsUsers .\IOCs\users.txt
Search for only user based IOCs.

.Example 
.\Hunt-Iocs.ps1 -UserName Administrator -UserPass Password -Subnet 172.16.8.* -LiveHosts  .\IOCs\hosts.txt -IocsHostsFile .\IOCs\hosts_file.txt
Search for only hosts file modification based IOCs.

.Example
.\Hunt-Iocs.ps1 -UserName Administrator -UserPass Password -Subnet 172.16.8.* -LiveHosts  .\IOCs\hosts.txt -IocsFiles .\IOCs\files.txt -IocsRegkeys .\IOCs\regkeys.txt -IocsDns .\IOCs\dns.txt -IocsUsers .\IOCs\users.txt -IocsHostsFile .\IOCs\hosts_file.txt
Search for all currently available options.

.Parameter UserName
User name of account to access all local/remote machines.

.Parameter UserPass
Password of account to access all local/remote machines.

.Parameter Subnet
Ipv4 address to add to WSMan:\localhost\Client\TrustedHosts on the host machine used to run Hunt-Iocs.ps1 to allow for connections to hosts passed in from -LiveHosts

.Parameter LiveHosts
File containing line separated list of IP addresses you wish to investigate.

.Parameter IocsFiles
File containing line separated list of known IOC file names (including extension) to look for on hosts passed in from -LiveHosts. 
Currently this script only looks within the C:\ drive. Future versions will include ability to look within multiple drive paths.

.Parameter IocsIps
File containing line separated list of known IOC IP addresses to look for on hosts passed in from -LiveHosts. 
Currently this script utilizes Get-NetTCPConnection on the remote hosts to look for connections to known IOC IP addresses. 
Future versions will include ability to utilize other methods.

.Parameter IocsHostsFile
File containing line separated list of known IOC host file entries to look for on hosts passed in from -LiveHosts. 

.Parameter IocsRegkeys
File containing line separated list of known IOC registry keys to look for on hosts passed in from -LiveHosts. 
Currently this script only looks within the following registry paths:
HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run
HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce
HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run
HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce
Future version will include ability to look within other registry paths.

.Parameter IocsDns
File containing line separated list of known IOC domains to look for on hosts passed in from -LiveHosts. 
Currently this script utilizes Get-DnsClientCache on the remote hosts to look for entries that match known IOC domains. 
Future versions will include ability to utilize other methods.
    
.Inputs
Mandatory inputs are -UserName, -UserPass, -Subnet, -LiveHosts, and at least one of the following optional inputs: -IocsFiles, -IocsIps, -IocsRegkeys, -IocsDns. 
Mandatory inputs are strings. 
Optional inputs are paths to line separated files containing their appropriate contents based on input.
   
.Outputs
Script currently outputs .csv files containing the results (if any are found) of each type of optional inputs. 
   
.Notes
Author: Ashton J. Hanisch
Version: 0.1
Troubleshooting: All script process output will be in .\Hunt-Iocs.log.
#>


[cmdletbinding()]
Param (
    [Parameter(Mandatory=$true)]
    [string]$UserName,
    [Parameter(Mandatory=$true)]
    [string]$UserPass,
    [Parameter(Mandatory=$true)]
    $Subnet,
    [Parameter(Mandatory=$true)]
    $LiveHosts,
    $IocsFiles,
    $IocsIps,
    $IocsRegkeys,
    $IocsDns,
    $IocsUsers,
    $IocsHostsFile
)

$FileLog = "$(Get-Location | Select-Object -ExpandProperty Path)\$(Get-Item $PSCommandPath | Select-Object -ExpandProperty Basename).log"
Start-Transcript -Path $FileLog

.\Setup-Investigation -Subnet $Subnet

$UserPassSecure = ConvertTo-SecureString $UserPass -AsPlainText -Force
$UserCredentials = New-Object -TypeName System.Management.Automation.PSCredential $UserName,$UserPassSecure 

if($IocsDns)
{
    .\Investigate-DnsIocs -LiveHosts $LiveHosts -UserCredentials $UserCredentials -IocsDns $IocsDns
}

if($IocsRegkeys) 
{ 
    .\Investigate-RegistryIocs -LiveHosts $LiveHosts -UserCredentials $UserCredentials -IocsRegkeys $IocsRegkeys
}

if($IocsIps) 
{ 
    .\Investigate-IpIocs -LiveHosts $LiveHosts -UserCredentials $UserCredentials -IocsIps $IocsIps
}

if($IocsUsers)
{
    .\Investigate-UserIocs -LiveHosts $LiveHosts -UserCredentials $UserCredentials -IocsUsers $IocsUsers
}

if($IocsHostsFile)
{
    .\Investigate-HostsFileIocs.ps1 -LiveHosts $LiveHosts -UserCredentials $UserCredentials -IocsHostsFile $IocsHostsFile
}

if($IocsFiles)
{
    .\Investigate-FileIocs -LiveHosts $LiveHosts -UserCredentials $UserCredentials -IocsFiles $IocsFiles
}

Stop-Transcript