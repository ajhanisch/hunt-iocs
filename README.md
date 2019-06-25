![Hunt-Iocs](/images/main_menu.png)

# Hunt-Iocs
Automation framework built in PowerShell to quickly and easily assist with investigating, collecting, and documenting known indicators of compromise (IOCs) on any number of remote machines as well as automating various other investigative tasks.

## Installation / Getting Started
No installation is needed in order to get a copy of the project up and running. If it has not been done already in your environment, ensure to set your execution policy to allow PowerShell scripts to run. 

The following may not be best practice for your environment, but will work within test environments to get up and running quickly.
```powershell
Set-ExecutionPolicy -ExecutionPolicy Unrestricted
```

## Features
* Simple text-based user interface (TUI)
* Progress indication during each hunt
* Ability to perform simple ping scan to identify live hosts on the network
* Ability to investigate multiple types of IOCs on any amount of remote hosts
* Ability to collect results from investigating multiple types of IOCs into easy to visualize .csv files
* Ability to download/aggregate file based IOCs discovered during investigations to local machine for static/dynamic analysis

## Starting Your First Hunt
Starting a hunt can be broken up into two set of tasks: Configuration and Hunting.

### Configuration
#### TrustedHosts
PowerShell utilizes the TrustedHosts file to allow for remote connections to machines. Pass the host(s) you would like to add to the TrustedHosts file within the **Setup your IOCs hunt** menu. The framework will concatenate the list of TrustedHosts with the given input, it will not overwrite the current TrustedHosts value(s).

#### Results Directory
The framework will output all results of investigations to a user-specified directory. Pass the directory you would like all results to output to within the **Setup your IOCs hunt** menu. If the directory name given does not exist, the framework will create it for you.

#### Credentials
In order to access the hosts you would like to investigate, the framework will need a set of credentials (currently username and password) to use on the remote hosts. Pass the username and password into the framework within the **Setup your IOCs hunt** menu.

#### Remote Hosts
You can use the frameworks built in scanning functionality to create the file for your or simply define your own list of IPv4 addresses. Once you have created the file or used the built in ping scan, pass the file into the framework within the **Setup your IOCs hunt** menu.

#### Indicators of Compromise
The framework works on simple input files. These input files contain the various kinds of indicators of compromise (IOCs) the framework is capable of investigating. Simply create files that contain each kind of IOC you wish to search for and pass them into the framework within the **Setup your IOCs hunt** menu.

The following are the currently supported types of known bad IOCs the framework can search for. This list and the frameworks capabilities will continue to grow over time as development continues.

1. Registry entries
1. DNS resolutions
1. IP connections
1. Files
1. Users
1. Host file entries
1. Scheduled tasks

### Hunting
Once you have properly setup the framework with the TrustedHosts, Results Directory, Credentials, Remote Hosts, and IOCs you are ready to begin hunting. If a hunt discovers any IOC, it will output the results to the output directory specified during configuration into a single .csv file containing the results of the hunt for all hosts investigated.

#### Registry Entries
The framework will look for registry key names or values that contain each of the registry key based IOCs within certain HK paths on the remote hosts. The list of currently supported paths is limited to:

* HKLM:\Software\Microsoft\Windows\CurrentVersion\Run
* HKLM:\Software\Microsoft\Windows\CurrentVersion\RunOnce
* HKCU:\Software\Microsoft\Windows\CurrentVersion\Run
* HKCU:\Software\Microsoft\Windows\CurrentVersion\RunOnce

#### DNS Resolutions
The framework will look for domain name based IOCs utilizing Get-DnsClientCache on the remote hosts, looking for entries that match each of the dns based IOCs configured.

#### IP Connections
The framework will look for IP based IOCs utilizing Get-NetTCPConnection on the remote hosts, looking for established connections that match each of the IP based IOCs configured.

#### Files
The framework will look for file based IOCs utilizing recursive directory searching on the remote hosts within the C:\ drive, looking for entries that match each of the file based IOCs configured.

#### Users
The framework will look for user based IOCs utilizing Get-LocalUser on the remote hosts, looking for users that match each of the user based IOCs configured.

#### Host File Entries
The framework will look for hosts file based IOCs within the *C:\Windows\System32\drivers\etc\hosts* file on the remote hosts, looking for entries that match each of the hosts file based IOCs configured.

#### Scheduled Tasks
The framework will look for scheduled task names utilizing Get-ScheduledTask on the remote hosts, looking for names that match each of the scheduled task based IOCs configured.

## Authors
* **Ashton Hanisch** - *Initial Work*

## License
This project is licensed under the Apache 2.0 license - see the (LICENSE) file for details

## To Do
- [ ] Documentation
- [ ] Add Show-HelpMenu detailing script capabilities, needs, output, etc.
- [ ] Add ability to perform current state baselining tasks (hashing drives/files/folders/etc.)
- [ ] Add ability to compare known good baseline to current state
- [ ] Standardize each tasks functionality and output
- [ ] Add more input validation
- [ ] Add more error handling
