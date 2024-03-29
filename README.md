# Hunt-Iocs
Automation framework built in PowerShell to quickly and easily assist with investigating, collecting, and documenting known indicators of compromise (IOCs) on any number of remote machines as well as automating various other investigative tasks.

## Installation
No installation is needed in order to get a copy of the project up and running. If it has not been done already in your environment, ensure to set your execution policy to allow PowerShell scripts to run. 

The following may not be best practice for your environment, but will work within test environments to get up and running quickly.
```powershell
Set-ExecutionPolicy -ExecutionPolicy Unrestricted
```

## Features
- Simple menu based interface
- Progress indication during each hunt
- Ability to perform simple ping scan to identify live hosts on the network
- Ability to investigate multiple types of IOCs on any amount of remote hosts
- Ability to collect results from investigating multiple types of IOCs into easy to visualize .csv files
- Ability to download/aggregate file based IOCs discovered during investigations to local machine for static/dynamic analysis
- Ability to establish a baseline on any amount of remote hosts
- Remote host baseline consists of gathering and documenting the following host properties:
  - Services
  - Processes
  - Network connections
  - Local users
  - Local administrators
  - Local groups
  - Drives
  - Shares
  - Network adapters
  - Scheduled tasks
  - Dns resolutions
  - Registry run keys
  - MD5 hashes of all files on all drives

## Quickstart
Check out the Hunt-Iocs [Wiki](https://github.com/ajhanisch/hunt-iocs/wiki) for instructions on getting started with Hunt-Iocs.
