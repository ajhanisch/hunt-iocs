# Hunt-Iocs
Automation framework built in PowerShell to quickly and easily assist with investigating, collecting, and documenting known indicators of compromise (IOCs) on any number of remote machines as well as automating various other investigative tasks.

## Installation
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

## Quickstart
Check out the [Hunt-Iocs wiki](https://github.com/ajhanisch/hunt-iocs/wiki) for instructions on getting started with Hunt-Iocs.
