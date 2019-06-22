# Hunt-Iocs
![GitHub Logo](/images/main_menu.png)
PowerShell script designed to quickly and easily assist with investigating known indicators of compromise (IOCs) on multiple remote machines.

# Usage Examples
## Ping Scan
![Ping Sweep](/images/example_ping_sweep.png)
From [2] Hunt for IOCs -> [1] Determine live hosts on network, the script is able to take simple input of a /24 network ending in .0, IP to start ping scan, IP to end ping scan, and amount of pings to send. Output is a single text file containing the IPv4 addresses of machines that responded to this simple ping scan.

## Registry Hunt
![Registry Hunt](/images/example_registry_hunt.png)
After going through [1] Setup your IOCs hunt and telling the script which registry based IOCs to look for, From [2] Hunt for IOCs -> [2] Investigate registry key based IOCs, the script is able to look through a certain set of registry keys on any amount of given machines for a name or value of the given IOCs. Output is a single csv file containing the results from any/all remote machines where the given IOCs were found.

# Work To Do
- [ ] Documentation
- [ ] Add ability to retrieve all file based IOCs discovered from remote hosts to analyze  
- [ ] Add ability to look for scheduled task IOCs  
- [ ] Add ability to look through windows event logs and construct a timeline of events  
- [ ] Add ability to run SysInternal Suite tools (handle, strings, etc.) and output/analyze results
- [ ] Standardize functionality and output
- [ ] Add more input validation  
- [ ] Add error handling 
