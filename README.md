# hunt-iocs
PowerShell scripts designed to assist with investigating known indicators of compromise (IOCs) on multiple remote machines.

# to-do
- [x] Replace all .lengths with .count  
- [ ] Replace write host with write verbose/debug/error  
- [x] Replace -Subnet with -TrustedHosts. Allow multiple from command line with commas and allow file input. Add each to trusted hosts.   
- [ ] Turn -Subnet into -Networks. Allow multiple from command line with commas and allow file input. Scan each network, determine live hosts, investigate live hosts.   
- [ ] Allow -LiveHosts to accept multiple from command line with commas and file input.   
- [ ] If given -Networks, scan input networks for live hosts, create hosts file, then start investigating.   
- [ ] If given -LiveHosts, do not scan networks for live hosts, simply start investigation.   
- [ ] Add live host detection (ping sweep)  
- [ ] Add ability to retrieve all file based IOCs discovered from remote hosts to analyze  
- [ ] Add ability to look for scheduled task IOCs  
- [ ] Add ability to look through windows event logs and construct a timeline of events  
- [ ] Add ability to run SysInternal Suite tools (handle, strings, etc.) on remote machines and capture/analyze results from remote hosts  
- [ ] Investigate code redundancy resolutions  
- [ ] Standardize functionality and output between current scripts  
- [ ] Add progress bars?  
- [ ] Add input validation  
- [ ] Add error handling  
