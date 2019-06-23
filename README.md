# Hunt-Iocs
## Script designed to quickly and easily assist with investigating known indicators of compromise (IOCs) on multiple remote machines.
![Hunt-Iocs_Banner](/images/main_menu.png)

# Usage Examples
## Ping Scan
### Ping scan results will be saved to a live_hosts.txt file and can be used as a basis to start all hunts.
### Steps to start ping scan.
1. Select `[2] Hunt for IOCs` from the main menu.
1. Select `[1] : Determine live hosts on network` from the hunt menu.
1. Enter the network (/24 ending in .0) you would like to scan. Example : `172.16.12.0`
1. Enter the IP to start the ping scan. Example : `2`
1. Enter the IP to end the ping scan. Example : `20`
1. Enter the amount of pings to send. Example : `1`
![Ping Sweep](/images/example_ping_sweep.png)
  
### Ping Scan Results
Output is a single text file containing the IPv4 addresses of machines that responded to this simple ping scan.
![Ping Sweep Results](/images/example_ping_sweep_results.png)
  
## Registry Hunt
### Steps to set your remote hosts in the setup menu before hunts.
1. Select `[1] : Setup your IOCs hunt` option from the main menu.
1. Select `[4] : Set remote hosts` option from the setup menu.
1. Enter path to live hosts file from the above ping scan. Example : `live_hosts.txt`
![Remote_Hosts_Setup](/images/remote_hosts_setup.png)
  
### Steps to start registry hunt.
1. Create regs.txt file within IOCs directory containing the keys you are looking for.
![Registry_Hunt_1](/images/example_registry_hunt_1.png)
1. Select `[1] : Setup your IOCs hunt` option from the main menu.
![Registry_Hunt_2](/images/example_registry_hunt_2.png)
1. Select `[5] : Set registry key based IOCs` option from the setup menu.
![Registry_Hunt_3](/images/example_registry_hunt_3.png)
1. Enter the path to the regs.txt file you created.
![Registry_Hunt_4](/images/example_registry_hunt_4.png)
1. Select `[R] : Return to previous menu` to return to main menu.
![Registry_Hunt_5](/images/example_registry_hunt_5.png)
1. Select `[2] : Hunt for IOCs` from the main menu.
![Registry_Hunt_6](/images/example_registry_hunt_6.png)
1. Select `[2] : Investigate registry key based IOCs` from the hunt menu.
![Registry_Hunt_7](/images/example_registry_hunt_7.png)
  
### Registry Hunt Results
After going through the above steps, the script is able to look through a certain set of registry keys on any amount of given machines for a name or value of the given IOCs. Output is a single csv file containing the results from any/all remote machines where the given IOCs were found.
![Registry Hunt Results](/images/example_registry_hunt_results.PNG)
  
# Work To Do
- [ ] Documentation
- [ ] Add ability to retrieve all file based IOCs discovered from remote hosts to analyze  
- [ ] Add ability to look for scheduled task IOCs  
- [ ] Add ability to look through windows event logs and construct a timeline of events  
- [ ] Add ability to run SysInternal Suite tools (handle, strings, etc.) and output/analyze results
- [ ] Standardize functionality and output
- [ ] Add more input validation  
- [ ] Add error handling 
