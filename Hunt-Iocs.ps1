Function Show-MainMenu {
    Clear-Host
    $global:Banner = 
@"
 __  __                  __           ______                           
/\ \/\ \                /\ \__       /\__  _\                          
\ \ \_\ \  __  __    ___\ \ ,_\      \/_/\ \/     ___     ___    ____  
 \ \  _  \/\ \/\ \  /' _ \ \ \/  _______\ \ \    / __`\  /'___\ /',__\ 
  \ \ \ \ \ \ \_\ \/\ \/\ \ \ \_/\______\\_\ \__/\ \L\ \/\ \__//\__, `\
   \ \_\ \_\ \____/\ \_\ \_\ \__\/______//\_____\ \____/\ \____\/\____/
    \/_/\/_/\/___/  \/_/\/_/\/__/        \/_____/\/___/  \/____/\/___/ 

"@
    $global:Info = 
@"
        Tool    :: Hunt-Iocs
        Author  :: Ashton Hanisch
        Github  :: https://github.com/ajhanisch/hunt-iocs
        Version :: 1.0
        License :: Apache License, Version 2.0

"@
    $Options = 
@" 
        [1] : Setup your IOCs hunt
        [2] : Hunt for IOCs
        [Q] : Quit

"@

    Write-Host $global:Banner -ForegroundColor Green
    Write-Host $global:Info -ForegroundColor Magenta
    Write-Host $Options -ForegroundColor Yellow
}

Function Show-SetupMenu {
    $Options = 
@"
        [1]  : Set local TrustedHosts file
        [2]  : Set local results output directory
        [3]  : Set remote credentials
        [4]  : Set remote hosts
        [5]  : Set registry key based IOCs
        [6]  : Set dns based IOCs
        [7]  : Set ip based IOCs
        [8]  : Set file based IOCs
        [9]  : Set user based IOCs
        [10] : Set hosts file based IOCs
        [11] : Set scheduled task based IOCs
        [R]  : Return to previous menu

"@
    do
    {
        Clear-Host
        Write-Host $global:Banner -ForegroundColor Green
        Write-Host $global:Info -ForegroundColor Magenta
        Write-Host $Options -ForegroundColor Yellow
        $Input = Read-Host -Prompt "Please make a selection"
        switch($Input)
        {
            '1' { 
                $LocalSubnet = ((Get-NetIPAddress -AddressFamily IPv4).Where({$_.InterfaceAlias -notmatch "Bluetooth|Loopback"}).IPAddress -replace "\d{1,3}$","0").Split(".")[0..2] -join "."
                $ExampleInfo = 
@"

Example input using your local subnet [$LocalSubnet]:
[Single host]    :: $LocalSubnet.10
[Multiple hosts] :: $LocalSubnet.10,$LocalSubnet.20
[Single subnet]  :: $LocalSubnet.*

"@
                Write-Host $ExampleInfo -ForegroundColor Cyan
                $TrustedHosts = Read-Host -Prompt "Enter host(s) "
                Modify-TrustedHosts -TrustedHosts $TrustedHosts
             }
            '2' { 
                $ExampleInfo = 
@"

Example input:
[In Current Directory] : output
[In Other Directory]   : C:\Users\YOU\Desktop\Hunt-Iocs\output

"@
                Write-Host $ExampleInfo -ForegroundColor Cyan
                $global:OutputDirectory = Read-Host -Prompt "Enter directory: "
                Create-Directory -Directory $global:OutputDirectory
             }
             '3' {
                $ExampleInfo = 
@"

Example input:
[User] : Administrator
[Pass] : Password

"@
                Write-Host $ExampleInfo -ForegroundColor Cyan
                $UserName = Read-Host -Prompt "Enter username for remote access to hosts "
                $UserPass = Read-Host -Prompt "Enter password for remote access to hosts "
                Create-SecureCredentials -UserName $UserName -UserPass $UserPass
             }
             '4' {
                $ExampleInfo = 
@"

Example input:
[Path to Hosts File] : live_hosts.txt

"@
                Write-Host $ExampleInfo -ForegroundColor Cyan
                $RemoteHosts = Read-Host -Prompt "Enter path to live hosts file "
                $global:RemoteHosts = Get-Content -Path $RemoteHosts
                $global:RemoteHostsCount = $global:RemoteHosts.Count
                Write-Host "Remote hosts set. Investigating [$global:RemoteHostsCount] remote hosts." -ForegroundColor Green
             }
             '5' {
                $ExampleInfo = 
@"

Example input:
[Path to Registry Key Based IOCs] : IOCs\regs.txt

"@
                Write-Host $ExampleInfo -ForegroundColor Cyan
                $RegistryIocs = Read-Host -Prompt "Enter path to registry key based IOCs "
                $global:RegistryIocs = Get-Content -Path $RegistryIocs
                $global:RegistryIocsCount = $global:RegistryIocs.Count
                Write-Host "Registry key based IOCs set. Investigating [$global:RegistryIocsCount] IOCs." -ForegroundColor Green
             }
             '6' {
                $ExampleInfo = 
@"

Example input:
[Path to Dns Based IOCs] : IOCs\dns.txt

"@
                Write-Host $ExampleInfo -ForegroundColor Cyan
                $DnsIocs = Read-Host -Prompt "Enter path to dns based IOCs "
                $global:DnsIocs = Get-Content -Path $DnsIocs
                $global:DnsIocsCount = $global:DnsIocs.Count
                Write-Host "Dns based IOCs set. Investigating [$global:DnsIocsCount] IOCs." -ForegroundColor Green
             }
             '7' {
                $ExampleInfo = 
@"

Example input:
[Path to Ip Based IOCs] : IOCs\ips.txt

"@
                Write-Host $ExampleInfo -ForegroundColor Cyan
                $IpIocs = Read-Host -Prompt "Enter path to ip based IOCs"
                $global:IpIocs = Get-Content -Path $IpIocs
                $global:IpIocsCount = $global:IpIocs.Count
                Write-Host "Ip based IOCs set. Investigating [$global:IpIocsCount] IOCs." -ForegroundColor Green
             }
             '8' {
                $ExampleInfo = 
@"

Example input:
[Path to File Based IOCs] : IOCs\files.txt

"@
                Write-Host $ExampleInfo -ForegroundColor Cyan
                $FileIocs = Read-Host -Prompt "Enter path to file based IOCs"
                $global:FileIocs = Get-Content -Path $FileIocs
                $global:FileIocsCount = $global:FileIocs.Count
                Write-Host "File based IOCs set. Investigating [$global:FileIocsCount] IOCs." -ForegroundColor Green
             }
             '9' {
                $ExampleInfo = 
@"

Example input:
[Path to User Based IOCs] : IOCs\users.txt

"@
                Write-Host $ExampleInfo -ForegroundColor Cyan
                $UserIocs = Read-Host -Prompt "Enter path to user based IOCs"
                $global:UserIocs = Get-Content -Path $UserIocs
                $global:UserIocsCount = $global:UserIocs.Count
                Write-Host "User based IOCs set. Investigating [$global:UserIocsCount] IOCs." -ForegroundColor Green
             }
             '10' {
                $ExampleInfo = 
@"

Example input:
[Path to Hosts File Based IOCs] : IOCs\hosts_files.txt

"@
                Write-Host $ExampleInfo -ForegroundColor Cyan
                $HostsFileIocs = Read-Host -Prompt "Enter path to hosts file based IOCs"
                $global:HostsFileIocs = Get-Content -Path $HostsFileIocs
                $global:HostsFileIocsCount = $global:HostsFileIocs.Count
                Write-Host "Hosts file based IOCs set. Investigating [$global:HostsFileIocsCount] IOCs." -ForegroundColor Green
             }
             '11' {
                $ExampleInfo = 
@"

Example input:
[Path to Scheduled Task Based IOCs] : IOCs\scheduled_tasks.txt

"@
                Write-Host $ExampleInfo -ForegroundColor Cyan
                $ScheduledTaskIocs = Read-Host -Prompt "Enter path to scheduled task based IOCs"
                $global:ScheduledTaskIocs = Get-Content -Path $ScheduledTaskIocs
                $global:ScheduledTaskIocsCount = $global:ScheduledTaskIocs.Count
                Write-Host "Scheduled task based IOCs set. Investigating [$global:ScheduledTaskIocsCount] IOCs." -ForegroundColor Green                
             }
            'r' { return }
            default { 'Invalid option' }
        }
        Pause
    }
    until($Input -eq 'r')
}

Function Modify-TrustedHosts {
    param(
        [string]$TrustedHosts
    )

    $TrustedHostsPath = "WSMan:\localhost\Client\TrustedHosts"

    foreach($TrustedHost in $TrustedHosts.Split(','))
    {
        if(!((Get-Item -Path $TrustedHostsPath).Value.Contains($TrustedHost)))
        {
            Write-Host "Adding ${TrustedHost}" -ForegroundColor Green
            Set-Item $TrustedHostsPath -Concatenate -Value $TrustedHost -Force
        }
        else
        {
            Write-Host "${TrustedHost} already trusted host(s)" -ForegroundColor Yellow
        }
    }
}

Function Create-Directory {
    param(
        [string]$Directory
    )

    if(!(Test-Path -Path $Directory))
    {
        New-Item -Path $Directory -ItemType Directory -Force | Out-Null
    }
}

Function Create-SecureCredentials {
    param(
        [Parameter(Mandatory=$true)]
        [string]$UserName,
        [Parameter(Mandatory=$true)]
        [string]$UserPass
    )

    $UserPassSecure = ConvertTo-SecureString $UserPass -AsPlainText -Force
    $global:UserCredentials = New-Object -TypeName System.Management.Automation.PSCredential $UserName,$UserPassSecure
    Write-Host "Remote credentials set." -ForegroundColor Green
}

Function Show-HuntMenu {
    $Options = 
@"
        [1] : Determine live hosts on network
        [2] : Investigate registry key based IOCs
        [3] : Investigate dns based IOCs
        [4] : Investigate ip based IOCs
        [5] : Investigate file based IOCs
        [6] : Investigate user based IOCs
        [7] : Investigate host file based IOCs
        [8] : Investigate scheduled task based IOCs
        [9] : Download discovered file based IOCs
        [R] : Return to previous menu

"@
    do
    {
        Clear-Host
        Write-Host $global:Banner -ForegroundColor Green
        Write-Host $global:Info -ForegroundColor Magenta
        Write-Host $Options -ForegroundColor Yellow
        $Input = Read-Host -Prompt "Please make a selection"
        switch($Input)
        {
            '1' { 
                $LocalSubnet = ((Get-NetIPAddress -AddressFamily IPv4).Where({$_.InterfaceAlias -notmatch "Bluetooth|Loopback"}).IPAddress -replace "\d{1,3}$","0")
                $ExampleInfo = 
@"

Example input using your local subnet [$LocalSubnet]:
[Network] : $LocalSubnet
[Start]   : 1
[End]     : 254
[Pings]   : 1

"@
                Write-Host $ExampleInfo -ForegroundColor Cyan
                $Network = Read-Host -Prompt "Enter an IPv4 network ending in 0 "
                $Start = Read-Host -Prompt "Enter starting IP "
                $End = Read-Host -Prompt "Enter ending IP "
                $Ping = Read-Host -Prompt "Enter the # of pings to use "
                Determine-LiveHosts -Network $Network -Start $Start -End $End -Ping $Ping
             }
             '2' { Investigate-RegistryIocs }
             '3' { Investigate-DnsIocs }
             '4' { Investigate-IpIocs }
             '5' { Investigate-FileIocs }
             '6' { Investigate-UserIocs }
             '7' { Investigate-HostsFileIocs }
             '8' { Investigate-ScheduledTaskIocs }
             '9' {
                $ExampleInfo =
@"

Example input using your current output directory [$global:OutputDirectory]:
[Path to Discovered File IOCs] : $($global:OutputDirectory)\iocs_file.csv

"@
                Write-Host $ExampleInfo -ForegroundColor Cyan
                $DiscoveredFileIocs = Read-Host -Prompt "Enter path to discovered file IOCs "
                Download-FileIocs -DiscoveredFileIocs $DiscoveredFileIocs
             }
            'r' { return }
            default { 'Invalid option' }
        }
        Pause
    }
    until($Input -eq 'r')
}

Function Determine-LiveHosts {
    Param(
    [Parameter(HelpMessage="Enter an IPv4 subnet ending in 0.")]
    [ValidatePattern("\d{1,3}\.\d{1,3}\.\d{1,3}\.0")]
    [string]$Network,
 
    [ValidateRange(1,254)]
    [int]$Start,
 
    [ValidateRange(1,254)]
    [int]$End,
 
    [ValidateRange(1,10)]
    [Alias("count")]
    [int]$Ping
    )

    $LiveHostsOutput = "$((Get-Location).Path)\live_hosts.txt"

    $ProgressHashTable = @{
        Activity = "Ping Sweep"
        CurrentOperation = "None"
        Status = "Pinging IP Address"
        PercentComplete = 0
    }
 
    $Count = ($End - $Start)+1 
    $Base = $Network.Split(".")[0..2] -join "." 
    $i = 0 
    while ($Start -le $End) {
      $i++
      $ProgressHashTable.PercentComplete = ($i/$Count)*100
      $IP = "$Base.$Start" 
      $ProgressHashTable.currentoperation = $IP
      Write-Progress @ProgressHashTable
 
      if (Test-Connection -ComputerName $IP -Count $Ping -Quiet) 
      {
        Write-Host "Host [${IP}] responded to ping!" -ForegroundColor Green
        $IP | Out-File -FilePath $LiveHostsOutput -Append -Force
      }
      
      $Start++
    }

    if(Test-Path -Path $LiveHostsOutput)
    {
        $LiveHostsOutputCount = $((Get-Content -Path $LiveHostsOutput).Count-1)
        Write-Host "Ping sweep finished with [$LiveHostsOutputCount] live host(s) found. Results in [$LiveHostsOutput]." -ForegroundColor Green
    }
    else
    {
        Write-Host "Ping sweep finished with [0] live hosts found." -ForegroundColor Yellow
        Write-Host "If you are not getting results you expect, hosts may not be responding to ping." -ForegroundColor Yellow
        Write-Host "You can create your own line separated file containing the IPv4 addresses you with to investigate." -ForegroundColor Yellow
    }
}

Function Investigate-RegistryIocs {
    $IocsResultsOutput = "$($global:OutputDirectory)\iocs_registry.csv"
    $ProgressHashTable = @{
        Activity = "Registry Investigation"
        CurrentOperation = "None"
        Status = "Investigating IP Address"
        PercentComplete = 0
    }
    $i = 0
    foreach($RemoteHost in $global:RemoteHosts)
    {
        $i ++
        $ProgressHashTable.PercentComplete = ($i/$global:RemoteHostsCount)*100
        $ProgressHashTable.CurrentOperation = $RemoteHost
        Write-Progress @ProgressHashTable

        $ServerResults = Invoke-Command -ComputerName $RemoteHost -Credential $global:UserCredentials -ScriptBlock {
            (Get-ItemProperty HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run -ErrorAction SilentlyContinue).PSObject.Properties | Select-Object -Property Name,Value,PSComputerName,@{Name="HiveKey"; Expression={"HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run"}};
            (Get-ItemProperty HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce -ErrorAction SilentlyContinue).PSObject.Properties | Select-Object -Property Name,Value,PSComputerName,@{Name="HiveKey"; Expression={"HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce"}};
            (Get-ItemProperty HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run -ErrorAction SilentlyContinue).PSObject.Properties | Select-Object -Property Name,Value,PSComputerName,@{Name="HiveKey"; Expression={"HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run"}}
            (Get-ItemProperty HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce -ErrorAction SilentlyContinue).PSObject.Properties | Select-Object -Property Name,Value,PSComputerName,@{Name="HiveKey"; Expression={"HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce"}};
            Write-Output $ServerResults
        }

        foreach($Ioc in $global:RegistryIocs)
        {
            foreach($Result in $ServerResults)
            {
                if($Result.Value -match $Ioc -or $Result.Name -match $Ioc)
                {
                    Write-Host "Found registry key based IOC [${Ioc}] on [${RemoteHost}]! " -ForegroundColor Red -NoNewline
                    Write-Host "Adding to [${IocsResultsOutput}]." -ForegroundColor Yellow
                    Export-Csv -InputObject $Result -Path $IocsResultsOutput -NoTypeInformation -Append
                }
            }
        }
    }

    if(Test-Path -Path $IocsResultsOutput)
    {
        $IocsResultsOutputCount = $((Get-Content -Path $IocsResultsOutput).Count-1)
        Write-Host "Registry investigation finished with [$IocsResultsOutputCount] result(s) found. Results in [$IocsResultsOutput]." -ForegroundColor Green
    }
    else
    {
        Write-Host "Registry investigation finished with [0] results found." -ForegroundColor Yellow
    }
}

Function Investigate-DnsIocs {
    $IocsResultsOutput = "$($global:OutputDirectory)\iocs_dns.csv"
    $ProgressHashTable = @{
        Activity = "Dns Investigation"
        CurrentOperation = "None"
        Status = "Investigating IP Address"
        PercentComplete = 0
    }
    $i = 0
    foreach($RemoteHost in $global:RemoteHosts)
    {
        $i ++
        $ProgressHashTable.PercentComplete = ($i/$global:RemoteHostsCount)*100
        $ProgressHashTable.CurrentOperation = $RemoteHost
        Write-Progress @ProgressHashTable

        $ServerResults = Invoke-Command -ComputerName $RemoteHost -Credential $global:UserCredentials -ScriptBlock {
            Get-DnsClientCache
            Write-Output $ServerResults
        }   

        foreach($Ioc in $global:DnsIocs)
        {
            if($Ioc -in $ServerResults.Entry)
            {
                Write-Host "Found dns based IOC [${Ioc}] on [${RemoteHost}]! " -ForegroundColor Red -NoNewline
                Write-Host "Adding to [${IocsResultsOutput}]." -ForegroundColor Yellow
                $ServerResults | ? { $_.Entry -eq $Ioc } | Export-Csv -Path $IocsResultsOutput -NoTypeInformation -Append -Force
            }
        }
    }

    if(Test-Path -Path $IocsResultsOutput)
    {
        $IocsResultsOutputCount = $((Get-Content -Path $IocsResultsOutput).Count-1)
        Write-Host "DNS investigation finished with [$IocsResultsOutputCount] result(s) found. Results in [$IocsResultsOutput]." -ForegroundColor Green
    }
    else
    {
        Write-Host "DNS investigation finished with [0] results found." -ForegroundColor Yellow
    }
}

Function Investigate-IpIocs {
    $IocsResultsOutput = "$($global:OutputDirectory)\iocs_ip.csv"
    $ProgressHashTable = @{
        Activity = "IP Investigation"
        CurrentOperation = "None"
        Status = "Investigating IP Address"
        PercentComplete = 0
    }
    $i = 0
    foreach($RemoteHost in $global:RemoteHosts)
    {
        $i ++
        $ProgressHashTable.PercentComplete = ($i/$global:RemoteHostsCount)*100
        $ProgressHashTable.CurrentOperation = $RemoteHost
        Write-Progress @ProgressHashTable

        $ServerResults = Invoke-Command -ComputerName $RemoteHost -Credential $global:UserCredentials -ScriptBlock {
            Get-NetTCPConnection
            Write-Output $ServerResults
        }
  
        foreach($Ioc in $global:IpIocs)
        {
            if($ServerResults.RemoteAddress -eq $Ioc)
            {
                Write-Host "Found IP based IOC [${Ioc}] on [${RemoteHost}]! " -ForegroundColor Red -NoNewline
                Write-Host "Adding to [${IocsResultsOutput}]." -ForegroundColor Yellow
                $IocsFinding = New-Object System.Object
                $IocsFinding | Add-Member -MemberType NoteProperty -Name "Host" -Value $RemoteHost
                $IocsFinding | Add-Member -MemberType NoteProperty -Name "Ip" -Value $Ioc
                $IocsFinding | Export-Csv -Path $IocsResultsOutput -NoTypeInformation -Append -Force            
            }
        }
    }

    if(Test-Path -Path $IocsResultsOutput)
    {
        $IocsResultsOutputCount = $((Get-Content -Path $IocsResultsOutput).Count-1)
        Write-Host "IP investigation finished with [$IocsResultsOutputCount] result(s) found. Results in [$IocsResultsOutput]." -ForegroundColor Green
    }
    else
    {
        Write-Host "IP investigation finished with [0] results found." -ForegroundColor Yellow
    }
}

Function Investigate-FileIocs {
    $IocsResultsOutput = "$($global:OutputDirectory)\iocs_file.csv"
    $ProgressHashTable = @{
        Activity = "File Investigation"
        CurrentOperation = "None"
        Status = "Investigating IP Address"
        PercentComplete = 0
    }
    $i = 0
    foreach($RemoteHost in $global:RemoteHosts)
    {
        $i ++
        $ProgressHashTable.PercentComplete = ($i/$global:RemoteHostsCount)*100
        $ProgressHashTable.CurrentOperation = $RemoteHost
        Write-Progress @ProgressHashTable

        $ServerResults = Invoke-Command -ComputerName $RemoteHost -Credential $global:UserCredentials -ScriptBlock {
            Get-ChildItem -Path C:\ -Include $using:global:FileIocs -Recurse -Force -ErrorAction SilentlyContinue | 
            Select-Object -Property Name,FullName,Length,CreationTime,CreationTimeUtc,LastAccessTime,LastAccessTimeUtc,LastWriteTime,LastWriteTimeUtc,PSComputerName
        }
     
        $ServerResultsCount = $ServerResults.Count 
        if($ServerResultsCount -gt 0)
        {
            foreach($Result in $ServerResults)
            {
                Write-Host "Found file based IOC result [$($Result.FullName)] on [${RemoteHost}]! " -ForegroundColor Red -NoNewline
                Write-Host "Adding to [${IocsResultsOutput}]." -ForegroundColor Yellow
                Export-Csv -InputObject $Result -Path $IocsResultsOutput -NoTypeInformation -Append
            }
        }
        else
        {
            Write-Host "Did not find any file based IOCs on [${RemoteHost}]" -ForegroundColor Green
        }
    }

    if(Test-Path -Path $IocsResultsOutput)
    {
        $IocsResultsOutputCount = $((Get-Content -Path $IocsResultsOutput).Count-1)
        Write-Host "File investigation finished with [$IocsResultsOutputCount] result(s) found. Results in [$IocsResultsOutput]." -ForegroundColor Green
    }
    else
    {
        Write-Host "File investigation finished with [0] results found." -ForegroundColor Yellow
    }
}

Function Investigate-UserIocs {
    $IocsResultsOutput = "$($global:OutputDirectory)\iocs_user.csv"
    $ProgressHashTable = @{
        Activity = "User Investigation"
        CurrentOperation = "None"
        Status = "Investigating IP Address"
        PercentComplete = 0
    }
    $i = 0
    foreach($RemoteHost in $global:RemoteHosts)
    {
        $i ++
        $ProgressHashTable.PercentComplete = ($i/$global:RemoteHostsCount)*100
        $ProgressHashTable.CurrentOperation = $RemoteHost
        Write-Progress @ProgressHashTable

        $ServerResults = Invoke-Command -ComputerName $RemoteHost -Credential $global:UserCredentials -ScriptBlock {
            Get-LocalUser
            Write-Output $ServerResults
        }

        foreach($User in $global:UserIocs)
        {
            if($User -in $ServerResults.Name)
            {
                Write-Host "Found user based IOC [${User}] on [${RemoteHost}]! " -ForegroundColor Red -NoNewline
                Write-Host "Adding to [${IocsResultsOutput}]." -ForegroundColor Yellow
                $ServerResults | ? { $_.Name -eq $User } | Export-Csv -Path $IocsResultsOutput -NoTypeInformation -Append -Force
            }
        }
    }

    if(Test-Path -Path $IocsResultsOutput)
    {
        $IocsResultsOutputCount = $((Get-Content -Path $IocsResultsOutput).Count-1)
        Write-Host "User investigation finished with [$IocsResultsOutputCount] result(s) found. Results in [$IocsResultsOutput]." -ForegroundColor Green
    }
    else
    {
        Write-Host "User investigation finished with [0] results found." -ForegroundColor Yellow
    }
}

Function Investigate-HostsFileIocs {
    $IocsResultsOutput = "$($global:OutputDirectory)\iocs_hosts_file.csv"
    $ProgressHashTable = @{
        Activity = "Hosts File Investigation"
        CurrentOperation = "None"
        Status = "Investigating IP Address"
        PercentComplete = 0
    }
    $i = 0
    foreach($RemoteHost in $global:RemoteHosts)
    {
        $i ++
        $ProgressHashTable.PercentComplete = ($i/$global:RemoteHostsCount)*100
        $ProgressHashTable.CurrentOperation = $RemoteHost
        Write-Progress @ProgressHashTable

        $ServerResults = Invoke-Command -ComputerName $RemoteHost -Credential $global:UserCredentials -ScriptBlock {
            Get-Content -Path C:\Windows\System32\drivers\etc\hosts
            Write-Output $ServerResults
        }
  
        foreach($HostsFile in $global:HostsFileIocs)
        {
            if($ServerResults | Select-String -SimpleMatch $HostsFile)
            {
                Write-Host "Found hosts file based IOC [${HostsFile}] on [${RemoteHost}]! " -ForegroundColor Red -NoNewline
                Write-Host "Adding to [${IocsResultsOutput}]." -ForegroundColor Yellow
                $IocsFinding = New-Object System.Object
                $IocsFinding | Add-Member -MemberType NoteProperty -Name "Host" -Value $RemoteHost
                $IocsFinding | Add-Member -MemberType NoteProperty -Name "Entry" -Value $HostsFile
                $IocsFinding | Export-Csv -Path $IocsResultsOutput -NoTypeInformation -Append -Force            
            }
        }
    }

    if(Test-Path -Path $IocsResultsOutput)
    {
        $IocsResultsOutputCount = $((Get-Content -Path $IocsResultsOutput).Count-1)
        Write-Host "Hosts file investigation finished with [$IocsResultsOutputCount] result(s) found. Results in [$IocsResultsOutput]." -ForegroundColor Green
    }
    else
    {
        Write-Host "Hosts file investigation finished with [0] results found." -ForegroundColor Yellow
    }
}

Function Investigate-ScheduledTaskIocs {
    $IocsResultsOutput = "$($global:OutputDirectory)\iocs_scheduled_tasks.csv"
    $ProgressHashTable = @{
        Activity = "Scheduled Tasks Investigation"
        CurrentOperation = "None"
        Status = "Investigating IP Address"
        PercentComplete = 0
    }
    $i = 0
    foreach($RemoteHost in $global:RemoteHosts)
    {
        $i ++
        $ProgressHashTable.PercentComplete = ($i/$global:RemoteHostsCount)*100
        $ProgressHashTable.CurrentOperation = $RemoteHost
        Write-Progress @ProgressHashTable

        $ServerResults = Invoke-Command -ComputerName $RemoteHost -Credential $global:UserCredentials -ScriptBlock {
            Get-ScheduledTask
            Write-Output $ServerResults
        }
  
        foreach($ScheduledTask in $global:ScheduledTaskIocs)
        {
            if($ScheduledTask -in $ServerResults.TaskName)
            {
                Write-Host "Found scheduled task based IOC [${ScheduledTask}] on [${RemoteHost}]! " -ForegroundColor Red -NoNewline
                Write-Host "Adding to [${IocsResultsOutput}]." -ForegroundColor Yellow
                $ServerResults | 
                ? { $_.TaskName -eq $ScheduledTask } |
                # For the love of god, there has to be a better way to do the next line. 
                # I want to get all of the properties, even when they are properties inside of properties.
                # It works, but I am quite sure there is a better way.
                Select-Object -Property PSComputerName,@{Name="Actions";Expression={$_.Actions | Select-Object -Property *}},Author,Date,State,Description,Documentation,@{Name="Principal";Expression={$_.Principal | Select-Object -Property *}},SecurityDescriptor,@{Name="Settings";Expression={$_.Settings | Select-Object -Property *}},Source,TaskName,TaskPath,@{Name="Triggers";Expression={$_.Triggers | Select-Object -Property *}},URI,Version |
                Export-Csv -Path $IocsResultsOutput -NoTypeInformation -Append -Force
            }
        }
    }

    if(Test-Path -Path $IocsResultsOutput)
    {
        $IocsResultsOutputCount = $((Get-Content -Path $IocsResultsOutput).Count-1)
        Write-Host "Scheduled task investigation finished with [$IocsResultsOutputCount] result(s) found. Results in [$IocsResultsOutput]." -ForegroundColor Green
    }
    else
    {
        Write-Host "Scheduled task investigation finished with [0] results found." -ForegroundColor Yellow
    }
}

Function Download-FileIocs {
    Param(
        [Parameter()]
        [string]$DiscoveredFileIocs
    )    

    $global:DiscoveredFileIocs = Import-Csv -Path $DiscoveredFileIocs
    $global:DiscoveredFileIocsCount = $global:DiscoveredFileIocs.Count

    $ProgressHashTable = @{
        Activity = "File IOC Download"
        CurrentOperation = "None"
        Status = "Downloading File"
        PercentComplete = 0
    }

    $i = 0
    foreach($DiscoveredFileIoc in $global:DiscoveredFileIocs)
    {
        $i ++
        $ProgressHashTable.PercentComplete = ($i/$global:DiscoveredFileIocsCount)*100
        $ProgressHashTable.CurrentOperation = $DiscoveredFileIoc.Name
        Write-Progress @ProgressHashTable

        $RemoteSessionOutput = "$($global:OutputDirectory)\$($DiscoveredFileIoc.PSComputerName)"
        Create-Directory -Directory $RemoteSessionOutput

        try
        {
            $RemoteSession = New-PSSession -ComputerName $DiscoveredFileIoc.PSComputerName -Credential $global:UserCredentials
            Copy-Item -FromSession $RemoteSession -Path $DiscoveredFileIoc.FullName -Destination $RemoteSessionOutput
        }
        catch
        {
            $ErrorMessage = $_.Exception.Message
            $FailedItem = $_.Exception.ItemName
            Write-Host "Something went downloading $($DiscoveredFileIoc.Name) from $($DiscoveredFileIoc.PSComputerName) to $($RemoteSessionOutput)!" -ForegroundColor Red
            Write-Host "Error Message :: $ErrorMessage" -ForegroundColor Red
            Write-Host "Failed Item   :: $FailedItem" -ForegroundColor Red
        }
        finally
        {
            Remove-PSSession -Session $RemoteSession
        }
    }
}

##########################
# Entry point of script. #
##########################
do
{
    Show-MainMenu
    $Input = Read-Host -Prompt "Please make a selection"
    switch($Input)
    {
        '1' { Show-SetupMenu }
        '2' { Show-HuntMenu }
        'q' { return }
    }
}
until($Input -eq 'q')
