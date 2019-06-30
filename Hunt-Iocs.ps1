<#
    SHOW MENU FUNCTIONS
#>
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
        Github  :: https://ajhanisch.github.io/hunt-iocs/
        Version :: 1.0
        License :: Apache License, Version 2.0

"@
    $Options = 
@" 
        [1] : Setup Menu
        [2] : Hunt Menu
        [3] : Baseline Menu
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
        [12] : Set service based IOCs
        [13] : Set process based IOCs
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
                $global:LocalSubnet = ((Get-NetIPAddress -AddressFamily IPv4).Where({$_.InterfaceAlias -notmatch "Bluetooth|Loopback"}).IPAddress -replace "\d{1,3}$","0").Split(".")[0..2] -join "."
                $ExampleInfo = 
@"

Example input using your local subnet [$global:LocalSubnet]:
[Single host]    :: $global:LocalSubnet.10
[Multiple hosts] :: $global:LocalSubnet.10,$global:LocalSubnet.20
[Single subnet]  :: $global:LocalSubnet.*

"@
                Write-Host $ExampleInfo -ForegroundColor Cyan
                $TrustedHosts = Read-Host -Prompt "Enter host(s) "
                # Modified Valid IPv4 address regex pattern from https://gchq.github.io/CyberChef
                # Meant to allow for valid IPv4 addresses including wildcard *.
                # This is by design of how TrustedHosts file input works.
                $TrustedHostsValidated = Test-Pattern -Items $TrustedHosts -Pattern "(?:(?:\d|[01]?\d\d|2[0-4]\d|25[0-5]|\*)\.){3}(?:25[0-5]|2[0-4]\d|[01]?\d\d|\d|\*)(?:\/\d{1,2})?"
                Set-TrustedHosts -TrustedHosts $TrustedHostsValidated
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
                Set-Directory -Directory $global:OutputDirectory
             }
             '3' {
                $ExampleInfo = 
@"

Example input:
[User] : Administrator
[Pass] : Password

"@
                Write-Host $ExampleInfo -ForegroundColor Cyan
                $global:UserCredentials = $host.ui.PromptForCredential("Administrative Credentials", "Please enter user name and password.", "", "NetBiosUserName")
                Write-Host "Remote credentials set." -ForegroundColor Green
             }
             '4' {
                $ExampleInfo = 
@"

Example input:
[Path to Hosts File] : live_hosts.txt
        OR
[List of Hosts]      : 192.168.1.10,192.168.1.15

"@
                Write-Host $ExampleInfo -ForegroundColor Cyan
                $RemoteHosts = Read-Host -Prompt "Enter live hosts  "
                Set-RemoteHosts -RemoteHosts $RemoteHosts
             }
             '5' {
                $ExampleInfo = 
@"

Example input:
[Path to Registry Key Based IOCs] : iocs\regs.txt

"@
                Write-Host $ExampleInfo -ForegroundColor Cyan
                $RegistryIocs = Read-Host -Prompt "Enter path to registry key based IOCs "
                Test-UserPathExists -UserPath $RegistryIocs
                $global:RegistryIocs = Get-Content -Path $RegistryIocs
                $global:RegistryIocsCount = $global:RegistryIocs.Count
                Write-Host "Registry key based IOCs set. Investigating [$global:RegistryIocsCount] IOCs." -ForegroundColor Green
             }
             '6' {
                $ExampleInfo = 
@"

Example input:
[Path to Dns Based IOCs] : iocs\dns.txt

"@
                Write-Host $ExampleInfo -ForegroundColor Cyan
                $DnsIocs = Read-Host -Prompt "Enter path to dns based IOCs "
                Test-UserPathExists -UserPath $DnsIocs
                $global:DnsIocs = Get-Content -Path $DnsIocs
                $global:DnsIocsCount = $global:DnsIocs.Count
                Write-Host "Dns based IOCs set. Investigating [$global:DnsIocsCount] IOCs." -ForegroundColor Green
             }
             '7' {
                $ExampleInfo = 
@"

Example input:
[Path to Ip Based IOCs] : iocs\ips.txt

"@
                Write-Host $ExampleInfo -ForegroundColor Cyan
                $IpIocs = Read-Host -Prompt "Enter path to ip based IOCs"
                Test-UserPathExists -UserPath $IpIocs
                $global:IpIocs = Get-Content -Path $IpIocs
                $global:IpIocsCount = $global:IpIocs.Count
                Write-Host "Ip based IOCs set. Investigating [$global:IpIocsCount] IOCs." -ForegroundColor Green
             }
             '8' {
                $ExampleInfo = 
@"

Example input:
[Path to File Based IOCs] : iocs\files.txt

"@
                Write-Host $ExampleInfo -ForegroundColor Cyan
                $FileIocs = Read-Host -Prompt "Enter path to file based IOCs"
                Test-UserPathExists -UserPath $FileIocs
                $global:FileIocs = Get-Content -Path $FileIocs
                $global:FileIocsCount = $global:FileIocs.Count
                Write-Host "File based IOCs set. Investigating [$global:FileIocsCount] IOCs." -ForegroundColor Green
             }
             '9' {
                $ExampleInfo = 
@"

Example input:
[Path to User Based IOCs] : iocs\users.txt

"@
                Write-Host $ExampleInfo -ForegroundColor Cyan
                $UserIocs = Read-Host -Prompt "Enter path to user based IOCs"
                Test-UserPathExists -UserPath $UserIocs
                $global:UserIocs = Get-Content -Path $UserIocs
                $global:UserIocsCount = $global:UserIocs.Count
                Write-Host "User based IOCs set. Investigating [$global:UserIocsCount] IOCs." -ForegroundColor Green
             }
             '10' {
                $ExampleInfo = 
@"

Example input:
[Path to Hosts File Based IOCs] : iocs\hosts_files.txt

"@
                Write-Host $ExampleInfo -ForegroundColor Cyan
                $HostsFileIocs = Read-Host -Prompt "Enter path to hosts file based IOCs"
                Test-UserPathExists -UserPath $HostsFileIocs
                $global:HostsFileIocs = Get-Content -Path $HostsFileIocs
                $global:HostsFileIocsCount = $global:HostsFileIocs.Count
                Write-Host "Hosts file based IOCs set. Investigating [$global:HostsFileIocsCount] IOCs." -ForegroundColor Green
             }
             '11' {
                $ExampleInfo = 
@"

Example input:
[Path to Scheduled Task Based IOCs] : iocs\scheduled_tasks.txt

"@
                Write-Host $ExampleInfo -ForegroundColor Cyan
                $ScheduledTaskIocs = Read-Host -Prompt "Enter path to scheduled task based IOCs"
                Test-UserPathExists -UserPath $ScheduledTaskIocs
                $global:ScheduledTaskIocs = Get-Content -Path $ScheduledTaskIocs
                $global:ScheduledTaskIocsCount = $global:ScheduledTaskIocs.Count
                Write-Host "Scheduled task based IOCs set. Investigating [$global:ScheduledTaskIocsCount] IOCs." -ForegroundColor Green                
             }
             '12' {
                $ExampleInfo = 
@"

Example input:
[Path to Service Based IOCs] : iocs\services.txt

"@
                Write-Host $ExampleInfo -ForegroundColor Cyan
                $ServiceIocs = Read-Host -Prompt "Enter path to service based IOCs"
                Test-UserPathExists -UserPath $ServiceIocs
                $global:ServiceIocs = Get-Content -Path $ServiceIocs
                $global:ServiceIocsCount = $global:ServiceIocs.Count
                Write-Host "Service based IOCs set. Investigating [$global:ServiceIocsCount] IOCs." -ForegroundColor Green   
            }
             '13' {
                $ExampleInfo = 
@"

Example input:
[Path to Process Based IOCs] : iocs\processes.txt

"@
                Write-Host $ExampleInfo -ForegroundColor Cyan
                $ProcessIocs = Read-Host -Prompt "Enter path to process based IOCs"
                Test-UserPathExists -UserPath $ProcessIocs
                $global:ProcessIocs = Get-Content -Path $ProcessIocs
                $global:ProcessIocsCount = $global:ProcessIocs.Count
                Write-Host "Process based IOCs set. Investigating [$global:ProcessIocsCount] IOCs." -ForegroundColor Green   
            }
            'r' { return }
            default { 'Invalid option' }
        }
        Pause
    }
    until($Input -eq 'r')
}

Function Show-HuntMenu {
    $Options = 
@"
        [1]  : Find live hosts on network
        [2]  : Find registry key based IOCs
        [3]  : Find dns based IOCs
        [4]  : Find ip based IOCs
        [5]  : Find file based IOCs
        [6]  : Find user based IOCs
        [7]  : Find host file based IOCs
        [8]  : Find scheduled task based IOCs
        [9]  : Download discovered file based IOCs
        [10] : Find service based IOCs
        [11] : Find process based IOCs
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
                $ExampleInfo = 
@"

Example input using your local subnet [$global:LocalSubnet.0]:
[Network] : $global:LocalSubnet.0
[Start]   : 1
[End]     : 254
[Pings]   : 1

"@
                Write-Host $ExampleInfo -ForegroundColor Cyan
                $Network = Read-Host -Prompt "Enter an IPv4 network ending in 0 "
                $Start = Read-Host -Prompt "Enter starting IP "
                $End = Read-Host -Prompt "Enter ending IP "
                $Ping = Read-Host -Prompt "Enter the # of pings to use "
                Find-LiveHosts -Network $Network -Start $Start -End $End -Ping $Ping
             }
             '2' { Find-RegistryIocs }
             '3' { Find-DnsIocs }
             '4' { Find-IpIocs }
             '5' { Find-FileIocs }
             '6' { Find-UserIocs }
             '7' { Find-HostsFileIocs }
             '8' { Find-ScheduledTaskIocs }
             '9' {
                $ExampleInfo =
@"

Example input using your current output directory [$global:OutputDirectory]:
[Path to Discovered File IOCs] : $($global:OutputDirectory)\iocs_file.csv

"@
                Write-Host $ExampleInfo -ForegroundColor Cyan
                $DiscoveredFileIocs = Read-Host -Prompt "Enter path to discovered file IOCs "
                Get-FileIocs -DiscoveredFileIocs $DiscoveredFileIocs
             }
             '10' { Find-ServiceIocs }
             '11' { Find-ProcessIocs }
            'r' { return }
            default { 'Invalid option' }
        }
        Pause
    }
    until($Input -eq 'r')
}

Function Show-BaselineMenu {
    $Options = 
@"
        [1]  : Baseline remote hosts
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
            '1' { Get-HostBaseline }
            'r' { return }
            default { 'Invalid option' }
        }
        Pause
    }
    until($Input -eq 'q')
}


<#
    SETUP MENU FUNCTIONS
#>
Function Set-TrustedHosts {
    param(
        $TrustedHosts
    )

    $TrustedHostsPath = "WSMan:\localhost\Client\TrustedHosts"

    foreach($TrustedHost in $TrustedHosts)
    {
        if(!((Get-Item -Path $TrustedHostsPath).Value.Contains($TrustedHost)))
        {
            try {
                Set-Item $TrustedHostsPath -Concatenate -Value $TrustedHost -Force   
                Write-Host "Added $TrustedHost." -ForegroundColor Green
            }
            catch {
                $e = $_.Exception
                $LineNumber = $_.InvocationInfo.ScriptLineNumber
                Write-Host "Caught exception: $e" -ForegroundColor Red 
                Write-Host "Line number [$LineNumber]!"  -ForegroundColor Red
                exit
            }
        }
        else
        {
            Write-Host "$TrustedHost already trusted host(s)" -ForegroundColor Yellow
        }
    }
}

Function Set-Directory {
    param(
        [string]$Directory
    )

    if(!(Test-Path -Path $Directory))
    {
        try {
            New-Item -Path $Directory -ItemType Directory -Force | Out-Null
            Write-Host "[$Directory] created successfully!" -ForegroundColor Green
        }
        catch {
            $e = $_.Exception
            $LineNumber = $_.InvocationInfo.ScriptLineNumber
            Write-Host "Caught exception: $e" -ForegroundColor Red 
            Write-Host "Line number [$LineNumber]!"  -ForegroundColor Red
            exit
        }
    }
}

Function Set-RemoteHosts {
    Param(
        $RemoteHosts
    )

    try {
        if(Test-Path -Path $RemoteHosts)
        {
            $global:RemoteHosts = Get-Content -Path $RemoteHosts
            $global:RemoteHostsCount = $global:RemoteHosts.Count
            Write-Host "Remote hosts set. Investigating [$global:RemoteHostsCount] remote hosts." -ForegroundColor Green
        }
        elseif($RemoteHosts.Split(',').Count -gt 0)
        {        
            # Valid IPv4 address regex pattern from https://gchq.github.io/CyberChef
            $global:RemoteHosts = Test-Pattern -Items $RemoteHosts -Pattern "(?:(?:\d|[01]?\d\d|2[0-4]\d|25[0-5])\.){3}(?:25[0-5]|2[0-4]\d|[01]?\d\d|\d)(?:\/\d{1,2})?"
            $global:RemoteHostsCount = $global:RemoteHosts.Count
            Write-Host "Remote hosts set. Investigating [$global:RemoteHostsCount] remote hosts." -ForegroundColor Green
        }
    }
    catch {
        $e = $_.Exception
        $LineNumber = $_.InvocationInfo.ScriptLineNumber
        Write-Host "Exception     : $e" -ForegroundColor Red 
        Write-Host "Line number   : $LineNumber"  -ForegroundColor Red
        Write-Host "Help Info     : Input expected is either a path to a file or comma separated list of IPv4 addresses" -ForegroundColor Yellow
        exit
    }
}


<#
    HUNT MENU FUNCTIONS
#>
Function Find-LiveHosts {
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
        Write-Host "Host [$IP] responded to ping!" -ForegroundColor Green
        $IP | Out-File -FilePath $LiveHostsOutput -Append -Force
      }
      
      $Start++
    }

    if(Test-Path -Path $LiveHostsOutput)
    {
        $LiveHostsOutputCount = $((Get-Content -Path $LiveHostsOutput).Count)
        Write-Host "Ping sweep finished with [$LiveHostsOutputCount] live host(s) found. Results in [$LiveHostsOutput]." -ForegroundColor Green
    }
    else
    {
        Write-Host "Ping sweep finished with [0] live hosts found." -ForegroundColor Yellow
        Write-Host "If you are not getting results you expect, hosts may not be responding to ping." -ForegroundColor Yellow
        Write-Host "You can create your own line separated file containing the IPv4 addresses you with to investigate." -ForegroundColor Yellow
    }
}

Function Find-RegistryIocs {
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

        try {
            $ServerResults = Invoke-Command -ComputerName $RemoteHost -Credential $global:UserCredentials -ScriptBlock {
                (Get-ItemProperty HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run -ErrorAction SilentlyContinue).PSObject.Properties | Select-Object -Property Name,Value,PSComputerName,@{Name="HiveKey"; Expression={"HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run"}} | Where-Object { $_.Name -notlike "PS*" }
                (Get-ItemProperty HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce -ErrorAction SilentlyContinue).PSObject.Properties | Select-Object -Property Name,Value,PSComputerName,@{Name="HiveKey"; Expression={"HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce"}} | Where-Object { $_.Name -notlike "PS*" }
                (Get-ItemProperty HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run -ErrorAction SilentlyContinue).PSObject.Properties | Select-Object -Property Name,Value,PSComputerName,@{Name="HiveKey"; Expression={"HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run"}} | Where-Object { $_.Name -notlike "PS*" }
                (Get-ItemProperty HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce -ErrorAction SilentlyContinue).PSObject.Properties | Select-Object -Property Name,Value,PSComputerName,@{Name="HiveKey"; Expression={"HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce"}} | Where-Object { $_.Name -notlike "PS*" }
                Write-Output $ServerResults
            }
        }
        catch {
            $e = $_.Exception
            $LineNumber = $_.InvocationInfo.ScriptLineNumber
            Write-Host "Something went wrong investigating remote host [$RemoteHost]!" -ForegroundColor Red
            Write-Host "Caught exception: $e" -ForegroundColor Red 
            Write-Host "Line number [$LineNumber]!"  -ForegroundColor Red
            exit
        }

        foreach($Ioc in $global:RegistryIocs)
        {
            foreach($Result in $ServerResults)
            {
                if($Result.Value -match $Ioc -or $Result.Name -match $Ioc)
                {
                    Write-Host "Found registry key based IOC [$Ioc] on [$RemoteHost]! " -ForegroundColor Red -NoNewline
                    Write-Host "Adding to [$IocsResultsOutput]." -ForegroundColor Yellow
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

Function Find-DnsIocs {
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

        try {
            $ServerResults = Invoke-Command -ComputerName $RemoteHost -Credential $global:UserCredentials -ScriptBlock {
                Get-DnsClientCache
                Write-Output $ServerResults
            }
        }
        catch {
            $e = $_.Exception
            $LineNumber = $_.InvocationInfo.ScriptLineNumber
            Write-Host "Something went wrong investigating remote host [$RemoteHost]!" -ForegroundColor Red
            Write-Host "Caught exception: $e" -ForegroundColor Red 
            Write-Host "Line number [$LineNumber]!"  -ForegroundColor Red
            exit
        }

        foreach($Ioc in $global:DnsIocs)
        {
            if($Ioc -in $ServerResults.Entry)
            {
                Write-Host "Found dns based IOC [$Ioc] on [$RemoteHost]! " -ForegroundColor Red -NoNewline
                Write-Host "Adding to [$IocsResultsOutput]." -ForegroundColor Yellow
                $ServerResults | Where-Object { $_.Entry -eq $Ioc } | Export-Csv -Path $IocsResultsOutput -NoTypeInformation -Append -Force
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

Function Find-IpIocs {
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

        try {
            $ServerResults = Invoke-Command -ComputerName $RemoteHost -Credential $global:UserCredentials -ScriptBlock {
                Get-NetTCPConnection
                Write-Output $ServerResults
            }
        }
        catch {
            $e = $_.Exception
            $LineNumber = $_.InvocationInfo.ScriptLineNumber
            Write-Host "Something went wrong investigating remote host [$RemoteHost]!" -ForegroundColor Red
            Write-Host "Caught exception: $e" -ForegroundColor Red 
            Write-Host "Line number [$LineNumber]!"  -ForegroundColor Red
            exit
        }
  
        foreach($Ioc in $global:IpIocs)
        {
            if($ServerResults.RemoteAddress -eq $Ioc)
            {
                Write-Host "Found IP based IOC [$Ioc] on [$RemoteHost]! " -ForegroundColor Red -NoNewline
                Write-Host "Adding to [$IocsResultsOutput]." -ForegroundColor Yellow
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

Function Find-FileIocs {
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

        try {
            $ServerResults = Invoke-Command -ComputerName $RemoteHost -Credential $global:UserCredentials -ScriptBlock {
                Get-ChildItem -Path C:\ -Include $using:global:FileIocs -Recurse -Force -ErrorAction SilentlyContinue | 
                Select-Object -Property Name,FullName,Length,CreationTime,CreationTimeUtc,LastAccessTime,LastAccessTimeUtc,LastWriteTime,LastWriteTimeUtc,PSComputerName
            }
        }
        catch {
            $e = $_.Exception
            $LineNumber = $_.InvocationInfo.ScriptLineNumber
            Write-Host "Something went wrong investigating remote host [$RemoteHost]!" -ForegroundColor Red
            Write-Host "Caught exception: $e" -ForegroundColor Red 
            Write-Host "Line number [$LineNumber]!"  -ForegroundColor Red
            exit
        }
     
        $ServerResultsCount = $ServerResults.Count 
        if($ServerResultsCount -gt 0)
        {
            foreach($Result in $ServerResults)
            {
                Write-Host "Found file based IOC result [$($Result.FullName)] on [$RemoteHost]! " -ForegroundColor Red -NoNewline
                Write-Host "Adding to [$IocsResultsOutput]." -ForegroundColor Yellow
                Export-Csv -InputObject $Result -Path $IocsResultsOutput -NoTypeInformation -Append
            }
        }
        else
        {
            Write-Host "Did not find any file based IOCs on [$RemoteHost]" -ForegroundColor Green
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

Function Find-UserIocs {
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

        try {
            $ServerResults = Invoke-Command -ComputerName $RemoteHost -Credential $global:UserCredentials -ScriptBlock {
                Get-LocalUser
                Write-Output $ServerResults
            }
        }
        catch {
            $e = $_.Exception
            $LineNumber = $_.InvocationInfo.ScriptLineNumber
            Write-Host "Something went wrong investigating remote host [$RemoteHost]!" -ForegroundColor Red
            Write-Host "Caught exception: $e" -ForegroundColor Red 
            Write-Host "Line number [$LineNumber]!"  -ForegroundColor Red
            exit
        }

        foreach($User in $global:UserIocs)
        {
            if($User -in $ServerResults.Name)
            {
                Write-Host "Found user based IOC [$User] on [$RemoteHost]! " -ForegroundColor Red -NoNewline
                Write-Host "Adding to [$IocsResultsOutput]." -ForegroundColor Yellow
                $ServerResults | Where-Object { $_.Name -eq $User } | Export-Csv -Path $IocsResultsOutput -NoTypeInformation -Append -Force
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

Function Find-HostsFileIocs {
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

        try {
            $ServerResults = Invoke-Command -ComputerName $RemoteHost -Credential $global:UserCredentials -ScriptBlock {
                Get-Content -Path C:\Windows\System32\drivers\etc\hosts
                Write-Output $ServerResults
            }
        }
        catch {
            $e = $_.Exception
            $LineNumber = $_.InvocationInfo.ScriptLineNumber
            Write-Host "Something went wrong investigating remote host [$RemoteHost]!" -ForegroundColor Red
            Write-Host "Caught exception: $e" -ForegroundColor Red 
            Write-Host "Line number [$LineNumber]!"  -ForegroundColor Red
            exit
        }
  
        foreach($HostsFile in $global:HostsFileIocs)
        {
            if($ServerResults | Select-String -SimpleMatch $HostsFile)
            {
                Write-Host "Found hosts file based IOC [$HostsFile] on [$RemoteHost]! " -ForegroundColor Red -NoNewline
                Write-Host "Adding to [$IocsResultsOutput]." -ForegroundColor Yellow
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

Function Find-ScheduledTaskIocs {
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

        try {
            $ServerResults = Invoke-Command -ComputerName $RemoteHost -Credential $global:UserCredentials -ScriptBlock {
                Get-ScheduledTask
                Write-Output $ServerResults
            }
        }
        catch {
            $e = $_.Exception
            $LineNumber = $_.InvocationInfo.ScriptLineNumber
            Write-Host "Something went wrong investigating remote host [$RemoteHost]!" -ForegroundColor Red
            Write-Host "Caught exception: $e" -ForegroundColor Red 
            Write-Host "Line number [$LineNumber]!"  -ForegroundColor Red
            exit
        }
  
        foreach($ScheduledTask in $global:ScheduledTaskIocs)
        {
            if($ScheduledTask -in $ServerResults.TaskName)
            {
                Write-Host "Found scheduled task based IOC [$ScheduledTask] on [$RemoteHost]! " -ForegroundColor Red -NoNewline
                Write-Host "Adding to [$IocsResultsOutput]." -ForegroundColor Yellow
                $ServerResults | 
                Where-Object { $_.TaskName -eq $ScheduledTask } |
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

Function Get-FileIocs {
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

        $RemoteSessionOutput = "$($global:OutputDirectory)\$($DiscoveredFileIoc.PSComputerName)\downloaded_iocs"
        Set-Directory -Directory $RemoteSessionOutput

        try
        {
            $RemoteSession = New-PSSession -ComputerName $DiscoveredFileIoc.PSComputerName -Credential $global:UserCredentials
            Copy-Item -FromSession $RemoteSession -Path $DiscoveredFileIoc.FullName -Destination $RemoteSessionOutput
        }
        catch
        {
            $e = $_.Exception
            $LineNumber = $_.InvocationInfo.ScriptLineNumber
            Write-Host "Something went wrong downloading $($DiscoveredFileIoc.Name) from $($DiscoveredFileIoc.PSComputerName) to $($RemoteSessionOutput)!" -ForegroundColor Red
            Write-Host "Caught exception: $e" -ForegroundColor Red 
            Write-Host "Line number [$LineNumber]!"  -ForegroundColor Red
            exit
        }
        finally
        {
            Remove-PSSession -Session $RemoteSession
        }
    }
}

Function Find-ServiceIocs {
    $IocsResultsOutput = "$($global:OutputDirectory)\iocs_service.csv"
    $ProgressHashTable = @{
        Activity = "Service Investigation"
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

        try {
            $ServerResults = Invoke-Command -ComputerName $RemoteHost -Credential $global:UserCredentials -ScriptBlock {
                Get-Service
                Write-Output $ServerResults
            }
        }
        catch {
            $e = $_.Exception
            $LineNumber = $_.InvocationInfo.ScriptLineNumber
            Write-Host "Something went wrong investigating remote host [$RemoteHost]!" -ForegroundColor Red
            Write-Host "Caught exception: $e" -ForegroundColor Red 
            Write-Host "Line number [$LineNumber]!"  -ForegroundColor Red
            exit
        }

        foreach($Service in $global:ServiceIocs)
        {
            if($Service -in $ServerResults.Name)
            {
                Write-Host "Found service based IOC [$Service] on [$RemoteHost]! " -ForegroundColor Red -NoNewline
                Write-Host "Adding to [$IocsResultsOutput]." -ForegroundColor Yellow
                $ServerResults | Where-Object { $_.Name -eq $Service } | Export-Csv -Path $IocsResultsOutput -NoTypeInformation -Append -Force
            }
        }
    }

    if(Test-Path -Path $IocsResultsOutput)
    {
        $IocsResultsOutputCount = $((Get-Content -Path $IocsResultsOutput).Count-1)
        Write-Host "Service investigation finished with [$IocsResultsOutputCount] result(s) found. Results in [$IocsResultsOutput]." -ForegroundColor Green
    }
    else
    {
        Write-Host "Service investigation finished with [0] results found." -ForegroundColor Yellow
    }
}

Function Find-ProcessIocs {
    $IocsResultsOutput = "$($global:OutputDirectory)\iocs_process.csv"
    $ProgressHashTable = @{
        Activity = "Process Investigation"
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

        try {
            $ServerResults = Invoke-Command -ComputerName $RemoteHost -Credential $global:UserCredentials -ScriptBlock {
                Get-Process
                Write-Output $ServerResults
            }
        }
        catch {
            $e = $_.Exception
            $LineNumber = $_.InvocationInfo.ScriptLineNumber
            Write-Host "Something went wrong investigating remote host [$RemoteHost]!" -ForegroundColor Red
            Write-Host "Caught exception: $e" -ForegroundColor Red 
            Write-Host "Line number [$LineNumber]!"  -ForegroundColor Red
            exit
        }        

        foreach($Process in $global:ProcessIocs)
        {
            if($Process -in $ServerResults.ProcessName)
            {
                Write-Host "Found process based IOC [$Process] on [$RemoteHost]! " -ForegroundColor Red -NoNewline
                Write-Host "Adding to [$IocsResultsOutput]." -ForegroundColor Yellow
                $ServerResults | Where-Object { $_.ProcessName -eq $Process } | Export-Csv -Path $IocsResultsOutput -NoTypeInformation -Append -Force
            }
        }
    }

    if(Test-Path -Path $IocsResultsOutput)
    {
        $IocsResultsOutputCount = $((Get-Content -Path $IocsResultsOutput).Count-1)
        Write-Host "Process investigation finished with [$IocsResultsOutputCount] result(s) found. Results in [$IocsResultsOutput]." -ForegroundColor Green
    }
    else
    {
        Write-Host "Process investigation finished with [0] results found." -ForegroundColor Yellow
    }
}


<#
    BASELINE MENU FUNCTIONS
#>
Function Get-HostBaseline {
    $ProgressHashTable = @{
        Activity = "Host Baseline"
        CurrentOperation = "None"
        Status = "Baselining IP Address"
        PercentComplete = 0
    }

    $i = 0
    foreach($RemoteHost in $global:RemoteHosts)
    {
        $i ++
        $ProgressHashTable.PercentComplete = ($i/$global:RemoteHostsCount)*100
        $ProgressHashTable.CurrentOperation = $RemoteHost
        Write-Progress @ProgressHashTable

        $RemoteSessionOutput = "$($global:OutputDirectory)\$($RemoteHost)\baseline\$((Get-Date).ToString('yyyyMMdd_hh-mm-ss_tt'))"
        Set-Directory -Directory $RemoteSessionOutput

        try
        {
            $RemoteSession = New-PSSession -ComputerName $RemoteHost -Credential $global:UserCredentials
            $ServerResults = @{
                Services = Invoke-Command -Session $RemoteSession -ScriptBlock { Get-Service }
                Processes = Invoke-Command -Session $RemoteSession -ScriptBlock { Get-Process }
                TCPConnections = Invoke-Command -Session $RemoteSession -ScriptBlock { Get-NetTCPConnection }
                LocalUsers = Invoke-Command -Session $RemoteSession -ScriptBlock { Get-LocalUser }
                LocalAdministrators = Invoke-Command -Session $RemoteSession -ScriptBlock { Get-LocalGroupMember -Group "Administrators" }
                LocalGroups = Invoke-Command -Session $RemoteSession -ScriptBlock { Get-LocalGroup }
                ComputerInfo = Invoke-Command -Session $RemoteSession -ScriptBlock { Get-ComputerInfo }
                Drives = Invoke-Command -Session $RemoteSession -ScriptBlock { Get-PSDrive }
                Shares = Invoke-Command -Session $RemoteSession -ScriptBlock { Get-SmbShare }
                NetworkAdapters = Invoke-Command -Session $RemoteSession -ScriptBlock { Get-NetIPAddress }
                ScheduledTasks = Invoke-Command -Session $RemoteSession -ScriptBlock { Get-ScheduledTask | Select-Object -Property PSComputerName,@{Name="Actions";Expression={$_.Actions | Select-Object -Property *}},Author,Date,State,Description,Documentation,@{Name="Principal";Expression={$_.Principal | Select-Object -Property *}},SecurityDescriptor,@{Name="Settings";Expression={$_.Settings | Select-Object -Property *}},Source,TaskName,TaskPath,@{Name="Triggers";Expression={$_.Triggers | Select-Object -Property *}},URI,Version }
                DnsCache = Invoke-Command -Session $RemoteSession -ScriptBlock { Get-DnsClientCache }
                RunKeys = Invoke-Command -Session $RemoteSession -ScriptBlock { 
                    (Get-ItemProperty HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run -ErrorAction SilentlyContinue).PSObject.Properties | Select-Object -Property Name,Value,PSComputerName,@{Name="HiveKey"; Expression={"HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run"}} | Where-Object { $_.Name -notlike "PS*" }
                    (Get-ItemProperty HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce -ErrorAction SilentlyContinue).PSObject.Properties | Select-Object -Property Name,Value,PSComputerName,@{Name="HiveKey"; Expression={"HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce"}} | Where-Object { $_.Name -notlike "PS*" }
                    (Get-ItemProperty HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run -ErrorAction SilentlyContinue).PSObject.Properties | Select-Object -Property Name,Value,PSComputerName,@{Name="HiveKey"; Expression={"HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run"}} | Where-Object { $_.Name -notlike "PS*" }
                    (Get-ItemProperty HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce -ErrorAction SilentlyContinue).PSObject.Properties | Select-Object -Property Name,Value,PSComputerName,@{Name="HiveKey"; Expression={"HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce"}} | Where-Object { $_.Name -notlike "PS*" }
                }
            }

            # Determine which drives to hash.
            $DrivesToHash = $ServerResults.Drives | Where-Object { $_.Provider -like '*\FileSystem' }

            # Hash determined drives.
            $HashResults = @()
            foreach($Drive in $DrivesToHash)
            {
                Write-Host "Hashing [$($Drive.Root)] on [$RemoteHost]. This will take a while." -ForegroundColor Yellow
                $DriveResults = Invoke-Command -Session $RemoteSession -ScriptBlock { 
                    Get-ChildItem -Path $using:Drive.Root -Include * -Recurse -Force -ErrorAction SilentlyContinue | Get-FileHash -Algorithm MD5 -ErrorAction SilentlyContinue
                    Write-Output $DriveResults
                }
                $HashResults += $DriveResults
                Write-Host "Finished hashing [$($Drive.Root)] on [$RemoteHost]" -ForegroundColor Green
            }

            # Add $HashResults to $ServerResults.
            if($HashResults.Length -gt 0)
            {
                $ServerResults.Add('DrivesHashes',$HashResults)
            }
            else
            {
                Write-Host "Did not get any drive hashing results from drives [$DrivesToHash] on [$RemoteHost]!" -ForegroundColor Red
            }

            # Output all keys/values from hashtable.
            foreach($Key in $ServerResults.Keys)
            {
                $Value = $ServerResults[$Key]
                if($null -ne $Value)
                {
                    Write-Host "Writing [$Key] results for [$RemoteHost] to [${RemoteSessionOutput}\${Key}.csv]" -ForegroundColor Green
                    $Value | Export-Csv -Path "${RemoteSessionOutput}\${Key}.csv" -NoTypeInformation -Force -ErrorAction SilentlyContinue
                }
            }
        }
        catch
        {
            $e = $_.Exception
            $LineNumber = $_.InvocationInfo.ScriptLineNumber
            Write-Host "Something went wrong investigating remote host [$RemoteHost]!" -ForegroundColor Red
            Write-Host "Caught exception: $e" -ForegroundColor Red 
            Write-Host "Line number [$LineNumber]!"  -ForegroundColor Red
            exit
        }
        finally
        {
            Remove-PSSession -Session $RemoteSession
        }
    }
}


<#
    VALIDATION FUNCTIONS
#>
Function Test-UserPathExists {
    Param(
        $UserPath
    )

    if(!(Test-Path -Path $UserPath))
    {        
        Write-Host "Path [$UserPath] does not exist. Try again with proper input." -ForegroundColor Red
        exit
    }
}

Function Test-Pattern {
    Param(
        $Items,
        $Pattern
    )

    try {
        [System.Collections.ArrayList]$Items = $Items.Split(',')
        $ItemsToRemove = @()
        foreach($Item in $Items)
        {
            if($Item -notmatch $Pattern)
            {
                Write-Host "Input [$Item] does not match required input pattern. Removing from input." -ForegroundColor Yellow
                $ItemsToRemove += $Item
            }
        }

        foreach($ItemToRemove in $ItemsToRemove)
        {
            $Items.Remove($ItemToRemove)
        }

        return $Items
    }
    catch {
        $e = $_.Exception
        $LineNumber = $_.InvocationInfo.ScriptLineNumber
        Write-Host "Something went wrong validating [$Items]!" -ForegroundColor Red
        Write-Host "Caught exception: $e" -ForegroundColor Red 
        Write-Host "Line number [$LineNumber]!"  -ForegroundColor Red
        exit
    }
}


<#
    ENTRY POINT OF SCRIPT
#>
try {
    do
    {
        Show-MainMenu
        $Input = Read-Host -Prompt "Please make a selection"
        switch($Input)
        {
            '1' { Show-SetupMenu }
            '2' { Show-HuntMenu }
            '3' { Show-BaselineMenu }
            'q' { return }
        }
    }
    until($Input -eq 'q')   
}
finally {
    Clear-Variable -Name UserCredentials -Scope Global -ErrorAction SilentlyContinue
}