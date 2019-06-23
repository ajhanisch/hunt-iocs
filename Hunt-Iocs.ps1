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
        [10] : Set hosts file bases IOCs
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

    Write-Host "Checking [${TrustedHostsPath}] for [${TrustedHosts}]" -ForegroundColor Cyan
    foreach($TrustedHost in $TrustedHosts.Split(','))
    {
        if(!((Get-Item -Path $TrustedHostsPath).Value.Contains($TrustedHost)))
        {
            Write-Host "Adding ${TrustedHost}" -ForegroundColor Green
            Set-Item $TrustedHostsPath -Concatenate -Value $TrustedHost.ToString() -Force
        }
        else
        {
            Write-Host "${TrustedHost} already trusted host(s)" -ForegroundColor Yellow
        }
    }
    Write-Host "Finished checking [${TrustedHostsPath}] for [${TrustedHosts}]" -ForegroundColor Cyan
}

Function Create-Directory {
    param(
        [string]$Directory
    )

    Write-Host "Checking if [${Directory}] exists" -ForegroundColor Cyan
    if(!(Test-Path -Path $Directory))
    {
        Write-Host "Creating [$Directory] now" -ForegroundColor Yellow
        New-Item -Path $Directory -ItemType Directory -Force | Out-Null
    }
    else
    {
        Write-Host "[${Directory}] exists already" -ForegroundColor Green
    }
    Write-Host "Finished checking if [${Directory}] exists" -ForegroundColor Cyan
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
    Write-Host "Remote credentials set" -ForegroundColor Green
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

    #a hash table of parameter values to splat to Write-Progress
    $ProgressHashTable = @{
     Activity = "Ping Sweep"
     CurrentOperation = "None"
     Status = "Pinging IP Address"
     PercentComplete = 0
    }
 
    #How many addresses need to be pinged?
    $Count = ($End - $Start)+1
 
    <#
    take the Network and split it into an array then join the first
    3 elements back into a string separated by a period.
    This will be used to construct an IP address.
    #>
 
    $Base = $Network.Split(".")[0..2] -join "."
 
    #Initialize a counter
    $i = 0
 
    #loop while the value of $start is <= $end
    while ($Start -le $End) {
      #increment the counter 
      $i++

      #calculate % processed for Write-Progress
      $ProgressHashTable.PercentComplete = ($i/$Count)*100
 
      #define the IP address to be pinged by using the current value of $start
      $IP = "$Base.$Start" 
 
      #Use the value in Write-Progress
      $ProgressHashTable.currentoperation = $IP
      Write-Progress @ProgressHashTable
 
      #test the connection
      if (Test-Connection -ComputerName $IP -Count $Ping -Quiet) {
        #write the pingable address to the pipeline if it responded
        Write-Host "Host [${IP}] responded to ping!" -ForegroundColor Green
        $IP | Out-File -FilePath $LiveHostsOutput -Append -Force
      } #if test ping
 
      #increment the value $start by 1
      $Start++
    } #close while loop

    Write-Host "Ping sweep finished with [$((Get-Content -Path $LiveHostsOutput).Count)] live hosts found. Results in [$LiveHostsOutput]." -ForegroundColor Green
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
