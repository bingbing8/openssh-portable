﻿param ([string]$Suite = "openssh", [string]$OpenSSHBinPath, [string]$TestDir = "$env:temp\opensshtest")

If ($PSVersiontable.PSVersion.Major -le 2) {$PSScriptRoot = Split-Path -Parent $MyInvocation.MyCommand.Path}
$Script:newProcess = $null
$Script:SSHBinaryPath = ""
$Script:TestDirectory = $TestDir
$Script:TestSuite = $Suite
$Script:SSH_Config_file = "$Script:TestDirectory\ssh_config"
$Script:Authorized_keys_file = $null
$Script:Known_host_file = $null

function Find-OpenSSHBinPath
{
    param([string]$Configuration = "Release")

    [string] $NativeHostArch = $env:PROCESSOR_ARCHITECTURE
    if($NativeHostArch -ieq 'x86')
    {
        $NativeHostArch = "Win32"
    }
    else
    {
        $NativeHostArch = "x64"
    }
    $sshdPath = Resolve-Path (join-path "$psscriptroot\..\..\bin\$NativeHostArch" "$Configuration\sshd.exe") -ErrorAction Ignore
    if($sshdPath -eq $null)
    {
        $sshdPath = get-command sshd.exe -ErrorAction SilentlyContinue 
    }
    
    if($sshdPath -eq $null)
    {
        Throw "Cannot find sshd.exe. Please build openssh in repro or set the Path environment to openssh daemon."
    }

    $SSHDBinPath = $sshdPath.Path

    $Script:SSHBinaryPath = Split-Path $SSHDBinPath
    $Script:SSHBinaryPath
}

function Set-TestCommons
{
    param(
        [string]$target = "test_target",
        [string]$port = 47002,
        [string[]]$host_key_type = "ed25519",
        [string]$user_key_type = "ed25519",
        [string]$user_key_file = "$Script:TestDirectory\user_key_$user_key_type",
        [string]$server = "localhost",
        [string]$ExtraArglist)
        
        $host_key_files = @()
        $host_key_type | % {
            $host_key = "$Script:TestDirectory\hostkey_$_"
            $host_key_files += $host_key
            ssh-keygen.exe -t $_ -P "`"`"" -f $host_key
        }
   
        ssh-keygen.exe -t $user_key_type -P "`"`"" -f $user_key_file

        $Script:Authorized_keys_file = "$Script:TestDirectory\Authorized_Keys"
        copy-item "$user_key_file.pub" $Script:Authorized_keys_file -force

        Write-SSHDConfig -Port $port -Host_Key_Files $host_key_files -Authorized_Keys_File $Script:Authorized_keys_file -SSHD_Config_Path "$Script:TestDirectory\sshd_config"
        Start-SSHDDaemon -SSHD_Config_Path "$Script:TestDirectory\sshd_config" -ExtraArglist $ExtraArglist

        #generate known hosts
        $Script:Known_host_file = "$Script:TestDirectory\known_hosts"
        Set-Content -Path "$Script:TestDirectory\tmp.txt" -Value $server
        cmd /c "ssh-keyscan.exe -p $port -f `"$Script:TestDirectory\tmp.txt`" 2> `"$Script:TestDirectory\error.txt`"" | Set-Content "$Script:known_host_file" -force

        Write-SSHConfig -Target $target -HostName $server -Port $port -IdentityFile $user_key_file -UserKnownHostsFile $Script:Known_host_file -SSH_Config_Path $ssh_config_file
}

function Start-SSHDDaemon
{
    param(
    [string]$SSHD_Config_Path = "$Script:TestDirectory\sshd_config",
    [string]$ExtraArglist)    
    
    $Script:newProcess = $null
    if(($existingProcesses = Get-Process -name sshd -ErrorAction SilentlyContinue)){
        $existingProcesses | Stop-Process
    }

    #suppress the firewall blocking dialogue on win7
    #netsh advfirewall firewall add rule name="sshd" program="$Script:SSHBinaryPath\sshd.exe" protocol=any action=allow dir=in
    
    if($psversiontable.BuildVersion.Major -le 6)
    {
        #suppress the firewall blocking dialogue on win7
        netsh advfirewall firewall add rule name="sshd" program="$Script:SSHBinaryPath\sshd.exe" protocol=any action=allow dir=in
    }
    Start-process -FilePath "$($Script:SSHBinaryPath)\sshd.exe" -ArgumentList "-f `"$SSHD_Config_Path`" $ExtraArglist" -NoNewWindow
    
    #Sleep for 1 seconds for process to ready to listen
    $num = 0
    do
    {
        $Script:newProcess = Get-Process -name sshd -ErrorAction SilentlyContinue
        start-sleep 1
        $num++
        if($num -gt 30) { break }
    } while ($Script:newProcess -eq $null)    
}

function Clear-TestCommons
{
    Stop-SSHDDaemon
    if($env:path.tolower().startswith($Script:SSHBinaryPath.tolower())){
        $env:path = $env:path.replace("$Script:SSHBinaryPath.tolower();", "")
    }

}

function Stop-SSHDDaemon
{   
    if($Script:newProcess) {
        $Script:newProcess | Stop-Process -ErrorAction SilentlyContinue
    }
    $Script:newProcess = $null
     
    if($psversiontable.BuildVersion.Major -le 6)
    {            
        netsh advfirewall firewall delete rule name="sshd" program="$Script:SSHBinaryPath\sshd.exe" protocol=any dir=in
    }
 
}

function Write-SSHDConfig
{
    param(
        $Port = 47002,
        [parameter(Mandatory=$true)]
        [string[]]$Host_Key_Files,
        [parameter(Mandatory=$true)]
        $Authorized_Keys_File,
        $SSHD_Config_Path = "$Script:TestDirectory\sshd_config")

    $dir = split-path $SSHD_Config_Path
    if(-not (Test-Path $dir))
    {
        New-Item $dir -ItemType directory -Force -ErrorAction SilentlyContinue | Out-Null
    }

    Set-Content -Path $SSHD_Config_Path -Value "# sshd config for $TestSuite tests" -Force

    "Port $Port" | Add-Content $SSHD_Config_Path
    $Host_Key_Files | % {
        $Host_Key = $_.replace("\", "/")    
        "HostKey $Host_Key" | Add-Content $SSHD_Config_Path
    }
    $Authorized_Keys = $Authorized_Keys_File.Replace("\", "/")
    "AuthorizedKeysFile $Authorized_Keys" | Add-Content $SSHD_Config_Path
    "LogLevel DEBUG3" | Add-Content $SSHD_Config_Path
    "SyslogFacility LOCAL0" | Add-Content $SSHD_Config_Path
    "Subsystem sftp	sftp-server.exe -l DEBUG3" | Add-Content $SSHD_Config_Path
}

function Write-SSHConfig
{
    param(
        $Target = "test_target",
        $HostName="localhost",
        $Port = 47002,
        $IdentityFile,
        $UserKnownHostsFile,
        $SSH_Config_Path = "$Script:TestDirectory\ssh_config")

        $dir = split-path $SSH_Config_Path
        if(-not (Test-Path $dir))
        {
            New-Item $dir -ItemType directory -Force -ErrorAction SilentlyContinue | Out-Null
        }

        Set-Content -Path $SSH_Config_Path -Value "# host alias for $TestSuite tests" -Force
        "Host $Target" | Add-Content $SSH_Config_Path
        "    HostName $HostName" | Add-Content $SSH_Config_Path
        "    Port $port" | Add-Content $SSH_Config_Path
        if(-not [String]::IsNullOrWhiteSpace($IdentityFile)) {
            "    IdentityFile $IdentityFile" | Add-Content $SSH_Config_Path
        }
        if(-not [String]::IsNullOrWhiteSpace($UserKnownHostsFile)) {
            "    UserKnownHostsFile $UserKnownHostsFile" | Add-Content $SSH_Config_Path
        }
}

if(-not [string]::IsNullOrWhiteSpace($OpenSSHBinPath)) {
    $Script:SSHBinaryPath = $OpenSSHBinPath
}
else {
    $Script:SSHBinaryPath = Find-OpenSSHBinPath
}

if(-not $env:path.tolower().startswith($Script:SSHBinaryPath.tolower())){
    $env:path = "$Script:SSHBinaryPath;$env:path"
}

if(-not (Test-Path $Script:TestDirectory))
{
    New-Item $Script:TestDirectory -ItemType directory -Force -ErrorAction SilentlyContinue | Out-Null
}
else {
    Get-ChildItem $Script:TestDirectory | Remove-Item -Recurse | Out-Null
}