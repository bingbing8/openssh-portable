param ([string]$Suite = "openssh", [string]$OpenSSHBinPath, [string]$TestDir = "$env:temp\opensshtest")

If ($PSVersiontable.PSVersion.Major -le 2) {$PSScriptRoot = Split-Path -Parent $MyInvocation.MyCommand.Path}
$Script:SSHBinaryPath = ""
$Script:TestDirectory = $TestDir
$Script:TestSuite = $Suite
$Script:Authorized_keys_file = $null
$Script:Known_host_file = $null
$Script:ArgumentList = $null

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

function Restart-SSHDDaemon
{
        if($Script:ArgumentList -eq $null){
            return
        }
        if(($existingProcesses = Get-Process -name sshd -ErrorAction SilentlyContinue)){
            $existingProcesses | Stop-Process -ErrorAction SilentlyContinue -force
        }
        Start-process -FilePath "$($Script:SSHBinaryPath)\sshd.exe" -ArgumentList $Script:ArgumentList -NoNewWindow

        #Sleep for 1 seconds for process to ready to listen
        $num = 0
        do
        {
            $newProcess = Get-Process -name sshd -ErrorAction SilentlyContinue
            start-sleep 1
            $num++
            if($num -gt 30) { break }
        } while ($newProcess -eq $null)
}
function Start-SSHDDaemon
{
    param(
        [string]$port = 47002,
        [string[]]$host_key_files = $null,
        [string]$Authorized_Keys_File = $null,
        [string]$SSHD_Log_File = $null,
        [string]$ExtraArglist="")

        if(!$host_key_files) {
            $host_key_files = @()
            "ed25519","ecdsa","dsa","rsa" | % {
                $host_key = "$Script:TestDirectory\hostkey_$_"
                if(Test-path $host_key -PathType leaf) {
                    Remove-Item $host_key -force
                }
                $host_key_files += $host_key
                ssh-keygen.exe -t $_ -P "`"`"" -f $host_key
            }
        }

        $sshd_config_path = "$Script:TestDirectory\sshd_config"
        $params = @{
            "Port" = $port;
            "Host_Key_Files" = $host_key_files
            "SSHD_Config_Path" = $sshd_config_path
        }
        
        if($Authorized_Keys_File)
        {
            $params.Add("Authorized_Keys_File", $Authorized_Keys_File);
        }
        Write-SSHDConfig @params
        if(($existingProcesses = Get-Process -name sshd -ErrorAction SilentlyContinue)){
            $existingProcesses | Stop-Process -ErrorAction SilentlyContinue -Force
        }
        if($SSHD_Log_File)
        {
            $ExtraArglist += " -E $SSHD_Log_File"
        }
        $Script:ArgumentList = "-f `"$sshd_config_path`" $ExtraArglist"
        Start-process -FilePath "$($Script:SSHBinaryPath)\sshd.exe" -ArgumentList $Script:ArgumentList -NoNewWindow

        #Sleep for 1 seconds for process to ready to listen
        $num = 0
        do
        {
            $newProcess = Get-Process -name sshd -ErrorAction SilentlyContinue
            start-sleep 1
            $num++
            if($num -gt 30) { break }
        } while ($newProcess -eq $null)
}

function Set-TestCommons
{
    param(
        [string]$target = "test_target",
        [string]$port = 47002,
        [string[]]$host_key_files = $null,
        [string]$user_key_type = "ed25519",
        [string]$user_key_file = "$Script:TestDirectory\user_key_$user_key_type",
        [string]$ssh_config_file = "$Script:TestDirectory\ssh_config",
        [string]$server = "localhost",
        [string]$SSHD_Log_File = $null,
        [string]$ExtraArglist = "")

        if(-not (Test-Path $user_key_file -PathType Leaf)) {
            ssh-keygen.exe -t $user_key_type -P "`"`"" -f $user_key_file
        }

        $Script:Authorized_keys_file = "$Script:TestDirectory\Authorized_Keys"
        copy-item "$user_key_file.pub" $Script:Authorized_keys_file -force
        $params = @{
            "Port" = $port;
            "host_key_files" = $host_key_files;
            "Authorized_Keys_File" = $Script:Authorized_keys_file;
            "ExtraArglist" = $ExtraArglist;
        }
        if($SSHD_Log_File)
        {
            $params.Add("SSHD_Log_File", $SSHD_Log_File);
        }
        Start-SSHDDaemon @params

        #generate known hosts
        $Script:Known_host_file = "$Script:TestDirectory\known_hosts"
        Set-Content -Path "$Script:TestDirectory\tmp.txt" -Value $server
        cmd /c "ssh-keyscan.exe -p $port -f `"$Script:TestDirectory\tmp.txt`" 2> `"$Script:TestDirectory\error.txt`"" | Set-Content "$Script:known_host_file" -force

        Write-SSHConfig -Target $target -HostName $server -Port $port -IdentityFile $user_key_file -UserKnownHostsFile $Script:Known_host_file -SSH_Config_Path $ssh_config_file
}

function Stop-SSHDDaemon
{
    if(($sshdprocess = get-process -name sshd -ErrorAction SilentlyContinue)) {
        $sshdprocess | Stop-Process -ErrorAction SilentlyContinue -force
    }
}

function Clear-TestCommons
{
    Stop-SSHDDaemon
    if($env:path.tolower().startswith($Script:SSHBinaryPath.tolower())){
        $env:path = $env:path.replace("$Script:SSHBinaryPath.tolower();", "")
    }
}

function Write-SSHDConfig
{
    param(
        $Port = 47002,
        [parameter(Mandatory=$true)]
        [string[]]$Host_Key_Files,
        $Authorized_Keys_File = $null,
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

    if($Authorized_Keys_File -and (Test-Path $Authorized_Keys_File)) {
        $Authorized_Keys = $Authorized_Keys_File.Replace("\", "/")
        "AuthorizedKeysFile $Authorized_Keys" | Add-Content $SSHD_Config_Path
    }
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

function Add-PasswordSetting
{
    param([string] $pass)
    if (-not($env:DISPLAY)) {$env:DISPLAY = 1}
    $env:SSH_ASKPASS="cmd.exe /c echo $pass"
}

function Remove-PasswordSetting
{
    if ($env:DISPLAY -eq 1) { Remove-Item env:\DISPLAY }
    Remove-item "env:SSH_ASKPASS" -ErrorAction SilentlyContinue
}

Stop-SSHDDaemon

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