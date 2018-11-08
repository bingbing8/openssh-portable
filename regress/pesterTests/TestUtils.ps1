If ($PSVersiontable.PSVersion.Major -le 2) {$PSScriptRoot = Split-Path -Parent $MyInvocation.MyCommand.Path}
Import-Module $PSScriptRoot\..\..\contrib\win32\openssh\OpenSSHUtils.psd1 -Force
$Script:newProcesses = @()
$Script:OpenSSHBinPath=""

function Get-OpenSSHBinPath
{
    param([string]$Configuration = "Release")

    [string] $NativeHostArch = $env:PROCESSOR_ARCHITECTURE
    if($NativeHostArch -eq 'x86')
    {
        $NativeHostArch = "Win32"
    }
    else
    {
        $NativeHostArch = "x64"
    }  
    

    $BinPath = Resolve-Path (join-path "..\..\bin\$NativeHostArch" "$Configuration\sshd.exe") -ErrorAction Ignore
    if($BinPath -eq $null)
    {
        $BinPath = get-command sshd.exe -ErrorAction SilentlyContinue 
    }
    
    if($BinPath -eq $null)
    {
        Throw "Cannot find sshd.exe. Please build openssh in repro or set the Path environment to openssh daemon."
    }

    $SSHDBinPath = $BinPath.Path

    $Script:OpenSSHBinPath = Split-Path $SSHDBinPath
    $Script:OpenSSHBinPath
}

function Start-SSHDDaemon
{
    param(
    [parameter(Mandatory=$true)]
    [string]$SSHD_Config_Path)    
    
    $Script:newProcesses = $null
    $existingProcesseIDs = @()
    if(($existingProcesses = Get-Process -name sshd -ErrorAction SilentlyContinue)){
        $existingProcesseIDs = $existingProcesses.id
    }    
    
    Start-process -FilePath "$($Script:OpenSSHBinPath)\sshd.exe" -ArgumentList "-f $SSHD_Config_Path" -NoNewWindow
    #Start-Process -FilePath "$Script:OpenSSHBinPath\sshd.exe" -ArgumentList @("-ddd", "-f $SSHD_Config_Path")
    
    #Sleep for 1 seconds for process to ready to listener
    $num = 0
    do
    {
        $Script:newProcesses = Get-Process -name sshd -ErrorAction SilentlyContinue | Where-Object {$_.id -notin $existingProcesseIDs}
        start-sleep 1
        $num++
        if($num -gt 30) { break }
    } while ($Script:newProcesses -eq $null)    
}

function Stop-SSHDDaemon
{
    if($Script:newProcesses -and $Script:newProcesses.count -gt 0) {
        $Script:newProcesses | Stop-Process -ErrorAction SilentlyContinue
     }
     $Script:newProcesses = $null
 
}

function Write-SSHDConfig
{
    param(
        $Port = 47002,
        [parameter(Mandatory=$true)]
        $Host_Key_File,
        [parameter(Mandatory=$true)]
        $Authorized_Keys_File,
        [parameter(Mandatory=$true)]
        $BinPath,
        $SSHD_Config_Path = "$env:temp\openssh\ssh_config")

    $default_sshd_config = Get-content "$BinPath\sshd_config_default"
    $sshd_config = $default_sshd_config.Replace("#Port 22", "Port $Port")
    $Host_Key = $Host_Key_File.replace("\", "/")
    $sshd_config = $sshd_config.Replace("#HostKey __PROGRAMDATA__/ssh/ssh_host_ed25519_key", "HostKey $Host_Key")
    $Authorized_Keys = $Authorized_Keys_File.Replace("\", "/")
    $sshd_config = $sshd_config.Replace(".ssh/authorized_keys", "$Authorized_Keys")
    $sshd_config = $sshd_config.Replace("#LogLevel INFO", "LogLevel DEBUG3")
    $sshd_config = $sshd_config.Replace("#SyslogFacility AUTH", "SyslogFacility LOCAL0")

    $dir = split-path $SSHD_Config_Path
    if(-not (Test-Path $dir))
    {
        New-Item $dir -ItemType directory -Force -ErrorAction SilentlyContinue | Out-Null
    }    
    Set-Content -Path $SSHD_Config_Path -Value $sshd_config -Force
}

function Write-SSHConfig
{
    param(
        $Suite = "OpenSSH",
        $Target = "test_target",        
        $HostName="localhost",        
        $Port = 47002,        
        $IdentityFile,
        $UserKnownHostsFile,
        $SSH_Config_Path = "$env:temp\openssh\ssh_config")

        $dir = split-path $SSH_Config_Path
        if(-not (Test-Path $dir))
        {
            New-Item $dir -ItemType directory -Force -ErrorAction SilentlyContinue | Out-Null
        }

        Set-Content -Path $SSH_Config_Path -Value "# host alias for $Suite tests" -Force
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