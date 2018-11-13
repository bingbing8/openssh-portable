If ($PSVersiontable.PSVersion.Major -le 2) {$PSScriptRoot = Split-Path -Parent $MyInvocation.MyCommand.Path}
$tC = 1
$tI = 0
$suite = "log_fileperm"
$testDir = "C:\Users\yawang\$suite"
. $PSScriptRoot\common.ps1 -suite $suite -TestDir $testDir
Import-Module "$Script:SSHBinaryPath\OpenSSHUtils" -force
Describe "Tests for log file permission" -Tags "CI" {
    BeforeAll {        
        $port = 47002
        $logName = "log.txt"
        $server = "localhost"
        $ssh_config_file = "$testDir\ssh_config"
        
        $systemSid = Get-UserSID -WellKnownSidType ([System.Security.Principal.WellKnownSidType]::LocalSystemSid)
        $adminsSid = Get-UserSID -WellKnownSidType ([System.Security.Principal.WellKnownSidType]::BuiltinAdministratorsSid)                        
        $currentUserSid = Get-UserSID -User "$($env:USERDOMAIN)\$($env:USERNAME)"        

        Remove-Item (Join-Path $testDir "*$logName") -Force -ErrorAction SilentlyContinue
        
        if($psversiontable.BuildVersion.Major -le 6)
        {
            #suppress the firewall blocking dialogue on win7
            netsh advfirewall firewall add rule name="sshd" program="$($OpenSSHTestInfo['OpenSSHBinPath'])\sshd.exe" protocol=any action=allow dir=in
        }

        #only validate owner and ACEs of the file
        function ValidateLogFilePerm {
            param([string]$FilePath)
            
            $myACL = Get-ACL $FilePath
            $currentOwnerSid = Get-UserSid -User $myACL.Owner
            $currentOwnerSid.Equals($currentUserSid) | Should Be $true
            $myACL.Access | Should Not Be $null            

            $ReadWriteAccessPerm = ([System.UInt32] [System.Security.AccessControl.FileSystemRights]::Read.value__) -bor `
                    ([System.UInt32] [System.Security.AccessControl.FileSystemRights]::ReadAndExecute.value__)  -bor `
                    ([System.UInt32] [System.Security.AccessControl.FileSystemRights]::Write.value__)  -bor `
                    ([System.UInt32] [System.Security.AccessControl.FileSystemRights]::Modify.value__)  -bor `
                    ([System.UInt32] [System.Security.AccessControl.FileSystemRights]::Synchronize.value__)

            $FullControlPerm = [System.UInt32] [System.Security.AccessControl.FileSystemRights]::FullControl.value__
            
            $myACL.Access.Count | Should Be 3
            $identities = @($systemSid, $adminsSid, $currentUserSid)            

            foreach ($a in $myACL.Access) {
                $id = Get-UserSid -User $a.IdentityReference
                $identities -contains $id | Should Be $true           

                switch ($id)
                {
                    {@($systemSid, $adminsSid) -contains $_}
                    {
                        ([System.UInt32]$a.FileSystemRights.value__) | Should Be $FullControlPerm
                        break;
                    }
                    $currentUserSid
                    {
                        ([System.UInt32]$a.FileSystemRights.value__) | Should Be $ReadWriteAccessPerm
                        break;
                    }
                }
            
                $a.AccessControlType | Should Be ([System.Security.AccessControl.AccessControlType]::Allow)
                $a.IsInherited | Should Be $false
                $a.InheritanceFlags | Should Be ([System.Security.AccessControl.InheritanceFlags]::None)
                $a.PropagationFlags | Should Be ([System.Security.AccessControl.PropagationFlags]::None)
            }
        }
    }

    BeforeEach {
        $logPath = Join-Path $testDir "$tC.$tI.$logName"
    }

    AfterEach {$tI++;}
    AfterAll {
        if($psversiontable.BuildVersion.Major -le 6)
        {            
            netsh advfirewall firewall delete rule name="sshd" program="$($OpenSSHTestInfo['OpenSSHBinPath'])\sshd.exe" protocol=any dir=in
        }    
    }

    Context "$tC-SSHD -E Log file permission" {
        BeforeAll { $tI=1 }
        
        AfterAll { $tC++ }

        It "$tC.$tI-SSHD -E Log file permission" {
            Set-TestCommons -port $port -Server $server -ssh_config_file $ssh_config_file -ExtraArglist "-E $logPath"
            ValidateLogFilePerm -FilePath $logPath
            Clear-TestCommons
        }
    }
}