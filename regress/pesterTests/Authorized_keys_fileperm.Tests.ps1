If ($PSVersiontable.PSVersion.Major -le 2) {$PSScriptRoot = Split-Path -Parent $MyInvocation.MyCommand.Path}
$tC = 1
$tI = 0
$suite = "authorized_keys_fileperm"
$testDir = "$env:temp\$suite"
. $PSScriptRoot\common.ps1 -suite $suite -TestDir $testDir
Import-Module "$Script:SSHBinaryPath\OpenSSHUtils" -force
Describe "Tests for authorized_keys file permission" -Tags "CI" {
    BeforeAll {
        $sshLogName = "test.txt"
        $sshdLogName = "sshdlog.txt"
        $port = 47002
        $server = "localhost"

        #$PwdUser = $OpenSSHTestInfo["PasswdUser"]
        #$ssouserProfile = $OpenSSHTestInfo["SSOUserProfile"]
        Remove-Item -Path (Join-Path $testDir "*$sshLogName") -Force -ErrorAction SilentlyContinue
    }

    AfterEach { $tI++ }

    Context "Authorized key file permission" {
        BeforeAll {            
            $systemSid = Get-UserSID -WellKnownSidType ([System.Security.Principal.WellKnownSidType]::LocalSystemSid)
            $adminsSid = Get-UserSID -WellKnownSidType ([System.Security.Principal.WellKnownSidType]::BuiltinAdministratorsSid)
            $currentUserSid = Get-UserSID -User "$($env:USERDOMAIN)\$($env:USERNAME)"

            $ssh_config_file = "$testDir\ssh_config"
            #other default vars: -TargetName "test_target" -user_key_type "ed25519" -user_key_file "$testDir\user_key_$user_key_type" -known_host_file "$testDir\known_hosts"
            Set-TestCommons -port $port -Server $server -ssh_config_file $ssh_config_file -ExtraArglist "-E $logfile"

            $authorized_keys = $Script:Authorized_keys_file
                        
            #add wrong password so ssh does not prompt password if failed with authorized keys
            Add-PasswordSetting -Pass "WrongPass"
            $tI=1
        }

        AfterEach{
            Start-Sleep -Milliseconds 1000
        }

        AfterAll {
            Clear-TestCommons
            Remove-PasswordSetting
            $tC++
        }

        It "$tC.$tI-authorized_keys-positive(authorized_keys is owned by local system)"{
            Write-Host "In $tC.$tI"
            #setup to have system as owner and grant it full control
            Repair-FilePermission -Filepath $authorized_keys -Owner $systemSid -FullAccessNeeded  $adminsSid,$systemSid,$currentUserSid -confirm:$false
            $o = ssh  -F $ssh_config_file test_target echo 1234
            $o | Should Be "1234"
            Write-Host "finish $tC.$tI"
            Write-Host Get-Process -name sshd
        }

        It "$tC.$tI-authorized_keys-positive(authorized_keys is owned by admins group and pwd does not have explict ACE)" {
            Write-Host "In $tC.$tI"
            #setup to have admin group as owner and grant it full control
            Repair-FilePermission -Filepath $authorized_keys -Owner $adminsSid -FullAccessNeeded $adminsSid,$systemSid -confirm:$false
            $o = ssh  -F $ssh_config_file test_target echo 1234
            $o | Should Be "1234"
            Write-Host "finish $tC.$tI"
        }

        It "$tC.$tI-authorized_keys-positive(authorized_keys is owned by admins group and pwd have explict ACE)" {
            Write-Host "In $tC.$tI"
            #setup to have admin group as owner and grant it full control
            Repair-FilePermission -Filepath $authorized_keys -Owner $adminsSid -FullAccessNeeded $adminsSid,$systemSid,$currentUserSid -confirm:$false
            $o = ssh  -F $ssh_config_file test_target echo 1234
            $o | Should Be "1234"
            Write-Host "finish $tC.$tI"
        }

        It "$tC.$tI-authorized_keys-positive(pwd user is the owner)" {
            Write-Host "In $tC.$tI"
            #setup to have ssouser as owner and grant current user read and write, admins group, and local system full control
            Repair-FilePermission -Filepath $authorized_keys -Owners $currentUserSid -FullAccessNeeded  $adminsSid,$systemSid,$currentUserSid -confirm:$false
            $o = ssh -F $ssh_config_file test_target echo 1234
            $o | Should Be "1234"
            Write-Host "finish $tC.$tI"
        }

        <#It "$tC.$tI-authorized_keys-negative(authorized_keys is owned by other admin user)"{
            #setup to have current user (admin user) as owner and grant it full control
            Repair-FilePermission -Filepath $authorizedkeyPath -Owner $currentUserSid -FullAccessNeeded $adminsSid,$systemSid -confirm:$false

            #Run
            Start-SSHDTestDaemon -WorkDir $opensshbinpath -Arguments "-d -p $port -o `"AuthorizedKeysFile .testssh/authorized_keys`" -E $sshdlog"
            ssh -p $port -E $sshlog -o "UserKnownHostsFile $testknownhosts" $ssouser@$server echo 1234
            $LASTEXITCODE | Should Not Be 0
            Stop-SSHDTestDaemon                  
            $sshlog | Should -FileContentMatch "Permission denied"
            $sshdlog | Should -FileContentMatch "Authentication refused."
        }

        It "$tC.$tI-authorized_keys-negative(other account can access private key file)"{
            #setup to have current user as owner and grant it full control            
            Repair-FilePermission -Filepath $authorizedkeyPath -Owner $objUserSid -FullAccessNeeded $adminsSid,$systemSid,$objUserSid -confirm:$false

            #add $PwdUser to access the file authorized_keys
            $objPwdUserSid = Get-UserSid -User $PwdUser
            Set-FilePermission -FilePath $authorizedkeyPath -User $objPwdUserSid -Perm "Read"

            #Run
            Start-SSHDTestDaemon -workDir $opensshbinpath -Arguments "-d -p $port -o `"AuthorizedKeysFile .testssh/authorized_keys`" -E $sshdlog"
            ssh -p $port -E $sshlog -o "UserKnownHostsFile $testknownhosts" $ssouser@$server echo 1234
            $LASTEXITCODE | Should Not Be 0
            Stop-SSHDTestDaemon
            $sshlog | Should Contain "Permission denied"
            $sshdlog | Should Contain "Authentication refused."
        }

        It "$tC.$tI-authorized_keys-negative(authorized_keys is owned by other non-admin user)"{
            #setup to have PwdUser as owner and grant it full control            
            $objPwdUserSid = Get-UserSid -User $PwdUser
            Repair-FilePermission -Filepath $authorizedkeyPath -Owner $objPwdUserSid -FullAccessNeeded $adminsSid,$systemSid,$objPwdUser -confirm:$false

            #Run
            Start-SSHDTestDaemon -WorkDir $opensshbinpath -Arguments "-d -p $port -o `"AuthorizedKeysFile .testssh/authorized_keys`" -E $sshdlog"
            ssh -p $port -E $sshlog -o "UserKnownHostsFile $testknownhosts" $ssouser@$server echo 1234
            $LASTEXITCODE | Should Not Be 0
            Stop-SSHDTestDaemon
            $sshlog | Should Contain "Permission denied"
            $sshdlog | Should Contain "Authentication refused."            
        }#>
    }
}
