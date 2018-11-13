If ($PSVersiontable.PSVersion.Major -le 2) {$PSScriptRoot = Split-Path -Parent $MyInvocation.MyCommand.Path}
Import-Module $PSScriptRoot\CommonUtils.psm1 -Force
Import-Module OpenSSHUtils -Force
$tC = 1
$tI = 0
$suite = "authorized_keys_fileperm"
$testDir = "C:\Users\yawang\$suite"
. $PSScriptRoot\common.ps1 -suite $suite -TestDir $testDir
Describe "Tests for authorized_keys file permission" -Tags "CI" {
    BeforeAll {
        $sshLogName = "test.txt"
        $sshdLogName = "sshdlog.txt"
        $port = 47002
        $server = "localhost"
        $ssh_config_file = "$testDir\ssh_config"
        
        #other default vars: -TargetName "test_target" -host_key_type "ed25519" -user_key_type "ed25519" -user_key_file "$testDir\user_key_$user_key_type" -known_host_file "$testDir\known_hosts"
        Set-TestCommons -port $port -Server $server -ssh_config_file $ssh_config_file

        $ssh_config = $script:SSH_Config_file
        $known_host = $Script:Known_host_file
        $authorized_keys = $Script:Authorized_keys_file

        #$PwdUser = $OpenSSHTestInfo["PasswdUser"]
        #$ssouserProfile = $OpenSSHTestInfo["SSOUserProfile"]        
        Remove-Item -Path (Join-Path $testDir "*$sshLogName") -Force -ErrorAction SilentlyContinue
                
        if([Environment]::OSVersion.Version.Major -le 6)
        {
            #suppress the firewall blocking dialogue on win7
            netsh advfirewall firewall add rule name="sshd" program="$($OpenSSHTestInfo['OpenSSHBinPath'])\sshd.exe" protocol=any action=allow dir=in
        }        
    }

    AfterEach { $tI++ }
    
    AfterAll {        
        if($psversiontable.BuildVersion.Major -le 6)
        {            
            netsh advfirewall firewall delete rule name="sshd" program="$($OpenSSHTestInfo['OpenSSHBinPath'])\sshd.exe" protocol=any dir=in
        }    
    }

    Context "Authorized key file permission" {
        BeforeAll {
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
            $systemSid = Get-UserSID -WellKnownSidType ([System.Security.Principal.WellKnownSidType]::LocalSystemSid)
            $adminsSid = Get-UserSID -WellKnownSidType ([System.Security.Principal.WellKnownSidType]::BuiltinAdministratorsSid)                        
            $currentUserSid = Get-UserSID -User "$($env:USERDOMAIN)\$($env:USERNAME)"

            Repair-AuthorizedKeyPermission -Filepath $authorized_keys -confirm:$false           
                        
            #add wrong password so ssh does not prompt password if failed with authorized keys
            Add-PasswordSetting -Pass "WrongPass"
            $tI=1
        }

        AfterAll {
            Repair-AuthorizedKeyPermission -Filepath $authorized_keys -confirm:$false
            Remove-PasswordSetting
            $tC++
        }        

        It "$tC.$tI-authorized_keys-positive(pwd user is the owner and running process can access to the file)" {            

            #setup to have ssouser as owner and grant current user read and write, admins group, and local system full control            
            Repair-FilePermission -Filepath $authorized_keys -Owners $currentUserSid -FullAccessNeeded  $adminsSid,$systemSid -confirm:$false
            $o = ssh -F $ssh_config test_target echo 1234
            $o | Should Be "1234"
        }

        It "$tC.$tI-authorized_keys-positive(authorized_keys is owned by local system)"  -skip:$skip {
            #setup to have system as owner and grant it full control            
            Repair-FilePermission -Filepath $authorized_keys -Owner $systemSid -FullAccessNeeded  $adminsSid,$systemSid,$currentUserSid -confirm:$false            
            $o = ssh  -F $ssh_config test_target echo 1234
            $o | Should Be "1234"
        }

        It "$tC.$tI-authorized_keys-positive(authorized_keys is owned by admins group and pwd does not have explict ACE)" {
            #setup to have admin group as owner and grant it full control            
            Repair-FilePermission -Filepath $authorized_keys -Owner $adminsSid -FullAccessNeeded $adminsSid,$systemSid -confirm:$false
            $o = ssh  -F $ssh_config test_target echo 1234            
            $o | Should Be "1234"
        }

        It "$tC.$tI-authorized_keys-positive(authorized_keys is owned by admins group and pwd have explict ACE)" {
            #setup to have admin group as owner and grant it full control
            Repair-FilePermission -Filepath $authorized_keys -Owner $adminsSid -FullAccessNeeded $adminsSid,$systemSid,$currentUserSid -confirm:$false
            $o = ssh  -F $ssh_config test_target echo 1234           
            $o | Should Be "1234"          
        }

        <#It "$tC.$tI-authorized_keys-negative(authorized_keys is owned by other admin user)"  -skip:$skip {
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

        It "$tC.$tI-authorized_keys-negative(other account can access private key file)"  -skip:$skip {
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

        It "$tC.$tI-authorized_keys-negative(authorized_keys is owned by other non-admin user)"  -skip:$skip {
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
