If ($PSVersiontable.PSVersion.Major -le 2) {$PSScriptRoot = Split-Path -Parent $MyInvocation.MyCommand.Path}

$tC = 1
$tI = 0
$suite = "userkey_fileperm"
$testDir = "$env:temp\$suite"
. $PSScriptRoot\common.ps1 -suite $suite -TestDir $testDir
Import-Module "$Script:SSHBinaryPath\OpenSSHUtils" -force
Describe "Tests for user Key file permission" -Tags "Scenario" {
    BeforeAll {
        $logName = "log.txt"
        $port = 47002
        $server = "localhost"
        $ssh_config_file = "$testDir\ssh_config"
        $userName = "$env:USERNAME@$env:USERDOMAIN"
        $keypassphrase = "testpassword"        
                
        $systemSid = Get-UserSID -WellKnownSidType ([System.Security.Principal.WellKnownSidType]::LocalSystemSid)
        $adminsSid = Get-UserSID -WellKnownSidType ([System.Security.Principal.WellKnownSidType]::BuiltinAdministratorsSid)                        
        $currentUserSid = Get-UserSID -User "$($env:USERDOMAIN)\$($env:USERNAME)"
        $everyoneSid = Get-UserSID -WellKnownSidType ([System.Security.Principal.WellKnownSidType]::WorldSid)
                
        Add-PasswordSetting -Pass $keypassphrase
    }

    AfterAll {
        Remove-PasswordSetting
    }
    BeforeEach {
        $logPath = Join-Path $testDir "$tC.$tI.$logName"
    }

    AfterEach {$tI++;}    

    Context "$tC-ssh with private key file" {
        BeforeAll {
            $user_key_type = "ed25519"
            $user_key_Path = "$testDir\user_key_$user_key_type" 
            Set-TestCommons -port $port -Server $server -ssh_config_file $ssh_config_file -user_key_type $user_key_type -user_key_file $user_key_Path
            $tI=1
        }
        AfterAll {$tC++ }        

        It "$tC.$tI-ssh with private key file -- positive (Secured private key owned by current user)" {
            Repair-FilePermission -FilePath $user_key_Path -Owners $currentUserSid -FullAccessNeeded $adminsSid,$systemSid,$currentUserSid -confirm:$false
            
            #Run
            $o = ssh -F $ssh_config_file test_target echo 1234
            $o | Should Be "1234"
        }

        It "$tC.$tI-ssh with private key file -- positive(Secured private key owned by Administrators group and current user has no explicit ACE)" {
            #setup to have local admin group as owner and grant it full control
            Repair-FilePermission -FilePath $user_key_Path -Owners $adminsSid -FullAccessNeeded $adminsSid,$systemSid -confirm:$false

            #Run
            $o = ssh -F $ssh_config_file test_target echo 1234
            $o | Should Be "1234"
        }

        It "$tC.$tI-ssh with private key file -- positive(Secured private key owned by Administrators group and current user has explicit ACE)" {
            #setup to have local admin group as owner and grant it full control
            Repair-FilePermission -FilePath $user_key_Path -Owners $adminsSid -FullAccessNeeded $adminsSid,$systemSid -ReadAccessNeeded $currentUserSid -confirm:$false

            #Run
            $o = ssh -F $ssh_config_file test_target echo 1234
            $o | Should Be "1234"
        }

        It "$tC.$tI-ssh with private key file -- positive (Secured private key owned by local system)" {
            #setup to have local system as owner and grant it full control
            Repair-FilePermission -FilePath $user_key_Path -Owners $systemSid -FullAccessNeeded $adminsSid,$systemSid -confirm:$false

            #Run
            $o = ssh -F $ssh_config_file test_target echo 1234
            $o | Should Be "1234"
        }
        
        <#It "$tC.$tI-ssh with private key file -- negative(other account can access private key file)" {
            #setup to have current user as owner and grant it full control
            Repair-FilePermission -FilePath $keyFilePath -Owners $currentUserSid -FullAccessNeeded $currentUser,$adminsSid,$systemSid -ReadAccessNeeded $objUserSid -confirm:$false

            #Run
            $o = ssh -p $port -i $keyFilePath -E $logPath $pubKeyUser@$server echo 1234
            $LASTEXITCODE | Should Not Be 0

            $logPath | Should Contain "UNPROTECTED PRIVATE KEY FILE!"
        }

        It "$tC.$tI-ssh with private key file -- negative(the private key has wrong owner)" {
            #setup to have ssouser as owner and grant it full control
            Repair-FilePermission -FilePath $keyFilePath -Owners $objUserSid -FullAccessNeeded $objUserSid,$adminsSid,$systemSid -ReadAccessNeeded $objUserSid -confirm:$false

            $o = ssh -p $port -i $keyFilePath -E $logPath $pubKeyUser@$server echo 1234
            $LASTEXITCODE | Should Not Be 0

            $logPath | Should Contain "UNPROTECTED PRIVATE KEY FILE!"
        }#>
    }
}
