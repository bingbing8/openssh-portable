If ($PSVersiontable.PSVersion.Major -le 2) {$PSScriptRoot = Split-Path -Parent $MyInvocation.MyCommand.Path}
$tC = 1
$tI = 0
$suite = "Cfginclude"
$testDir = "C:\Users\yawang\$suite"
. $PSScriptRoot\common.ps1 -suite $suite -TestDir $testDir
Describe "Tests for ssh config" -Tags "Scenario" {
    BeforeAll {
        
        $logName = "testlog.txt"
        $port = 47002
        $logName = "log.txt"
        $server = "localhost"
        $ssh_config_file = "$testDir\ssh_config"
        
        Remove-Item -Path (Join-Path $testDir "*logName") -Force -ErrorAction SilentlyContinue
    }

    AfterEach {$tI++}

    Context "$tC-User SSHConfig--ReadConfig" {
        BeforeAll {
            $systemSid = Get-UserSID -WellKnownSidType ([System.Security.Principal.WellKnownSidType]::LocalSystemSid)
            $adminsSid = Get-UserSID -WellKnownSidType ([System.Security.Principal.WellKnownSidType]::BuiltinAdministratorsSid)                        
            $currentUserSid = Get-UserSID -User "$($env:USERDOMAIN)\$($env:USERNAME)"

            $userConfigFile = Join-Path $home ".ssh\config"
            if( -not (Test-path $userConfigFile) ) {
                Copy-item "$PSScriptRoot\testdata\ssh_config" $userConfigFile -force
            }
            Enable-Privilege SeRestorePrivilege | out-null
            $oldACL = Get-ACL $userConfigFile
            $tI=1
        }

        BeforeEach {
            $logPath = Join-Path $testDir "$tC.$tI.$logName"
        }

        AfterEach {            
            Set-Acl -Path $userConfigFile -AclObject $oldACL -confirm:$false
        }

        AfterAll {
            $tC++
        }

        It "$tC.$tI-User SSHConfig-ReadConfig positive (current logon user is the owner)" {
            #setup
            Repair-FilePermission -Filepath $userConfigFile -Owners $currentUserSid -FullAccessNeeded $adminsSid,$systemSid,$currentUserSid -confirm:$false

            #Run
            $o = ssh test_target echo 1234
            $o | Should Be "1234"
        }

        It "$tC.$tI-User SSHConfig-ReadConfig positive (local system is the owner)" {
            #setup
            Repair-FilePermission -Filepath $userConfigFile -Owners $systemSid -FullAccessNeeded $adminsSid,$systemSid -confirm:$false

            #Run
            $o = ssh test_target echo 1234
            $o | Should Be "1234"
        }

        It "$tC.$tI-User SSHConfig-ReadConfig positive (admin is the owner and current user has no explict ACE)" {
            #setup
            Repair-FilePermission -Filepath $userConfigFile -Owners $adminsSid -FullAccessNeeded $adminsSid,$systemSid -confirm:$false
            Set-FilePermission -Filepath $userConfigFile -UserSid $currentUserSid -Action Delete

            #Run
            $o = ssh test_target echo 1234
            $o | Should Be "1234"
        }

        It "$tC.$tI-User SSHConfig-ReadConfig positive (admin is the owner and current user has explict ACE)" {
            #setup
            Repair-FilePermission -Filepath $userConfigFile -Owners $adminsSid -FullAccessNeeded $adminsSid,$systemSid,$currentUserSid -confirm:$false
            
            #Run
            $o = ssh test_target echo 1234
            $o | Should Be "1234"
        }

        It "$tC.$tI-User SSHConfig-ReadConfig negative (wrong owner)" {
            #setup
            Repair-FilePermission -Filepath $userConfigFile -Owners $objUserSid -FullAccessNeeded $adminsSid,$systemSid,$objUserSid -confirm:$false

            #Run
            cmd /c "ssh test_target echo 1234 2> $logPath"
            $LASTEXITCODE | Should Not Be 0
            Get-Content $logPath | Should Match "^Bad owner or permissions on [a-fA-F]:[/\\]{1,}Users[/\\]{1,}\w+[/\\]{1,}.ssh[/\\]{1,}config$"
        }

        It "$tC.$tI-User SSHConfig-ReadConfig negative (others has permission)" {
            #setup
            Repair-FilePermission -Filepath $userConfigFile -Owners $currentUserSid -FullAccessNeeded $adminsSid,$systemSid,$currentUserSid -ReadAccessNeeded $objUserSid -confirm:$false

            #Run
            cmd /c "ssh test_target echo 1234 2> $logPath"
            $LASTEXITCODE | Should Not Be 0
            Get-Content $logPath | Should Match "^Bad owner or permissions on [a-fA-F]:[/\\]{1,}Users[/\\]{1,}\w+[/\\]{1,}.ssh[/\\]{1,}config$"
        }
    }
}
