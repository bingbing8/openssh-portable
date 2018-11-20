If ($PSVersiontable.PSVersion.Major -le 2) {$PSScriptRoot = Split-Path -Parent $MyInvocation.MyCommand.Path}
$tC = 1
$tI = 0
$suite = "Cfginclude"
$testDir = "$env:temp\$suite"
. $PSScriptRoot\common.ps1 -suite $suite -TestDir $testDir
Import-Module "$Script:SSHBinaryPath\OpenSSHUtils" -force
Describe "Tests for ssh config" -Tags "CI" {
    BeforeAll {
        $port = 47002
        $logName = "log.txt"
        $server = "localhost"        
        
        Remove-Item -Path (Join-Path $testDir "*logName") -Force -ErrorAction SilentlyContinue
    }

    AfterEach {$tI++}

    Context "$tC-User SSHConfig--ReadConfig" {
        BeforeAll {
            $systemSid = Get-UserSID -WellKnownSidType ([System.Security.Principal.WellKnownSidType]::LocalSystemSid)
            $adminsSid = Get-UserSID -WellKnownSidType ([System.Security.Principal.WellKnownSidType]::BuiltinAdministratorsSid)                        
            $currentUserSid = Get-UserSID -User "$($env:USERDOMAIN)\$($env:USERNAME)"

            $userConfigFile = "$testDir\ssh_config"
            
            Set-TestCommons -port $port -Server $server -ssh_config_file $userConfigFile
            Enable-Privilege SeRestorePrivilege | out-null
            $oldACL = Get-ACL $userConfigFile
            $tI=1

            function Set-FilePermission
            {    
                param(
                    [parameter(Mandatory=$true)]
                    [string]$FilePath,
                    [parameter(Mandatory=$true)]
                    [System.Security.Principal.SecurityIdentifier] $UserSid,
                    [System.Security.AccessControl.FileSystemRights[]]$Perms,
                    [System.Security.AccessControl.AccessControlType] $AccessType = "Allow",
                    [ValidateSet("Add", "Delete")]
                    [string]$Action = "Add"
                )    

                $myACL = Get-ACL $FilePath
                $account = Get-UserAccount -UserSid $UserSid
                if($Action -ieq "Delete")
                {
                    $myACL.SetAccessRuleProtection($True, $True)
                    Enable-Privilege SeRestorePrivilege | out-null
                    Set-Acl -Path $FilePath -AclObject $myACL
                    $myACL = Get-ACL $FilePath
        
                    if($myACL.Access) 
                    {        
                        $myACL.Access | % {
                            if($_.IdentityReference.Equals($account))
                            {
                                if($_.IsInherited)
                                {
                                    $myACL.SetAccessRuleProtection($True, $True)
                                    Enable-Privilege SeRestorePrivilege | out-null
                                    Set-Acl -Path $FilePath -AclObject $myACL
                                    $myACL = Get-ACL $FilePath
                                }
                    
                                if(-not ($myACL.RemoveAccessRule($_)))
                                {
                                    throw "failed to remove access of $($_.IdentityReference) rule in setup "
                                }
                            }
                        }
                    } 
                }
                elseif($Perms)
                {
                    $Perms | % { 
                        $userACE = New-Object System.Security.AccessControl.FileSystemAccessRule `
                            ($UserSid, $_, "None", "None", $AccessType)
                        $myACL.AddAccessRule($userACE)
                    }
                }
                Enable-Privilege SeRestorePrivilege | out-null
                Set-Acl -Path $FilePath -AclObject $myACL -confirm:$false
            }
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
            $o = ssh -F $userConfigFile test_target echo 1234
            $o | Should Be "1234"
        }

        It "$tC.$tI-User SSHConfig-ReadConfig positive (local system is the owner)" {
            #setup
            Repair-FilePermission -Filepath $userConfigFile -Owners $systemSid -FullAccessNeeded $adminsSid,$systemSid -confirm:$false

            #Run
            $o = ssh -F $userConfigFile test_target echo 1234
            $o | Should Be "1234"
        }

        It "$tC.$tI-User SSHConfig-ReadConfig positive (admin is the owner and current user has no explict ACE)" {
            #setup
            Repair-FilePermission -Filepath $userConfigFile -Owners $adminsSid -FullAccessNeeded $adminsSid,$systemSid -confirm:$false
            Set-FilePermission -Filepath $userConfigFile -UserSid $currentUserSid -Action Delete

            #Run
            $o = ssh -F $userConfigFile test_target echo 1234
            $o | Should Be "1234"
        }

        It "$tC.$tI-User SSHConfig-ReadConfig positive (admin is the owner and current user has explict ACE)" {
            #setup
            Repair-FilePermission -Filepath $userConfigFile -Owners $adminsSid -FullAccessNeeded $adminsSid,$systemSid,$currentUserSid -confirm:$false
            
            #Run
            $o = ssh -F $userConfigFile test_target echo 1234
            $o | Should Be "1234"
        }

        <#It "$tC.$tI-User SSHConfig-ReadConfig negative (wrong owner)" {
            #setup
            Repair-FilePermission -Filepath $userConfigFile -Owners $objUserSid -FullAccessNeeded $adminsSid,$systemSid,$objUserSid -confirm:$false

            #Run
            cmd /c "ssh -F $userConfigFile test_target echo 1234 2> $logPath"
            $LASTEXITCODE | Should Not Be 0
            $logPath | Should -FileContentMatch "^Bad owner or permissions on [a-fA-F]:[/\\]{1,}Users[/\\]{1,}\w+[/\\]{1,}.ssh[/\\]{1,}config$"
        }

        It "$tC.$tI-User SSHConfig-ReadConfig negative (others has permission)" {
            #setup
            Repair-FilePermission -Filepath $userConfigFile -Owners $currentUserSid -FullAccessNeeded $adminsSid,$systemSid,$currentUserSid -ReadAccessNeeded $objUserSid -confirm:$false

            #Run
            cmd /c "ssh -F $userConfigFile test_target echo 1234 2> $logPath"
            $LASTEXITCODE | Should Not Be 0
            $logPath | Should  -FileContentMatch "^Bad owner or permissions on [a-fA-F]:[/\\]{1,}Users[/\\]{1,}\w+[/\\]{1,}.ssh[/\\]{1,}config$"
        }#>
    }
}
