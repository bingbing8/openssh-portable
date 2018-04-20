﻿If ($PSVersiontable.PSVersion.Major -le 2) {$PSScriptRoot = Split-Path -Parent $MyInvocation.MyCommand.Path}
Import-Module $PSScriptRoot\CommonUtils.psm1 -Force
$suite = "Setup"
$tC = 1
$tI = 0
Describe "Setup Tests" -Tags "Setup" {
    BeforeAll {
        if($OpenSSHTestInfo -eq $null)
        {
            Throw "`$OpenSSHTestInfo is null. Please run Set-OpenSSHTestEnvironment to set test environments."
        }
        
        $testDir = "$($OpenSSHTestInfo["TestDataPath"])\$suite"
        if( -not (Test-path $testDir -PathType Container))
        {
            $null = New-Item $testDir -ItemType directory -Force -ErrorAction SilentlyContinue
        }        
        
        $windowsInBox = $OpenSSHTestInfo["WindowsInBox"]
        $binPath = $OpenSSHTestInfo["OpenSSHBinPath"]
        $dataPath = Join-path $env:ProgramData ssh
        
        $systemSid = Get-UserSID -WellKnownSidType ([System.Security.Principal.WellKnownSidType]::LocalSystemSid)
        $adminsSid = Get-UserSID -WellKnownSidType ([System.Security.Principal.WellKnownSidType]::BuiltinAdministratorsSid)
        $usersSid = Get-UserSID -WellKnownSidType ([System.Security.Principal.WellKnownSidType]::BuiltinUsersSid)
        $authenticatedUserSid = Get-UserSID -WellKnownSidType ([System.Security.Principal.WellKnownSidType]::AuthenticatedUserSid)
        $trustedInstallerSid = Get-UserSID -User "NT SERVICE\TrustedInstaller"
        $allApplicationPackagesSid = Get-UserSID -User "ALL APPLICATION PACKAGES"
        $allRestrictedApplicationPackagesSid = Get-UserSID -User "ALL RESTRICTED APPLICATION PACKAGES"

        $FSReadAccessPerm = ([System.UInt32] [System.Security.AccessControl.FileSystemRights]::ReadAndExecute.value__)  -bor `
                    ([System.UInt32] [System.Security.AccessControl.FileSystemRights]::Synchronize.value__)
        $FSReadWriteAccessPerm = ([System.UInt32] [System.Security.AccessControl.FileSystemRights]::ReadAndExecute.value__)  -bor `
                ([System.UInt32] [System.Security.AccessControl.FileSystemRights]::Write.value__)  -bor `
                ([System.UInt32] [System.Security.AccessControl.FileSystemRights]::Modify.value__)  -bor `
                ([System.UInt32] [System.Security.AccessControl.FileSystemRights]::Synchronize.value__)

        $FSFullControlPerm = [System.UInt32] [System.Security.AccessControl.FileSystemRights]::FullControl.value__
        $FSReadAndExecutePerm = ([System.UInt32] [System.Security.AccessControl.FileSystemRights]::ReadAndExecute.value__)  -bor `
                ([System.UInt32] [System.Security.AccessControl.FileSystemRights]::Synchronize.value__)

        $RegReadKeyPerm = ([System.UInt32] [System.Security.AccessControl.RegistryRights]::ReadKey.value__)
        $RegFullControlPerm = [System.UInt32] [System.Security.AccessControl.RegistryRights]::FullControl.value__        

        #only validate owner and ACEs of the registry
        function ValidateRegistryACL {
            param([string]$RegPath, $Ownersid = $adminsSid, $IdAcls)
            Test-Path -Path $RegPath | Should Be $true                      
            $myACL = Get-ACL $RegPath
            $OwnerSid = Get-UserSid -User $myACL.Owner
            $OwnerSid.Equals($Ownersid) | Should Be $true
            $myACL.Access | Should Not Be $null
            $CAPABILITY_SID = "S-1-15-3-1024-1065365936-1281604716-3511738428-1654721687-432734479-3232135806-4053264122-3456934681"            
            $nonPropagate = $myACL.Access | ? {($_.PropagationFlags -eq ([System.Security.AccessControl.PropagationFlags]::None)) -and ($_.IdentityReference -ine $CAPABILITY_SID)}

            $IdAcls | % { $nonPropagate.IdentityReference -contains (Get-UserAccount -UserSid ($_.Identity)) }

            foreach ($a in $nonPropagate) {
                $findItem = $IdAcls | ? {
                    ($a.IdentityReference -eq (Get-UserAccount -UserSid ($_.Identity))) -and `
                    ($a.IsInherited -eq $_.IsInherited) -and `
                    ($a.AccessControlType -eq ([System.Security.AccessControl.AccessControlType]::Allow)) -and  `
                    ($a.PropagationFlags -eq ([System.Security.AccessControl.PropagationFlags]::None) -and  `
                    (([System.Int32]$a.RegistryRights.value__) -eq ($_.RegistryRights))) 
                }
                $findItem | Should Not Be $null
            }         
        }

        #only validate owner and ACEs of the file
        function ValidateFileSystem {
            param(
                [string]$FilePath,
                [bool]$IsDirectory = $false,
                [switch]$IsDataFile,
                $OwnerSid = $trustedInstallerSid)

            if($IsDirectory)
            {
                Test-Path -Path $FilePath -PathType Container | Should Be $true
            }
            else
            {
                Test-Path -Path $FilePath -PathType Leaf | Should Be $true
            }

            $myACL = Get-ACL $FilePath
            $currentOwnerSid = Get-UserSid -User $myACL.Owner
            if(-not $windowsInBox) {return}            
            $currentOwnerSid.Equals($OwnerSid) | Should Be $true            
            $myACL.Access | Should Not Be $null
            if($IsDirectory)
            {
                $identities = @($systemSid, $adminsSid)
            }
            elseif($IsDataFile)
            {
                $identities = @($systemSid, $adminsSid, $authenticatedUserSid)
            }
            else
            {
                $identities = @($systemSid, $adminsSid, $trustedInstallerSid, $allApplicationPackagesSid, $allRestrictedApplicationPackagesSid, $usersSid)
            }

            $identities | % {
                $myACL.Access.IdentityReference -contains (Get-UserAccount -UserSid $_) | Should Be $true
            }

            foreach ($a in $myACL.Access) {
                $id = Get-UserSid -User $a.IdentityReference
                if($id -eq $null)
                {
                    $idRefShortValue = ($a.IdentityReference.Value).split('\')[-1]
                    $id = Get-UserSID -User $idRefShortValue                                      
                }

                $identities -contains $id | Should Be $true

                switch ($id)
                {
                    {@($systemSid, $adminsSid) -contains $_}
                    {
                        if($IsDataFile)
                        {
                            ([System.UInt32]$a.FileSystemRights.value__) | Should Be $FSFullControlPerm
                        }
                        else
                        {
                            ([System.UInt32]$a.FileSystemRights.value__) | Should Be $FSReadAndExecutePerm
                        }                        
                        break;
                    }
                    {@($usersSid, $allApplicationPackagesSid, $allRestrictedApplicationPackagesSid, $authenticatedUserSid) -contains $_}
                    {                        
                        ([System.UInt32]$a.FileSystemRights.value__) | Should Be $FSReadAndExecutePerm                     
                        break;
                    }
                    $trustedInstallerSid
                    {
                        ([System.UInt32]$a.FileSystemRights.value__) | Should Be $FSFullControlPerm
                        break;
                    }
                }
            
                $a.AccessControlType | Should Be ([System.Security.AccessControl.AccessControlType]::Allow)
                if($IsDirectory)
                {
                    $a.InheritanceFlags | Should Be (([System.Security.AccessControl.InheritanceFlags]::ContainerInherit.value__ -bor `
                         [System.Security.AccessControl.InheritanceFlags]::ObjectInherit.value__))
                }
                else
                {
                    $a.InheritanceFlags | Should Be ([System.Security.AccessControl.InheritanceFlags]::None)
                }
                $a.PropagationFlags | Should Be ([System.Security.AccessControl.PropagationFlags]::None)
            }
        }        
    }    

    Context "$tC - Validate Openssh binary files" {

        BeforeAll {
            $tI=1
            $binaries =  @(
                @{
                    Name = 'sshd.exe'
                },
                @{
                    Name = 'ssh.exe'
                },
                @{
                    Name = 'ssh-agent.exe'
                },
                @{
                    Name = 'ssh-add.exe'
                },
                @{
                    Name = 'sftp.exe'
                },
                @{
                    Name = 'sftp-server.exe'
                },
                @{
                    Name = 'scp.exe'
                },
                @{
                    Name = 'ssh-shellhost.exe'
                },
                @{
                    Name = 'ssh-agent.exe'
                },
                @{
                    Name = 'ssh-keyscan.exe'
                }
            )
            $dataFile =  @(
                @{
                    Name = 'sshd_config_default'
                },
                @{
                    Name = 'install-sshd.ps1'
                },
                @{
                    Name = 'uninstall-sshd.ps1'
                },
                @{
                    Name = 'FixHostFilePermissions.ps1'
                },
                @{
                    Name = 'FixUserFilePermissions.ps1'
                },
                @{
                    Name = 'OpenSSHUtils.psm1'
                },
                @{
                    Name = 'OpenSSHUtils.psd1'
                },
                @{
                    Name = 'openssh-events.man'
                }
            )

            $dataFile1 = @(
                @{
                    Name = "sshd_config"
                }
                @{
                    Name = "logs"
                    IsDirectory = $true
                }
            )
        }
        AfterAll{$tC++}        
        AfterEach { $tI++ }

        It "$tC.$tI - Validate Openssh binary files--<Name>" -TestCases:$binaries{
            param([string]$Name, [boolean]$IsDirectory = $false)
            ValidateFileSystem -FilePath (join-path $binPath $Name)
        }
        It "$tC.$tI - Validate Openssh script files--<Name>" -TestCases:$dataFile {
            param([string]$Name, [boolean]$IsDirectory = $false)            
            if(-not $WindowsInbox) { ValidateFileSystem -FilePath (join-path $binPath $Name) }
        }

        It "$tC.$tI - Validate data files--<Name>" -TestCases:$dataFile1 {
            param([string]$Name, [boolean]$IsDirectory = $false)
            if(-not (Test-Path $dataPath -PathType Container))
            {
                Start-Service sshd
            }
            
            ValidateFileSystem -FilePath (join-path $dataPath $Name) -IsDirectory $IsDirectory -OwnerSid $adminsSid -IsDataFile
        }
    } 
    
    Context "$tC - Validate Openssh registry entries" {
        BeforeAll {
            $tI=1
            $servicePath = "HKLM:\SYSTEM\ControlSet001\Services"
            $opensshRegPath = "HKLM:\SOFTWARE\OpenSSH"
            
            $opensshACLs = @(
                @{
                    Identity=$systemSid
                    IsInherited = $false
                    RegistryRights = $RegFullControlPerm
                    PropagationFlags = "None"
                },
                @{
                    Identity=$adminsSid
                    IsInherited = $false
                    RegistryRights = $RegFullControlPerm
                    PropagationFlags = "None"
                },                
                @{
                    Identity=$authenticatedUserSid
                    IsInherited = $false
                    RegistryRights = $RegReadKeyPerm -bor ([System.UInt32] [System.Security.AccessControl.RegistryRights]::SetValue.value__)
                    PropagationFlags = "None"
                }
            )
        }        
        AfterAll{$tC++}
        AfterEach { $tI++ }               

        It "$tC.$tI - Validate Registry key ssh-agent\Description" {
            $p = Get-ItemPropertyValue (Join-Path $servicePath "ssh-agent") -Name "Description"
            $p | Should Not Be $null
        }

        It "$tC.$tI - Validate Registry key ssh-agent\ErrorControl" {
            $p = Get-ItemPropertyValue (Join-Path $servicePath "ssh-agent") -Name "ErrorControl"
            $p | Should Be 1
        }

        It "$tC.$tI - Validate Registry key ssh-agent\ImagePath" {
            $p = Get-ItemPropertyValue (Join-Path $servicePath "ssh-agent") -Name "ImagePath"
            $imagePath = (Join-Path $binPath "ssh-agent.exe").ToLower()
            $p | Should Match "[`"]?$($imagePath.Replace("\", "\\"))[`"]?"
        }

        It "$tC.$tI - Validate Registry key ssh-agent\ObjectName" {
            $p = Get-ItemPropertyValue (Join-Path $servicePath "ssh-agent") -Name "ObjectName"            
            $p | Should Be "LocalSystem"
        }

        It "$tC.$tI - Validate Registry key ssh-agent\Start" {
            $p = Get-ItemPropertyValue (Join-Path $servicePath "ssh-agent") -Name "Start"            
            $p | Should Be 3
        }

        It "$tC.$tI - Validate Registry key ssh-agent\Type" {
            $p = Get-ItemPropertyValue (Join-Path $servicePath "ssh-agent") -Name "Type"            
            $p | Should Be 16
        }
        

        It "$tC.$tI - Validate Registry key to ssh-agent\Security\Security" { 
            $p = Get-ItemPropertyValue (Join-Path $servicePath "ssh-agent\Security") -Name Security            
            $p.Gettype() | Should Be byte[]
        }

        It "$tC.$tI - Validate security access to ssh-agent service" {            
            $a = @(cmd /c "sc sdshow ssh-agent")
            $b = $a[-1] -split "[D:S]:"

            $c = @($b | ? { -not [string]::IsNullOrWhiteSpace($_) })            
            $dacl = $c[0]
            $dacl_aces = $dacl -split "(\([;|\w]+\))"
            $dacl_aces -contains "(A;;CCLCSWRPWPDTLOCRRC;;;SY)" | Should Be $true
            $dacl_aces -contains "(A;;CCDCLCSWRPWPDTLOCRSDRCWDWO;;;BA)" | Should Be $true
            $dacl_aces -contains "(A;;CCLCSWLOCRRC;;;IU)" | Should Be $true
            $dacl_aces -contains "(A;;CCLCSWLOCRRC;;;SU)" | Should Be $true
            $dacl_aces -contains "(A;;RP;;;AU)" | Should Be $true
            if($c.Count -gt 1)
            {                
                $sacl = $c[1]
                $sacl_aces = $sacl -split "(\([;\w]+\))"
                $sacl_aces -contains "(AU;FA;CCDCLCSWRPWPDTLOCRSDRCWDWO;;;WD)" | Should Be $true
            }
        }

        It "$tC.$tI - Validate security access to sshd service" {            
            $a = @(cmd /c "sc sdshow sshd")
            $b = $a[-1] -split "[D:S]:"

            $c = @($b | ? { -not [string]::IsNullOrWhiteSpace($_) })            
            $dacl = $c[0]
            $dacl_aces = $dacl -split "(\([;|\w]+\))"
            $dacl_aces -contains "(A;;CCLCSWRPWPDTLOCRRC;;;SY)" | Should Be $true
            $dacl_aces -contains "(A;;CCDCLCSWRPWPDTLOCRSDRCWDWO;;;BA)" | Should Be $true
            $dacl_aces -contains "(A;;CCLCSWLOCRRC;;;IU)" | Should Be $true
            $dacl_aces -contains "(A;;CCLCSWLOCRRC;;;SU)" | Should Be $true
            if($c.Count -gt 1)
            {                
                $sacl = $c[1]
                $sacl_aces = $sacl -split "(\([;\w]+\))"
                $sacl_aces -contains "(AU;FA;CCDCLCSWRPWPDTLOCRSDRCWDWO;;;WD)" | Should Be $true
            }
        }
        

        It "$tC.$tI - Validate Registry key sshd\Description" {
            $p = Get-ItemPropertyValue (Join-Path $servicePath "sshd") -Name "Description"            
            $p | Should not Be $null
        }

        It "$tC.$tI - Validate Registry key sshd\ErrorControl" {
            $p = Get-ItemPropertyValue (Join-Path $servicePath "sshd") -Name "ErrorControl"            
            $p | Should Be 1
        }

        It "$tC.$tI - Validate Registry key sshd\ImagePath" {
            $p = Get-ItemPropertyValue (Join-Path $servicePath "sshd") -Name "ImagePath"
            $imagePath = (Join-Path $binPath "sshd.exe").ToLower()
            $p | Should Match "[`"]?$($imagePath.Replace("\", "\\"))[`"]?"
        }

        It "$tC.$tI - Validate Registry key sshd\ObjectName" {
            $p = Get-ItemPropertyValue (Join-Path $servicePath "sshd") -Name "ObjectName"            
            $p | Should Be "LocalSystem"
        }

        It "$tC.$tI - Validate Registry key sshd\Start" {
            $p = Get-ItemPropertyValue (Join-Path $servicePath "sshd") -Name "Start"            
            $p | Should Be 3
        }

        It "$tC.$tI - Validate Registry key sshd\Type" {
            $p = Get-ItemPropertyValue (Join-Path $servicePath "sshd") -Name "Type"            
            $p | Should Be 16
        }

        It "$tC.$tI - Validate Registry openssh entry" {
            ValidateRegistryACL -RegPath $opensshRegPath -IdAcls $opensshACLs
        }
        It "$tC.$tI - Validate Registry openssh\agent entry" {
            $agentPath = Join-Path $opensshRegPath "Agent"
            if(-not (Test-Path $agentPath -PathType Container))
            {
                Start-Service ssh-agent
            }

            ValidateRegistryACL -RegPath $agentPath -IdAcls $opensshACLs
        }
    }

    Context "$tC - Validate Firewall settings" {
        BeforeAll {
            $firwallRuleName = "OpenSSH-Server-In-TCP"
            $tI=1
        }
        
        AfterAll{$tC++}
        AfterEach { $tI++ }

        It "$tC.$tI - Validate Firewall settings" -skip:(!$windowsInBox) {
            $rule = Get-NetFirewallRule -Name $firwallRuleName            
            $rule.Group | Should BeLike "OpenSSH*"
            $rule.Description | Should BeLike "*OpenSSH*"
            $rule.DisplayName | Should BeLike "OpenSSH*"
            $rule.Enabled | Should Be $true
            $rule.Profile.ToString() | Should Be 'Any'
            $rule.Direction.ToString() | Should Be 'Inbound'
            $rule.Action.ToString() | Should Be 'Allow'
            $rule.StatusCode | Should Be 65536
        }        
    }    
}
