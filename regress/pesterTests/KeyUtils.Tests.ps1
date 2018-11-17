If ($PSVersiontable.PSVersion.Major -le 2) {$PSScriptRoot = Split-Path -Parent $MyInvocation.MyCommand.Path}
$tC = 1
$tI = 0
$suite = "keyutils"
$testDir = "$env:temp\$suite"
. $PSScriptRoot\common.ps1 -suite $suite -TestDir $testDir
Import-Module "$Script:SSHBinaryPath\OpenSSHUtils" -force
Describe "E2E scenarios for ssh key management" -Tags "CI" {
    BeforeAll {
        $keytypes = @("ed25519")

        $systemSid = Get-UserSID -WellKnownSidType ([System.Security.Principal.WellKnownSidType]::LocalSystemSid)
        $adminsSid = Get-UserSID -WellKnownSidType ([System.Security.Principal.WellKnownSidType]::BuiltinAdministratorsSid)                        
        $currentUserSid = Get-UserSID -User "$($env:USERDOMAIN)\$($env:USERNAME)"
        $everyoneSid = Get-UserSID -WellKnownSidType ([System.Security.Principal.WellKnownSidType]::WorldSid)

        $keypassphrase = "testpassword"

        function ValidateRegistryACL {
            param([string]$UserSid = $currentUserSid, $count)
            $agentPath = "Registry::HKEY_Users\$UserSid\Software\OpenSSH\Agent"
            $myACL = Get-ACL $agentPath
            $OwnerSid = Get-UserSid -User $myACL.Owner
            $OwnerSid.Equals($adminsSid) | Should Be $true
            $myACL.Access | Should Not Be $null
            $FullControlPerm = [System.UInt32] [System.Security.AccessControl.RegistryRights]::FullControl.value__
            $identities = @($systemSid, $adminsSid)

            foreach ($a in $myACL.Access) {
                $id = Get-UserSid -User $a.IdentityReference
                $identities -contains $id | Should Be $true
                ([System.UInt32]$a.RegistryRights.value__) | Should Be $FullControlPerm            
                $a.AccessControlType | Should Be ([System.Security.AccessControl.AccessControlType]::Allow)
                $a.IsInherited | Should Be $false
                $a.InheritanceFlags | Should Be ([System.Security.AccessControl.InheritanceFlags]::None)
                $a.PropagationFlags | Should Be ([System.Security.AccessControl.PropagationFlags]::None)
            }

            $entries = @(Get-ChildItem $agentPath\keys)
            $entries.Count | Should Be $count
            if($count -gt 0)
            {
                Test-Path $agentPath\keys | Should be $true
                $entries | % {
                    $keyentryAcl = Get-Acl $_.pspath
                    $OwnerSid = Get-UserSid -User $keyentryAcl.Owner
                    $OwnerSid.Equals($adminsSid) | Should Be $true
                    $keyentryAcl.Access | Should Not Be $
                    foreach ($a in $keyentryAcl.Access) {
                        $id = Get-UserSid -User $a.IdentityReference
                        $identities -contains $id | Should Be $true
                        ([System.UInt32]$a.RegistryRights.value__) | Should Be $FullControlPerm            
                        $a.AccessControlType | Should Be ([System.Security.AccessControl.AccessControlType]::Allow)
                        $a.IsInherited | Should Be $false
                        $a.InheritanceFlags | Should Be ([System.Security.AccessControl.InheritanceFlags]::None)
                        $a.PropagationFlags | Should Be ([System.Security.AccessControl.PropagationFlags]::None)
                    }
                }
            }
            else
            {
                Test-Path $agentPath\keys | Should be $false
            }            
        }

        #only validate owner and ACEs of the file
        function ValidateKeyFile {
            param(
                [string]$FilePath,
                [bool]$IsHostKey = $true
            )

            $myACL = Get-ACL $FilePath
            $currentOwnerSid = Get-UserSid -User $myACL.Owner
            $currentOwnerSid.Equals($currentUserSid) | Should Be $true
            $myACL.Access | Should Not Be $null
            
            $ReadAccessPerm = ([System.UInt32] [System.Security.AccessControl.FileSystemRights]::Read.value__) -bor `
                    ([System.UInt32] [System.Security.AccessControl.FileSystemRights]::ReadAndExecute.value__)  -bor `
                    ([System.UInt32] [System.Security.AccessControl.FileSystemRights]::Synchronize.value__)
            $ReadWriteAccessPerm = ([System.UInt32] [System.Security.AccessControl.FileSystemRights]::Read.value__) -bor `
                    ([System.UInt32] [System.Security.AccessControl.FileSystemRights]::ReadAndExecute.value__)  -bor `
                    ([System.UInt32] [System.Security.AccessControl.FileSystemRights]::Write.value__)  -bor `
                    ([System.UInt32] [System.Security.AccessControl.FileSystemRights]::Modify.value__)  -bor `
                    ([System.UInt32] [System.Security.AccessControl.FileSystemRights]::Synchronize.value__)

            $FullControlPerm = [System.UInt32] [System.Security.AccessControl.FileSystemRights]::FullControl.value__
    
            if($FilePath.EndsWith(".pub")) {
                if ($IsHostKey) {
                    $myACL.Access.Count | Should Be 3
                    $identities = @($systemSid, $adminsSid, $currentUserSid)
                }
                else {
                    $myACL.Access.Count | Should Be 4
                    $identities = @($systemSid, $adminsSid, $currentUserSid, $everyoneSid)
                }
            }
            else {
                $myACL.Access.Count | Should Be 3
                $identities = @($systemSid, $adminsSid, $currentUserSid)
            }

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
                    $everyoneSid
                    {
                        ([System.UInt32]$a.FileSystemRights.value__) | Should Be $ReadAccessPerm
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
        $stderrFile=Join-Path $testDir "$tC.$tI.stderr.txt"
        $stdoutFile=Join-Path $testDir "$tC.$tI.stdout.txt"
        $logFile = Join-Path $testDir "$tC.$tI.log.txt"
    }        

    AfterEach {$tI++;}    

    Context "$tC -ssh-keygen all key types" {

        BeforeAll {$tI=1}
        AfterAll{$tC++}

       <# Tests changes the settings of system
        It "$tC.$tI - Keygen -A" {
            $proDir = "$env:ProgramData\ssh"
            Remove-Item "$proDir\ssh_host_*_key*" -ErrorAction SilentlyContinue | Out-Null
            ssh-keygen -A
            
            Get-ChildItem (join-path $proDir ssh_host_*_key) | % {
                ValidateKeyFile -FilePath $_.FullName
            }

            Get-ChildItem (join-path $proDir ssh_host_*_key.pub) | % {
                ValidateKeyFile -FilePath $_.FullName
            }
        }#>

        It "$tC.$tI - Keygen -t -f" {
            foreach($type in $keytypes)
            {
                $keyPath = Join-Path $testDir "id_$type"
                Remove-Item $keyPath -ErrorAction SilentlyContinue
                ssh-keygen -t $type -P $keypassphrase -f $keyPath
                ValidateKeyFile -FilePath $keyPath
                ValidateKeyFile -FilePath "$keyPath.pub" -IsHostKey $false
            }
        }
    }

    # This uses keys generated in above context
    <# require ssh-agent running as service
    Context "$tC -ssh-add test cases" {
        BeforeAll {
            $tI=1
            function WaitForStatus
            {
                param([string]$ServiceName, [string]$Status)
                while((((Get-Service $ServiceName).Status) -ine $Status) -and ($num++ -lt 4))
                {
                    Start-Sleep -Milliseconds 1000
                }
            }
        }
        AfterAll{$tC++}

        # Executing ssh-agent will start agent service
        # This is to support typical Unix scenarios where 
        # running ssh-agent will setup the agent for current session
        It "$tC.$tI - ssh-agent starts agent service" {
            if ((Get-Service ssh-agent).Status -eq "Running") {
                Stop-Service ssh-agent -Force
            }

            (Get-Service ssh-agent).Status | Should Be "Stopped"

            ssh-agent
            WaitForStatus -ServiceName ssh-agent -Status "Running"

            (Get-Service ssh-agent).Status | Should Be "Running"
        }

        It "$tC.$tI - ssh-add - add and remove all key types" {
            #set up SSH_ASKPASS
            Add-PasswordSetting -Pass $keypassphrase

            $nullFile = join-path $testDir ("$tC.$tI.nullfile")
            $null > $nullFile
            
            foreach($type in $keytypes)
            {
                $keyPath = Join-Path $testDir "id_$type"
                # for ssh-add to consume SSh_ASKPASS, stdin should not be TTY
                iex "cmd /c `"ssh-add $keyPath < $nullFile 2> nul `""
                #Check if -Raw presents for Get-Content cmdlet
                $rawParam = (get-command Get-Content).Parametersets | Select -ExpandProperty Parameters | ? {$_.Name -ieq "Raw"}
                if($rawParam)
                {
                    $keyPathDifferentEnding = Join-Path $testDir "id_$($type)_DifferentEnding"
                    if((Get-Content -Path $keyPath -raw).Contains("`r`n"))
                    {
                        $newcontent = (Get-Content -Path $keyPath -raw).Replace("`r`n", "`n")
                    }
                    else
                    {
                        $newcontent = (Get-Content -Path $keyPath -raw).Replace("`n", "`r`n")
                    }
                    Set-content -Path $keyPathDifferentEnding -value "$newcontent"
                    Repair-UserKeyPermission $keyPathDifferentEnding -confirm:$false
                    iex "cmd /c `"ssh-add $keyPathDifferentEnding < $nullFile 2> nul `""
                }                             
            }

            #remove SSH_ASKPASS
            Remove-PasswordSetting

            #ensure added keys are listed
            $allkeys = ssh-add -L
            $allkeys | Set-Content (Join-Path $testDir "$tC.$tI.allkeyonAdd.txt")
            ValidateRegistryACL -count $allkeys.Count
            
            foreach($type in $keytypes)
            {
                $keyPath = Join-Path $testDir "id_$type"
                $pubkeyraw = ((Get-Content "$keyPath.pub").Split(' '))[1]
                @($allkeys | where { $_.contains($pubkeyraw) }).count | Should Be 1
            }

            #delete added keys
            foreach($type in $keytypes)
            {
                $keyPath = Join-Path $testDir "id_$type"
                iex "cmd /c `"ssh-add -d $keyPath 2> nul `""
            }

            #check keys are deleted
            $allkeys = ssh-add -L
            $allkeys | Set-Content (Join-Path $testDir "$tC.$tI.allkeyonDelete.txt")

            foreach($type in $keytypes)
            {
                $keyPath = Join-Path $testDir "id_$type"
                $pubkeyraw = ((Get-Content "$keyPath.pub").Split(' '))[1]
                @($allkeys | where { $_.contains($pubkeyraw) }).count | Should Be 0
            }

            $allkeys = @(ssh-add -L)
            ValidateRegistryACL -count $allkeys.count
        }        
    }#>

    Context "$tC ssh-keygen known_hosts operations" {

        BeforeAll {$tI=1}
        AfterAll{$tC++}

        It "$tC.$tI - list and delete host key thumbprints" {
            $kh = Join-Path $testDir "$tC.$tI.known_hosts"
            $entry = "[localhost]:47002 ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIMtJMxwn+iJU0X4+EC7PSj/cfcMbdP6ahhodtXx+6RHv sshtest_hostkey_ed25519"
            $entry | Set-Content $kh
            $o = ssh-keygen -F [localhost]:47002 -f $kh
            $o.Count | Should Be 2
            $o[1] | Should Be $entry

            $o = ssh-keygen -H -F [localhost]:47002 -f $kh
            $o[1].StartsWith("|1|")  | Should Be $true

            $o = ssh-keygen -R [localhost]:47002 -f $kh
            $o.count | Should Be 3
            $o[0] | Should Be "# Host [localhost]:47002 found: line 1"
            (dir $kh).Length | Should Be 0
        }

    }

        <# require creating other account or installation of ssh-agent
        Context "$tC-ssh-add key files with different file perms" {
        BeforeAll {
            if(!(Get-Process -name ssh-agent -ErrorAction SilentlyContinue)) {
                ssh-agent
            }

            $keyFileName = "sshadd_userPermTestkey_ed25519"
            $keyFilePath = Join-Path $testDir $keyFileName
            Remove-Item -path "$keyFilePath*" -Force -ErrorAction SilentlyContinue
            ssh-keygen.exe -t ed25519 -f $keyFilePath -P $keypassphrase
            #set up SSH_ASKPASS
            Add-PasswordSetting -Pass $keypassphrase
            $tI=1
        }
        BeforeEach {
            $nullFile = join-path $testDir ("$tC.$tI.nullfile")
            $null > $nullFile
        }
        AfterEach {
            if(Test-Path $keyFilePath) {
                Repair-FilePermission -FilePath $keyFilePath -Owner $currentUserSid -FullAccessNeeded $currentUserSid,$systemSid,$adminsSid -confirm:$false
            }            
        }

        AfterAll {
            #remove SSH_ASKPASS
            Remove-PasswordSetting
            if ((Get-Service ssh-agent).Status -eq "Running") {
                Stop-Service ssh-agent -Force
            }
            $tC++
        }

        It "$tC.$tI-  ssh-add - positive (Secured private key owned by current user)" {
            #setup to have current user as owner and grant it full control
            Repair-FilePermission -FilePath $keyFilePath -Owner $currentUserSid -FullAccessNeeded $currentUserSid,$systemSid,$adminsSid -confirm:$false

            # for ssh-add to consume SSh_ASKPASS, stdin should not be TTY
            cmd /c "ssh-add $keyFilePath < $nullFile 2> nul"
            $LASTEXITCODE | Should Be 0
            $allkeys = ssh-add -L
            $pubkeyraw = ((Get-Content "$keyFilePath.pub").Split(' '))[1]
            @($allkeys | where { $_.contains($pubkeyraw) }).count | Should Be 1
            
            #clean up
            cmd /c "ssh-add -d $keyFilePath 2> nul "
        }

        It "$tC.$tI - ssh-add - positive (Secured private key owned by Administrators group and the current user has no explicit ACE)" {
            #setup to have local admin group as owner and grant it full control            
            Repair-FilePermission -FilePath $keyFilePath -Owner $adminsSid -FullAccessNeeded $adminsSid,$systemSid -confirm:$false

            # for ssh-add to consume SSh_ASKPASS, stdin should not be TTY
            cmd /c "ssh-add $keyFilePath < $nullFile 2> nul "
            $LASTEXITCODE | Should Be 0
            $allkeys = ssh-add -L
            $pubkeyraw = ((Get-Content "$keyFilePath.pub").Split(' '))[1]
            @($allkeys | where { $_.contains($pubkeyraw) }).count | Should Be 1
            
            #clean up
            cmd /c "ssh-add -d $keyFilePath 2> nul "
        }

        It "$tC.$tI - ssh-add - positive (Secured private key owned by Administrators group and the current user has explicit ACE)" {
            #setup to have local admin group as owner and grant it full control
            Repair-FilePermission -FilePath $keyFilePath -Owners $adminsSid -FullAccessNeeded $currentUserSid,$adminsSid,$systemSid -confirm:$false

            # for ssh-add to consume SSh_ASKPASS, stdin should not be TTY
            cmd /c "ssh-add $keyFilePath < $nullFile 2> nul "
            $LASTEXITCODE | Should Be 0
            $allkeys = ssh-add -L
            $pubkeyraw = ((Get-Content "$keyFilePath.pub").Split(' '))[1]
            @($allkeys | where { $_.contains($pubkeyraw) }).count | Should Be 1
            
            #clean up
            cmd /c "ssh-add -d $keyFilePath 2> nul "
        }

        It "$tC.$tI - ssh-add - positive (Secured private key owned by local system group)" {
            #setup to have local admin group as owner and grant it full control
            Repair-FilePermission -FilePath $keyFilePath -Owners $systemSid -FullAccessNeeded $systemSid,$adminsSid -confirm:$false

            # for ssh-add to consume SSh_ASKPASS, stdin should not be TTY
            cmd /c "ssh-add $keyFilePath < $nullFile 2> nul "
            $LASTEXITCODE | Should Be 0
            $allkeys = ssh-add -L
            $pubkeyraw = ((Get-Content "$keyFilePath.pub").Split(' '))[1]
            @($allkeys | where { $_.contains($pubkeyraw) }).count | Should Be 1
            
            #clean up
            cmd /c "ssh-add -d $keyFilePath 2> nul "
        }
        

        It "$tC.$tI-  ssh-add - negative (other account can access private key file)" {
            #setup to have current user as owner and grant it full control
            Repair-FilePermission -FilePath $keyFilePath -Owners $currentUserSid -FullAccessNeeded $currentUserSid,$adminsSid, $systemSid -ReadAccessNeeded $objUserSid -confirm:$false

            cmd /c "ssh-add $keyFilePath < $nullFile 2> nul "
            $LASTEXITCODE | Should Not Be 0

            $allkeys = ssh-add -L
            $pubkeyraw = ((Get-Content "$keyFilePath.pub").Split(' '))[1]
            @($allkeys | where { $_.contains($pubkeyraw) }).count | Should Be 0
        }

        It "$tC.$tI - ssh-add - negative (the private key has wrong owner)" {
            #setup to have ssouser as owner and grant it full control
            Repair-FilePermission -FilePath $keyFilePath -Owners $objUserSid -FullAccessNeeded $objUserSid,$adminsSid, $systemSid -confirm:$false

            cmd /c "ssh-add $keyFilePath < $nullFile 2> nul "
            $LASTEXITCODE | Should Not Be 0

            $allkeys = ssh-add -L
            $pubkeyraw = ((Get-Content "$keyFilePath.pub").Split(' '))[1]
            @($allkeys | where { $_.contains($pubkeyraw) }).count | Should Be 0
        }
    }#>
		
    Context "$tC - ssh-keyscan test cases" {
        BeforeAll {
            $tI=1
            $port = 47002
            $server = "localhost"
            $user_key_type = "ed25519"
            $user_key_file = "$testDir\user_key_$user_key_type"
            $ssh_config_file = "$testDir\ssh_config"

            Set-TestCommons -port $port -Server $server -user_key_file $user_key_file -host_key_type @("ed25519","rsa","dsa","ecdsa") -SSH_config_file $ssh_config_file
            Remove-item (join-path $testDir "$tC.$tI.out.txt") -force -ErrorAction SilentlyContinue
        }
        BeforeEach {
            $outputFile = join-path $testDir "$tC.$tI.out.txt"
        }
        AfterAll{
            $tC++
            Clear-TestCommons
        }

		It "$tC.$tI - ssh-keyscan with default arguments"{
			cmd /c "ssh-keyscan -p $port 127.0.0.1 2>&1 > $outputFile"
			$outputFile | Should -FileContentMatch '.*ssh-rsa.*'
		}

        It "$tC.$tI - ssh-keyscan with -p"{
			cmd /c "ssh-keyscan -p $port 127.0.0.1 2>&1 > $outputFile"
			$outputFile | Should -FileContentMatch '.*ssh-rsa.*'
		}

		It "$tC.$tI - ssh-keyscan with -f"{
			Set-Content -Path "$testDir\tmp.txt" -Value "127.0.0.1"
			cmd /c "ssh-keyscan -p $port -f `"$testDir\tmp.txt`" 2>&1 > $outputFile"
			$outputFile | Should -FileContentMatch '.*ssh-rsa.*'
		}

		It "$tC.$tI - ssh-keyscan with -f -t"{
			Set-Content -Path "$testDir\tmp.txt" -Value "127.0.0.1"
			cmd /c "ssh-keyscan -p $port -f `"$testDir\tmp.txt`" -t rsa,dsa 2>&1 > $outputFile"
			$outputFile | Should -FileContentMatch '.*ssh-rsa.*'
		}
	}
}
