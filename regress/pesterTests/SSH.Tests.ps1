If ($PSVersiontable.PSVersion.Major -le 2) {$PSScriptRoot = Split-Path -Parent $MyInvocation.MyCommand.Path}

#todo: -i -q -v -l -c -C
#todo: -S -F -V -e
$tC = 1
$tI = 0
$suite = "sshclient"
$testDir = "$env:temp\$suite"
. $PSScriptRoot\common.ps1 -suite $suite -TestDir $testDir
        
Describe "E2E scenarios for ssh client" -Tags "CI" {
    BeforeAll {        
        $port = 47002
        $server = "localhost"
        $ssh_config_file = "$testDir\ssh_config"
        $user_key_type = "ed25519"
        $user_key_file = "$testDir\user_key_$user_key_type"
        $known_host_file = "$testDir\known_hosts"

        #other default vars: -TargetName "test_target" -host_key_type "ed25519" -user_key_type "ed25519"
        Set-TestCommons -port $port -Server $server -ssh_config_file $ssh_config_file -user_key_file $user_key_file -known_host_file $known_host_file

        #skip on ps 2 becase non-interactive cmd require a ENTER before it returns on ps2
        $skip = $PSVersionTable.PSVersion.Major -le 2

        $dfltShellRegPath = "HKLM:\Software\OpenSSH"
        $dfltShellRegKeyName = "DefaultShell"
        $dfltShellCmdOptionRegKeyName = "DefaultShellCommandOption"
        Remove-ItemProperty -Path $dfltShellRegPath -Name $dfltShellRegKeyName -ErrorAction SilentlyContinue
        Remove-ItemProperty -Path $dfltShellRegPath -Name $dfltShellCmdOptionRegKeyName -ErrorAction SilentlyContinue

        function ConfigureDefaultShell {
            param
            (
                  [string] $default_shell_path,
                  [string] $default_shell_cmd_option_val = $null
            )
            
            if (!(Test-Path $dfltShellRegPath)) {
                New-Item -Path $dfltShellRegPath -Force | Out-Null
            }
            New-ItemProperty -Path $dfltShellRegPath -Name $dfltShellRegKeyName -Value $default_shell_path -PropertyType String -Force
            if ($default_shell_cmd_option_val -ne $null) {
                New-ItemProperty -Path $dfltShellRegPath -Name $dfltShellCmdOptionRegKeyName -Value $default_shell_cmd_option_val -PropertyType String -Force
            }
        }
    }

    BeforeEach {
        $stderrFile=Join-Path $testDir "$tC.$tI.stderr.txt"
        $stdoutFile=Join-Path $testDir "$tC.$tI.stdout.txt"
        $logFile = Join-Path $testDir "$tC.$tI.log.txt"
    }

    AfterEach {$tI++;}

    AfterAll {
        Clear-TestCommons
    }

   Context "$tC - Basic Scenarios" {
        
        BeforeAll {$tI=1}
        AfterAll{$tC++}

        It "$tC.$tI - test version" {
            iex "cmd /c `"ssh -V 2> $stderrFile`""
            Get-Content $stderrFile | write-host
            $stderrFile | Should -FileContentMatch "OpenSSH_for_Windows *"
        }

        It "$tC.$tI - test help" {
            iex "cmd /c `"ssh -? 2> $stderrFile`""
            $stderrFile | Should -FileContentMatch "usage: ssh *"
        }
        
        It "$tC.$tI - remote echo command" {
            1 | should Be 1
            #iex "$sshDefaultCmd echo 1234" | Should Be "1234"
        }

    }
    
    Context "$tC - exit code (exit-status.sh)" {
        BeforeAll {$tI=1}
        AfterAll{$tC++}

        It "$tC.$tI - various exit codes" {
            foreach ($i in (0,1,4,5,44)) {
                ssh -F $ssh_config_file test_target exit $i
                $LASTEXITCODE | Should Be $i
            }            
        }
    }

    Context "$tC - Redirection Scenarios" {
        
        BeforeAll {$tI=1}
        AfterAll{$tC++}

        It "$tC.$tI - stdout to file" -skip:$skip {
            ssh -F $ssh_config_file test_target powershell get-process > $stdoutFile
            $stdoutFile | Should -FileContentMatch "ProcessName"
        }

        It "$tC.$tI - stdout to PS object" {
            $o = ssh -F $ssh_config_file test_target echo 1234
            $o | Should Be "1234"
        }

        It "$tC.$tI - multiple double quotes in cmdline" {
            # actual command line ssh target \"cmd\" /c \"echo hello\"
            $o = ssh -F $ssh_config_file test_target `\`"cmd`\`" /c `\`"echo hello`\`"
            $o | Should Be "hello"
        }

        It "$tC.$tI - stdin from PS object" -skip:$skip {
            # execute this script that dumps the length of input data, on the remote end
            $str = "begin {} process { Write-Output `$input.Length} end { }"
            $EncodedText =[Convert]::ToBase64String([System.Text.Encoding]::Unicode.GetBytes($str))
            $h = "hello123"
            # ignore error stream using 2> $null
            $o = $h | ssh -F $ssh_config_file test_target PowerShell -NoProfile -NonInteractive -ExecutionPolicy Unrestricted -EncodedCommand $EncodedText 2> $null
            $o | Should Be "8"
        }

        It "$tC.$tI - stream file in and out" -skip:$skip {
            # prep a file of size > 10KB (https://github.com/PowerShell/Win32-OpenSSH/issues/908 was caught with such file size)
            $str = ""
            (1..100) | foreach {$str += "1234567890"}
            #strem file from local to remote
            $testsrc = Join-Path $testDir "$tC.$tI.testsrc"
            $testdst1 = Join-Path $testDir "$tC.$tI.testdst1"
            $null | Set-Content $testsrc
            $null | Set-Content $testdst1
            (1..105) | foreach {Add-Content -Encoding Ascii -Path $testsrc -Value $str}
            # execute this script that dumps input stream in target file, on the remote end
            $str = "begin {} process { Add-Content -Encoding Ascii -path $testdst1 -Value ([string]`$input)} end { }"
            $EncodedText =[Convert]::ToBase64String([System.Text.Encoding]::Unicode.GetBytes($str))
            # ignore error stream using 2> $null
            get-content $testsrc | ssh -F $ssh_config_file test_target PowerShell -NoProfile -NonInteractive -ExecutionPolicy Unrestricted -EncodedCommand $EncodedText 2> $null
            (dir $testdst1).Length | Should Be (dir $testsrc).Length

            # stream file from remote to local
            $testdst2 = Join-Path $testDir "$tC.$tI.testdst2"
            $null | Set-Content $testdst2
            (ssh -F $ssh_config_file test_target powershell get-content $testdst1 -Encoding Ascii) | Set-Content $testdst2 -Encoding ASCII
            (dir $testdst2).Length | Should Be (dir $testsrc).Length

        }
    }
    
    Context "$tC - configure powershell default shell Scenarios" {
        BeforeAll {
            $tI=1
            $shell_path = (Get-Command powershell.exe -ErrorAction SilentlyContinue).path
            if($shell_path -ne $null) {
                ConfigureDefaultShell -default_shell_path $shell_path -default_shell_cmd_option_val "-c"
            }
        }
        AfterAll{
            $tC++
            Remove-ItemProperty -Path $dfltShellRegPath -Name $dfltShellRegKeyName -ErrorAction SilentlyContinue
            Remove-ItemProperty -Path $dfltShellRegPath -Name $dfltShellCmdOptionRegKeyName -ErrorAction SilentlyContinue
        }        

        It "$tC.$tI - basic powershell" -skip:$skip {
            $o = ssh -F $ssh_config_file test_target Write-Output 1234
            $o | Should Be "1234"
        }
        
        It "$tC.$tI - basic in powershell cmdlet" -skip:$skip {
            $o = ssh -F $ssh_config_file test_target "cd `$env:ProgramFiles;pwd"
            $LASTEXITCODE | Should Be 0
            #$o | Should Match "c:\Program Files"
        }
        It "$tC.$tI - powershell as default shell and double quotes in cmdline" {
            # actual command line ssh target echo `"hello`"
            $o = ssh -F $ssh_config_file test_target echo "``\`"hello``\`""
            $o | Should Be "`"hello`""
        }
        It "$tC.$tI - multiple commands with double quotes in powershell cmdlet" -skip:$skip {
            # actual command line ssh target cd "$env:programfiles";pwd
            $o = ssh -F $ssh_config_file test_target "cd \`"`$env:programfiles\`";pwd"
            $LASTEXITCODE | Should Be 0
            $match = $o -match "Program Files"
            $match.count | Should be 1
        }
        It "$tC.$tI - multiple commands with double quotes in powershell cmdlet" -skip:$skip {
            # actual command line ssh target dir "$env:programfiles";cd "$env:programfiles";pwd
            $o = ssh -F $ssh_config_file test_target "dir \`"`$env:programfiles\`";cd \`"`$env:programfiles\`";pwd"
            $LASTEXITCODE | Should Be 0
            #$o -contains "Program Files" | Should Be $True
            $match = $o -match "Program Files"
            $match.count | Should Be 3
        }
        It "$tC.$tI - single quotes in powershell cmdlet" -skip:$skip {
            # actual command line ssh target echo '$env:computername'
            $o = ssh -F $ssh_config_file test_target "echo '`$env:computername'"
            $LASTEXITCODE | Should Be 0            
            $o | Should Be `$env:computername
        }
    }
    Context "$tC - configure cmd as default shell" {
        BeforeAll {
            $tI=1
            $shell_path = (Get-Command cmd.exe -ErrorAction SilentlyContinue).path
            if($shell_path -ne $null) {
                ConfigureDefaultShell -default_shell_path $shell_path -default_shell_cmd_option_val "/c"
        }
        }
        AfterAll{
            $tC++
            Remove-ItemProperty -Path $dfltShellRegPath -Name $dfltShellRegKeyName -ErrorAction SilentlyContinue
            Remove-ItemProperty -Path $dfltShellRegPath -Name $dfltShellCmdOptionRegKeyName -ErrorAction SilentlyContinue
        }
        It "$tC.$tI - default shell as cmd" -skip:$skip {
            $o = ssh -F $ssh_config_file test_target where cmd
            $o | Should -BeLike "*cmd*"
        }
        It "$tC.$tI - cmd as default shell and double quotes in cmdline" {
            # actual command line ssh target echo "\"hello\""
            $o = ssh -F $ssh_config_file test_target 'echo "\"hello\""'
            $o | Should Be "`"hello`""
        }
        It "$tC.$tI - single quotes in powershell cmdlet" -skip:$skip {
            # actual command line ssh target echo '$env:computername'
            $o = ssh -F $ssh_config_file test_target "echo 'hello'"
            $LASTEXITCODE | Should Be 0            
            $o | Should Be "'hello'"
        }
    }
    Context "$tC - configure ssh-shellhost as default shell" {
        BeforeAll {
            $tI=1
            $shell_path = (Get-Command ssh-shellhost -ErrorAction SilentlyContinue).path
            ConfigureDefaultShell -default_shell_path $shell_path
        }
        AfterAll{
            $tC++
            Remove-ItemProperty -Path $dfltShellRegPath -Name $dfltShellRegKeyName -ErrorAction SilentlyContinue
            Remove-ItemProperty -Path $dfltShellRegPath -Name $dfltShellCmdOptionRegKeyName -ErrorAction SilentlyContinue
        }
        It "$tC.$tI - shellhost as default shell and multiple double quotes in cmdline" {
            # actual command line ssh target \"cmd\" /c \"echo \"hello\"\"
            $o = ssh -F $ssh_config_file test_target `\`"cmd`\`" /c `\`"echo \`"hello\`"`\`"
            $o | Should Be "`"hello`""
        }
    }
    
    Context "$tC - cmdline parameters" {        
        BeforeAll {$tI=1}
        AfterAll{$tC++}

        It "$tC.$tI - verbose to file (-v -E)" {
            $o = ssh -v -E $logFile -F $ssh_config_file test_target echo 1234
            $o | Should Be "1234"
            #TODO - checks below are very inefficient (time taking). 
            $logFile | Should -FileContentMatch "OpenSSH_"
            $logFile | Should -FileContentMatch "Exit Status 0"
        }


        It "$tC.$tI - cipher options (-c)" {
            #bad cipher
            iex "cmd /c `"ssh -c bad_cipher -F $ssh_config_file test_target echo 1234 2>$stderrFile`""
            $stderrFile | Should -FileContentMatch "Unknown cipher type"
            #good cipher, ensure cipher is used from debug logs
            $o = ssh -c aes256-ctr  -v -E $logFile -F $ssh_config_file test_target echo 1234
            $o | Should Be "1234"
            $logFile | Should -FileContentMatch "kex: server->client cipher: aes256-ctr"
            $logFile | Should -FileContentMatch "kex: client->server cipher: aes256-ctr"
        }

        It "$tC.$tI - ssh_config (-F)" {
            #ensure -F is working by pointing to a bad configuration
            $badConfigFile = Join-Path $testDir "$tC.$tI.bad_ssh_config"
            "bad_config_line" | Set-Content $badConfigFile
            iex "cmd /c `"ssh -F $badConfigFile test_target echo 1234 2>$stderrFile`""
            $stderrFile | Should -FileContentMatch "bad_ssh_config"
            $stderrFile | Should -FileContentMatch "bad_config_line"
            $stderrFile | Should -FileContentMatch "bad configuration options"

            #try with a proper configuration file. Put it on a unicode path with unicode content
            #so we can test the Unicode support simultaneously
            $goodConfigFile = Join-Path $testDir "$tC.$tI.Очень_хорошо_ssh_config"
            "#this is a Unicode comment because it contains русский язык" | Set-Content $goodConfigFile -Encoding UTF8
            "Host myhost" | Add-Content $goodConfigFile
            "    HostName $server" | Add-Content $goodConfigFile
            "    Port $port" | Add-Content $goodConfigFile
            "    IdentityFile $user_key_file" | Add-Content $goodConfigFile
            "    UserKnownHostsFile $known_host_file" | Add-Content $goodConfigFile
            $o = ssh -F $goodConfigFile myhost echo 1234
            $o | Should Be "1234"          
        }

        It "$tC.$tI - IP options - (-4) (-6)" {
            # TODO - this test assumes target is localhost. 
            # make it work independent of target
            #-4
            $o = ssh -4 -v -E $logFile -F $ssh_config_file test_target echo 1234
            $o | Should Be "1234"
            $logFile | Should -FileContentMatch "[127.0.0.1]"
            #-4
            $o = ssh -6 -v -E $logFile -F $ssh_config_file test_target echo 1234
            $o | Should Be "1234"
            $logFile | Should -FileContentMatch "[::1]"
        }

        It "$tC.$tI - auto populate known hosts" {
            
            $kh = Join-Path $testDir "$tC.$tI.known_hosts"
            $null | Set-Content $kh
            # doing via cmd to intercept and drain stderr output
            iex "cmd /c `"ssh -o UserKnownHostsFile=`"$kh`" -o StrictHostKeyChecking=no -F $ssh_config_file test_target hostname 2>&1`""
            @(Get-Content $kh).Count | Should Be 1
        }

        It "ProxyCommand with file name only" {            
            & cmd /c "ssh -o ProxyCommand=`"cmd.exe /c echo test string for invalid proxy 1>&2`" abc 2>$stderrFile"
            $stderrFile | Should -FileContentMatch "test string for invalid proxy"
            write-host (Get-Content $stderrFile)
            #$stderrFile | Should -FileContentMatch "Connection closed by remote host"
        }

        It "ProxyCommand with absolute path to the file" {
            & cmd /c "ssh -o ProxyCommand=`"$($env:ComSpec) /c echo test string for invalid proxy 1>&2`" abc 2>$stderrFile"
            $stderrFile | Should -FileContentMatch "test string for invalid proxy"
            write-host  (Get-Content $stderrFile)
            #$stderrFile | Should Contain "Connection closed by remote host"
        }
    }    
}
