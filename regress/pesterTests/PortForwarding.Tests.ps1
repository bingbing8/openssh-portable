If ($PSVersiontable.PSVersion.Major -le 2) {$PSScriptRoot = Split-Path -Parent $MyInvocation.MyCommand.Path}
$tC = 1
$tI = 0
$suite = "portfwd"
$testDir = "$env:temp\$suite"
. $PSScriptRoot\common.ps1 -suite $suite -TestDir $testDir
Describe "E2E scenarios for port forwarding" -Tags "CI" {
    BeforeAll {
        $port = 47002
        $server = "localhost"
        $ssh_config_file = "$testDir\ssh_config"

        #skip on ps 2 becase non-interactive cmd require a ENTER before it returns on ps2
        $skip = $PSVersionTable.PSVersion.Major -le 2

        #other default vars: -TargetName "test_target" -user_key_type "ed25519" -user_key_file "$testDir\user_key_$user_key_type" -known_host_file "$testDir\known_hosts"
        Set-TestCommons -port $port -Server $server -ssh_config_file $ssh_config_file
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

    Context "$tC - Basic port forwarding scenarios"  {
        BeforeAll {$tI=1}
        AfterAll{$tC++}

        #TODO - this relies on winrm (that is windows specific)
        It "$tC.$tI - local port forwarding" -skip:$skip {
            ssh -F $ssh_config_file -L 5432:127.0.0.1:47001 test_target powershell.exe Test-WSMan -computer 127.0.0.1 -port 5432 | Set-Content $stdoutFile
            $stdoutFile | Should  -FileContentMatch "wsmid"
        }

        It "$tC.$tI - remote port forwarding" -skip:$skip {
            ssh -F $ssh_config_file -R 5432:127.0.0.1:47001 test_target powershell.exe Test-WSMan -computer 127.0.0.1 -port 5432  | Set-Content $stdoutFile
            $stdoutFile | Should  -FileContentMatch "wsmid"
        }
    }        
}
