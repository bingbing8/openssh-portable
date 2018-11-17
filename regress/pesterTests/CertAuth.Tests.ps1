If ($PSVersiontable.PSVersion.Major -le 2) {$PSScriptRoot = Split-Path -Parent $MyInvocation.MyCommand.Path}
$tC = 1
$tI = 0
$suite = "certauth"
$testDir = "$env:temp\$suite"
. $PSScriptRoot\common.ps1 -suite $suite -TestDir $testDir
Describe "E2E scenarios for certificate authentication" -Tags "CI" {
    BeforeAll {
        $port = 47002
        $server = "localhost"
        $ssh_config_file = "$testDir\ssh_config"
        $cakey = "$testDir\ca_key_file"
        $userName = "$env:USERNAME@$env:USERDOMAIN"
        $user_key = Join-Path $testDir "cert_auth_user_key"
        $keypassphrase = "testpassword" 

        $ca_key_type = "ed25519"
        $ca_key_Path = "$testDir\user_key_$ca_key_type" 
        if(Test-Path $ca_key_Path -PathType Leaf) {
            Remove-Item $ca_key_Path -Force | Out-Null
        }
        ssh-keygen.exe -t $ca_key_type -P `"$keypassphrase`" -f $ca_key_Path
    }

    BeforeEach {
        $stderrFile=Join-Path $testDir "$tC.$tI.stderr.txt"
        $stdoutFile=Join-Path $testDir "$tC.$tI.stdout.txt"
        $logFile = Join-Path $testDir "$tC.$tI.log.txt"
    }        

    AfterEach {$tI++;}

    Context "$tC - generate certificates" {
        
        BeforeAll {$tI=1}
        AfterAll{$tC++}

        It "$tC.$tI - sign user keys" {
            Remove-Item "$($user_key)*"
            ssh-keygen -t ed25519 -f $user_key -P $keypassphrase
            $user_key | Should Exist
            $nullFile = join-path $testDir ("$tC.$tI.nullfile")
            $null > $nullFile
            $user_key_pub = ($user_key + ".pub")
            iex "cmd /c `"ssh-keygen -s $cakey -I $userName -V -1w:+54w5d  -n $userName $user_key_pub < $nullFile 2> nul `""
        }

    }

    Context "$tC - ssh with certificate" {
        BeforeAll {$tI=1}
        AfterAll{$tC++}

        It "$tC.$tI - authenticate using certificate" {
            #set up SSH_ASKPASS for key passphrase
            Add-PasswordSetting -Pass $keypassphrase
            Set-TestCommons -port $port -Server $server -ssh_config_file $ssh_config_file -user_key_file $user_key
            $o = ssh -i $user_key -F $ssh_config_file test_target echo 1234
            $o | Should Be "1234"
            Remove-PasswordSetting            
        }
    }

}
