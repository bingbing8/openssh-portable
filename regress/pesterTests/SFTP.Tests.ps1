If ($PSVersiontable.PSVersion.Major -le 2) {$PSScriptRoot = Split-Path -Parent $MyInvocation.MyCommand.Path}
$tI = 0
$suite = "sftp"
$rootDirectory = "$env:temp\$suite"
. $PSScriptRoot\common.ps1 -suite $suite -TestDir $rootDirectory
Import-Module "$Script:SSHBinaryPath\OpenSSHUtils" -force
Describe "SFTP Test Cases" -Tags "CI" {
    BeforeAll {
        $outputFileName = "output.txt"
        $batchFileName = "sftp-batchcmds.txt"
        $tempFileName = "tempFile.txt"
        $tempFilePath = Join-Path $rootDirectory $tempFileName

        $tempUnicodeFileName = "tempFile_язык.txt"
        $tempUnicodeFilePath = Join-Path $rootDirectory $tempUnicodeFileName

        $clientDirectory = Join-Path $rootDirectory 'client_dir'
        $serverDirectory = Join-Path $rootDirectory 'server_dir'

        New-Item $clientDirectory -ItemType directory -Force | Out-Null
        New-Item $serverDirectory -ItemType directory -Force | Out-Null
        New-Item $tempFilePath -ItemType file -Force -value "temp file data" | Out-Null
        New-Item $tempUnicodeFilePath -ItemType file -Force -value "temp file data" | Out-Null

        $port = 47002
        $server = "localhost"
        $user_key_type = "ed25519"
        $user_key_file = "$testDir\user_key_$user_key_type"

        #other default vars: -TargetName "test_target" -host_key_type "ed25519" -user_key_type "ed25519"
        Set-TestCommons -port $port -Server $server -user_key_file $user_key_file

        $ssh_config = $script:SSH_Config_file        

        Remove-item (Join-Path $rootDirectory "*.$outputFileName") -Force -ErrorAction SilentlyContinue                
        Remove-item (Join-Path $rootDirectory "*.$batchFileName") -Force -ErrorAction SilentlyContinue
        Remove-item (Join-Path $rootDirectory "*.log") -Force -ErrorAction SilentlyContinue        

        $skip = $PSVersionTable.PSVersion.Major -le 2

        $testData1 = @(
             @{
                title = "put, ls for non-unicode file names"
                options = ''
                commands = "put $tempFilePath $serverDirectory
                            ls $serverDirectory"
                expectedoutput = (join-path $serverdirectory $tempFileName)
             },
             @{
                title = "get, ls for non-unicode file names"
                options = ''
                commands = "get $tempFilePath $clientDirectory
                            ls $clientDirectory"
                expectedoutput = (join-path $clientDirectory $tempFileName)
             },
             @{
                title = "mput, ls for non-unicode file names"
                options = ''
                commands = "mput $tempFilePath $serverDirectory
                            ls $serverDirectory"
                expectedoutput = (join-path $serverdirectory $tempFileName)
             },
             @{
                title = "mget, ls for non-unicode file names"
                options = ''
                commands = "mget $tempFilePath $clientDirectory
                            ls $clientDirectory"
                expectedoutput = (join-path $clientDirectory $tempFileName)
             },
             @{
                title = "mkdir, cd, pwd for non-unicode directory names"
                options = ''
                commands = "cd $serverdirectory
                            mkdir server_test_dir
                            cd server_test_dir
                            pwd"
                expectedoutput = (join-path $serverdirectory "server_test_dir")
             },
             @{
                Title = "lmkdir, lcd, lpwd for non-unicode directory names"
                Options = ''
                Commands = "lcd $clientDirectory
                            lmkdir client_test_dir
                            lcd client_test_dir
                            lpwd"
                ExpectedOutput = (Join-Path $clientDirectory "client_test_dir")
             },
             @{
                title = "put, ls for unicode file names"
                options = ''
                commands = "put $tempUnicodeFilePath $serverDirectory
                            ls $serverDirectory"
                expectedoutput = (join-path $serverdirectory $tempUnicodeFileName)			
             },
             @{
                title = "get, ls for unicode file names"
                options = ''
                commands = "get $tempUnicodeFilePath $clientDirectory
                            ls $clientDirectory"
                expectedoutput = (join-path $clientDirectory $tempUnicodeFileName)
             },
             @{
                title = "mput, ls for unicode file names"
                options = ''
                commands = "mput $tempUnicodeFilePath $serverDirectory
                            ls $serverDirectory"
                expectedoutput = (join-path $serverdirectory $tempUnicodeFileName)
             },
             @{
                title = "mget, ls for unicode file names"
                options = ''
                commands = "mget $tempUnicodeFilePath $clientDirectory
                            ls $clientDirectory"
                expectedoutput = (join-path $clientDirectory $tempUnicodeFileName)
             },
             @{
                title = "mkdir, cd, pwd for unicode directory names"
                options = ''
                commands = "cd $serverdirectory
                            mkdir server_test_dir_язык
                            cd server_test_dir_язык
                            pwd"
                expectedoutput = (join-path $serverdirectory "server_test_dir_язык")
             },
             @{
                Title = "lmkdir, lcd, lpwd for unicode directory names"
                Options = ''
                Commands = "lcd $clientDirectory
                            lmkdir client_test_dir_язык
                            lcd client_test_dir_язык
                            lpwd
                            lls $clientDirectory"
                ExpectedOutput = (Join-Path $clientDirectory "client_test_dir_язык")
             }
        )
        
        $testData2 = @(
            @{
                title = "rm, rmdir, rename for unicode file, directory"
                options = '-b $batchFilePath'
                
                tmpFileName1 = $tempUnicodeFileName
                tmpFilePath1 = $tempUnicodeFilePath
                tmpFileName2 = "tempfile_язык_2.txt"
                tmpFilePath2 = (join-path $serverDirectory "tempfile_язык_2.txt")

                tmpDirectoryName1 = "test_dir_язык_1"
                tmpDirectoryPath1 = (join-path $serverDirectory "test_dir_язык_1")
                tmpDirectoryName2 = "test_dir_язык_2"
                tmpDirectoryPath2 = (join-path $serverDirectory "test_dir_язык_2")
            },
            @{
                title = "rm, rmdir, rename for non-unicode file, directory"
                options = '-b $batchFilePath'
                
                tmpFileName1 = $tempFileName
                tmpFilePath1 = $tempFilePath
                tmpFileName2 = "tempfile_2.txt"
                tmpFilePath2 = (join-path $serverDirectory "tempfile_2.txt")

                tmpDirectoryName1 = "test_dir_1"
                tmpDirectoryPath1 = (join-path $serverDirectory "test_dir_1")
                tmpDirectoryName2 = "test_dir_2"
                tmpDirectoryPath2 = (join-path $serverDirectory "test_dir_2")
            }
        )        
    }

    AfterAll {
       if(Test-path $serverDirectory -pathtype Container) { Get-ChildItem $serverDirectory | Remove-Item -Recurse -Force -ErrorAction SilentlyContinue }
       if(Test-path $clientDirectory -pathtype Container) { Get-ChildItem $clientDirectory | Remove-Item -Recurse -Force -ErrorAction SilentlyContinue }
       Clear-TestCommons
    }

    BeforeEach {
       if(Test-path $serverDirectory -pathtype Container) { Get-ChildItem $serverDirectory | Remove-Item -Recurse -Force -ErrorAction SilentlyContinue }
       if(Test-path $clientDirectory -pathtype Container) { Get-ChildItem $clientDirectory | Remove-Item -Recurse -Force -ErrorAction SilentlyContinue }
       $outputFilePath = Join-Path $rootDirectory "$tI.$outputFileName"
       $batchFilePath = Join-Path $rootDirectory "$tI.$batchFileName"
    }

    AfterEach { $tI++}    

    It '<Title>' -TestCases:$testData1 {
       param([string]$Title, $Options, $Commands, $ExpectedOutput)

       Set-Content $batchFilePath -Encoding UTF8 -value $Commands
       $str = $ExecutionContext.InvokeCommand.ExpandString("sftp -F $ssh_config -P $port $($Options) -b $batchFilePath test_target > $outputFilePath")
       iex $str

       #validate file content.
       Test-Path $ExpectedOutput | Should be $true
    }

    It '<Title>' -TestCases:$testData2 {
       param([string]$Title, $Options, $tmpFileName1, $tmpFilePath1, $tmpFileName2, $tmpFilePath2, $tmpDirectoryName1, $tmpDirectoryPath1, $tmpDirectoryName2, $tmpDirectoryPath2)
       if($skip) { return }

       #rm (remove file)
       $commands = "mkdir $tmpDirectoryPath1
                    put $tmpFilePath1 $tmpDirectoryPath1
                    ls $tmpDirectoryPath1"
       Set-Content $batchFilePath  -Encoding UTF8 -value $commands
       $str = $ExecutionContext.InvokeCommand.ExpandString("sftp -F $ssh_config -P $port $($Options) test_target > $outputFilePath")
       iex $str
       Test-Path (join-path $tmpDirectoryPath1 $tmpFileName1) | Should be $true

       $commands = "rm $tmpDirectoryPath1\*
                    ls $tmpDirectoryPath1
                    pwd
                   "
       Set-Content $batchFilePath  -Encoding UTF8 -value $commands
       $str = $ExecutionContext.InvokeCommand.ExpandString("sftp -F $ssh_config -P $port $($Options) test_target > $outputFilePath")
       iex $str
       Test-Path (join-path $tmpDirectoryPath1 $tmpFileName1) | Should be $false

       #rename file
       Remove-Item $outputFilePath
       Copy-Item $tmpFilePath1 -destination $tmpDirectoryPath1
       $commands = "rename $tmpDirectoryPath1\$tmpFileName1 $tmpDirectoryPath1\$tmpFileName2
                    ls $tmpDirectoryPath1
                    pwd"
       Set-Content $batchFilePath -Encoding UTF8 -value $commands
       $str = $ExecutionContext.InvokeCommand.ExpandString("sftp -F $ssh_config -P $port $($Options) test_target > $outputFilePath")
       iex $str
       Test-Path (join-path $tmpDirectoryPath1 $tmpFileName2) | Should be $true

       #rename directory
       Remove-Item $outputFilePath
       $commands = "rm $tmpDirectoryPath1\*
                    rename $tmpDirectoryPath1 $tmpDirectoryPath2
                    ls $serverDirectory"
       Set-Content $batchFilePath -Encoding UTF8 -value $commands
       $str = $ExecutionContext.InvokeCommand.ExpandString("sftp -F $ssh_config -P $port $($Options) test_target > $outputFilePath")
       iex $str
       Test-Path $tmpDirectoryPath2 | Should be $true

       #rmdir (remove directory)
       Remove-Item $outputFilePath
       $commands = "rmdir $tmpDirectoryPath2
                    ls $serverDirectory"
       Set-Content $batchFilePath -Encoding UTF8 -value $commands
       $str = $ExecutionContext.InvokeCommand.ExpandString("sftp -F $ssh_config -P $port $($Options) test_target > $outputFilePath")
       iex $str
       Test-Path $tmpDirectoryPath2 | Should be $false
    }

    It "$script:testId-ls lists items the user has no read permission" {
       $adminsSid = Get-UserSID -WellKnownSidType ([System.Security.Principal.WellKnownSidType]::BuiltinAdministratorsSid)                        
       $currentUserSid = Get-UserSID -User "$($env:USERDOMAIN)\$($env:USERNAME)"
            
       $permTestHasAccessFile = "permTestHasAccessFile.txt"
       $permTestHasAccessFilePath = Join-Path $serverDirectory $permTestHasAccessFile
       Remove-Item $permTestHasAccessFilePath -Force -ErrorAction SilentlyContinue
       New-Item $permTestHasAccessFilePath -ItemType file -Force -value "perm test has access file data" | Out-Null

       $permTestNoAccessFile = "permTestNoAccessFile.txt"
       $permTestNoAccessFilePath = Join-Path $serverDirectory $permTestNoAccessFile
       Remove-Item $permTestNoAccessFilePath -Force -ErrorAction SilentlyContinue
       New-Item $permTestNoAccessFilePath -ItemType file -Force -value "perm test no access file data" | Out-Null
       Repair-FilePermission -Filepath $permTestNoAccessFilePath -Owners $currentUserSid -FullAccessNeeded $adminsSid,$currentUserSid -confirm:$false

       $Commands = "ls $serverDirectory"
       Set-Content $batchFilePath -Encoding UTF8 -value $Commands
       $str = $ExecutionContext.InvokeCommand.ExpandString("sftp -F $ssh_config -b $batchFilePath test_target > $outputFilePath")
       iex $str
       $content = Get-Content $outputFilePath
       Write-host $content
       #cleanup
       $HasAccessPattern = $permTestHasAccessFilePath.Replace("\", "[/\\]")
       Write-host $content
       $matches = @($content | select-string -Pattern "^/$HasAccessPattern\s{0,}$")
       $matches.count | Should be 1

       $NoAccessPattern = $permTestNoAccessFilePath.Replace("\", "[/\\]")
       $matches = @($content | select-string -Pattern "^/$NoAccessPattern\s{0,}$")
       $matches.count | Should be 1
    }
}
