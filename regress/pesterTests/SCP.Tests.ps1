If ($PSVersiontable.PSVersion.Major -le 2) {$PSScriptRoot = Split-Path -Parent $MyInvocation.MyCommand.Path}
#covered -i -p -q -r -v -c -S -C
#todo: -F, -l and -P should be tested over the network
$tI = 0
$suite = "SCP"
$testDir = "$env:temp\$suite"
. $PSScriptRoot\common.ps1 -suite $suite -TestDir $testDir
Describe "Tests for scp command" -Tags "CI" {
    BeforeAll {
        $port = 47002
        $server = "localhost"
        $ssh_config_file = "$testDir\ssh_config"
        
        #other default vars: -TargetName "test_target" -host_key_type "ed25519" -user_key_type "ed25519" -user_key_file "$testDir\user_key_$user_key_type" -known_host_file "$testDir\known_hosts"
        Set-TestCommons -port $port -Server $server -ssh_config_file $ssh_config_file

        $fileName1 = "test.txt"
        $fileName2 = "test2.txt"
        $fileName3 = "test3.txt"
        $wildcardFileName1 = "te?t.txt"
        $wildcardFileName2 = "test*"
        $SourceDirName = "SourceDir"
        $SourceDir = Join-Path $testDir $SourceDirName
        $SourceFilePath = Join-Path $SourceDir $fileName1
        $SourceFilePath3 = Join-Path $SourceDir $fileName3
        $SourceFileWildCardFile1 = Join-Path $SourceDir $wildcardFileName1
        $DestinationDir = Join-Path "$testDir" "DestDir"
        $DestinationDirWildcardPath = Join-Path "$testDir" "DestD?r"
        $DestinationFilePath = Join-Path $DestinationDir $fileName1        
        $NestedSourceDir= Join-Path $SourceDir "nested"
        $NestedSourceFilePath = Join-Path $NestedSourceDir $fileName2
        New-Item $SourceDir -ItemType directory -Force -ErrorAction SilentlyContinue | Out-Null
        New-Item $NestedSourceDir -ItemType directory -Force -ErrorAction SilentlyContinue | Out-Null
        New-item -path $SourceFilePath -ItemType file -force -ErrorAction SilentlyContinue | Out-Null
        New-item -path $NestedSourceFilePath -ItemType file -force -ErrorAction SilentlyContinue | Out-Null
        "Test content111" | Set-content -Path $SourceFilePath
        "Test content333" | Set-content -Path $SourceFilePath3
        "Test content in nested dir" | Set-content -Path $NestedSourceFilePath
        New-Item $DestinationDir -ItemType directory -Force -ErrorAction SilentlyContinue | Out-Null
        $sshcmd = (get-command ssh).Path

        $testData = @(
            @{
                Title = 'Simple copy local file to local file'
                Source = $SourceFilePath                   
                Destination = $DestinationFilePath
            },
            @{
                Title = 'Simple copy local file to remote file'
                Source = $SourceFilePath
                Destination = "test_target:$DestinationFilePath"
                Options = "-S `"$sshcmd`" -F $ssh_config_file"
            },
            @{
                Title = 'Simple copy remote file to local file'
                Source = "test_target:$SourceFilePath"
                Destination = $DestinationFilePath
                Options = "-p -c aes128-ctr -C -F $ssh_config_file"
            },            
            @{
                Title = 'Simple copy local file to local dir'
                Source = $SourceFilePath
                Destination = $DestinationDir
            },
            @{
                Title = 'simple copy local file to remote dir'         
                Source = $SourceFilePath
                Destination = "test_target:$DestinationDir"
                Options = "-C -q -F $ssh_config_file"
            },
            @{
                Title = 'simple copy remote file to local dir'
                Source = "test_target:$SourceFilePath"
                Destination = $DestinationDir
                Options = "-F $ssh_config_file"
            },
            @{
                Title = 'Simple copy local file with wild card name to local dir'
                Source = $SourceFileWildCardFile1
                Destination = $DestinationDir
            },
            @{
                Title = 'simple copy remote file with wild card name to local dir'
                Source = "test_target:$SourceFileWildCardFile1"
                Destination = $DestinationDir
                Options = "-F $ssh_config_file"
            },
            @{
                Title = 'simple copy local file to remote dir with wild card name'         
                Source = $SourceFilePath
                Destination = "test_target:$DestinationFilePath"
                Options = "-C -q -F $ssh_config_file"
            }
        )

        $testData1 = @(
            @{
                Title = 'copy from local dir to remote dir'
                Source = $sourceDir
                Destination = "test_target:$DestinationDir"
                Options = "-r -p -c aes128-ctr -F $ssh_config_file"
            },
            @{
                Title = 'copy from local dir to local dir'
                Source = $sourceDir
                Destination = $DestinationDir
                Options = "-r "
            },
            @{
                Title = 'copy from remote dir to local dir'            
                Source = "test_target:$sourceDir"
                Destination = $DestinationDir
                Options = "-C -r -q -F $ssh_config_file"
            }
        )
    }
    AfterAll {
        if((-not [string]::IsNullOrEmpty($SourceDir)) -and (Test-Path $SourceDir -PathType Container))
        {
            Get-Item $SourceDir | Remove-Item -Recurse -Force -ErrorAction SilentlyContinue
        }
        if(-not [string]::IsNullOrEmpty($DestinationDir)-and (Test-Path $DestinationDir -PathType Container))
        {
            Get-Item $DestinationDir | Remove-Item -Recurse -Force -ErrorAction SilentlyContinue
        }
    }

    BeforeAll {
        New-Item $DestinationDir -ItemType directory -Force -ErrorAction SilentlyContinue | Out-Null
    }

    AfterEach {
        Get-ChildItem $DestinationDir -Recurse | Remove-Item -Recurse -Force -ErrorAction SilentlyContinue | Out-Null
        Start-Sleep 1
        $tI++
    }       
    

    It 'File copy: <Title> ' -TestCases:$testData {
        param([string]$Title, $Source, $Destination, [string]$Options)
            
        iex  "scp $Options $Source $Destination"
        $LASTEXITCODE | Should Be 0
        #validate file content. DestPath is the path to the file.
        Test-Path $DestinationFilePath -PathType leaf | Should -Be $true

        $equal = @(Compare-Object (Get-ChildItem -path $SourceFilePath) (Get-ChildItem -path $DestinationFilePath) -Property Name, Length ).Length -eq 0
        $equal | Should Be $true

        if($Options.contains("-p "))
        {
            $equal = @(Compare-Object (Get-ChildItem -path $SourceFilePath).LastWriteTime.DateTime (Get-ChildItem -path $DestinationFilePath).LastWriteTime.DateTime ).Length -eq 0
            $equal | Should Be $true
        }
    }
                
    It 'Directory recursive copy: <Title> ' -TestCases:$testData1 {
        param([string]$Title, $Source, $Destination, [string]$Options)                        
            
        iex  "scp $Options $Source $Destination"
        $LASTEXITCODE | Should Be 0
        Test-Path (join-path $DestinationDir $SourceDirName) -PathType Container | Should -Be $true

        $equal = @(Compare-Object (Get-Item -path $SourceDir ) (Get-Item -path (join-path $DestinationDir $SourceDirName) ) -Property Name, Length).Length -eq 0        
        $equal | Should Be $true

        if($Options.contains("-p "))
        {
            $equal = @(Compare-Object (Get-Item -path $SourceDir).LastWriteTime.DateTime (Get-Item -path (join-path $DestinationDir $SourceDirName)).LastWriteTime.DateTime).Length -eq 0            
            $equal | Should Be $true
        }

        $equal = @(Compare-Object (Get-ChildItem -Recurse -path $SourceDir) (Get-ChildItem -Recurse -path (join-path $DestinationDir $SourceDirName) ) -Property Name, Length).Length -eq 0
        $equal | Should Be $true

        if($Options.contains("-p ") -and ($PSVersionTable.PSVersion.Major -gt 2))
        {
            $equal = @(Compare-Object (Get-ChildItem -Recurse -path $SourceDir).LastWriteTime.DateTime (Get-ChildItem -Recurse -path (join-path $DestinationDir $SourceDirName) ).LastWriteTime.DateTime).Length -eq 0            
            $equal | Should Be $true
        }
    }

    It 'File copy: path contains wildcards ' {
        $Source = Join-Path $SourceDir $wildcardFileName2
        scp -p $Source $DestinationDir
        $LASTEXITCODE | Should Be 0
        #validate file content. DestPath is the path to the file.
        Test-Path $DestinationFilePath -PathType Leaf| Should -Be $true
        Test-Path (Join-path $DestinationDir $fileName3) -pathType leaf | Should -Be $true

        $equal = @(Compare-Object (Get-ChildItem -path $Source) (Get-ChildItem -path (join-path $DestinationDir $wildcardFileName2)) -Property Name, Length ).Length -eq 0
        $equal | Should Be $true
        
        $equal = @(Compare-Object (Get-ChildItem -path $Source).LastWriteTime.DateTime (Get-ChildItem -path (join-path $DestinationDir $wildcardFileName2)).LastWriteTime.DateTime ).Length -eq 0
        $equal | Should Be $true        
    }
}   
