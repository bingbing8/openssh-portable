$ErrorActionPreference = 'Stop'
Set-StrictMode -Version 2.0
If ($PSVersiontable.PSVersion.Major -le 2) {$PSScriptRoot = Split-Path -Parent $MyInvocation.MyCommand.Path}
Import-Module $PSScriptRoot\OpenSSHBuildHelper.psm1 -Force

$script:messageFile = join-path $env:temp "BuildMessage.log"
$Script:TestResultsDir = "$env:temp\OpenSSHTestResults\"
$Script:E2EResult = "$Script:TestResultsDir\E2Eresult.xml"
$Script:UnitTestResult = "$Script:TestResultsDir\UnittestTestResult.txt"

# Write the build message
Function Write-BuildMessage
{
    param(
        [Parameter(Mandatory=$true)]
        [ValidateNotNullOrEmpty()]
        [string] $Message,
        $Category,
        [string]$Details)

    if($env:AppVeyor)
    {
        Add-AppveyorMessage @PSBoundParameters
    }

    # write it to the log file, if present.
    if (-not ([string]::IsNullOrEmpty($script:messageFile)))
    {
        Add-Content -Path $script:messageFile -Value "$Category--$Message"
    }
}

# Sets a build variable
Function Set-BuildVariable
{
    param(
        [Parameter(Mandatory=$true)]
        [string]
        $Name,

        [Parameter(Mandatory=$true)]
        [string]
        $Value
    )

    if($env:AppVeyor -and (Get-Command Set-AppveyorBuildVariable -ErrorAction Ignore) -ne $null)
    {
        Set-AppveyorBuildVariable @PSBoundParameters
    }
    elseif($env:AppVeyor)
    {
        appveyor SetVariable -Name $Name -Value $Value
    } 
    else
    {
        Set-Item env:$Name -Value $Value
    }
}

# Emulates running all of AppVeyor but locally
# should not be used on AppVeyor
function Invoke-AppVeyorFull
{
    param(
        [switch] $APPVEYOR_SCHEDULED_BUILD,
        [switch] $CleanRepo
    )
    if($CleanRepo)
    {
        Clear-PSRepo
    }

    if($env:APPVEYOR)
    {
        throw "This function is to simulate appveyor, but not to be run from appveyor!"
    }

    if($APPVEYOR_SCHEDULED_BUILD)
    {
        $env:APPVEYOR_SCHEDULED_BUILD = 'True'
    }
    try {
        Invoke-AppVeyorBuild
        Install-OpenSSH
        Invoke-OpenSSHTests
        Publish-Artifact
    }
    finally {
        if($APPVEYOR_SCHEDULED_BUILD -and $env:APPVEYOR_SCHEDULED_BUILD)
        {
            Remove-Item env:APPVEYOR_SCHEDULED_BUILD
        }
    }
}

# Implements the AppVeyor 'build_script' step
function Invoke-AppVeyorBuild
{
      Set-BuildVariable TestPassed True
      Start-OpenSSHBuild -Configuration Release -NativeHostArch x64
      Start-OpenSSHBuild -Configuration Release -NativeHostArch x86
      Write-BuildMessage -Message "OpenSSH binaries build success!" -Category Information
}

<#
    .Synopsis
    Adds a build log to the list of published artifacts.
    .Description
    If a build log exists, it is renamed to reflect the associated CLR runtime then added to the list of
    artifacts to publish.  If it doesn't exist, a warning is written and the file is skipped.
    The rename is needed since publishing overwrites the artifact if it already exists.
    .Parameter artifacts
    An array list to add the fully qualified build log path
    .Parameter buildLog
    The build log file produced by the build.    
#>
function Add-BuildLog
{
    param
    (
        [ValidateNotNull()]
        [System.Collections.ArrayList] $artifacts,

        [Parameter(Mandatory=$true)]
        [ValidateNotNullOrEmpty()]
        [string] $buildLog
    )

    if (Test-Path -Path $buildLog)
    {   
        $null = $artifacts.Add($buildLog)
    }
    else
    {
        Write-Warning "Skip publishing build log. $buildLog does not exist"
    }
}

function Install-Pester
{
	Write-BuildMessage -Message "install pester"
	# Install chocolatey
    if(-not (Get-Command "choco" -ErrorAction SilentlyContinue))
    {
        Invoke-Expression ((new-object net.webclient).DownloadString('https://chocolatey.org/install.ps1'))
    }

    $isModuleAvailable = Get-Module 'Pester' -ListAvailable
    if (-not ($isModuleAvailable))
    {
        Write-BuildMessage -Message "Installing Pester..." -Category Information
        choco install Pester -y --force 
        Get-Module pester -ListAvailable -ErrorAction Ignore
    }
}

<#
    .Synopsis
    Publishes package build artifacts.
    .Parameter artifacts
    An array list to add the fully qualified build log path
    .Parameter FileToAdd
    Path to the file
#>
function Add-Artifact
{
    param
    (
        [ValidateNotNull()]
        [System.Collections.ArrayList] $artifacts,
        [string] $FileToAdd
    )
    
    if ([string]::IsNullOrEmpty($FileToAdd) -or (-not (Test-Path $FileToAdd -PathType Leaf)) )
    {            
        Write-Host "Skip publishing package artifacts. $FileToAdd does not exist"
    }
    else
    {
        $null = $artifacts.Add($FileToAdd)
    }
}

<#
    .Synopsis
    After build and test run completes, upload all artifacts from the build machine.
#>
function Publish-Artifact
{
    Write-Host -ForegroundColor Yellow "Publishing project artifacts"
    [System.Collections.ArrayList] $artifacts = new-object System.Collections.ArrayList

    # Get the build.log file for each build configuration        
    Add-BuildLog -artifacts $artifacts -buildLog (Get-BuildLogFile -root $env:APPVEYOR_BUILD_FOLDER -Configuration Release -NativeHostArch x64)
    Add-BuildLog -artifacts $artifacts -buildLog (Get-BuildLogFile -root $env:APPVEYOR_BUILD_FOLDER -Configuration Release -NativeHostArch x86)

    Add-Artifact -artifacts $artifacts -FileToAdd $Script:E2EResult
    Add-Artifact -artifacts $artifacts -FileToAdd $Script:UnitTestResult

    foreach ($artifact in $artifacts)
    {
        Write-Host "Publishing $artifact as Appveyor artifact"
        Push-AppveyorArtifact $artifact -ErrorAction Continue
    }
}

<#
      .Synopsis
      Runs the tests for this repo
#>
function Invoke-OpenSSHTests
{
    if(-not (Test-Path $Script:TestResultsDir -PathType Container)) {
        New-Item $Script:TestResultsDir -ItemType Directory -Force -ErrorAction SilentlyContinue| Out-Null
    }
    Invoke-OpenSSHUnitTests
    Invoke-OpenSSHE2ETests
}

<#
      .Synopsis
      Runs E2E pester tests for this repo
#>
function Invoke-OpenSSHE2ETests
{
    Get-Module pester -ListAvailable -ErrorAction Ignore
    Import-Module pester -force -global
    Write-BuildMessage -Message "Running OpenSSH tests..." -Category Information
    Push-Location "$env:APPVEYOR_BUILD_FOLDER\regress\pesterTests"
    #only ssh tests for now
    $testFolders = @(Get-ChildItem *.tests.ps1 -Recurse | ForEach-Object{ Split-Path $_.FullName} | Sort-Object -Unique)

    Invoke-Pester $testFolders -OutputFormat NUnitXml -OutputFile $Script:E2EResult -Tag 'CI' -PassThru
    Pop-Location

    $xml = [xml](Get-Content $Script:E2EResult | out-string)
    if ([int]$xml.'test-results'.failures -gt 0) 
    {
        $errorMessage = "$($xml.'test-results'.failures) setup tests in regress\pesterTests failed. Detail test log is at $Script:E2EResult."
        Write-BuildMessage -Message $errorMessage -Category Error
        Set-BuildVariable TestPassed False
        return
    }

    # Writing out warning when the $Error.Count is non-zero. Tests Should clean $Error after success.
    if ($Error.Count -gt 0) 
    {
        Write-BuildMessage -Message "Tests Should clean $Error after success." -Category Warning
    }
}

<#
    .Synopsis
    Get-UnitTestDirectory.
#>
function Get-UnitTestDirectory
{
    [CmdletBinding()]
    param
    (
        [ValidateSet('Debug', 'Release')]
        [string]$Configuration = "Release"
    )

    [string] $NativeHostArch = $env:PROCESSOR_ARCHITECTURE
    if($NativeHostArch -eq 'x86')
    {
        $NativeHostArch = "Win32"
    }
    else
    {
        $NativeHostArch = "x64"
    }
    
    $unitTestdir = (Resolve-Path "$psscriptroot\..\..\..\bin\$NativeHostArch\$Configuration").Path
    $unitTestDir
}

function Invoke-OpenSSHUnitTests
{
    $bindir = Get-UnitTestDirectory
    if(-not $env:path.tolower().startswith($bindir.tolower())){
        $env:path = "$bindir;$env:path"
    }

    Push-Location $bindir
    Write-BuildMessage -Message "Running OpenSSH unit tests..." -Category Information
    if (Test-Path $Script:UnitTestResult)
    {
        Remove-Item -Path $Script:UnitTestResult -Force -ErrorAction SilentlyContinue | Out-Null
    }
    $testFolders = Get-ChildItem -filter unittest-*.exe -Recurse |
                 ForEach-Object{ Split-Path $_.FullName} |
                 Sort-Object -Unique

    if ($testFolders -ne $null)
    {
        $testFolders | % {
            $unittestFile = "$(Split-Path $_ -Leaf).exe"
            $unittestFilePath = join-path $_ $unittestFile
            if(Test-Path $unittestFilePath -pathtype leaf)
            {                
                $pinfo = New-Object System.Diagnostics.ProcessStartInfo
                $pinfo.FileName = "$unittestFilePath"
                $pinfo.RedirectStandardError = $true
                $pinfo.RedirectStandardOutput = $true
                $pinfo.UseShellExecute = $false
                $pinfo.WorkingDirectory = "$_"
                $p = New-Object System.Diagnostics.Process
                $p.StartInfo = $pinfo
                $p.Start() | Out-Null
                $stdout = $p.StandardOutput.ReadToEnd()
                $stderr = $p.StandardError.ReadToEnd()
                $p.WaitForExit()
                $errorCode = $p.ExitCode
                Write-Host "Running unit test: $unittestFile ..."
                if(-not [String]::IsNullOrWhiteSpace($stdout))
                {
                    Add-Content $Script:UnitTestResult $stdout -Force -ErrorAction Ignore
                }
                if(-not [String]::IsNullOrWhiteSpace($stderr))
                {
                    Add-Content $Script:UnitTestResult $stderr -Force -ErrorAction Ignore
                }
                if ($errorCode -ne 0)
                {
                    $errorMessage = "$unittestFile failed.`nExitCode: $errorCode."
                    Write-BuildMessage -Message $errorMessage -Category Error
                    Write-Host $errorMessage
                    Set-BuildVariable TestPassed False                   
                }
                else
                {
                    Write-Host "$unittestFile passed!"
                }
            }
        }
    }
    Pop-Location
}

<#
      .Synopsis
      upload OpenSSH pester test results.
#>
function Publish-OpenSSHTestResults
{
	Write-BuildMessage -Message "Publishing OpenSSHTestResults" -Category Information
    if ($env:APPVEYOR_JOB_ID)
    {
        $E2EresultFile = Resolve-Path $Script:E2EResult -ErrorAction Ignore
        if( (Test-Path $Script:E2EResult) -and $E2EresultFile)
        {
            (New-Object 'System.Net.WebClient').UploadFile("https://ci.appveyor.com/api/testresults/nunit/$($env:APPVEYOR_JOB_ID)", $E2EresultFile)
             Write-BuildMessage -Message "E2E test results uploaded!" -Category Information
        }
    }

    if($env:TestPassed -ieq 'True')
    {
        Write-BuildMessage -Message "The checkin validation success!" -Category Information
    }
    else
    {
        Write-BuildMessage -Message "The checkin validation failed!" -Category Error
        throw "The checkin validation failed!"
    }
}
