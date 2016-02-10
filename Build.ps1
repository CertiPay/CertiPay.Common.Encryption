$ErrorActionPreference = "Stop"

$Here = "$(Split-Path -parent $MyInvocation.MyCommand.Definition)"

$SolutionFile = Join-Path $Here "CertiPay.Common.Encryption.sln"

## This comes from the build server iteration
if(!$BuildNumber) { $BuildNumber = $env:APPVEYOR_BUILD_NUMBER }
if(!$BuildNumber) { $BuildNumber = "1"}

## This comes from the Hg commit hash used to build
if(!$CommitHash) { $CommitHash = $env:APPVEYOR_REPO_COMMIT }
if(!$CommitHash) { $CommitHash = "local-build" }

## The build configuration, i.e. Debug/Release
if(!$Configuration) { $Configuration = $env:Configuration }
if(!$Configuration) { $Configuration = "Release" }

if(!$Version) { $Version = $env:APPVEYOR_BUILD_VERSION }
if(!$Version) { $Version = "0.1.$BuildNumber" }

# Bootstap ensures we have what we need to build the project

$MSBuild = "${env:ProgramFiles(x86)}\MSBuild\12.0\Bin\msbuild.exe"

# Build the solution

& $MSBuild $SolutionFile /v:quiet /p:Configuration=$Configuration 

EXIT $LASTEXITCODE