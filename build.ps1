# Copyright (C) 2026 Florian Mücke
# SPDX-License-Identifier: GPL-3.0-only
# Project: https://github.com/fmuecke/user-net-lock.git


[CmdletBinding()]
param(
    [ValidateSet('Debug', 'Release')]
    [string]$Configuration = 'Release',

    [string]$IntegrationUser,

    [string]$IntegrationOtherUser
)

$ErrorActionPreference = 'Stop'
$projectRoot = $PSScriptRoot

if ($IntegrationUser -or $IntegrationOtherUser) {
    if (-not $IntegrationUser -or -not $IntegrationOtherUser) {
        throw '-IntegrationUser and -IntegrationOtherUser must be supplied together.'
    }
    $env:USER_NET_LOCK_INTEGRATION_USER = $IntegrationUser
    $env:USER_NET_LOCK_INTEGRATION_OTHER_USER = $IntegrationOtherUser
}

$vswhere = Join-Path ${env:ProgramFiles(x86)} 'Microsoft Visual Studio\Installer\vswhere.exe'
if (-not (Test-Path -LiteralPath $vswhere)) {
    throw 'Visual Studio Installer (vswhere.exe) was not found.'
}

$installation = & $vswhere -latest -products * `
    -requires Microsoft.VisualStudio.Component.VC.Tools.x86.x64 `
    -property installationPath
if (-not $installation) {
    throw 'A Visual Studio C++ toolchain was not found.'
}

$devShell = Join-Path $installation 'Common7\Tools\Microsoft.VisualStudio.DevShell.dll'
Import-Module $devShell
Enter-VsDevShell -VsInstallPath $installation -SkipAutomaticLocation -DevCmdArguments '-arch=x64 -host_arch=x64'

# auto-format source files
$nativeSourceRoots = @(
    (Join-Path $projectRoot 'src')
    (Join-Path $projectRoot 'tests')
)
$nativeSourceFiles = @(
    Get-ChildItem `
        -LiteralPath $nativeSourceRoots `
        -Recurse `
        -File |
    Where-Object { $_.Extension -in '.cpp', '.h', '.hpp' } |
    Sort-Object -Property FullName |
    ForEach-Object -MemberName FullName
)
$clangFormat = Get-Command -Name 'clang-format' -CommandType Application -ErrorAction SilentlyContinue
if ($null -eq $clangFormat) {
    Write-Warning 'clang-format was not found on PATH; continuing without formatting native C++ sources.'
}
else {
    Write-Host 'Formatting native C++ sources'
    & $clangFormat.Source -i -- @nativeSourceFiles
    if ($LASTEXITCODE -ne 0) {
        throw "clang-format failed with exit code $LASTEXITCODE."
    }
}

$buildDirectory = Join-Path $PSScriptRoot 'out\build'
cmake -S $PSScriptRoot -B $buildDirectory -G Ninja "-DCMAKE_BUILD_TYPE=$Configuration"
if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }

cmake --build $buildDirectory
if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }

ctest --test-dir $buildDirectory --output-on-failure
exit $LASTEXITCODE
