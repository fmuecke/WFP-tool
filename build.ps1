# Copyright (C) 2026 Florian Mücke
# SPDX-License-Identifier: GPL-3.0-only
# Project: https://github.com/fmuecke/WFP-tool.git


[CmdletBinding()]
param(
    [ValidateSet('Debug', 'Release')]
    [string]$Configuration = 'Release',

    [string]$IntegrationUser,

    [string]$IntegrationOtherUser
)

$ErrorActionPreference = 'Stop'

if ($IntegrationUser -or $IntegrationOtherUser) {
    if (-not $IntegrationUser -or -not $IntegrationOtherUser) {
        throw '-IntegrationUser and -IntegrationOtherUser must be supplied together.'
    }
    $env:WFP_TOOL_INTEGRATION_USER = $IntegrationUser
    $env:WFP_TOOL_INTEGRATION_OTHER_USER = $IntegrationOtherUser
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

$buildDirectory = Join-Path $PSScriptRoot 'out\build'
cmake -S $PSScriptRoot -B $buildDirectory -G Ninja "-DCMAKE_BUILD_TYPE=$Configuration"
if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }

cmake --build $buildDirectory
if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }

ctest --test-dir $buildDirectory --output-on-failure
exit $LASTEXITCODE
