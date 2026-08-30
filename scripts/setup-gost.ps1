[CmdletBinding()]
param(
    [string]$Policy,
    [switch]$SelfTest
)

$ErrorActionPreference = 'Stop'
$Utf8NoBom = [Text.UTF8Encoding]::new($false)

function Test-Hostname([string]$Hostname) {
    if ($Hostname.Length -gt 253) { return $false }
    foreach ($label in $Hostname.Split('.')) {
        if ($label -notmatch '^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$') { return $false }
    }
    return $true
}

function Read-Policy([string]$Path) {
    $port = $null
    $allow = [Collections.Generic.List[object]]::new()
    $section = ''
    foreach ($rawLine in [IO.File]::ReadAllLines($Path)) {
        $line = $rawLine.Trim()
        if (-not $line -or $line[0] -in '#', ';') { continue }
        if ($line -match '^\[([^\]]+)\]$') { $section = $Matches[1].ToLowerInvariant(); continue }
        $equals = $line.IndexOf('=')
        if ($equals -lt 1) { throw "Invalid policy line: $rawLine" }
        $key = $line.Substring(0, $equals).Trim().ToLowerInvariant()
        $value = $line.Substring($equals + 1).Trim()
        if ($section -eq 'policy' -and $key -eq 'proxy_port') {
            $port = [uint16]$value
        }
        elseif ($section -eq 'allow') {
            if (-not (Test-Hostname $key)) { throw "Invalid allowlist hostname: $key" }
            $allowedPort = [uint16]$value
            if ($allowedPort -notin 80, 443) { throw 'GOST allowlist ports must be 80 or 443' }
            $allow.Add([pscustomobject]@{ Hostname = $key; Port = $allowedPort })
        }
    }
    if (-not $port -or $allow.Count -eq 0) { throw 'Policy is missing proxy_port or allowlist entries' }
    [pscustomobject]@{ Port = $port; Allow = $allow }
}

function Get-GostRoot {
    $scriptRoot = [IO.Path]::GetFullPath((Join-Path $env:ProgramData 'SandboxNetwork'))
    if (-not [string]::Equals([IO.Path]::GetFullPath($PSScriptRoot), $scriptRoot,
            [StringComparison]::OrdinalIgnoreCase)) { throw "Place this script at $scriptRoot" }
    return Join-Path $scriptRoot 'gost'
}

function New-GostConfig($Parsed, [string]$Root) {
    $logPath = (Join-Path $Root 'gost.log').Replace('\', '/')
    $lines = [Collections.Generic.List[string]]::new()
    $lines.Add('services:')
    foreach ($address in @("127.0.0.1:$($Parsed.Port)", "[::1]:$($Parsed.Port)")) {
        $name = if ($address.StartsWith('127.')) { 'sandbox-network-v4' } else { 'sandbox-network-v6' }
        $lines.Add("- name: $name")
        $lines.Add("  addr: `"$address`"")
        $lines.Add('  admission: loopback')
        $lines.Add('  bypass: allowlist')
        $lines.Add('  handler:')
        $lines.Add('    type: http')
        $lines.Add('  listener:')
        $lines.Add('    type: tcp')
    }
    $lines.Add('admissions:')
    $lines.Add('- name: loopback')
    $lines.Add('  whitelist: true')
    $lines.Add('  matchers:')
    $lines.Add('  - 127.0.0.1')
    $lines.Add('  - ::1')
    $lines.Add('bypasses:')
    $lines.Add('- name: allowlist')
    $lines.Add('  whitelist: true')
    $lines.Add('  matchers:')
    foreach ($entry in $Parsed.Allow) { $lines.Add("  - $($entry.Hostname):$($entry.Port)") }
    $lines.Add('log:')
    $lines.Add("  output: `"$logPath`"")
    $lines.Add('  level: info')
    $lines.Add('  format: json')
    $lines.Add('')
    $lines -join "`r`n"
}

function Invoke-Setup([string]$PolicyPath) {
    $root = Get-GostRoot
    $executable = Join-Path $root 'gost.exe'
    if (-not (Test-Path -LiteralPath $executable -PathType Leaf)) { throw "GOST is not installed at $executable" }
    $configPath = Join-Path $root 'gost.yml'
    $temporary = "$configPath.new.yml"
    [IO.File]::WriteAllText($temporary, (New-GostConfig (Read-Policy $PolicyPath) $root), $Utf8NoBom)
    & $executable -C $temporary -O yaml | Out-Null
    if ($LASTEXITCODE -ne 0) { Remove-Item -LiteralPath $temporary -Force; throw 'GOST rejected the generated configuration' }
    Move-Item -LiteralPath $temporary -Destination $configPath -Force
}

function Invoke-SelfTest {
    $directory = Join-Path ([IO.Path]::GetTempPath()) ('setup-gost-' + [guid]::NewGuid().ToString('N'))
    [IO.Directory]::CreateDirectory($directory) | Out-Null
    try {
        $policyPath = Join-Path $directory 'policy.ini'
        [IO.File]::WriteAllText($policyPath, @"
[policy]
proxy_port=8080
[allow]
api.example.com=443
downloads.example.com=80
"@, $Utf8NoBom)
        $config = New-GostConfig (Read-Policy $policyPath) 'C:\ProgramData\SandboxNetwork\gost'
        if (-not $config.Contains('addr: "127.0.0.1:8080"') -or
            -not $config.Contains('addr: "[::1]:8080"') -or
            -not $config.Contains('whitelist: true') -or
            -not $config.Contains('  - api.example.com:443') -or
            -not $config.Contains('  - downloads.example.com:80')) { throw 'GOST setup self-test failed' }
    }
    finally { [IO.Directory]::Delete($directory, $true) }
}

try {
    if ($SelfTest) { Invoke-SelfTest; exit 0 }
    if (-not $Policy) { throw '-Policy is required' }
    Invoke-Setup $Policy
}
catch {
    Write-Error $_.Exception.Message
    exit 1
}
