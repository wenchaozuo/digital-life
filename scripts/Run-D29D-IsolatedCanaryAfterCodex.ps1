#requires -Version 5.1

<#
.SYNOPSIS
    Waits for Codex writers to exit, then runs the D29-D isolated global canary.

.DESCRIPTION
    This is a one-shot operator helper. Start it from an independent PowerShell
    window while Codex is still open, then close Codex. The helper waits until
    the Codex process tree has been absent for a stable interval before it runs
    the existing ignored Rust canary test.

    The helper does not read Codex configuration contents and does not create,
    repair, migrate, delete, move, or overwrite anything under the user's
    .codex directory. The Rust test fingerprints only the three canary files
    immediately before and after the official smoke.

    Do not start this script from a Codex terminal. Use a separate PowerShell
    window, because the script deliberately refuses to run inside a Codex
    process tree.

.EXAMPLE
    powershell.exe -NoProfile -ExecutionPolicy Bypass -File .\scripts\Run-D29D-IsolatedCanaryAfterCodex.ps1

.EXAMPLE
    powershell.exe -NoProfile -ExecutionPolicy Bypass -File .\scripts\Run-D29D-IsolatedCanaryAfterCodex.ps1 -StableSeconds 15
#>

[CmdletBinding()]
param(
    [Parameter()]
    [string] $RepoRoot = '',

    [Parameter()]
    [string] $OfficialFixture = 'C:\Users\zuo\AppData\Local\Temp\digital-life-d29-d-official\codex-app-server-x86_64-pc-windows-msvc.exe',

    [Parameter()]
    [string] $CargoPath = '',

    [Parameter()]
    [ValidateRange(1, 60)]
    [int] $PollSeconds = 2,

    [Parameter()]
    [ValidateRange(1, 300)]
    [int] $StableSeconds = 10,

    [Parameter()]
    [ValidateRange(1, 1440)]
    [int] $TimeoutMinutes = 120,

    [Parameter()]
    [switch] $AllowAlreadyClosed
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$ExpectedFixtureSize = [uint64] 227369264
$ExpectedFixtureSha256 = 'cb8e6cd9996b0647ccecd37d324438c8625738deca754faa74d98e4d7398a98c'
$CanaryTestFilter = 'execution_enclave::tests::official_smoke_preserves_user_codex_global_canary'
$ToolchainBin = 'C:\Users\zuo\.rustup\toolchains\stable-x86_64-pc-windows-msvc\bin'

function Write-Status {
    param([Parameter(Mandatory = $true)][string] $Message)

    Write-Host ('[{0}] {1}' -f (Get-Date -Format 'yyyy-MM-dd HH:mm:ss'), $Message)
}

function Get-ProcessInventory {
    try {
        # Deliberately request metadata only. In particular, do not request or
        # print CommandLine, which could contain prompts, tokens, or paths.
        @(Get-CimInstance -ClassName Win32_Process -Property ProcessId, Name, ExecutablePath, ParentProcessId -ErrorAction Stop |
                ForEach-Object {
                    [PSCustomObject] @{
                        Id = [int] $_.ProcessId
                        Name = [string] $_.Name
                        Path = if ($null -eq $_.ExecutablePath) { '' } else { [string] $_.ExecutablePath }
                        ParentId = [int] $_.ParentProcessId
                    }
                })
    }
    catch {
        throw ('Cannot enumerate process metadata safely; refusing to run the canary: {0}' -f $_.Exception.Message)
    }
}

function Test-CodexRootProcess {
    param([Parameter(Mandatory = $true)] $Process)

    $name = ([IO.Path]::GetFileNameWithoutExtension($Process.Name)).ToLowerInvariant()
    $path = ([string] $Process.Path).Replace('/', '\').ToLowerInvariant()

    # Known Codex executable names include the desktop's CLI/host/runner and
    # the official app-server fixture. The path rules also cover child runtime
    # and plugin processes whose executable name is node, pwsh, or extension-host.
    if ($name -match '^codex(?:-|$)') {
        return $true
    }
    if ($path -match '\\appdata\\local\\openai\\codex\\') {
        return $true
    }
    if ($path -match '\\appdata\\local\\openai\.codex_') {
        return $true
    }
    if ($path -match '\\\.codex\\') {
        return $true
    }
    if ($path -match '\\\.cache\\codex-runtimes\\') {
        return $true
    }

    return ($name -eq 'chatgpt' -and $path -match '\\windowsapps\\openai\.codex_')
}

function Get-CodexWriterProcesses {
    $inventory = @(Get-ProcessInventory)
    $byId = @{}
    foreach ($process in $inventory) {
        $byId[$process.Id] = $process
    }

    $roots = @($inventory | Where-Object { Test-CodexRootProcess $_ })
    $writerIds = [System.Collections.Generic.HashSet[int]]::new()
    $queue = [System.Collections.Generic.Queue[int]]::new()

    foreach ($root in $roots) {
        if ($writerIds.Add($root.Id)) {
            $queue.Enqueue($root.Id)
        }
    }

    # Include descendants so a shell/runtime child with a generic process name
    # cannot be mistaken for a closed Codex writer.
    while ($queue.Count -gt 0) {
        $parentId = $queue.Dequeue()
        foreach ($child in $inventory | Where-Object { $_.ParentId -eq $parentId }) {
            if ($writerIds.Add($child.Id)) {
                $queue.Enqueue($child.Id)
            }
        }
    }

    if ($writerIds.Contains($PID)) {
        throw 'This watcher is running inside the Codex process tree. Start it from an independent PowerShell window.'
    }

    @($writerIds | ForEach-Object { $byId[[int] $_] } | Sort-Object Name, Id)
}

function Resolve-CargoExecutable {
    if (-not [string]::IsNullOrWhiteSpace($CargoPath)) {
        $resolved = (Resolve-Path -LiteralPath $CargoPath -ErrorAction Stop).Path
        if (-not (Test-Path -LiteralPath $resolved -PathType Leaf)) {
            throw "Cargo executable is not a file: $resolved"
        }
        return $resolved
    }

    $toolchainCargo = Join-Path $ToolchainBin 'cargo.exe'
    if (Test-Path -LiteralPath $toolchainCargo -PathType Leaf) {
        return (Resolve-Path -LiteralPath $toolchainCargo).Path
    }

    $pathCargo = Get-Command cargo.exe -ErrorAction SilentlyContinue
    if ($null -ne $pathCargo) {
        return $pathCargo.Source
    }

    throw "cargo.exe was not found. Pass -CargoPath explicitly or install the stable Rust toolchain."
}

function Assert-OfficialFixture {
    $resolved = (Resolve-Path -LiteralPath $OfficialFixture -ErrorAction Stop).Path
    $item = Get-Item -LiteralPath $resolved -Force -ErrorAction Stop
    if ($item.PSIsContainer) {
        throw "Official fixture is a directory: $resolved"
    }
    if ([uint64] $item.Length -ne $ExpectedFixtureSize) {
        throw "Official fixture size mismatch: expected $ExpectedFixtureSize, got $($item.Length)"
    }

    Write-Status "Verifying the pinned official fixture hash (metadata/content read only; no writes): $resolved"
    $actualSha256 = (Get-FileHash -LiteralPath $resolved -Algorithm SHA256 -ErrorAction Stop).Hash.ToLowerInvariant()
    if ($actualSha256 -ne $ExpectedFixtureSha256) {
        throw "Official fixture SHA-256 mismatch: expected $ExpectedFixtureSha256, got $actualSha256"
    }

    return $resolved
}

function Format-WriterSummary {
    param([Parameter(Mandatory = $true)][array] $Processes)

    if ($Processes.Count -eq 0) {
        return 'none'
    }

    return (($Processes | ForEach-Object { '{0} (PID {1})' -f $_.Name, $_.Id }) -join ', ')
}

$originalLocation = Get-Location
$originalEnvironment = @{}
$environmentNames = @(
    'DIGITAL_LIFE_D29_C_OFFICIAL_APP_SERVER_FIXTURE',
    'DIGITAL_LIFE_D29_D_CANARY_PROCESSES_CLOSED',
    'RUSTC',
    'CARGO_TERM_COLOR',
    'Path'
)
foreach ($name in $environmentNames) {
    $originalEnvironment[$name] = [Environment]::GetEnvironmentVariable($name, 'Process')
}

$exitCode = 1
$locationChanged = $false

try {
    if ([string]::IsNullOrWhiteSpace($RepoRoot)) {
        $RepoRoot = Split-Path -Parent $PSScriptRoot
    }
    $resolvedRepoRoot = (Resolve-Path -LiteralPath $RepoRoot -ErrorAction Stop).Path
    $manifestPath = Join-Path $resolvedRepoRoot 'src-tauri\Cargo.toml'
    $srcTauriRoot = Join-Path $resolvedRepoRoot 'src-tauri'
    if (-not (Test-Path -LiteralPath $manifestPath -PathType Leaf)) {
        throw "Repository manifest was not found: $manifestPath"
    }

    $fixturePath = Assert-OfficialFixture
    $cargo = Resolve-CargoExecutable
    $rustc = Join-Path (Split-Path -Parent $cargo) 'rustc.exe'
    if (-not (Test-Path -LiteralPath $rustc -PathType Leaf)) {
        throw "The rustc.exe next to cargo.exe was not found: $rustc"
    }

    Write-Status 'Watching Codex process metadata. Close Codex Desktop and any Codex CLI/IDE/runner windows now.'
    Write-Status 'No Codex process will be terminated by this helper.'

    $deadline = (Get-Date).AddMinutes($TimeoutMinutes)
    $seenWriter = $false
    $emptySince = $null
    $lastSummary = $null

    while ($true) {
        $writers = @(Get-CodexWriterProcesses)
        if ($writers.Count -gt 0) {
            $seenWriter = $true
            $emptySince = $null
            $summary = Format-WriterSummary $writers
            if ($summary -ne $lastSummary) {
                Write-Status "Codex writers still present: $summary"
                $lastSummary = $summary
            }
        }
        elseif (-not $seenWriter -and -not $AllowAlreadyClosed) {
            if ($lastSummary -ne 'not-seen') {
                Write-Status 'No Codex writer is visible yet. Waiting for one to be observed before accepting a close event.'
                $lastSummary = 'not-seen'
            }
        }
        else {
            if ($null -eq $emptySince) {
                $emptySince = Get-Date
                Write-Status "No Codex writers detected; requiring $StableSeconds seconds of stability before launch."
            }
            $emptyFor = ((Get-Date) - $emptySince).TotalSeconds
            if ($emptyFor -ge $StableSeconds) {
                break
            }
        }

        if ((Get-Date) -ge $deadline) {
            throw "Timed out after $TimeoutMinutes minute(s) while waiting for Codex writers to close."
        }
        Start-Sleep -Seconds $PollSeconds
    }

    # The stable interval above is only a gate; perform one final fail-closed
    # enumeration immediately before the test process is created.
    $finalWriters = @(Get-CodexWriterProcesses)
    if ($finalWriters.Count -ne 0) {
        throw "A Codex writer reappeared before launch: $(Format-WriterSummary $finalWriters)"
    }

    $env:DIGITAL_LIFE_D29_C_OFFICIAL_APP_SERVER_FIXTURE = $fixturePath
    $env:DIGITAL_LIFE_D29_D_CANARY_PROCESSES_CLOSED = '1'
    $env:RUSTC = $rustc
    $env:CARGO_TERM_COLOR = 'never'
    if ([string]::IsNullOrWhiteSpace($originalEnvironment['Path'])) {
        $env:Path = Split-Path -Parent $cargo
    }
    else {
        $env:Path = "$(Split-Path -Parent $cargo);$($originalEnvironment['Path'])"
    }

    Push-Location -LiteralPath $srcTauriRoot
    $locationChanged = $true
    Write-Status "Starting the exact ignored canary: $CanaryTestFilter"
    Write-Status 'The test will fingerprint only the three user Codex files before and after the official smoke.'

    & $cargo test --locked --offline --lib $CanaryTestFilter -- --ignored --exact --nocapture
    $exitCode = [int] $LASTEXITCODE
    if ($exitCode -eq 0) {
        Write-Status 'D29-D isolated global canary: PASS'
    }
    else {
        Write-Status "D29-D isolated global canary: FAIL (cargo exit code $exitCode)"
    }
}
catch {
    Write-Error $_.Exception.Message
    $exitCode = 1
}
finally {
    if ($locationChanged) {
        Set-Location -LiteralPath $originalLocation
    }

    foreach ($name in $environmentNames) {
        $value = $originalEnvironment[$name]
        if ($null -eq $value) {
            Remove-Item -LiteralPath "Env:$name" -ErrorAction SilentlyContinue
        }
        else {
            Set-Item -LiteralPath "Env:$name" -Value $value
        }
    }
}

exit $exitCode
