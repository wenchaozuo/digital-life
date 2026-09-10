$ErrorActionPreference = 'Stop'

$repoRoot = Split-Path -Parent $PSScriptRoot
$manifest = Join-Path $repoRoot 'vita-agent/Cargo.toml'
$binary = Join-Path $repoRoot 'vita-agent/target/release/vita-agent.exe'

& cargo build --manifest-path $manifest --release --locked --bin vita-agent
if ($LASTEXITCODE -ne 0) {
    exit $LASTEXITCODE
}

if (-not (Test-Path -LiteralPath $binary -PathType Leaf)) {
    throw "Vita sidecar release image was not produced: $binary"
}

$sourceRoots = @(
    (Join-Path $repoRoot 'vita-agent/src'),
    (Join-Path $repoRoot 'vita-agent/Cargo.toml'),
    (Join-Path $repoRoot 'vita-agent/Cargo.lock'),
    (Join-Path $repoRoot 'vita-agent-protocol/src'),
    (Join-Path $repoRoot 'vita-agent-protocol/Cargo.toml'),
    (Join-Path $repoRoot 'vita-agent-protocol/Cargo.lock')
)
$sourceFiles = foreach ($sourceRoot in $sourceRoots) {
    if (Test-Path -LiteralPath $sourceRoot -PathType Container) {
        Get-ChildItem -LiteralPath $sourceRoot -Recurse -File
    } elseif (Test-Path -LiteralPath $sourceRoot -PathType Leaf) {
        Get-Item -LiteralPath $sourceRoot
    }
}
$latestSource = $sourceFiles |
    Sort-Object LastWriteTimeUtc -Descending |
    Select-Object -First 1
if ($null -ne $latestSource -and (Get-Item -LiteralPath $binary).LastWriteTimeUtc -lt $latestSource.LastWriteTimeUtc) {
    throw "Vita sidecar release image is stale relative to $($latestSource.FullName)"
}

Write-Host "Vita sidecar staged: $binary"
