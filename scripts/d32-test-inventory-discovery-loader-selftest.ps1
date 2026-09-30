#Requires -Version 7.5
[CmdletBinding()]
param()

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$scriptRoot = [IO.Path]::GetFullPath($PSScriptRoot)
$repository = [IO.Path]::GetFullPath((Split-Path -Parent $scriptRoot))
$discoveryScript = [IO.Path]::GetFullPath((Join-Path $scriptRoot 'd32-test-inventory-discovery.ps1'))
$baselineScript = [IO.Path]::GetFullPath((Join-Path $scriptRoot 'd32-test-inventory-baseline.ps1'))
$pwshImage = [IO.Path]::GetFullPath((Join-Path $PSHOME 'pwsh.exe'))
foreach ($path in @($discoveryScript, $baselineScript, $pwshImage)) {
    if (-not (Test-Path -LiteralPath $path -PathType Leaf)) { throw "SELFTEST_BLOCKED: required PowerShell discovery loader image is missing: $path" }
}

function Invoke-D32DiscoveryLoaderChild {
    param(
        [Parameter(Mandatory = $true)][string]$RunnerScript,
        [Parameter(Mandatory = $true)][string[]]$Arguments
    )

    $startInfo = [Diagnostics.ProcessStartInfo]::new()
    $startInfo.FileName = $pwshImage
    $startInfo.WorkingDirectory = $repository
    $startInfo.UseShellExecute = $false
    $startInfo.CreateNoWindow = $true
    $startInfo.RedirectStandardOutput = $true
    $startInfo.RedirectStandardError = $true
    foreach ($argument in @('-NoLogo', '-NoProfile', '-NonInteractive', '-File', $RunnerScript) + $Arguments) {
        [void]$startInfo.ArgumentList.Add([string]$argument)
    }

    $process = [Diagnostics.Process]::new()
    try {
        $process.StartInfo = $startInfo
        if (-not $process.Start()) { throw 'SELFTEST_BLOCKED: fresh PowerShell child did not start' }
        $stdoutTask = $process.StandardOutput.ReadToEndAsync()
        $stderrTask = $process.StandardError.ReadToEndAsync()
        if (-not $process.WaitForExit(60000)) {
            try { $process.Kill() } catch { }
            throw 'SELFTEST_FAILED: fresh PowerShell discovery loader exceeded 60 seconds'
        }
        $process.WaitForExit()
        return [PSCustomObject]@{
            ExitCode = [int]$process.ExitCode
            StdOut = [string]$stdoutTask.GetAwaiter().GetResult()
            StdErr = [string]$stderrTask.GetAwaiter().GetResult()
        }
    }
    finally { $process.Dispose() }
}

$probeRoot = Join-Path ([IO.Path]::GetTempPath()) ('D32-discovery-loader-selftest-NOT-CREATED-' + [Guid]::NewGuid().ToString('N'))
if (Test-Path -LiteralPath $probeRoot) { throw 'SELFTEST_BLOCKED: generated no-create probe path already exists' }
$zeroSha40 = '0' * 40
$zeroSha64 = '0' * 64
$requiredArguments = @(
    '-Repository', $repository,
    '-EvidenceRoot', $probeRoot,
    '-ExpectedCandidateSha', $zeroSha40,
    '-ToolchainProfilePath', (Join-Path $probeRoot 'profile.json'),
    '-ExpectedToolchainProfileSha256', $zeroSha64,
    '-PinnedGitPath', (Join-Path $probeRoot 'git.exe'),
    '-PinnedGitSha256', $zeroSha64,
    '-TauriMacrosSourceAuthorityPath', (Join-Path $probeRoot 'source-authority.json'),
    '-ExpectedTauriMacrosSourceAuthoritySha256', $zeroSha64,
    '-VendoredProtocAuthorityPath', (Join-Path $probeRoot 'protoc-authority.json'),
    '-ExpectedVendoredProtocAuthoritySha256', $zeroSha64
)

$loader = Invoke-D32DiscoveryLoaderChild -RunnerScript $discoveryScript -Arguments ($requiredArguments + @('-LoaderSelfTest'))
$loaderOutput = $loader.StdOut + $loader.StdErr
if ($loader.ExitCode -ne 0 -or $loaderOutput -notmatch 'D32_TEST_INVENTORY_DISCOVERY_LOADER=PASS' -or
    $loaderOutput -notmatch 'discovery_admission=PAST_IMPORT' -or
    $loaderOutput -notmatch 'cargo_invocations=0' -or
    $loaderOutput -notmatch 'evidence_root_claimed=false') {
    throw "SELFTEST_FAILED: fresh-process loader dependency check failed (exit=$($loader.ExitCode)): $loaderOutput"
}

# Omit the caller-pinned timeouts intentionally. Reaching this exact admission
# failure proves imports and the dependency guard passed; the runner stops
# before validating/creating EvidenceRoot or invoking Cargo.
$admission = Invoke-D32DiscoveryLoaderChild -RunnerScript $discoveryScript -Arguments $requiredArguments
$admissionOutput = $admission.StdOut + $admission.StdErr
if ($admission.ExitCode -eq 0 -or $admissionOutput -notmatch 'TEST_INVENTORY_DISCOVERY_BLOCKED: caller must explicitly pin -Phase0TimeoutSeconds') {
    throw "SELFTEST_FAILED: fresh discovery did not stop at the caller-pin admission check after import (exit=$($admission.ExitCode)): $admissionOutput"
}
if (Test-Path -LiteralPath $probeRoot) { throw 'SELFTEST_FAILED: no-create EvidenceRoot probe path was created' }

$baselineArguments = @(
    '-Repository', $repository,
    '-ExpectedCandidateSha', 'not-an-exact-sha',
    '-DiscoveryPath', (Join-Path $probeRoot 'discovery.json'),
    '-ExpectedDiscoverySha256', $zeroSha64,
    '-ToolchainProfilePath', (Join-Path $probeRoot 'profile.json'),
    '-ExpectedToolchainProfileSha256', $zeroSha64,
    '-PinnedGitPath', (Join-Path $probeRoot 'git.exe'),
    '-PinnedGitSha256', $zeroSha64,
    '-BaselineOutputPath', (Join-Path $probeRoot 'baseline.json')
)
$baseline = Invoke-D32DiscoveryLoaderChild -RunnerScript $baselineScript -Arguments $baselineArguments
$baselineOutput = $baseline.StdOut + $baseline.StdErr
if ($baseline.ExitCode -eq 0 -or $baselineOutput -notmatch 'TEST_INVENTORY_BASELINE_BLOCKED: exact lowercase candidate/Profile/Git/discovery caller pins are required') {
    throw "SELFTEST_FAILED: baseline builder did not stop at its caller-pin admission check after import (exit=$($baseline.ExitCode)): $baselineOutput"
}
if (Test-Path -LiteralPath $probeRoot) { throw 'SELFTEST_FAILED: no-create EvidenceRoot probe path was created' }

Write-Output 'D32 discovery loader self-test: PASS'
Write-Output 'fresh_pwsh_import_and_transitive_inventory_runner_dependencies=PASS'
Write-Output 'discovery_and_baseline_admission_after_import=PASS'
Write-Output 'cargo_invocations=0'
Write-Output 'evidence_root_claimed=false'
Write-Output "custom_function_dependencies=$(([regex]::Match($loaderOutput, 'custom_function_dependencies=(\d+)')).Groups[1].Value)"
Write-Output "cmdlet_modules=$(([regex]::Match($loaderOutput, 'cmdlet_modules=([^\r\n]*)')).Groups[1].Value)"
