# publish-nuget.ps1
# Usage: .\publish-nuget.ps1
# Requires env var NUGET_API_KEY to be set on your machine.

$apiKey = $env:NUGET_API_KEY

if (-not $apiKey) {
    Write-Error "NUGET_API_KEY environment variable is not set."
    Write-Host "Set it with: [System.Environment]::SetEnvironmentVariable('NUGET_API_KEY', 'your-key', 'User')"
    exit 1
}

$packages = @(
    "src\AiTrace\bin\Release\AiTrace.*.nupkg",
    "src\AiTrace.Pro\bin\Release\AiTrace.Pro.*.nupkg"
)

foreach ($pattern in $packages) {
    $files = Get-ChildItem -Path $pattern -ErrorAction SilentlyContinue | Sort-Object LastWriteTime -Descending | Select-Object -First 1
    if (-not $files) {
        Write-Warning "No package found for pattern: $pattern"
        continue
    }
    Write-Host "Publishing $($files.Name)..."
    dotnet nuget push $files.FullName --api-key $apiKey --source https://api.nuget.org/v3/index.json --skip-duplicate
}

Write-Host "Done."
