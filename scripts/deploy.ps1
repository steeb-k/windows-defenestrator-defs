# Deploy: push local changes, refresh NSRL cache, and trigger a forced definitions build.
# Usage: .\scripts\deploy.ps1 [-NoPush]

param(
    [switch]$NoPush
)

$ErrorActionPreference = "Stop"
$REPO = "steeb-k/windows-defenestrator-defs"

# Push
if (-not $NoPush) {
    $dirty = git status --porcelain
    if ($dirty) {
        Write-Error "Working tree has uncommitted changes - commit or stash before deploying.`n$dirty"
        exit 1
    }
    Write-Host "Pushing to origin..."
    git push
} else {
    Write-Host "(Skipping push)"
}

# Refresh NSRL
Write-Host "Triggering refresh-nsrl workflow..."
gh workflow run refresh-nsrl.yml --repo $REPO

Start-Sleep -Seconds 5
$nsrlRunId = gh run list --repo $REPO --workflow refresh-nsrl.yml --limit 1 --json databaseId --jq '.[0].databaseId'
Write-Host "  NSRL run: https://github.com/$REPO/actions/runs/$nsrlRunId"

Write-Host "Waiting for NSRL refresh to complete..."
gh run watch $nsrlRunId --repo $REPO --exit-status
Write-Host "  NSRL refresh done."

# Trigger definitions build
Write-Host "Triggering definitions build (force_release=true)..."
gh workflow run build-defs.yml --repo $REPO -f force_release=true

Start-Sleep -Seconds 5
$buildRunId = gh run list --repo $REPO --workflow build-defs.yml --limit 1 --json databaseId --jq '.[0].databaseId'
Write-Host "  Build run: https://github.com/$REPO/actions/runs/$buildRunId"

Write-Host "Waiting for definitions build to complete..."
gh run watch $buildRunId --repo $REPO --exit-status
Write-Host "  Definitions build done."

Write-Host ""
Write-Host "All done. Latest release: https://github.com/$REPO/releases/latest"
