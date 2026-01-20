# Backup Antigravity Chat Data to GitHub
# Just double-click this file to backup your chat!

Write-Host "========================================" -ForegroundColor Cyan
Write-Host "  Antigravity Chat Backup Script" -ForegroundColor Cyan
Write-Host "========================================" -ForegroundColor Cyan
Write-Host ""

Set-Location "C:\Users\Krish\.gemini"

# Check current status
Write-Host "Checking for changes..." -ForegroundColor Yellow
$status = git status --porcelain

if ($status) {
    Write-Host "Changes detected! Backing up..." -ForegroundColor Green
    
    # Add all changes
    git add -A
    
    # Commit with timestamp
    $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    git commit -m "Backup: $timestamp"
    
    # Push to GitHub
    Write-Host "Pushing to GitHub..." -ForegroundColor Yellow
    git push origin main
    
    if ($LASTEXITCODE -eq 0) {
        Write-Host ""
        Write-Host "SUCCESS! Backup complete!" -ForegroundColor Green
        Write-Host "View at: https://github.com/playauraai/gemini" -ForegroundColor Cyan
    } else {
        Write-Host "Push failed! Check your connection." -ForegroundColor Red
    }
} else {
    Write-Host "No changes to backup." -ForegroundColor Gray
}

Write-Host ""
Write-Host "Press any key to exit..."
$null = $Host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown")
