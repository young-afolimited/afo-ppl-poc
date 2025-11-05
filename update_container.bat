@echo off
echo WARNING: This operation will DELETE all app data and perform a hard update of the Docker environment.
set /p confirm="Are you sure you want to continue? (y/n): "
if /i "%confirm%"=="y" (
    call remove_container.bat
    call deploy_container.bat
    echo Hard update completed.
) else (
    echo Operation cancelled.
)
echo.
pause
start http://localhost:8080
pause
