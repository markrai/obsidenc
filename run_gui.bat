@echo off
REM Launch the Obsidenc Tauri GUI in development mode
REM - Runs `cargo tauri dev` in the `gui` directory

setlocal

REM Change to the project root where this script resides
cd /d "%~dp0"

REM Ensure the GUI directory exists
if not exist "gui" (
    echo [run_gui] Error: gui directory not found next to run_gui.bat
    exit /b 1
)

echo [run_gui] Starting Tauri app (cargo tauri dev) in a minimized background window...

REM Launch Tauri dev in a separate, minimized console window so this script can exit immediately.
REM The user is not forced to keep a visible console around, but logs still exist if needed.
start "obsidenc-gui" /min cmd /c "cd /d .\gui && cargo tauri dev"

endlocal & exit /b 0


