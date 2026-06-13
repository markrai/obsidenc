@echo off
REM Build and run obsidenc with passed arguments

echo Building obsidenc...
cargo build --release
if errorlevel 1 (
    echo Build failed!
    exit /b 1
)

echo.
echo Running obsidenc...
target\release\obsidenc.exe %*
