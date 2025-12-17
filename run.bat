@echo off
REM Build and run obsidenc with passed arguments

echo Building obsidenc...
cargo build --release
if %ERRORLEVEL% NEQ 0 (
    echo Build failed!
    exit /b %ERRORLEVEL%
)

echo.
echo Running obsidenc...
target\release\obsidenc.exe %*

