@echo off
REM SOAR Lite endpoint agent launcher. Run from an Administrator command prompt or PowerShell.
REM Set AGENT_TOKEN, SOAR_BACKEND_URL, SOAR_BACKEND_IP and SOAR_AGENT_ID first.

net session >nul 2>&1
if errorlevel 1 (
    echo ERROR: run this script as Administrator. Firewall and event log actions need elevation.
    exit /b 1
)

if "%AGENT_TOKEN%"=="" (
    echo ERROR: AGENT_TOKEN is not set. Use the same value as the backend.
    exit /b 1
)

if "%AGENT_PORT%"=="" set AGENT_PORT=5055

REM Run from the project root so the shared "common" package is importable.
cd /d "%~dp0.."
python -m uvicorn soar_agent.agent:app --host 0.0.0.0 --port %AGENT_PORT%
