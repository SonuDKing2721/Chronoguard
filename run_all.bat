@echo off
REM ╔══════════════════════════════════════════════════════╗
REM ║   Chronoguard — One-Click Runner (Windows)          ║
REM ║   Runs the full pipeline from training to dashboard  ║
REM ╚══════════════════════════════════════════════════════╝

echo.
echo ================================================
echo   CHRONOGUARD - Full Pipeline Runner (Windows)
echo ================================================
echo.

REM Check Python is available
python --version >nul 2>&1
IF %ERRORLEVEL% NEQ 0 (
    echo [ERROR] Python not found. Please install Python 3.10+ and add to PATH.
    pause
    exit /b 1
)

REM Install dependencies
echo [1/6] Installing dependencies...
pip install -r requirements.txt --quiet
IF %ERRORLEVEL% NEQ 0 (
    echo [ERROR] Failed to install dependencies.
    pause
    exit /b 1
)
echo [OK] Dependencies ready.
echo.

REM Step 1: Train classifier
echo [2/6] Training ML Classifier...
python notebooks\train_classifier.py
IF %ERRORLEVEL% NEQ 0 (
    echo [ERROR] Classifier training failed.
    pause
    exit /b 1
)
echo.

REM Step 2: Train anomaly model
echo [3/6] Training Anomaly Detection Model...
python notebooks\train_anomaly.py
IF %ERRORLEVEL% NEQ 0 (
    echo [ERROR] Anomaly training failed.
    pause
    exit /b 1
)
echo.

REM Step 3: Explainability + risk scoring
echo [4/6] Running Explainability & Risk Scoring...
python notebooks\explainability.py
IF %ERRORLEVEL% NEQ 0 (
    echo [ERROR] Explainability script failed.
    pause
    exit /b 1
)
echo.

REM Step 4: End-to-end pipeline (also generates dashboard data)
echo [5/6] Running Integration Pipeline + Dashboard Data...
python pipeline\run_pipeline.py
IF %ERRORLEVEL% NEQ 0 (
    echo [ERROR] Pipeline failed.
    pause
    exit /b 1
)
echo.

REM Step 5: Demo scenarios
echo [6/7] Selecting Demo Scenarios...
python pipeline\demo_scenarios.py
echo.

REM Step 6: Live Attack & Triage Simulation
echo [7/7] Generating Live Attack Simulation & Triage Scenarios...
python pipeline\simulate_attack.py
echo.

echo ================================================
echo   ALL DONE! Open dashboard\index.html in your browser.
echo ================================================
echo.
pause
