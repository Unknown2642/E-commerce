@echo off
echo ========================================
echo    E-Commerce Application Launcher
echo ========================================
echo.

echo [1/4] Checking Python installation...
python --version >nul 2>&1
if errorlevel 1 (
    echo ERROR: Python not found! Please install Python 3.7+
    pause
    exit /b 1
)
echo ✓ Python found

echo.
echo [2/4] Installing dependencies...
pip install -r requirements.txt
if errorlevel 1 (
    echo ERROR: Failed to install dependencies
    pause
    exit /b 1
)
echo ✓ Dependencies installed

echo.
echo [3/4] Initializing database...
if not exist "data" (
    python setup_data.py
    echo ✓ Database initialized
) else (
    echo ✓ Database already exists
)

echo.
echo [4/4] Starting application...
echo.
echo ========================================
echo   Application starting on port 5001
echo   Open: http://localhost:5001
echo.
echo   Admin: admin@ecommerce.com / admin123
echo   User:  user@ecommerce.com / user123
echo ========================================
echo.

python app.py