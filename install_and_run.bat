@echo off
chcp 65001 >nul
title 🍄 MYCELIUM AGENT — Instalator

echo.
echo  ███╗   ███╗██╗   ██╗ ██████╗███████╗██╗     ██╗██╗   ██╗███╗   ███╗
echo  ████╗ ████║╚██╗ ██╔╝██╔════╝██╔════╝██║     ██║██║   ██║████╗ ████║
echo  ██╔████╔██║ ╚████╔╝ ██║     █████╗  ██║     ██║██║   ██║██╔████╔██║
echo  ██║╚██╔╝██║  ╚██╔╝  ██║     ██╔══╝  ██║     ██║██║   ██║██║╚██╔╝██║
echo  ██║ ╚═╝ ██║   ██║   ╚██████╗███████╗███████╗██║╚██████╔╝██║ ╚═╝ ██║
echo  ╚═╝     ╚═╝   ╚═╝    ╚═════╝╚══════╝╚══════╝╚═╝ ╚═════╝ ╚═╝     ╚═╝
echo.
echo  🍄  Agent ktory rozrasta sie przez siec jak grzybnia...
echo  ════════════════════════════════════════════════════════
echo.

:: ── Sprawdź Python ────────────────────────────────────────────────────────────
python --version >nul 2>&1
if %errorlevel% neq 0 (
    echo  [!] Python nie jest zainstalowany.
    echo  [*] Pobieranie instalatora Python 3.12...
    echo.
    powershell -Command "Invoke-WebRequest -Uri 'https://www.python.org/ftp/python/3.12.4/python-3.12.4-amd64.exe' -OutFile '%TEMP%\python_installer.exe'"
    echo  [*] Uruchamianie instalatora Python (zaznacz "Add to PATH"!)...
    start /wait %TEMP%\python_installer.exe /quiet InstallAllUsers=1 PrependPath=1 Include_pip=1
    echo  [*] Python zainstalowany. Restart skryptu...
    echo.
    :: Odśwież PATH i kontynuuj
    call refreshenv >nul 2>&1
    python --version >nul 2>&1
    if %errorlevel% neq 0 (
        echo  [!] BŁĄD: Python nadal niedostępny. Zainstaluj ręcznie z https://python.org
        echo      i zaznacz "Add Python to PATH" podczas instalacji!
        pause
        exit /b 1
    )
)

for /f "tokens=*" %%i in ('python --version 2^>^&1') do echo  [✓] Znaleziono: %%i

:: ── Aktualizuj pip ────────────────────────────────────────────────────────────
echo.
echo  [*] Aktualizuję pip...
python -m pip install --upgrade pip --quiet

:: ── Instaluj zależności ───────────────────────────────────────────────────────
echo  [*] Instaluję zależności Mycelium...
echo.

pip install flask --quiet
if %errorlevel% neq 0 (
    echo  [!] BŁĄD przy instalacji flask!
    pause
    exit /b 1
)
echo  [✓] flask          — webowy dashboard
    
pip install bleak --quiet
if %errorlevel% neq 0 (
    echo  [!] OSTRZEŻENIE: bleak nie mógł zostać zainstalowany (brak Bluetooth BLE)
    echo      Skanowanie sieci LAN będzie działać normalnie.
) else (
    echo  [✓] bleak          — Bluetooth BLE scanner
)

pip install python-nmap --quiet >nul 2>&1
if %errorlevel% equ 0 (
    echo  [✓] python-nmap    — rozszerzone skanowanie portów (opcjonalne)
) else (
    echo  [-] python-nmap    — pominięto (opcjonalne)
)

echo.
echo  ════════════════════════════════════════════════════════
echo  [✓] Instalacja zakończona!
echo  ════════════════════════════════════════════════════════
echo.

:: ── Wybór trybu uruchomienia ──────────────────────────────────────────────────
echo  Wybierz tryb uruchomienia:
echo.
echo    [1] 🍄 Skanowanie + mapa grzybni (terminal)
echo    [2] 🌐 Dashboard webowy (http://localhost:5000)
echo    [3] 🍄 Oba naraz (skanowanie + dashboard)
echo.
set /p choice="  Twój wybór (1/2/3): "

if "%choice%"=="1" goto RUN_AGENT
if "%choice%"=="2" goto RUN_WEB
if "%choice%"=="3" goto RUN_BOTH
goto RUN_AGENT

:RUN_AGENT
echo.
echo  [*] Uruchamianie Mycelium Agent (skanowanie sieci)...
echo      Ctrl+C aby zatrzymać
echo.
python agent.py
pause
exit /b

:RUN_WEB
echo.
echo  [*] Uruchamianie dashboardu webowego...
echo  [*] Otwórz przeglądarkę: http://localhost:5000
echo      Ctrl+C aby zatrzymać
echo.
start http://localhost:5000
python web\app.py
pause
exit /b

:RUN_BOTH
echo.
echo  [*] Uruchamianie skanowania w tle...
start "🍄 Mycelium Scanner" cmd /k "python agent.py"
timeout /t 3 /nobreak >nul
echo  [*] Uruchamianie dashboardu webowego...
echo  [*] Otwórz przeglądarkę: http://localhost:5000
echo.
start http://localhost:5000
python web\app.py
pause
exit /b
