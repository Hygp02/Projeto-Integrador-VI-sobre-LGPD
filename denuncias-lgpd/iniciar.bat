@echo off
chcp 65001 >nul
cd /d "%~dp0"
echo === Canal de Denuncias - iniciando ===

where python >nul 2>nul
if errorlevel 1 (
  echo.
  echo Python nao encontrado. Instale em https://www.python.org/downloads/ ^(marque "Add Python to PATH"^) e rode de novo.
  pause
  exit /b 1
)

if not exist .venv (
  echo Criando ambiente e instalando dependencias ^(so na primeira vez^)...
  python -m venv .venv
)
call .venv\Scripts\activate.bat
python -m pip install -q -r requirements.txt

set ADMIN_EMAIL=dpo@empresa.com
set ADMIN_PASSWORD=SenhaForte123
python seed_demo.py

echo.
echo Abrindo http://localhost:8000  ^(feche esta janela para encerrar^)
start "" http://localhost:8000
python -m uvicorn app.main:app --port 8000
pause
