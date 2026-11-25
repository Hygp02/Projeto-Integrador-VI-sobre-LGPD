#!/usr/bin/env bash
# Linux / macOS: ./iniciar.sh
set -e
cd "$(dirname "$0")"
echo "=== Canal de Denúncias - iniciando ==="

PY=$(command -v python3 || command -v python || true)
if [ -z "$PY" ]; then
  echo "Python não encontrado. Instale o Python 3.10+ (https://www.python.org/downloads/)."; exit 1
fi

if [ ! -d .venv ]; then
  echo "Criando ambiente e instalando dependências (só na primeira vez)..."
  "$PY" -m venv .venv
fi
source .venv/bin/activate
python -m pip install -q -r requirements.txt

export ADMIN_EMAIL="dpo@empresa.com"
export ADMIN_PASSWORD="SenhaForte123"
python seed_demo.py

echo
echo "Abra no navegador: http://localhost:8000   (Ctrl+C para encerrar)"
(sleep 2; command -v xdg-open >/dev/null && xdg-open http://localhost:8000 >/dev/null 2>&1 || command -v open >/dev/null && open http://localhost:8000) &
exec python -m uvicorn app.main:app --port 8000
