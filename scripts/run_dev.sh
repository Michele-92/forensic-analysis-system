#!/bin/bash
# Startet Development-Umgebung (Backend + Frontend)

set -e

echo "=== Starting Forensic Analysis System (Development) ==="

# Check ob in richtigem Verzeichnis
if [ ! -f "requirements.txt" ]; then
    echo "❌ Error: Must run from project root"
    exit 1
fi

# Aktiviere Virtual Environment
if [ -d "venv" ]; then
    echo "📦 Aktiviere Virtual Environment..."
    source venv/bin/activate
else
    echo "❌ Virtual Environment nicht gefunden. Bitte erst 'python -m venv venv' ausführen."
    exit 1
fi

# Check Dependencies
echo "🔍 Prüfe Dependencies..."
pip install -q -r requirements.txt

# Starte Ollama (falls nicht läuft)
if ! curl -s http://localhost:11434/api/tags > /dev/null 2>&1; then
    echo "🚀 Starte Ollama..."
    ollama serve &
    sleep 3
fi

# Erstelle Verzeichnisse
echo "📁 Erstelle Verzeichnisse..."
mkdir -p data/{uploads,outputs,samples}
mkdir -p logs

# Starte Backend
echo "🚀 Starte Backend (Port 8000)..."
cd backend
uvicorn api:app --reload --host 0.0.0.0 --port 8000 &
BACKEND_PID=$!
cd ..

# Warte auf Backend
echo "⏳ Warte auf Backend..."
sleep 3

# Starte Frontend (falls vorhanden)
if [ -d "frontend" ]; then
    echo "🚀 Starte Frontend (Port 5173)..."
    cd frontend
    npm run dev &
    FRONTEND_PID=$!
    cd ..
fi

echo ""
echo "=== Development Server Running ==="
echo "✅ Backend:  http://localhost:8000"
echo "✅ API Docs: http://localhost:8000/docs"
if [ -n "$FRONTEND_PID" ]; then
    echo "✅ Frontend: http://localhost:5173"
fi
echo ""
echo "PIDs: Backend=$BACKEND_PID Frontend=$FRONTEND_PID"
echo "Stoppen mit: kill $BACKEND_PID $FRONTEND_PID"
echo ""
echo "Logs:"
echo "  tail -f logs/forensic.log"

# Keep script running
wait