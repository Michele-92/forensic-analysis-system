#!/bin/bash
# Installiert und konfiguriert Ollama für LLM-Agent

set -e

echo "=== Ollama Setup für Forensic Analysis System ==="

# Check OS
if [[ "$OSTYPE" == "linux-gnu"* ]]; then
    OS="linux"
elif [[ "$OSTYPE" == "darwin"* ]]; then
    OS="mac"
else
    echo "❌ Unsupported OS: $OSTYPE"
    exit 1
fi

# Installiere Ollama
echo "📦 Installiere Ollama..."
if [ "$OS" == "linux" ]; then
    curl -fsSL https://ollama.ai/install.sh | sh
elif [ "$OS" == "mac" ]; then
    brew install ollama
fi

# Starte Ollama-Server (background)
echo "🚀 Starte Ollama-Server..."
ollama serve &
OLLAMA_PID=$!

# Warte auf Server-Start
echo "⏳ Warte auf Server..."
sleep 5

# Lade Llama 3.1 (8B - schnell & effizient)
echo "📥 Lade Llama 3.1 Model..."
ollama pull llama3.1

# Optional: Weitere Models
read -p "Möchtest du auch Llama 3.1 70B laden? (mehr Qualität, braucht >40GB RAM) [y/N]: " -n 1 -r
echo
if [[ $REPLY =~ ^[Yy]$ ]]; then
    echo "📥 Lade Llama 3.1 70B..."
    ollama pull llama3.1:70b
fi

# Test
echo "🧪 Teste Ollama..."
if ollama list | grep -q "llama3.1"; then
    echo "✅ Ollama erfolgreich installiert!"
    echo ""
    echo "Verfügbare Models:"
    ollama list
else
    echo "❌ Ollama-Installation fehlgeschlagen"
    exit 1
fi

echo ""
echo "=== Ollama bereit! ==="
echo "Server läuft auf: http://localhost:11434"
echo "Process-ID: $OLLAMA_PID"
echo ""
echo "Stoppen mit: kill $OLLAMA_PID"