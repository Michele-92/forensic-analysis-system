#!/bin/bash
# Führt alle Tests aus

set -e

echo "=== Running Tests ==="

# Aktiviere Virtual Environment
if [ -d "venv" ]; then
    source venv/bin/activate
fi

# Install Test-Dependencies
pip install -q pytest pytest-cov pytest-asyncio

# Run Tests mit Coverage
echo "🧪 Running Unit Tests..."
pytest tests/ -v --cov=backend --cov-report=html --cov-report=term

echo ""
echo "=== Test Results ==="
echo "✅ Tests completed"
echo "📊 Coverage Report: htmlcov/index.html"