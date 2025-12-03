#!/bin/bash
# ===========================================
# Environment Setup Script
# ===========================================
# This script creates a Python virtual environment,
# activates it, and installs all required dependencies
# listed in requirements.txt.
#
# Usage:
#   bash setup.sh
#   source venv/bin/activate
# ===========================================

# Stop on any error
set -e

echo "🧰 Setting up environment..."

# --- Check Python version ---
if ! command -v python3 &> /dev/null; then
    echo "❌ Python3 not found. Please install Python 3.8+ first."
    exit 1
fi

PY_VERSION=$(python3 -V 2>&1)
echo "🐍 Using $PY_VERSION"

# --- Create venv if not exists ---
if [ ! -d "venv" ]; then
    echo "📦 Creating virtual environment..."
    python3 -m venv venv
else
    echo "✅ Virtual environment already exists."
fi

# --- Activate environment ---
echo "🔗 Activating environment..."
# shellcheck disable=SC1091
source venv/bin/activate

# --- Upgrade pip ---
echo "⬆️  Upgrading pip..."
pip install --upgrade pip

# --- Install dependencies ---
if [ -f "requirements.txt" ]; then
    echo "📚 Installing dependencies from requirements.txt..."
    pip install -r requirements.txt
else
    echo "⚠️  No requirements.txt found. Creating a new one..."
    pip freeze > requirements.txt
fi

# --- Confirm ---
echo "✅ Environment setup complete!"
echo ""
echo "To activate it manually next time, run:"
echo "  source venv/bin/activate"
echo ""
echo "To update dependencies later, run:"
echo "  pip freeze > requirements.txt"
