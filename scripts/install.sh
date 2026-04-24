#!/bin/bash
# Crucible — one-command install for Linux/macOS

echo "🔒 Installing Crucible Security..."
echo ""

# Check Python version
python3 --version 2>&1 | grep -E "Python 3\.(10|11|12)" > /dev/null
if [ $? -ne 0 ]; then
  echo "❌ Python 3.10+ required. Please upgrade Python."
  exit 1
fi

# Install
pip install crucible-security

echo ""
echo "✅ Crucible installed successfully!"
echo ""
echo "Quick start:"
echo "  crucible scan --target https://httpbin.org/post --name 'Demo Agent'"
echo ""
echo "Docs: github.com/crucible-security/crucible"
echo "Discord: discord.gg/m7wAxEv3"
