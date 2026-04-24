#!/bin/bash
# Crucible — run your first scan in 60 seconds

echo "🔒 Crucible Security — Quick Start"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo ""
echo "This will run a demo scan against httpbin.org"
echo "httpbin echoes all requests — making it a"
echo "perfectly vulnerable demo target (Grade F expected)"
echo ""
echo "Running scan..."
echo ""

crucible scan --target https://httpbin.org/post --name "Demo Agent"

echo ""
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "Now scan YOUR agent:"
echo "  crucible scan --target https://your-agent.com"
echo ""
echo "GitHub: github.com/crucible-security/crucible"
echo "Discord: discord.gg/m7wAxEv3"
