#!/bin/bash
# Pegasus Real Detector - Echte Überwachung

echo ""
echo "╔══════════════════════════════════════════════════════════════╗"
echo "║                PEGASUS REAL DETECTOR                        ║"
echo "║               Echte Systemüberwachung                       ║"
echo "╚══════════════════════════════════════════════════════════════╝"
echo ""

# Prüfe Root
if [ "$EUID" -ne 0 ]; then
    echo "❌ Root access required!"
    echo "⚠️  Please run with sudo: sudo $0"
    exit 1
fi

# Prüfe bpftrace
if ! command -v bpftrace >/dev/null 2>&1; then
    echo "❌ bpftrace not found!"
    echo "📦 Installing bpftrace..."
    sudo apt update && sudo apt install -y bpftrace
fi

# Prüfe ob Script existiert
SCRIPT="pegasus.py"
if [ ! -f "$SCRIPT" ]; then
    echo "❌ Script not found: $SCRIPT"
    exit 1
fi

# Starte echte Überwachung
echo "🔍 Starting REAL Pegasus Detector (3 minutes)..."
echo "📡 Monitoring live system activity..."
echo ""

python3 "$SCRIPT"

# Zeige Ergebnisse
echo ""
echo "📊 REAL-TIME RESULTS:"
if [ -f "/tmp/pegasus_real_analysis.json" ]; then
    if command -v jq >/dev/null 2>&1; then
        detections=$(jq '.total_detections' /tmp/pegasus_real_analysis.json)
        duration=$(jq '.scan_duration' /tmp/pegasus_real_analysis.json)
        real_scan=$(jq '.environment.real_scan' /tmp/pegasus_real_analysis.json)
        
        echo "   Real Scan: $real_scan"
        echo "   Detections: $detections"
        echo "   Duration: ${duration}s"
        
        if [ "$detections" -gt 0 ]; then
            echo ""
            echo "🔝 LIVE DETECTIONS:"
            jq -r '.detections[0] | "   Process: \(.process)\n   PID: \(.pid)\n   IP: \(.ip)\n   Sensors: \(.sensors)\n   Probability: \(.probability)%\n   Risk: \(.risk)"' /tmp/pegasus_real_analysis.json
        fi
    else
        echo "   Real results saved in /tmp/pegasus_real_analysis.json"
        echo "   Install jq for better output: sudo apt install jq"
    fi
else
    echo "   No results found - system may be clean"
fi

echo ""
echo "✅ Real scan completed"
