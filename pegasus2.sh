#!/bin/bash
# Pegasus Real Detector - Korrigierte Version

echo ""
echo "╔══════════════════════════════════════════════════════════════╗"
echo "║                PEGASUS REAL DETECTOR                        ║"
echo "║               Echte 180-Sekunden Überwachung                ║"
echo "╚══════════════════════════════════════════════════════════════╝"
echo ""

# Prüfe Root
# Prüfe Root
if [ $(id -u) -ne 0 ]; then
    echo "❌ Root access required!"
    echo "⚠️  Please run with sudo: sudo $0"
    exit 1
fi
# Prüfe bpftrace
if ! command -v bpftrace >/dev/null 2>&1; then
    echo "❌ bpftrace not found!"
    echo "📦 Installing bpftrace..."
    sudo apt update && sudo apt install -y bpftrace
    if ! command -v bpftrace >/dev/null 2>&1; then
        echo "❌ Failed to install bpftrace"
        exit 1
    fi
fi

# Prüfe ob Script existiert
SCRIPT="pegasus.py"
if [ ! -f "$SCRIPT" ]; then
    echo "❌ Script not found: $SCRIPT"
    echo "📥 Please download the real detector script"
    exit 1
fi

# Starte echte Überwachung
echo "🔍 Starting REAL Pegasus Detector (180 seconds)..."
echo "📡 Monitoring live system activity..."
echo "⏰ This will take 3 minutes, please wait..."
echo ""

# Führe Python Script aus
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
            jq -r '.detections[0] | "   Process: \(.process)\n   PID: \(.pid)\n   IP: \(.ip)\n   Sensors: \(.sensors)\n   Probability: \(.probability)%\n   Risk: \(.risk)"' /tmp/pegasus
        fi
    fi
fi
