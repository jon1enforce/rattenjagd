#!/usr/bin/env python3
"""
Pegasus Universal Detector - Für Linux, Android und iOS
"""

import os
import sys
import time
import subprocess
import json
import platform
import socket
import re
from datetime import datetime
from collections import defaultdict

# Plattformerkennung
IS_ANDROID = 'android' in platform.system().lower() or os.path.exists('/system/bin/sh')
IS_IOS = 'darwin' in platform.system().lower() or os.path.exists('/Applications')
IS_LINUX = not IS_ANDROID and not IS_IOS

# Plattformspezifische Konfiguration
if IS_ANDROID:
    TEMP_DIR = "/data/local/tmp"
elif IS_IOS:
    TEMP_DIR = "/tmp"
else:
    TEMP_DIR = "/tmp"

RESULTS_FILE = f"{TEMP_DIR}/pegasus_universal_analysis.json"

def check_privileges():
    """Prüft benötigte Berechtigungen"""
    if IS_IOS:
        # iOS: Jailbreak-Priviligien prüfen
        try:
            result = subprocess.run(["whoami"], capture_output=True, text=True)
            return "root" in result.stdout
        except:
            return False
    elif IS_ANDROID:
        # Android: root oder shell
        return os.geteuid() in [0, 2000, 1000]
    else:
        # Linux: root
        return os.geteuid() == 0

def get_platform_info():
    """Detaillierte Plattforminformationen"""
    return {
        "platform": platform.system(),
        "release": platform.release(),
        "version": platform.version(),
        "machine": platform.machine(),
        "is_android": IS_ANDROID,
        "is_ios": IS_IOS,
        "is_linux": IS_LINUX,
        "timestamp": datetime.now().isoformat()
    }

def run_command(cmd, timeout=15):
    """Plattformübergreifender Befehlsexecutor"""
    try:
        if IS_IOS:
            # iOS-spezifische Anpassungen
            cmd = cmd.replace('ps aux', 'ps -A')
            cmd = cmd.replace('netstat -tun', 'netstat -an')
        
        result = subprocess.run(
            cmd, 
            capture_output=True, 
            text=True, 
            timeout=timeout, 
            shell=True,
            executable="/bin/bash" if not IS_IOS else "/bin/sh"
        )
        return result.returncode == 0, result.stdout, result.stderr
    except Exception as e:
        return False, "", str(e)

def monitor_network_connections():
    """Netzwerküberwachung für alle Plattformen"""
    connections = []
    pegasus_ports = ['4444', '5555', '6006', '8443', '5223', '5228', '5242', '5243']
    
    # Plattformspezifische Netzwerkbefehle
    if IS_IOS:
        network_cmds = [
            "netstat -an 2>/dev/null | grep -E '(:4444|:5555|:6006|:8443)' || true",
            "lsof -i -n 2>/dev/null | grep -E '(4444|5555|6006|8443)' || true"
        ]
    else:
        network_cmds = [
            "ss -tunp 2>/dev/null | head -50",
            "netstat -tunp 2>/dev/null | head -50",
            "lsof -i -n 2>/dev/null | head -50"
        ]
    
    for cmd in network_cmds:
        success, output, error = run_command(cmd)
        if success and output:
            for line in output.split('\n'):
                if any(port in line for port in pegasus_ports):
                    connections.append({
                        "type": "network",
                        "connection": line.strip(),
                        "timestamp": datetime.now().isoformat(),
                        "risk": "high"
                    })
            if connections:
                break
    
    return connections

def detect_sensor_access():
    """Erkennt Sensorzugriffe auf allen Plattformen"""
    sensor_events = []
    
    # Gemeinsame Sensor-Muster
    sensor_patterns = {
        'camera': ['/dev/video', 'camera', 'AVCapture', 'UIImagePicker'],
        'microphone': ['/dev/snd/', 'audio', 'microphone', 'AVAudio'],
        'touch': ['touch', 'gesture', 'UITouch', 'MultiTouch'],
        'accelerometer': ['accelerometer', 'motion', 'CMAccelerometer'],
        'gyroscope': ['gyroscope', 'CMGyro'],
        'gps': ['gps', 'location', 'CoreLocation'],
        'battery': ['battery', 'power', 'UIDeviceBattery'],
        'display': ['display', 'screen', 'framebuffer', 'UIScreen'],
        'keyboard': ['keyboard', 'UIKey', 'UIText'],
        'bluetooth': ['bluetooth', 'BT', 'CoreBluetooth'],
        'wifi': ['wifi', 'wireless', 'CWInterface']
    }
    
    # Prozessüberwachung
    if IS_IOS:
        ps_cmd = "ps -A 2>/dev/null"
    else:
        ps_cmd = "ps aux 2>/dev/null || ps -A 2>/dev/null"
    
    success, output, error = run_command(ps_cmd)
    if success:
        for line in output.split('\n'):
            for sensor_type, patterns in sensor_patterns.items():
                if any(pattern.lower() in line.lower() for pattern in patterns):
                    risk_level = "medium" if sensor_type in ['camera', 'microphone'] else "low"
                    sensor_events.append({
                        "type": "sensor",
                        "sensor": sensor_type,
                        "process": line.strip()[:100],
                        "timestamp": datetime.now().isoformat(),
                        "risk": risk_level
                    })
    
    # Gerätedateien überwachen (nicht auf iOS)
    if not IS_IOS:
        device_checks = [
            "ls -la /dev/video* 2>/dev/null || true",
            "ls -la /dev/snd/* 2>/dev/null || true",
            "ls -la /dev/input/event* 2>/dev/null || true"
        ]
        
        for cmd in device_checks:
            success, output, error = run_command(cmd)
            if success and output:
                for line in output.split('\n'):
                    if line.strip() and 'video' in line:
                        sensor_events.append({
                            "type": "device", 
                            "sensor": "camera", 
                            "device": line.strip(),
                            "timestamp": datetime.now().isoformat(),
                            "risk": "medium"
                        })
                    elif line.strip() and 'snd' in line:
                        sensor_events.append({
                            "type": "device", 
                            "sensor": "audio", 
                            "device": line.strip(),
                            "timestamp": datetime.now().isoformat(),
                            "risk": "medium"
                        })
                    elif line.strip() and 'input' in line:
                        sensor_events.append({
                            "type": "device", 
                            "sensor": "input", 
                            "device": line.strip(),
                            "timestamp": datetime.now().isoformat(),
                            "risk": "low"
                        })
    
    return sensor_events

def check_suspicious_activities():
    """Erkennt verdächtige Aktivitäten"""
    suspicious = []
    
    # Systemaufruf-Überwachung
    if IS_IOS:
        # iOS: Systemlogs prüfen
        log_cmds = [
            "log show --last 1m 2>/dev/null | grep -i -E '(camera|microphone|location)' | head -10 || true",
            "syslog 2>/dev/null | grep -i -E '(access|permission|privacy)' | head -10 || true"
        ]
    else:
        # Android/Linux: dmesg/logcat
        log_cmds = [
            "dmesg | tail -20 2>/dev/null || true",
            "logcat -d -b main 2>/dev/null | tail -20 || true"
        ]
    
    for cmd in log_cmds:
        success, output, error = run_command(cmd)
        if success and output:
            for line in output.split('\n'):
                if line.strip() and any(pattern in line.lower() for pattern in ['error', 'warning', 'denied', 'access']):
                    suspicious.append({
                        "type": "log",
                        "message": line.strip()[:200],
                        "timestamp": datetime.now().isoformat(),
                        "risk": "low"
                    })
    
    return suspicious

def correlate_events(network_events, sensor_events, suspicious_activities):
    """Korreliert Netzwerk- und Sensor-Events"""
    correlation = {
        "high_risk_ips": [],
        "sensor_network_correlation": [],
        "timeline_analysis": [],
        "risk_assessment": {
            "level": "low",
            "network_threat": False,
            "sensor_threat": False,
            "correlation_threat": False
        }
    }
    
    # Extrahiere IPs aus Netzwerkverbindungen
    ip_pattern = r'\b(?:\d{1,3}\.){3}\d{1,3}\b'
    network_ips = set()
    
    for event in network_events:
        if 'connection' in event:
            ips = re.findall(ip_pattern, event['connection'])
            network_ips.update(ips)
    
    # Korreliere mit Sensor-Events (mit Fehlerbehandlung)
    if network_ips:
        correlation["risk_assessment"]["network_threat"] = True
        correlation["risk_assessment"]["level"] = "medium"
    
    if sensor_events:
        correlation["risk_assessment"]["sensor_threat"] = True
        # Erhöhe Risikostufe wenn Kamera/Mikrofon erkannt
        high_risk_sensors = [e for e in sensor_events if e.get('risk') in ['high', 'medium'] and e.get('sensor') in ['camera', 'microphone']]
        if high_risk_sensors:
            correlation["risk_assessment"]["level"] = "high"
    
    # Korrelation zwischen Netzwerk und Sensoren
    if network_ips and sensor_events:
        correlation["risk_assessment"]["correlation_threat"] = True
        correlation["risk_assessment"]["level"] = "high"
        
        for ip in network_ips:
            high_risk_sensors = [
                e for e in sensor_events 
                if e.get('risk') in ['high', 'medium'] 
                and e.get('sensor') in ['camera', 'microphone', 'gps']
            ]
            
            correlation["high_risk_ips"].append({
                "ip": ip,
                "network_events": len([e for e in network_events if ip in str(e)]),
                "sensor_access": len(high_risk_sensors),
                "sensor_types": list(set(e.get('sensor', '') for e in high_risk_sensors))
            })
    
    # Timeline-Analyse (mit Fehlerbehandlung)
    all_events = []
    try:
        all_events = network_events + sensor_events + suspicious_activities
        all_events.sort(key=lambda x: x.get('timestamp', ''))
        correlation["timeline_analysis"] = all_events[-10:]  # Letzte 10 Events
    except:
        correlation["timeline_analysis"] = ["Timeline analysis failed"]
    
    return correlation

def generate_comprehensive_report(platform_info, network_events, sensor_events, suspicious_activities, correlation):
    """Generiert einen vollständigen Bericht"""
    report = {
        "metadata": platform_info,
        "network_analysis": {
            "total_connections": len(network_events),
            "connections": network_events,
            "pegasus_ports_detected": any('4444' in str(e) or '5555' in str(e) for e in network_events)
        },
        "sensor_analysis": {
            "total_events": len(sensor_events),
            "events_by_type": defaultdict(int),
            "events": sensor_events
        },
        "suspicious_activities": {
            "total": len(suspicious_activities),
            "activities": suspicious_activities
        },
        "correlation_analysis": correlation,
        "recommendations": []
    }
    
    # Zähle Sensor-Events nach Typ
    for event in sensor_events:
        if 'sensor' in event:
            report["sensor_analysis"]["events_by_type"][event['sensor']] += 1
    
    # Generiere Empfehlungen basierend auf Risikobewertung
    risk_level = correlation["risk_assessment"]["level"]
    
    if risk_level == "high":
        report["recommendations"].extend([
            "🔴 SOFORTIGES HANDELN: System isolieren",
            "🔴 Netzwerkverbindungen trennen",
            "🔴 Professionelle Untersuchung durchführen",
            "🔴 Alle sensiblen Zugänge ändern"
        ])
    elif risk_level == "medium":
        report["recommendations"].extend([
            "🟡 VORSICHT: Verdächtige Aktivitäten erkannt",
            "🟡 App-Berechtigungen überprüfen",
            "🟡 Netzwerkaktivitäten monitorieren",
            "🟡 System auf Updates prüfen"
        ])
    else:
        report["recommendations"].extend([
            "🟢 Keine akuten Bedrohungen erkannt",
            "🟢 Regelmäßige Sicherheitsüberprüfungen durchführen",
            "🟢 Berechtigungen von Apps überwachen"
        ])
    
    return report

def display_results(report):
    """Zeigt detaillierte Ergebnisse an"""
    print("\n" + "=" * 90)
    print("🔍 PEGASUS UNIVERSAL DETEKTION - VOLLSTÄNDIGE ANALYSE")
    print("=" * 90)
    
    print(f"📱 Plattform: {report['metadata']['platform']} {report['metadata']['release']}")
    print(f"🏷️  Android: {report['metadata']['is_android']} | iOS: {report['metadata']['is_ios']}")
    
    # Netzwerkergebnisse
    print(f"\n🌐 NETZWERKANALYSE:")
    print(f"   Verbindungen: {report['network_analysis']['total_connections']}")
    if report['network_analysis']['pegasus_ports_detected']:
        print("   🔴 PEGASUS-PORTS ERKANNT!")
    
    # Sensorergebnisse
    print(f"\n📡 SENSORANALYSE:")
    sensor_counts = report['sensor_analysis']['events_by_type']
    if sensor_counts:
        for sensor_type, count in sensor_counts.items():
            risk_icon = "🔴" if sensor_type in ['camera', 'microphone'] else "🟡"
            print(f"   {risk_icon} {sensor_type.upper()}: {count} Events")
    else:
        print("   🟢 Keine Sensorzugriffe erkannt")
    
    # Korrelationsanalyse
    print(f"\n🔗 KORRELATIONSANALYSE:")
    risk_level = report['correlation_analysis']['risk_assessment']['level']
    risk_icon = "🔴" if risk_level == "high" else "🟡" if risk_level == "medium" else "🟢"
    print(f"   Risikostufe: {risk_icon} {risk_level.upper()}")
    print(f"   Verdächtige IPs: {len(report['correlation_analysis']['high_risk_ips'])}")
    
    # Empfehlungen
    if report['recommendations']:
        print(f"\n💡 EMPFEHLUNGEN:")
        for rec in report['recommendations']:
            print(f"   • {rec}")
    
    print("=" * 90)

def main():
    """Hauptfunktion"""
    print("🦠 Pegasus Universal Detector - Linux/Android/iOS")
    print("🔍 Starte vollständige Systemanalyse...")
    
    if not check_privileges():
        print("❌ Erhöhte Berechtigungen erforderlich!")
        print("   Linux: sudo benötigt")
        print("   Android: adb shell oder root")
        print("   iOS: Jailbreak mit root required")
        return
    
    # Sammle Daten
    platform_info = get_platform_info()
    print(f"📋 Plattform erkannt: {platform_info['platform']}")
    
    print("🌐 Überwache Netzwerk...")
    network_events = monitor_network_connections()
    
    print("📡 Überwache Sensoren...")
    sensor_events = detect_sensor_access()
    
    print("🔍 Prüfe verdächtige Aktivitäten...")
    suspicious_activities = check_suspicious_activities()
    
    print("🔗 Korreliere Ereignisse...")
    correlation = correlate_events(network_events, sensor_events, suspicious_activities)
    
    # Generiere Bericht
    report = generate_comprehensive_report(
        platform_info, network_events, sensor_events, 
        suspicious_activities, correlation
    )
    
    display_results(report)
    
    # Speichere Bericht
    try:
        with open(RESULTS_FILE, 'w') as f:
            json.dump(report, f, indent=2, ensure_ascii=False)
        print(f"✅ Bericht gespeichert: {RESULTS_FILE}")
    except Exception as e:
        print(f"❌ Fehler beim Speichern: {e}")
    
    print(f"\n⏰ Analyse abgeschlossen um {datetime.now().strftime('%H:%M:%S')}")

if __name__ == "__main__":
    main()
