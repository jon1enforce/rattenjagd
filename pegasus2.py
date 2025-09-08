#!/usr/bin/env python3
"""
Pegasus Real Detector - Korrigierte Version mit voller 180s Überwachung
"""

import os
import sys
import time
import subprocess
import json
import re
from datetime import datetime
from collections import defaultdict

# Konfiguration
TEMP_DIR = "/tmp"
RESULTS_FILE = f"{TEMP_DIR}/pegasus_real_analysis.json"
SCAN_DURATION = 180  # 3 Minuten echte Überwachung

def check_root():
    return os.geteuid() == 0

def check_bpftrace():
    return subprocess.run(["which", "bpftrace"], capture_output=True).returncode == 0

def run_bpftrace_long(script, duration=180):
    """Führt bpftrace für die volle Dauer aus"""
    script_file = f"{TEMP_DIR}/pegasus_scan.bt"
    
    try:
        with open(script_file, 'w') as f:
            f.write(script)
        
        # Starte bpftrace im Hintergrund
        cmd = f"bpftrace {script_file}"
        process = subprocess.Popen(cmd, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        
        # Warte für die volle Dauer
        time.sleep(duration)
        
        # Beende bpftrace
        process.terminate()
        try:
            stdout, stderr = process.communicate(timeout=5)
        except subprocess.TimeoutExpired:
            process.kill()
            stdout, stderr = process.communicate()
        
        return stdout, stderr
        
    except Exception as e:
        return "", str(e)
    finally:
        if os.path.exists(script_file):
            os.remove(script_file)

def monitor_network_real():
    """Echte Netzwerküberwachung für volle Dauer"""
    print("🌐 Echte Netzwerküberwachung gestartet (180s)...")
    
    network_script = '''
BEGIN { printf("Network monitoring started\\n"); }
tracepoint:syscalls:sys_enter_connect
{
    $sockaddr = (struct sockaddr *)arg1;
    if ($sockaddr->sa_family == AF_INET) {
        $addr = (struct sockaddr_in *)arg1;
        $port = ntohs($addr->sin_port);
        
        // Pegasus und bekannte RAT Ports
        if ($port == 4444 || $port == 5555 || $port == 6006 || $port == 8443 ||
            $port == 5223 || $port == 5228 || $port == 5242 || $port == 5243 ||
            $port == 8000 || $port == 8001 || $port == 50050 || $port == 9999) {
            printf("NETWORK|%d|%s|%d|%s\\n", pid, comm, $port, ntop($addr->sin_addr.s_addr));
        }
    }
}
END { printf("Network monitoring completed\\n"); }
'''
    
    output, error = run_bpftrace_long(network_script, SCAN_DURATION)
    print("🌐 Netzwerküberwachung abgeschlossen")
    return parse_network_output(output)

def monitor_sensors_real():
    """Echte Sensorüberwachung für volle Dauer"""
    print("📡 Echte Sensorüberwachung gestartet (180s)...")
    
    sensor_script = '''
BEGIN { printf("Sensor monitoring started\\n"); }
tracepoint:syscalls:sys_enter_openat,
tracepoint:syscalls:sys_enter_open
{
    $filename = args->filename;
    
    if ($filename != 0) {
        $fname = str($filename);
        
        if (str($fname).contains("video") || str($fname).contains("camera") || 
            str($fname).contains("/dev/video")) {
            printf("SENSOR|%d|%s|camera|%s\\n", pid, comm, $fname);
        }
        if (str($fname).contains("snd") || str($fname).contains("audio") || 
            str($fname).contains("pcm") || str($fname).contains("/dev/snd")) {
            printf("SENSOR|%d|%s|microphone|%s\\n", pid, comm, $fname);
        }
        if (str($fname).contains("fb") || str($fname).contains("graphics") || 
            str($fname).contains("screen") || str($fname).contains("/dev/fb")) {
            printf("SENSOR|%d|%s|screen|%s\\n", pid, comm, $fname);
        }
    }
}
tracepoint:syscalls:sys_enter_ioctl
{
    // Framebuffer IOCTLs
    if (args->cmd == 0x4600 || args->cmd == 0x4601 || args->cmd == 0x4602) {
        printf("SENSOR|%d|%s|screen|ioctl\\n", pid, comm);
    }
}
END { printf("Sensor monitoring completed\\n"); }
'''
    
    output, error = run_bpftrace_long(sensor_script, SCAN_DURATION)
    print("📡 Sensorüberwachung abgeschlossen")
    return parse_sensor_output(output)

def parse_network_output(output):
    """Parse echte Netzwerk-Events"""
    events = []
    for line in output.split('\n'):
        if line.startswith('NETWORK|'):
            parts = line.split('|')
            if len(parts) >= 5:
                try:
                    events.append({
                        'type': 'network',
                        'pid': int(parts[1]),
                        'process': parts[2],
                        'port': int(parts[3]),
                        'ip': parts[4],
                        'timestamp': datetime.now().isoformat(),
                        'real': True
                    })
                except (ValueError, IndexError):
                    continue
    print(f"🌐 Gefundene Netzwerk-Events: {len(events)}")
    return events

def parse_sensor_output(output):
    """Parse echte Sensor-Events"""
    events = []
    for line in output.split('\n'):
        if line.startswith('SENSOR|'):
            parts = line.split('|')
            if len(parts) >= 5:
                try:
                    events.append({
                        'type': 'sensor',
                        'pid': int(parts[1]),
                        'process': parts[2],
                        'sensor': parts[3],
                        'device': parts[4],
                        'timestamp': datetime.now().isoformat(),
                        'real': True
                    })
                except (ValueError, IndexError):
                    continue
    print(f"📡 Gefundene Sensor-Events: {len(events)}")
    return events

def get_process_info(pid):
    """Echte Prozessinformationen holen"""
    try:
        cmd = f"ps -p {pid} -o comm= 2>/dev/null || echo 'unknown'"
        result = subprocess.run(cmd, shell=True, capture_output=True, text=True, timeout=5)
        process_name = result.stdout.strip()
        return process_name if process_name else f"pid_{pid}"
    except:
        return f"pid_{pid}"

def correlate_real_events(network_events, sensor_events):
    """Korreliert echte Events"""
    results = []
    
    print("🔗 Korreliere Ereignisse...")
    print(f"   Netzwerk-Events: {len(network_events)}")
    print(f"   Sensor-Events: {len(sensor_events)}")
    
    # Verwende echte Prozessinformationen
    process_map = defaultdict(lambda: {'network': [], 'sensors': set(), 'process_name': ''})
    
    # Netzwerk-Events verarbeiten
    for event in network_events:
        pid = event['pid']
        process_name = get_process_info(pid)
        process_map[pid]['network'].append(event)
        process_map[pid]['process_name'] = process_name
    
    # Sensor-Events verarbeiten
    for event in sensor_events:
        pid = event['pid']
        process_name = get_process_info(pid)
        process_map[pid]['sensors'].add(event['sensor'])
        process_map[pid]['process_name'] = process_name
    
    # Korrelation analysieren
    for pid, data in process_map.items():
        if data['network'] and data['sensors']:
            probability = calculate_real_probability(data['sensors'], data['network'])
            
            if probability > 0.1:  # Niedrigere Schwelle für echte Events
                # Echte IPs finden
                ip_counter = defaultdict(int)
                for net_event in data['network']:
                    ip_counter[net_event['ip']] += 1
                
                most_common_ip = max(ip_counter.items(), key=lambda x: x[1])[0] if ip_counter else "unknown"
                
                results.append({
                    'process': data['process_name'],
                    'pid': pid,
                    'ip': most_common_ip,
                    'ports': list(set(ev['port'] for ev in data['network'])),
                    'sensors': list(data['sensors']),
                    'network_count': len(data['network']),
                    'sensor_count': len(data['sensors']),
                    'probability': round(probability * 100, 2),
                    'risk': 'HIGH' if probability > 0.6 else 'MEDIUM' if probability > 0.3 else 'LOW',
                    'real_data': True
                })
    
    print(f"🔗 Gefundene Korrelationen: {len(results)}")
    return sorted(results, key=lambda x: x['probability'], reverse=True)

def calculate_real_probability(sensors, network_events):
    """Wahrscheinlichkeit für echte Daten"""
    prob = 0.0
    
    # Sensor-Kombinationen
    sensors_list = list(sensors)
    if 'microphone' in sensors_list and 'camera' in sensors_list:
        prob += 0.7
    elif 'microphone' in sensors_list and 'screen' in sensors_list:
        prob += 0.6
    elif len(sensors_list) >= 2:
        prob += 0.5
    elif len(sensors_list) == 1:
        prob += 0.2
    
    # Netzwerkaktivität
    rat_ports = {4444, 5555, 6006, 8443, 5223, 5228, 5242, 5243, 8000, 8001, 50050, 9999}
    network_score = sum(1 for ev in network_events if ev['port'] in rat_ports)
    prob += min(network_score * 0.3, 0.6)
    
    return min(prob, 1.0)

def generate_real_report(results, duration):
    """Generiert Report mit echten Daten"""
    report = {
        'timestamp': datetime.now().isoformat(),
        'scan_duration': duration,
        'total_detections': len(results),
        'detections': results,
        'environment': {
            'kernel': os.uname().release,
            'system': os.uname().sysname,
            'hostname': os.uname().nodename,
            'real_scan': True
        }
    }
    
    with open(RESULTS_FILE, 'w') as f:
        json.dump(report, f, indent=2)
    
    return report

def display_real_results(report):
    """Zeigt echte Ergebnisse"""
    print("\n" + "=" * 100)
    print("🔍 PEGASUS REAL DETECTOR - ECHTE ERGEBNISSE")
    print("=" * 100)
    
    print(f"⏰ Scan-Dauer: {report['scan_duration']}s")
    print(f"📊 Echte Detektionen: {report['total_detections']}")
    print(f"💻 System: {report['environment']['kernel']}")
    
    if report['detections']:
        print(f"\n{'Prozess':<20} {'PID':<6} {'IP':<18} {'Sensoren':<25} {'Wahrscheinlichkeit':<16} {'Risiko'}")
        print("-" * 95)
        
        for detection in report['detections']:
            sensors = "+".join(detection['sensors'])
            prob = detection['probability']
            risk_icon = "🔴" if prob > 60 else "🟡" if prob > 30 else "🟢"
            risk_text = "HOCH" if prob > 60 else "MITTEL" if prob > 30 else "NIEDRIG"
            
            print(f"{detection['process'][:18]:<20} {detection['pid']:<6} "
                  f"{detection['ip']:<18} {sensors[:23]:<25} "
                  f"{risk_icon} {prob:>5.1f}% {'':<3} {risk_text}")
    else:
        print("\n✅ Keine verdächtigen Aktivitäten erkannt")
        print("   Das System scheint sicher zu sein")
    
    print("=" * 100)

def main():
    """Hauptfunktion"""
    print("🦠 Pegasus Real Detector - Echte Überwachung")
    print("🔍 bpftrace-basiert - 180 Sekunden Scan")
    print("⏰ Bitte warten...")
    
    if not check_root():
        print("❌ Root Zugriff erforderlich!")
        return
    
    if not check_bpftrace():
        print("❌ bpftrace nicht gefunden!")
        print("📦 Installiere mit: sudo apt install bpftrace")
        return
    
    print("✅ bpftrace verfügbar")
    
    start_time = time.time()
    
    # Starte sequentielle Überwachung (kein Threading)
    print("\n🚀 Starte echte Systemüberwachung...")
    
    # Zuerst Netzwerk, dann Sensoren (sequentiell für Stabilität)
    network_events = monitor_network_real()
    sensor_events = monitor_sensors_real()
    
    # Korrelation
    results = correlate_real_events(network_events, sensor_events)
    
    # Report
    duration = int(time.time() - start_time)
    report = generate_real_report(results, duration)
    display_real_results(report)
    
    print(f"✅ Echter Report gespeichert: {RESULTS_FILE}")

if __name__ == "__main__":
    main()
