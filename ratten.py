#!/usr/bin/env python3
"""
RATTENJAGD - eBPF-basierter Malware-Detektor (Python-Version)
Erkennt Remote Access Trojans, Rootkits und andere Malware
"""

import os
import sys
import time
import logging
import subprocess
from datetime import datetime
from pathlib import Path

# Konfiguration
LOG_FILE = "/tmp/ratte.log"
ALERT_FILE = "/tmp/rattenjagd_alerts.log"
BPFTRACE_CHECK_INTERVAL = 5  # Sekunden

# Logging einrichten
def setup_logging():
    logging.basicConfig(
        level=logging.INFO,
        format='%(asctime)s - %(levelname)s - %(message)s',
        handlers=[
            logging.FileHandler(LOG_FILE),
            logging.StreamHandler(sys.stdout)
        ]
    )
    return logging.getLogger(__name__)

logger = setup_logging()

def check_bpftrace():
    """Überprüft ob bpftrace installiert ist"""
    try:
        result = subprocess.run(['which', 'bpftrace'], 
                              capture_output=True, text=True)
        if result.returncode == 0:
            logger.info(f"bpftrace gefunden: {result.stdout.strip()}")
            return True
        else:
            logger.error("bpftrace nicht gefunden. Installieren mit: sudo apt-get install bpftrace")
            return False
    except Exception as e:
        logger.error(f"Fehler bei bpftrace Check: {e}")
        return False

def create_bpf_script():
    """Erstellt das eBPF-Skript"""
    bpf_script = """
    BEGIN {
        printf("RATTENJAGD Advanced Monitoring started\\n");
        printf("Detecting: RATs, Rootkits, Trojans, Backdoors\\n");
    }

    // Überwache Prozessstarts
    tracepoint:syscalls:sys_enter_execve
    {
        $filename = str(args->filename);
        $comm = comm;
        $pid = pid;
        
        // Verdächtige Dateipfade
        if (strncmp($filename, "/tmp/", 5) == 0 ||
            strncmp($filename, "/dev/shm/", 9) == 0 ||
            strncmp($filename, "/var/tmp/", 9) == 0) {
            printf("SUSPICIOUS_EXEC| PID:%d %s -> EXEC: %s [Temporary directory]\\n", 
                   $pid, $comm, $filename);
        }
        
        // Versteckte Dateien
        if (strncmp($filename, ".", 1) == 0) {
            printf("SUSPICIOUS_EXEC| PID:%d %s -> EXEC: %s [Hidden file]\\n", 
                   $pid, $comm, $filename);
        }
    }

    // Überwache Netzwerkverbindungen
    kprobe:tcp_connect
    {
        $dport = (arg2 >> 8) | ((arg2 & 0xFF) << 8);
        $pid = pid;
        $comm = comm;
        
        // Bekannte bösartige Ports
        if ($dport == 4444 || $dport == 31337 || $dport == 1337 || 
            $dport == 6667 || $dport == 12345 || $dport == 54321) {
            printf("MALICIOUS_CONNECTION| PID:%d %s -> Port: %d [Known malicious port]\\n", 
                   $pid, $comm, $dport);
        }
    }

    // Überwache Dateioperationen
    tracepoint:syscalls:sys_enter_open
    {
        $filename = str(args->filename);
        $pid = pid;
        $comm = comm;
        
        // Kritische Systemdateien
        if (strncmp($filename, "/etc/passwd", 11) == 0 ||
            strncmp($filename, "/etc/shadow", 11) == 0 || 
            strncmp($filename, "/etc/sudoers", 12) == 0) {
            printf("CRITICAL_FILE_ACCESS| PID:%d %s -> OPEN: %s\\n", 
                   $pid, $comm, $filename);
        }
    }

    END {
        printf("RATTENJAGD Monitoring stopped\\n");
    }
    """
    
    script_path = "/tmp/rattenjagd.bt"
    try:
        with open(script_path, 'w') as f:
            f.write(bpf_script)
        logger.info(f"eBPF-Skript erstellt: {script_path}")
        return script_path
    except Exception as e:
        logger.error(f"Fehler beim Erstellen des eBPF-Skripts: {e}")
        return None

def analyze_event(line):
    """Analysiert eBPF-Ereignisse und erzeugt Alerts"""
    line = line.strip()
    if not line:
        return
    
    logger.info(line)
    
    # Echtzeit-Analyse der Ereignisse
    alert_msg = None
    severity = None
    
    if "SUSPICIOUS_EXEC" in line:
        severity = "HIGH"
        alert_msg = f"Verdächtige Prozessausführung: {line}"
    elif "MALICIOUS_CONNECTION" in line:
        severity = "CRITICAL"
        alert_msg = f"Verdächtige Netzwerkverbindung: {line}"
    elif "CRITICAL_FILE_ACCESS" in line:
        severity = "HIGH"
        alert_msg = f"Zugriff auf kritische Systemdatei: {line}"
    
    if alert_msg and severity:
        alert_line = f"{datetime.now().strftime('%Y-%m-%d %H:%M:%S')} - [{severity}] {alert_msg}"
        try:
            with open(ALERT_FILE, 'a') as f:
                f.write(alert_line + "\n")
            logger.warning(alert_line)
        except Exception as e:
            logger.error(f"Fehler beim Schreiben des Alerts: {e}")

def run_monitoring():
    """Startet die Überwachung"""
    if not check_bpftrace():
        return False
    
    script_path = create_bpf_script()
    if not script_path:
        return False
    
    logger.info("Starte erweiterte Überwachung...")
    logger.info(f"Logging nach: {LOG_FILE}")
    logger.info(f"Alerts nach: {ALERT_FILE}")
    logger.info("Drücken Sie Ctrl+C zum Beenden")
    
    # Alerts-Datei leeren
    try:
        with open(ALERT_FILE, 'w') as f:
            f.write("")
    except Exception as e:
        logger.error(f"Fehler beim Leeren der Alert-Datei: {e}")
    
    # bpftrace starten
    try:
        process = subprocess.Popen(
            ['bpftrace', script_path],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True
        )
        
        logger.info(f"Überwachung gestartet (PID: {process.pid})")
        
        # Ausgabe in Echtzeit verarbeiten
        while True:
            output = process.stdout.readline()
            if output == '' and process.poll() is not None:
                break
            if output:
                analyze_event(output)
        
    except KeyboardInterrupt:
        logger.info("Überwachung wird beendet...")
    except Exception as e:
        logger.error(f"Fehler bei der Überwachung: {e}")
    finally:
        if process:
            process.terminate()
        try:
            os.remove(script_path)
        except:
            pass
    
    return True

def generate_summary():
    """Erstellt eine Zusammenfassung der erkannten Bedrohungen"""
    if not os.path.exists(ALERT_FILE):
        return
    
    try:
        with open(ALERT_FILE, 'r') as f:
            alerts = f.readlines()
        
        if not alerts:
            logger.info("Keine Bedrohungen erkannt")
            return
        
        logger.info("=" * 50)
        logger.info("ZUSAMMENFASSUNG DER BEDROHUNGEN:")
        logger.info("=" * 50)
        
        for alert in alerts:
            logger.info(alert.strip())
        
        # Statistik
        critical_count = sum(1 for alert in alerts if "[CRITICAL]" in alert)
        high_count = sum(1 for alert in alerts if "[HIGH]" in alert)
        medium_count = sum(1 for alert in alerts if "[MEDIUM]" in alert)
        
        logger.info(f"Erkannte Bedrohungen: CRITICAL: {critical_count}, HIGH: {high_count}, MEDIUM: {medium_count}")
        
    except Exception as e:
        logger.error(f"Fehler beim Generieren der Zusammenfassung: {e}")

if __name__ == "__main__":
    logger.info("=" * 50)
    logger.info("RATTENJAGD Überwachung gestartet")
    logger.info("=" * 50)
    
    success = run_monitoring()
    
    if success:
        generate_summary()
    
    logger.info("RATTENJAGD beendet")
