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
import signal
import threading
from datetime import datetime

# Konfiguration
CURRENT_DIR = os.path.dirname(os.path.abspath(__file__)) or os.getcwd()
TIMESTAMP = datetime.now().strftime("%Y%m%d_%H%M%S")
LOG_FILE = os.path.join(CURRENT_DIR, f"rattenjagd_{TIMESTAMP}.log")
TARGET_LINES = 100000  # Ziel: 100.000 Zeilen für normierte Log-Größe

# Global variable to control monitoring
monitoring_active = True
line_count = 0

# Logging einrichten
def setup_logging():
    logger = logging.getLogger("RATTENJAGD")
    logger.setLevel(logging.INFO)
    
    formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')
    
    file_handler = logging.FileHandler(LOG_FILE)
    file_handler.setFormatter(formatter)
    
    console_handler = logging.StreamHandler(sys.stdout)
    console_handler.setFormatter(formatter)
    
    logger.addHandler(file_handler)
    logger.addHandler(console_handler)
    
    return logger

logger = setup_logging()

def signal_handler(sig, frame):
    global monitoring_active
    logger.info("Abbruch durch Benutzer...")
    monitoring_active = False

signal.signal(signal.SIGINT, signal_handler)

def print_progress():
    """Gibt einen Progress-Balken aus"""
    global line_count
    progress = min(100, int((line_count / TARGET_LINES) * 100))
    bar_length = 40
    filled_length = int(bar_length * progress / 100)
    bar = '█' * filled_length + '░' * (bar_length - filled_length)
    sys.stdout.write(f'\rProgress: |{bar}| {progress}% ({line_count}/{TARGET_LINES} lines)')
    sys.stdout.flush()

def check_bpftrace():
    try:
        result = subprocess.run(['which', 'bpftrace'], 
                              capture_output=True, text=True, timeout=5)
        if result.returncode != 0:
            logger.error("bpftrace nicht gefunden. Installieren mit: sudo apt-get install bpftrace")
            return False
            
        logger.info(f"bpftrace gefunden: {result.stdout.strip()}")
        
        # Einfacher Test
        test_result = subprocess.run(['bpftrace', '-e', 'BEGIN { printf("Test\\n"); exit() }'],
                                   capture_output=True, text=True, timeout=10)
        if test_result.returncode == 0:
            return True
        else:
            logger.error(f"bpftrace Test fehlgeschlagen: {test_result.stderr}")
            return False
            
    except Exception as e:
        logger.error(f"Fehler bei bpftrace Check: {e}")
        return False

def create_bpf_script():
    """Erstellt ein einfacheres eBPF-Skript ohne includes"""
    bpf_script = """
BEGIN {
    printf("RATTENJAGD_START| TargetLines:%d\\n", 100000);
}

// Prozessüberwachung
tracepoint:syscalls:sys_enter_execve {
    printf("EVENT_EXEC| PID:%d COMM:%s FILE:%s\\n", 
           pid, comm, str(args->filename));
}

// Dateioperationen
tracepoint:syscalls:sys_enter_open,
tracepoint:syscalls:sys_enter_openat {
    printf("EVENT_FILE| PID:%d COMM:%s FILE:%s\\n", 
           pid, comm, str(args->filename));
    
    // Kritische Dateien
    if (str(args->filename) == "/etc/passwd" || 
        str(args->filename) == "/etc/shadow" ||
        str(args->filename) == "/etc/sudoers") {
        printf("CRITICAL_FILE| PID:%d COMM:%s FILE:%s\\n", 
               pid, comm, str(args->filename));
    }
}

// Netzwerkverbindungen
kprobe:tcp_connect {
    $dport = (arg2 >> 8) | ((arg2 & 0xFF) << 8);
    printf("EVENT_NETWORK| PID:%d COMM:%s PORT:%d\\n", 
           pid, comm, $dport);
    
    // Verdächtige Ports
    if ($dport == 4444 || $dport == 31337 || $dport == 1337 || 
        $dport == 6667 || $dport == 12345 || $dport == 54321) {
        printf("SUSPICIOUS_PORT| PID:%d COMM:%s PORT:%d\\n", 
               pid, comm, $dport);
    }
}

// Heartbeat
interval:s:2 {
    printf("HEARTBEAT| STATUS:active\\n");
}

END {
    printf("RATTENJAGD_END| TotalLines:%d\\n", 100000);
}
"""
    
    script_path = f"/tmp/rattenjagd_{TIMESTAMP}.bt"
    try:
        with open(script_path, 'w') as f:
            f.write(bpf_script)
        os.chmod(script_path, 0o755)
        logger.info(f"eBPF-Skript erstellt: {script_path}")
        return script_path
    except Exception as e:
        logger.error(f"Fehler beim Erstellen des eBPF-Skripts: {e}")
        return None

def analyze_event(line):
    global line_count
    line = line.strip()
    if not line:
        return
    
    try:
        # Erhöhe Zeilenzähler
        line_count += 1
        
        # Logge alle Events für den Autoencoder
        logger.info(f"EVENT| {line}")
        
        # Fortschritt anzeigen
        if line_count % 100 == 0 or line_count >= TARGET_LINES:
            print_progress()
        
        # Spezielle Behandlung für kritische Events
        if "CRITICAL_FILE" in line:
            logger.warning(f"ALERT| {line}")
        elif "SUSPICIOUS_PORT" in line:
            logger.warning(f"ALERT| {line}")
            
    except Exception as e:
        logger.error(f"Fehler beim Analysieren: {e}")

def run_monitoring():
    global monitoring_active, line_count
    
    if not check_bpftrace():
        return False
    
    script_path = create_bpf_script()
    if not script_path:
        return False
    
    logger.info("=" * 60)
    logger.info("RATTENJAGD - Starte Überwachung")
    logger.info(f"Ziel: {TARGET_LINES} Zeilen für normierte Log-Größe")
    logger.info(f"Log: {LOG_FILE}")
    logger.info("=" * 60)
    
    process = None
    line_count = 0
    
    try:
        # Starte bpftrace
        cmd = ['bpftrace', script_path]
        
        process = subprocess.Popen(
            cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            bufsize=1,
            universal_newlines=True
        )
        
        logger.info(f"Überwachung gestartet (PID: {process.pid})")
        print_progress()
        
        # Stderr in separatem Thread lesen
        def read_stderr():
            while monitoring_active and process.poll() is None:
                try:
                    err_line = process.stderr.readline()
                    if err_line:
                        logger.error(f"BPFTRACE_ERR: {err_line.strip()}")
                    time.sleep(0.1)
                except Exception as e:
                    break
        
        stderr_thread = threading.Thread(target=read_stderr)
        stderr_thread.daemon = True
        stderr_thread.start()
        
        # Haupt-Loop für stdout
        while line_count < TARGET_LINES and monitoring_active:
            if process.poll() is not None:
                returncode = process.poll()
                stderr_output = process.stderr.read()
                if returncode != 0:
                    logger.error(f"bpftrace wurde beendet (Code: {returncode})")
                    if stderr_output:
                        logger.error(f"Fehlerausgabe: {stderr_output}")
                break
            
            # Read stdout
            try:
                output = process.stdout.readline()
                if output:
                    analyze_event(output)
                else:
                    time.sleep(0.1)
            except Exception as e:
                logger.error(f"Fehler beim Lesen: {e}")
                break
        
        monitoring_active = False
        print_progress()
        print()
        
    except KeyboardInterrupt:
        logger.info("Abbruch durch Benutzer")
    except Exception as e:
        logger.error(f"Fehler: {e}")
    finally:
        if process and process.poll() is None:
            try:
                process.terminate()
                time.sleep(1)
                if process.poll() is None:
                    process.kill()
            except Exception as e:
                logger.error(f"Fehler beim Beenden: {e}")
        
        try:
            os.remove(script_path)
            logger.info("eBPF-Skript gelöscht")
        except:
            pass
    
    return True

def generate_summary():
    if not os.path.exists(LOG_FILE):
        logger.info("Keine Log-Datei gefunden")
        return
    
    try:
        with open(LOG_FILE, 'r') as f:
            lines = f.readlines()
        
        event_count = len([l for l in lines if 'EVENT|' in l])
        alert_count = len([l for l in lines if 'ALERT|' in l])
        
        logger.info("=" * 60)
        logger.info("ZUSAMMENFASSUNG")
        logger.info("=" * 60)
        logger.info(f"Gesamte Zeilen: {len(lines)}")
        logger.info(f"Events: {event_count}")
        logger.info(f"Alerts: {alert_count}")
        logger.info("=" * 60)
        
    except Exception as e:
        logger.error(f"Fehler bei Zusammenfassung: {e}")

if __name__ == "__main__":
    try:
        logger.info("RATTENJAGD startet...")
        
        if os.geteuid() != 0:
            logger.warning("bpftrace benötigt normalerweise sudo Rechte")
        
        success = run_monitoring()
        generate_summary()
        logger.info("Fertig")
        
    except Exception as e:
        logger.error(f"Unerwarteter Fehler: {e}")
