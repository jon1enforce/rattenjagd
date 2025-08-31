#!/bin/bash
# Sensor Monitor für echte Hardware-Überwachung
# 1. Sensor-Monitoring starten
#chmod +x sensor_monitor.sh
#./sensor_monitor.sh start

# 2. Haupt-Detektor ausführen
#python3 pegasus_detector_complete.py

# 3. Ergebnisse analysieren
#cat /data/local/tmp/pegasus_complete_analysis.json

# 4. Monitoring stoppen
#./sensor_monitor.sh stop
# Überwache Camera Zugriffe
monitor_camera() {
    echo "📷 Überwache Kamerazugriffe..."
    inotifywait -m /dev/video* /dev/camera* 2>/dev/null | while read path action file; do
        echo "$(date): CAMERA_ACCESS - $path$file ($action)" >> /data/local/tmp/camera_access.log
    done
}

# Überwache Audio Zugriffe  
monitor_audio() {
    echo "🎤 Überwache Audiozugriffe..."
    inotifywait -m /dev/snd/ 2>/dev/null | while read path action file; do
        echo "$(date): AUDIO_ACCESS - $path$file ($action)" >> /data/local/tmp/audio_access.log
    done
}

# Überwache Framebuffer Zugriffe
monitor_screen() {
    echo "📺 Überwache Bildschirmzugriffe..."
    inotifywait -m /dev/fb* /dev/graphics/ 2>/dev/null | while read path action file; do
        echo "$(date): SCREEN_ACCESS - $path$file ($action)" >> /data/local/tmp/screen_access.log
    done
}

# Starte alle Monitor
start_monitoring() {
    monitor_camera &
    monitor_audio & 
    monitor_screen &
    echo "✅ Sensor-Monitoring gestartet"
}

case "$1" in
    "start")
        start_monitoring
        ;;
    "stop")
        pkill -f inotifywait
        echo "✅ Sensor-Monitoring gestoppt"
        ;;
    *)
        echo "Usage: $0 {start|stop}"
        ;;
esac
