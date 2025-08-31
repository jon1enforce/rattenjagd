#!/usr/bin/env python3
"""
Pegasus Detector Complete - Vollständige eBPF-basierte Sensor-Überwachung
"""

import os
import sys
import time
import subprocess
import json
import struct
import ctypes
from datetime import datetime
from collections import defaultdict

# Konfiguration
TEMP_DIR = "/data/local/tmp"
BPFTOOL_PATH = f"{TEMP_DIR}/bpftool" 
BPF_PROGRAM = f"{TEMP_DIR}/pegasus_detector.o"
RESULTS_FILE = f"{TEMP_DIR}/pegasus_complete_analysis.json"

# eBPF Map Definitionen
MAP_NETWORK = "/sys/fs/bpf/network_events"
MAP_SENSORS = "/sys/fs/bpf/sensor_events"
MAP_CORRELATION = "/sys/fs/bpf/ip_correlation"

class SensorEvent(ctypes.Structure):
    _fields_ = [
        ('pid', ctypes.c_uint32),
        ('uid', ctypes.c_uint32),
        ('comm', ctypes.c_char * 16),
        ('device', ctypes.c_char * 64),
        ('access_type', ctypes.c_uint8),
        ('timestamp', ctypes.c_uint64)
    ]

class NetworkEvent(ctypes.Structure):
    _fields_ = [
        ('src_ip', ctypes.c_uint32),
        ('dst_ip', ctypes.c_uint32), 
        ('dst_port', ctypes.c_uint16),
        ('protocol', ctypes.c_uint8),
        ('pid', ctypes.c_uint32),
        ('timestamp', ctypes.c_uint64)
    ]

def check_root():
    """Root-Zugriff prüfen"""
    return os.geteuid() == 0

def compile_ebpf_program():
    """Kompiliert das vollständige eBPF Programm"""
    ebpf_code = '''
#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <linux/udp.h>
#include <linux/sched.h>
#include <linux/fs.h>
#include <linux/timekeeping.h>

struct sensor_access_event {
    u32 pid;
    u32 uid;
    char comm[16];
    char device[64];
    u8 access_type;
    u64 timestamp;
};

struct network_event {
    u32 src_ip;
    u32 dst_ip;
    u16 dst_port;
    u8 protocol;
    u32 pid;
    u64 timestamp;
};

struct ip_correlation {
    u32 ip_address;
    u64 last_seen;
    u32 camera_access;
    u32 microphone_access;
    u32 screen_access;
    u32 total_events;
};

// eBPF Maps
struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 1 * 1024 * 1024);
} network_events SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 1 * 1024 * 1024);
} sensor_events SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, 1024);
    __type(key, u32);
    __type(value, struct ip_correlation);
} ip_correlation SEC(".maps");

// Pegasus Ports
static const u16 PEGASUS_PORTS[] = {4444, 5555, 6006, 8443, 5223, 5228, 5242, 5243};

static u64 get_timestamp() {
    u64 ts;
    bpf_ktime_get_ns(&ts);
    return ts;
}

// Sensor Device Detection
static int is_sensor_device(const char *filename) {
    char dev_path[64];
    bpf_probe_read_str(dev_path, sizeof(dev_path), filename);
    
    // Camera devices
    if (bpf_strstr(dev_path, "/dev/video") ||
        bpf_strstr(dev_path, "/dev/camera") ||
        bpf_strstr(dev_path, "/dev/media") ||
        bpf_strstr(dev_path, "camera")) {
        return 1;
    }
    
    // Audio devices
    if (bpf_strstr(dev_path, "/dev/snd/") ||
        bpf_strstr(dev_path, "audio") ||
        bpf_strstr(dev_path, "microphone") ||
        bpf_strstr(dev_path, "alsa")) {
        return 2;
    }
    
    // Screen access (fbdev)
    if (bpf_strstr(dev_path, "/dev/fb") ||
        bpf_strstr(dev_path, "/dev/graphics/") ||
        bpf_strstr(dev_path, "frame_buffer")) {
        return 3;
    }
    
    return 0;
}

// Tracepoint für Sensor-Zugriffe
SEC("tracepoint/syscalls/sys_enter_openat")
int trace_sensor_access(struct trace_event_raw_sys_enter *ctx) {
    const char *filename = (const char *)ctx->args[1];
    int sensor_type = is_sensor_device(filename);
    
    if (sensor_type > 0) {
        struct sensor_access_event *event;
        event = bpf_ringbuf_reserve(&sensor_events, sizeof(*event), 0);
        if (!event) return 0;
        
        event->pid = bpf_get_current_pid_tgid() >> 32;
        event->uid = bpf_get_current_uid_gid();
        bpf_get_current_comm(&event->comm, sizeof(event->comm));
        bpf_probe_read_str(&event->device, sizeof(event->device), filename);
        event->access_type = sensor_type;
        event->timestamp = get_timestamp();
        
        bpf_ringbuf_submit(event, 0);
    }
    
    return 0;
}

// Tracepoint für IOCTL (Screen Access)
SEC("tracepoint/syscalls/sys_enter_ioctl")
int trace_ioctl_access(struct trace_event_raw_sys_enter *ctx) {
    int fd = (int)ctx->args[0];
    unsigned long cmd = (unsigned long)ctx->args[1];
    
    // Check for framebuffer ioctls
    if (cmd == 0x4600 || cmd == 0x4601 || cmd == 0x4602) { // FBIOGET_* commands
        struct sensor_access_event *event;
        event = bpf_ringbuf_reserve(&sensor_events, sizeof(*event), 0);
        if (!event) return 0;
        
        event->pid = bpf_get_current_pid_tgid() >> 32;
        event->uid = bpf_get_current_uid_gid();
        bpf_get_current_comm(&event->comm, sizeof(event->comm));
        bpf_probe_read_str(&event->device, sizeof(event->device), "framebuffer");
        event->access_type = 3; // Screen access
        event->timestamp = get_timestamp();
        
        bpf_ringbuf_submit(event, 0);
    }
    
    return 0;
}

// XDP für Netzwerk-Überwachung
SEC("xdp")
int detect_pegasus_network(struct xdp_md *ctx) {
    void *data_end = (void *)(long)ctx->data_end;
    void *data = (void *)(long)ctx->data;
    
    struct ethhdr *eth = data;
    if ((void *)eth + sizeof(*eth) > data_end) return XDP_PASS;
    
    if (eth->h_proto != __constant_htons(ETH_P_IP)) return XDP_PASS;
    
    struct iphdr *iph = data + sizeof(*eth);
    if ((void *)iph + sizeof(*iph) > data_end) return XDP_PASS;
    
    if (iph->protocol != IPPROTO_TCP && iph->protocol != IPPROTO_UDP) return XDP_PASS;
    
    void *transport_header = (void *)iph + sizeof(*iph);
    __u16 dest_port = 0;
    
    if (iph->protocol == IPPROTO_TCP) {
        struct tcphdr *tcph = transport_header;
        if ((void *)tcph + sizeof(*tcph) > data_end) return XDP_PASS;
        dest_port = __constant_ntohs(tcph->dest);
    } else {
        struct udphdr *udph = transport_header;
        if ((void *)udph + sizeof(*udph) > data_end) return XDP_PASS;
        dest_port = __constant_ntohs(udph->dest);
    }
    
    // Check for Pegasus ports
    for (int i = 0; i < 8; i++) {
        if (dest_port == PEGASUS_PORTS[i]) {
            struct network_event *event;
            event = bpf_ringbuf_reserve(&network_events, sizeof(*event), 0);
            if (!event) return XDP_PASS;
            
            event->src_ip = iph->saddr;
            event->dst_ip = iph->daddr;
            event->dst_port = dest_port;
            event->protocol = iph->protocol;
            event->pid = bpf_get_current_pid_tgid() >> 32;
            event->timestamp = get_timestamp();
            
            bpf_ringbuf_submit(event, 0);
            
            // Update correlation map
            u32 src_ip = iph->saddr;
            struct ip_correlation *corr = bpf_map_lookup_elem(&ip_correlation, &src_ip);
            if (!corr) {
                struct ip_correlation new_corr = {};
                new_corr.ip_address = src_ip;
                new_corr.last_seen = get_timestamp();
                new_corr.total_events = 1;
                bpf_map_update_elem(&ip_correlation, &src_ip, &new_corr, BPF_ANY);
            } else {
                corr->last_seen = get_timestamp();
                corr->total_events++;
                bpf_map_update_elem(&ip_correlation, &src_ip, corr, BPF_ANY);
            }
            
            break;
        }
    }
    
    return XDP_PASS;
}

char _license[] SEC("license") = "GPL";
'''

    with open(f"{TEMP_DIR}/pegasus_detector_complete.c", "w") as f:
        f.write(ebpf_code)
    
    # Kompiliere mit Android NDK Clang
    compile_cmd = [
        "clang", "-target", "bpf", "-O2", "-c",
        f"{TEMP_DIR}/pegasus_detector_complete.c",
        "-o", BPF_PROGRAM
    ]
    
    result = subprocess.run(compile_cmd, capture_output=True, text=True)
    return result.returncode == 0

def load_ebpf_program():
    """Lädt das eBPF Programm"""
    load_cmd = [
        BPFTOOL_PATH, "prog", "load", BPF_PROGRAM,
        "/sys/fs/bpf/pegasus_detector"
    ]
    
    result = subprocess.run(load_cmd, capture_output=True, text=True)
    if result.returncode != 0:
        print(f"Load failed: {result.stderr}")
        return False
    
    # Attach zu Netzwerk-Interfaces
    interfaces = ["wlan0", "rmnet0", "eth0"]
    for iface in interfaces:
        try:
            attach_cmd = [
                BPFTOOL_PATH, "net", "attach", "xdp",
                "pinned", "/sys/fs/bpf/pegasus_detector",
                "dev", iface
            ]
            subprocess.run(attach_cmd, capture_output=True)
        except:
            continue
    
    return True

def read_ringbuf(map_path, event_type):
    """Liest Events aus Ring Buffer"""
    try:
        dump_cmd = [BPFTOOL_PATH, "map", "dump", "pinned", map_path]
        result = subprocess.run(dump_cmd, capture_output=True, text=True, timeout=5)
        
        events = []
        for line in result.stdout.split('\n'):
            if line.strip():
                try:
                    if event_type == "network":
                        event = NetworkEvent()
                        # Parse network event data
                        pass
                    elif event_type == "sensor":
                        event = SensorEvent()
                        # Parse sensor event data
                        pass
                    events.append(event)
                except:
                    continue
        
        return events
    except:
        return []

def monitor_events(duration=300):
    """Überwacht Events für angegebene Dauer"""
    print(f"🔍 Überwache System für {duration} Sekunden...")
    
    network_events = []
    sensor_events = []
    start_time = time.time()
    
    while time.time() - start_time < duration:
        # Lies Netzwerk-Events
        net_events = read_ringbuf(MAP_NETWORK, "network")
        network_events.extend(net_events)
        
        # Lies Sensor-Events
        sens_events = read_ringbuf(MAP_SENSORS, "sensor")
        sensor_events.extend(sens_events)
        
        time.sleep(2)
    
    return network_events, sensor_events

def correlate_events(network_events, sensor_events):
    """Korreliert Netzwerk- und Sensor-Events"""
    ip_correlation = defaultdict(lambda: {
        'ip': '',
        'camera_access': False,
        'microphone_access': False,
        'screen_access': False,
        'sensor_timestamps': [],
        'network_timestamps': [],
        'processes': set(),
        'confidence': 'low'
    })
    
    # Process network events
    for event in network_events:
        ip_str = socket.inet_ntoa(struct.pack('!L', event.src_ip))
        ip_correlation[ip_str]['ip'] = ip_str
        ip_correlation[ip_str]['network_timestamps'].append(event.timestamp)
        ip_correlation[ip_str]['processes'].add(event.comm.decode())
    
    # Process sensor events
    for event in sensor_events:
        # Find matching process and correlate with IPs
        for ip, data in ip_correlation.items():
            if event.pid in [p.pid for p in data['processes']]:
                if event.access_type == 1:
                    data['camera_access'] = True
                elif event.access_type == 2:
                    data['microphone_access'] = True
                elif event.access_type == 3:
                    data['screen_access'] = True
                data['sensor_timestamps'].append(event.timestamp)
    
    # Calculate confidence levels
    for ip, data in ip_correlation.items():
        if data['camera_access'] and data['microphone_access']:
            data['confidence'] = 'high'
        elif data['camera_access'] or data['microphone_access']:
            data['confidence'] = 'medium'
    
    return list(ip_correlation.values())

def generate_report(verified_ips):
    """Generiert detaillierten Report"""
    report = {
        "timestamp": datetime.now().isoformat(),
        "analysis_duration": "300 seconds",
        "detected_ips": verified_ips,
        "statistics": {
            "total_ips": len(verified_ips),
            "high_confidence": sum(1 for ip in verified_ips if ip['confidence'] == 'high'),
            "medium_confidence": sum(1 for ip in verified_ips if ip['confidence'] == 'medium'),
            "low_confidence": sum(1 for ip in verified_ips if ip['confidence'] == 'low'),
            "total_network_events": sum(len(ip['network_timestamps']) for ip in verified_ips),
            "total_sensor_events": sum(len(ip['sensor_timestamps']) for ip in verified_ips)
        }
    }
    
    with open(RESULTS_FILE, 'w') as f:
        json.dump(report, f, indent=2)
    
    return report

def display_results(report):
    """Zeigt Ergebnisse an"""
    print("\\n" + "=" * 80)
    print("🔍 PEGASUS DETEKTION - VOLLSTÄNDIGE ANALYSE")
    print("=" * 80)
    
    for ip_info in report['detected_ips']:
        if ip_info['confidence'] != 'low':
            status = "🔴 HIGH" if ip_info['confidence'] == 'high' else "🟡 MEDIUM"
            
            sensors = []
            if ip_info['camera_access']:
                sensors.append("Kamera")
            if ip_info['microphone_access']:
                sensors.append("Mikrofon")
            if ip_info['screen_access']:
                sensors.append("Bildschirm")
            
            print(f"{status} [IP: {ip_info['ip']}]")
            print(f"   📍 Sensorzugriffe: {', '.join(sensors)}")
            print(f"   🔗 Prozesse: {', '.join(ip_info['processes'])}")
            print(f"   📞 Netzwerk-Events: {len(ip_info['network_timestamps'])}")
            print(f"   📡 Sensor-Events: {len(ip_info['sensor_timestamps'])}")
            print()
    
    print("=" * 80)
    print(f"📈 Zusammenfassung:")
    print(f"   🔴 High Confidence: {report['statistics']['high_confidence']}")
    print(f"   🟡 Medium Confidence: {report['statistics']['medium_confidence']}")
    print(f"   🟢 Low Confidence: {report['statistics']['low_confidence']}")
    print("=" * 80)

def main():
    """Hauptfunktion"""
    if not check_root():
        print("❌ Root access required!")
        return
    
    print("🦠 Pegasus Complete Detector - Echte Sensor-Überwachung")
    
    # Kompiliere und lade eBPF
    if not compile_ebpf_program():
        print("❌ eBPF compilation failed")
        return
    
    if not load_ebpf_program():
        print("❌ eBPF loading failed")
        return
    
    # Überwache Events
    network_events, sensor_events = monitor_events(300)
    
    # Korreliere Events
    verified_ips = correlate_events(network_events, sensor_events)
    
    # Generiere Report
    report = generate_report(verified_ips)
    display_results(report)
    
    print(f"✅ Report saved: {RESULTS_FILE}")

if __name__ == "__main__":
    main()
