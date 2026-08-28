#!/usr/bin/env python3
"""
AIVA-KS Live Host OS Telemetry Collector.

Monitors real processes, network connections, and system activities on your
Linux host and streams them directly into the AIVA-KS Backend API in real time.
"""
import os
import socket
import sys
import time
import urllib.request
import json
import psutil

BACKEND_API_URL = os.environ.get("AIVA_API_URL", "http://127.0.0.1:8000/api/events/ingest")
HOST_ID = os.environ.get("AIVA_HOST_ID", socket.gethostname())

def post_event(event_dict: dict):
    try:
        data = json.dumps(event_dict).encode("utf-8")
        req = urllib.request.Request(
            BACKEND_API_URL,
            data=data,
            headers={"Content-Type": "application/json"}
        )
        with urllib.request.urlopen(req, timeout=2) as response:
            pass
    except Exception:
        pass

def stream_initial_process_tree():
    print(f"[*] Discovering running host processes on {HOST_ID}...")
    count = 0
    for proc in psutil.process_iter(['pid', 'ppid', 'name', 'cmdline']):
        try:
            pinfo = proc.info
            pid = pinfo['pid']
            ppid = pinfo['ppid'] or 1
            comm = pinfo['name'] or f"proc_{pid}"
            cmdline = " ".join(pinfo['cmdline'] or [])

            event = {
                "event_type": "execve",
                "pid": pid,
                "ppid": ppid,
                "comm": comm,
                "target_path": cmdline[:100] if cmdline else f"/{comm}",
                "anomaly_score": 0.0,
            }
            post_event(event)
            count += 1
            if count >= 30:  # Initial rich baseline
                break
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            continue

    print(f"[+] Initialized baseline with {count} active host processes.")

def stream_network_connections():
    try:
        connections = psutil.net_connections(kind='inet')
        for conn in connections:
            if conn.raddr and conn.pid:
                try:
                    p = psutil.Process(conn.pid)
                    comm = p.name()
                except Exception:
                    comm = "network_proc"

                event = {
                    "event_type": "connect",
                    "pid": conn.pid,
                    "ppid": 1,
                    "comm": comm,
                    "target_ip": conn.raddr.ip,
                    "target_port": conn.raddr.port,
                    "anomaly_score": 0.1,
                }
                post_event(event)
    except (psutil.AccessDenied, Exception):
        pass

def monitor_live():
    print(f"[+] Real-time OS telemetry collector active. Monitoring host: {HOST_ID}")
    seen_pids = set(psutil.pids())

    while True:
        try:
            current_pids = set(psutil.pids())
            new_pids = current_pids - seen_pids

            for pid in new_pids:
                try:
                    p = psutil.Process(pid)
                    ppid = p.ppid()
                    comm = p.name()
                    cmdline = " ".join(p.cmdline())

                    anomaly = 0.0
                    if any(susp in comm.lower() for susp in ["bash", "sh", "python", "curl", "wget", "nmap", "nc", "socat"]):
                        anomaly = 0.3

                    event = {
                        "event_type": "execve",
                        "pid": pid,
                        "ppid": ppid,
                        "comm": comm,
                        "target_path": cmdline[:120] if cmdline else f"/{comm}",
                        "anomaly_score": anomaly,
                    }
                    post_event(event)
                    print(f"[LIVE OS EVENT] New Process: {comm} (PID: {pid}, PPID: {ppid})")
                except (psutil.NoSuchProcess, psutil.AccessDenied):
                    pass

            seen_pids = current_pids
            stream_network_connections()
            time.sleep(1.5)
        except KeyboardInterrupt:
            break
        except Exception:
            time.sleep(2)

if __name__ == "__main__":
    stream_initial_process_tree()
    stream_network_connections()
    monitor_live()
