"""
CHRONOS Sensors — Live Host Telemetry Collector (Module 1).

Background async worker that collects live host telemetry via psutil and system sensors
to continuously feed the live security state.
"""
from __future__ import annotations

import asyncio
import os
import socket
import psutil
from chronos.intelligence.scanner import SignatureEngine

scanner = SignatureEngine()


async def live_collector_worker(app_manager):
    """Background async worker collecting live host process and network telemetry."""
    st = app_manager.live_state

    # 1. Baseline process tree snapshot
    count = 0
    for proc in psutil.process_iter(['pid', 'ppid', 'name', 'cmdline']):
        try:
            pinfo = proc.info
            pid = pinfo['pid']
            ppid = pinfo['ppid'] or 1
            comm = pinfo['name'] or f"proc_{pid}"
            cmdline = " ".join(pinfo['cmdline'] or [])

            st.add_event({
                "event_type": "execve",
                "pid": pid,
                "ppid": ppid,
                "comm": comm,
                "target_path": cmdline[:100] if cmdline else f"/{comm}",
                "anomaly_score": 0.0,
            })
            count += 1
            if count >= 35:
                break
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            continue

    # 2. Initial network connections
    try:
        connections = psutil.net_connections(kind='inet')
        for conn in connections:
            if conn.raddr and conn.pid:
                try:
                    p = psutil.Process(conn.pid)
                    comm = p.name()
                except Exception:
                    comm = "network_proc"

                st.add_event({
                    "event_type": "connect",
                    "pid": conn.pid,
                    "ppid": 1,
                    "comm": comm,
                    "target_ip": conn.raddr.ip,
                    "target_port": conn.raddr.port,
                    "anomaly_score": 0.05,
                })
    except (psutil.AccessDenied, Exception):
        pass

    # 3. Continuous real-time polling loop
    seen_pids = set(psutil.pids())
    tick = 0
    while True:
        try:
            await asyncio.sleep(0.5)
            tick += 1
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
                        anomaly = 0.25

                    try:
                        exe_path = p.exe()
                        if exe_path and os.path.exists(exe_path):
                            scan_res = scanner.scan_file(exe_path)
                            if scan_res.is_threat:
                                anomaly = max(anomaly, scan_res.confidence)
                    except (psutil.AccessDenied, Exception):
                        pass

                    st.add_event({
                        "event_type": "execve",
                        "pid": pid,
                        "ppid": ppid,
                        "comm": comm,
                        "target_path": cmdline[:120] if cmdline else f"/{comm}",
                        "anomaly_score": anomaly,
                    })
                except (psutil.NoSuchProcess, psutil.AccessDenied):
                    pass

            seen_pids = current_pids

            if tick % 3 == 0:
                try:
                    for conn in psutil.net_connections(kind='inet'):
                        if conn.raddr and conn.pid:
                            try:
                                p = psutil.Process(conn.pid)
                                comm = p.name()
                            except Exception:
                                comm = "network_proc"
                            st.add_event({
                                "event_type": "connect",
                                "pid": conn.pid,
                                "ppid": 1,
                                "comm": comm,
                                "target_ip": conn.raddr.ip,
                                "target_port": conn.raddr.port,
                                "anomaly_score": 0.05,
                            })
                except Exception:
                    pass

        except asyncio.CancelledError:
            break
        except Exception:
            await asyncio.sleep(2.0)
