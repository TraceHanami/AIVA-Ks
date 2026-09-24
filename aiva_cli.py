#!/usr/bin/env python3
"""
AIVA-KS Linux Defender CLI (MpCmdRun equivalent for Linux/Ubuntu).
Allows analysts and system administrators to run on-demand scans,
check protection status, manage quarantine, and trigger remediation from the terminal.
"""
import argparse
import json
import os
import sys
import urllib.request

API_BASE = os.environ.get("AIVA_API_URL", "http://127.0.0.1:8000")


def query_api(endpoint: str, method: str = "GET", data: dict = None):
    url = f"{API_BASE}{endpoint}"
    req_data = json.dumps(data).encode("utf-8") if data else None
    headers = {"Content-Type": "application/json"} if data else {}
    req = urllib.request.Request(url, data=req_data, headers=headers, method=method)
    try:
        with urllib.request.urlopen(req, timeout=5) as resp:
            return json.loads(resp.read().decode("utf-8"))
    except Exception as e:
        print(f"[!] Error connecting to AIVA Defender Daemon at {API_BASE}: {e}")
        sys.exit(1)


def cmd_status(args):
    data = query_api("/api/health?host=live")
    summary = query_api("/api/dashboard/summary?host=live")
    print("================================================================================")
    print("                AIVA-KS LINUX DEFENDER & EDR STATUS REPORT                      ")
    print("================================================================================")
    print(f"  Daemon Status:       ONLINE (Healthy)")
    print(f"  Protected Host:      {data.get('host')}")
    print(f"  Active OS Entities:  {summary['stats']['node_count']} processes/sockets tracked")
    print(f"  Live Threat Events:  {summary['stats']['total_events']} events ingested")
    print(f"  Overall Threat Risk: {summary['overall_risk'] * 100:.1f}%")
    print(f"  Pending Approvals:   {summary['stats']['pending_approvals']} actions awaiting analyst authorization")
    print("================================================================================")


def cmd_scan_file(args):
    filepath = os.path.abspath(args.path)
    print(f"[*] Scanning file: {filepath} ...")
    res = query_api("/api/scan/file", method="POST", data={"path": filepath})
    r = res["result"]
    print("--------------------------------------------------------------------------------")
    if r["is_threat"]:
        print(f"[!] THREAT DETECTED: {r['threat_name']}")
        print(f"    Threat Type: {r['threat_type']}")
        print(f"    Severity:    {r['severity']}")
        print(f"    Confidence:  {r['confidence'] * 100:.0f}%")
        print(f"    SHA-256:     {r['sha256']}")
        print(f"    Description: {r['description']}")
    else:
        print(f"[+] CLEAN: {r['path']}")
        print(f"    SHA-256: {r['sha256']}")
        print(f"    Status:  {r['description']}")
    print("--------------------------------------------------------------------------------")


def cmd_scan_dir(args):
    dirpath = os.path.abspath(args.path)
    print(f"[*] Recursively scanning directory: {dirpath} (max: {args.limit} files)...")
    res = query_api("/api/scan/directory", method="POST", data={"path": dirpath, "max_files": args.limit})
    threats = res["threats"]
    print("--------------------------------------------------------------------------------")
    print(f"  Scanned: {res['scanned_path']}")
    print(f"  Threats Found: {res['threats_found_count']}")
    for idx, t in enumerate(threats, 1):
        print(f"  [{idx}] {t['threat_name']} ({t['severity']}) -> {t['path']}")
    if not threats:
        print("  [+] No threat signatures detected in scanned files.")
    print("--------------------------------------------------------------------------------")


def main():
    parser = argparse.ArgumentParser(description="AIVA-KS Linux Defender Control Utility")
    subparsers = parser.add_subparsers(dest="command", required=True)

    # Status
    p_status = subparsers.add_parser("status", help="Show active defender and EDR engine status")
    p_status.set_defaults(func=cmd_status)

    # Scan File
    p_scan = subparsers.add_parser("scan", help="Scan a specific file on disk")
    p_scan.add_argument("path", help="Path to file to scan")
    p_scan.set_defaults(func=cmd_scan_file)

    # Scan Dir
    p_scandir = subparsers.add_parser("scandir", help="Scan a directory recursively")
    p_scandir.add_argument("path", help="Directory path to scan")
    p_scandir.add_argument("--limit", type=int, default=300, help="Max files to scan")
    p_scandir.set_defaults(func=cmd_scan_dir)

    args = parser.parse_args()
    args.func(args)


if __name__ == "__main__":
    main()
