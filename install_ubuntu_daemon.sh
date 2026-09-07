#!/usr/bin/env bash
# ==============================================================================
# AIVA-KS (AI Linux Defender for Ubuntu / Debian / Linux) Installer Script
# ==============================================================================
set -e

echo "=========================================================="
echo "  Installing AIVA-KS Linux Defender & System Service"
echo "=========================================================="

CURRENT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# 1. Verify / install Python virtualenv dependencies
if [ ! -d "$CURRENT_DIR/.venv" ]; then
    echo "[*] Initializing python virtual environment..."
    python3 -m venv "$CURRENT_DIR/.venv"
fi

echo "[*] Installing required Linux security & API dependencies..."
"$CURRENT_DIR/.venv/bin/pip" install -q -e "$CURRENT_DIR[dev,backend]"

# 2. Build Frontend UI
if [ -d "$CURRENT_DIR/frontend" ]; then
    echo "[*] Building SOC Visualizer Frontend..."
    (cd "$CURRENT_DIR/frontend" && npm run build)
fi

# 3. Register Systemd Service if root
if [ "$EUID" -eq 0 ]; then
    echo "[*] Registering systemd daemon service: /etc/systemd/system/aiva-ks.service"
    cat << SYSTEMD_EOF > /etc/systemd/system/aiva-ks.service
[Unit]
Description=AIVA-KS AI-Powered Linux Defender & Kernel Security Engine
Documentation=https://github.com/TraceHanami/AIVA-Ks
After=network.target network-online.target
Wants=network-online.target

[Service]
Type=simple
User=root
WorkingDirectory=$CURRENT_DIR
ExecStart=$CURRENT_DIR/.venv/bin/uvicorn app.main:app --app-dir backend --host 0.0.0.0 --port 8000
Restart=always
RestartSec=5s
LimitNOFILE=65536
LimitNPROC=4096
StandardOutput=journal
StandardError=journal
SyslogIdentifier=aiva-ks

[Install]
WantedBy=multi-user.target
SYSTEMD_EOF

    systemctl daemon-reload
    systemctl enable --now aiva-ks
    echo "[+] AIVA-KS Defender Service enabled and started successfully!"
    echo "    Check status with: systemctl status aiva-ks"
else
    echo "[!] Run as root (sudo) to install the systemd service automatically."
    echo "    Or run locally right now with: make run"
fi

echo "=========================================================="
echo "  AIVA-KS Linux Defender Ready!"
echo "  Web UI Dashboard: http://localhost:5173"
echo "  Defender API & Docs: http://localhost:8000/docs"
echo "=========================================================="
