#!/usr/bin/env bash
# ==============================================================================
# CHRONOS — Linux & Ubuntu Boot Security Scanner & Defender Service Installer
# ==============================================================================
set -e

echo "=========================================================="
echo "  Installing CHRONOS Linux Defender & Boot Security Service"
echo "=========================================================="

CURRENT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# 1. Verify / install Python virtualenv dependencies
if [ ! -d "$CURRENT_DIR/.venv" ]; then
    echo "[*] Initializing python virtual environment..."
    python3 -m venv "$CURRENT_DIR/.venv"
fi

echo "[*] Installing required Linux security & API dependencies..."
"$CURRENT_DIR/.venv/bin/pip" install -q -e "$CURRENT_DIR[dev,backend]"

# 2. Build Frontend UI if npm is available
if command -v npm >/dev/null 2>&1 && [ -d "$CURRENT_DIR/frontend" ]; then
    echo "[*] Building SOC Visualizer Frontend..."
    (cd "$CURRENT_DIR/frontend" && [ -d node_modules ] || npm install; npm run build)
fi

# 3. Create global symlink for 'chronos' CLI in /usr/local/bin
if [ "$EUID" -eq 0 ]; then
    echo "[*] Creating global /usr/local/bin/chronos CLI symlink..."
    ln -sf "$CURRENT_DIR/.venv/bin/chronos" /usr/local/bin/chronos

    # 4. Register Early-Boot Integrity & Vulnerability Scanner Service
    echo "[*] Registering early-boot auditor service: /etc/systemd/system/chronos-boot-scan.service"
    cat << BOOT_SYSTEMD_EOF > /etc/systemd/system/chronos-boot-scan.service
[Unit]
Description=CHRONOS Early Boot Security & Vulnerability Auditor
Documentation=https://github.com/TraceHanami/AIVA-Ks
DefaultDependencies=no
After=local-fs.target systemd-sysctl.service
Before=sysinit.target network.target basic.target multi-user.target
Conflicts=shutdown.target

[Service]
Type=oneshot
RemainAfterExit=yes
User=root
WorkingDirectory=$CURRENT_DIR
ExecStart=$CURRENT_DIR/.venv/bin/python -m chronos.intelligence.boot_scanner
StandardOutput=journal+console
StandardError=journal+console
TimeoutSec=30s

[Install]
WantedBy=sysinit.target
BOOT_SYSTEMD_EOF

    # 5. Register Continuous Defender Daemon Service
    echo "[*] Registering continuous defender daemon: /etc/systemd/system/chronos.service"
    cat << DAEMON_SYSTEMD_EOF > /etc/systemd/system/chronos.service
[Unit]
Description=CHRONOS Cyber Threat Understanding & Response OS Daemon
Documentation=https://github.com/TraceHanami/AIVA-Ks
After=network.target network-online.target chronos-boot-scan.service
Wants=network-online.target

[Service]
Type=simple
User=root
WorkingDirectory=$CURRENT_DIR
ExecStart=$CURRENT_DIR/.venv/bin/uvicorn chronos.api.app:app --host 0.0.0.0 --port 8000
Restart=always
RestartSec=5s
LimitNOFILE=65536
LimitNPROC=4096
StandardOutput=journal
StandardError=journal
SyslogIdentifier=chronos

[Install]
WantedBy=multi-user.target
DAEMON_SYSTEMD_EOF

    systemctl daemon-reload
    systemctl enable chronos-boot-scan.service
    systemctl enable --now chronos.service

    echo "[+] CHRONOS Boot Security Scanner and Defender Daemon enabled!"
    echo "    Check boot scan logs with:   journalctl -u chronos-boot-scan"
    echo "    Check boot report file:      /var/log/chronos-boot-audit.json"
    echo "    Check live daemon status:    systemctl status chronos"
    echo "    Run CLI status check:        chronos status"
    echo "    Run manual boot audit:       chronos boot-scan"
else
    echo "[!] Run as root (sudo) to install the systemd boot service automatically:"
    echo "    sudo ./install_ubuntu_daemon.sh"
    echo "    Or run a manual boot scan right now with:"
    echo "    make boot-scan   (or: $CURRENT_DIR/.venv/bin/chronos boot-scan)"
fi

echo "=========================================================="
echo "  CHRONOS Linux Defender Ready!"
echo "  Web UI Dashboard: http://localhost:5173"
echo "  Defender API & Docs: http://localhost:8000/docs"
echo "=========================================================="
