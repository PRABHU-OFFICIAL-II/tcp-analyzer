#!/usr/bin/env bash
# Full production deployment script for RHEL / AlmaLinux / Rocky Linux / CentOS.
# Must be run as root or with sudo.
set -e

APP_DIR="/opt/tcp-analyzer"
APP_USER="${SUDO_USER:-$(whoami)}"
VM_IP="${1:-YOUR_VM_IP}"

echo "=== TCP Analyzer — RHEL Production Deploy ==="
echo "  App directory : $APP_DIR"
echo "  App user      : $APP_USER"
echo "  Server IP     : $VM_IP"
echo ""

# ── 1. Build the React frontend ───────────────────────────────────────────────
echo "[1/6] Building frontend..."
cd "$APP_DIR/frontend"
npm install
npm run build
echo "[1/6] Frontend built → $APP_DIR/frontend/dist"

# ── 2. Install the systemd service ───────────────────────────────────────────
echo "[2/6] Installing systemd service..."

cat > /etc/systemd/system/tcp-analyzer-backend.service <<EOF
[Unit]
Description=TCP Analyzer Backend (FastAPI + Uvicorn)
After=network.target

[Service]
Type=simple
User=$APP_USER
WorkingDirectory=$APP_DIR/backend
ExecStart=$APP_DIR/backend/.venv/bin/uvicorn app.main:app --host 127.0.0.1 --port 8000 --workers 1
Environment=CORS_ORIGINS=http://$VM_IP
Restart=always
RestartSec=5
StandardOutput=journal
StandardError=journal
LimitNOFILE=65536

[Install]
WantedBy=multi-user.target
EOF

systemctl daemon-reload
systemctl enable tcp-analyzer-backend
systemctl restart tcp-analyzer-backend
echo "[2/6] Backend service enabled and started."

# ── 3. Configure nginx ────────────────────────────────────────────────────────
echo "[3/6] Writing nginx config to /etc/nginx/conf.d/tcp-analyzer.conf..."

cat > /etc/nginx/conf.d/tcp-analyzer.conf <<EOF
server {
    listen 80;
    server_name $VM_IP;

    root $APP_DIR/frontend/dist;
    index index.html;

    # React client-side routing fallback
    location / {
        try_files \$uri \$uri/ /index.html;
    }

    # Reverse proxy to FastAPI backend
    location /api/ {
        proxy_pass http://127.0.0.1:8000;
        proxy_set_header Host \$host;
        proxy_set_header X-Real-IP \$remote_addr;
        proxy_set_header X-Forwarded-For \$proxy_add_x_forwarded_for;

        # Large pcap uploads
        client_max_body_size 500M;

        # Long timeout for Gemma inference
        proxy_read_timeout    300s;
        proxy_connect_timeout  10s;
        proxy_send_timeout    300s;
    }
}
EOF

# ── 4. SELinux configuration ──────────────────────────────────────────────────
echo "[4/6] Configuring SELinux..."

# Allow nginx to proxy to localhost:8000 (fixes 502 Bad Gateway)
setsebool -P httpd_can_network_connect 1

# Label the frontend dist directory so nginx can serve the static files
chcon -Rt httpd_sys_content_t "$APP_DIR/frontend/dist/"

echo "[4/6] SELinux booleans and file contexts set."

# ── 5. Set ownership and filesystem permissions ───────────────────────────────
echo "[5/6] Setting permissions..."
chown -R "$APP_USER":"$APP_USER" "$APP_DIR"
mkdir -p "$APP_DIR/backend/data"
chmod 755 "$APP_DIR/backend/data"
echo "[5/6] Permissions set."

# ── 6. Firewalld and nginx ────────────────────────────────────────────────────
echo "[6/6] Configuring firewalld and starting nginx..."

systemctl enable firewalld
systemctl start firewalld

firewall-cmd --permanent --add-service=http
firewall-cmd --permanent --add-service=ssh
firewall-cmd --reload

nginx -t
systemctl enable nginx
systemctl restart nginx

echo ""
echo "=== Deployment complete ==="
echo ""
echo "  App        : http://$VM_IP"
echo "  API health : http://$VM_IP/api/health"
echo ""
echo "  View backend logs : sudo journalctl -u tcp-analyzer-backend -f"
echo "  Backend status    : sudo systemctl status tcp-analyzer-backend"
echo "  Nginx status      : sudo systemctl status nginx"
echo ""
echo "NOTE: The Gemma model loads on the FIRST /api/chat request (may take 2-5 min)."
echo "      Watch logs with: sudo journalctl -u tcp-analyzer-backend -f"
