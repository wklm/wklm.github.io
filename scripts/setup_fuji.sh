#!/bin/bash
# Script to set up the Tailscale SMTP listener on fuji
set -e

# Setup directory
cd /home/wojtek/crane_blog

# Install the Python aiosmtpd library from Debian repositories
sudo apt-get update
sudo apt-get install -y python3-aiosmtpd

# Create a systemd service file
cat <<EOF | sudo tee /etc/systemd/system/crane_blog_smtp.service
[Unit]
Description=Crane Blog Tailscale SMTP Server
After=network.target

[Service]
User=wojtek
WorkingDirectory=/home/wojtek/crane_blog
Environment="PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"
Environment="SMTP_PORT=2525"
ExecStart=/usr/bin/env python3 /home/wojtek/crane_blog/scripts/tailscale_smtp.py
Restart=always

[Install]
WantedBy=multi-user.target
EOF

sudo systemctl daemon-reload
sudo systemctl enable crane_blog_smtp
sudo systemctl restart crane_blog_smtp

echo ""
echo "Setup complete!"
echo "The SMTP server is now listening on port 2525."
echo ""
echo "TO CONFIGURE YOUR MACBOOK:"
echo "1. Open Mail.app"
echo "2. Go to Preferences -> Accounts -> Server Settings"
echo "3. Click the 'Outgoing Mail Account (SMTP)' dropdown -> Edit SMTP Server List..."
echo "4. Add a new server ('+') or select an existing one."
echo "5. Host Name: $(hostname) (or fuji's Tailscale IP)"
echo "6. Uncheck 'Automatically manage connection settings'"
echo "7. Port: 2525, TLS: None or Optional, Authentication: None"
echo "8. Send an email to any address (like blog@fuji) using this server to trigger the script!"
