---
title: "0. Migration from NGINX to Caddy"
authors: [asalucci]
tags: [HackTheBox, CTF, trustinveritas, alessandro]
published: 2025-05-25
categories: ["SOC", "Analyst", "Write", "Up", "HackTheBox"]
---

# Migration from NGINX to Caddy

## Installation

```bash
sudo apt install -y debian-keyring debian-archive-keyring apt-transport-https curl rsync
curl -1sLf 'https://dl.cloudsmith.io/public/caddy/stable/gpg.key' | sudo gpg --dearmor -o /usr/share/keyrings/caddy-stable-archive-keyring.gpg
curl -1sLf 'https://dl.cloudsmith.io/public/caddy/stable/debian.deb.txt' | sudo tee /etc/apt/sources.list.d/caddy-stable.list
sudo apt update
sudo apt install caddy
```

---

## Caddy - Config file `/etc/caddy/Caddyfile`

```bash
blog.salucci.ch {
    root * /var/www/blog.salucci.ch
    encode gzip
    file_server

    # Security Headers
    header {
        Strict-Transport-Security "max-age=63072000; includeSubDomains; preload"
        X-Frame-Options "DENY"
        X-Content-Type-Options "nosniff"
        Referrer-Policy "no-referrer-when-downgrade"
        X-XSS-Protection "1; mode=block"
        Permissions-Policy "geolocation=(), microphone=()"
        Content-Security-Policy "default-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline';"
    }

    # Reverse Proxy for GitHub WebHook
    @webhook path /webhook*
    reverse_proxy @webhook 127.0.0.1:5555 {
        header_up Host {host}
        header_up X-Real-IP {remote}
    }

    # Restrict HTTP methods to GET and HEAD
    @disallowed_methods {
        not method GET HEAD
    }
    respond @disallowed_methods "Method Not Allowed" 405

    # Deny access to hidden files and directories
    @hidden_files {
        path /.env* /.git* /.bash* /.cache* /.config* /.* /.*/*
    }
    respond @hidden_files "Access Denied" 403

    # Deny access to sensitive files
    @sensitive_files path_regexp sensitive_files ^.*(\.bak|\.config|\.env|\.git|~)$
    respond @sensitive_files "Access Denied" 403

    # Block PHP execution
    @php_files {
        path *.php
    }
    respond @php_files "PHP execution is disabled" 403

    # Static files fallback
    try_files {path} {path}/ /index.html
}

# Refer to the Caddy docs for more information:
# https://caddyserver.com/docs/caddyfile
```

### Validate the config

```bash
sudo caddy validate --config /etc/caddy/Caddyfile
```

---

## Set Up Directory Structure

```bash
sudo mkdir -p /etc/caddy
sudo mkdir -p /var/www/blog.salucci.ch
sudo chown -R caddy:caddy /var/www/blog.salucci.ch
```

---

## Disable and Remove NGINX

```bash
sudo systemctl stop nginx
```

### 🚫 1. Disable It From Starting on Boot

```bash
sudo systemctl disable nginx
```

### ❌ 2. Remove It Completely

If you're sure you no longer need it:

```bash
sudo apt remove --purge nginx nginx-common
sudo apt autoremove
```

---

## ✅ Ensure Caddy Is Active and Binding Correctly

### 🔁 Reload or Restart Caddy

```bash
sudo systemctl restart caddy
```

### 🔍 Verify Caddy is Listening on 80/443

```bash
sudo ss -tuln | grep ':80\|:443'
```

You should see something like:

```bash
udp   UNCONN 0      0                      *:443             *:*
tcp   LISTEN 0      4096                   *:443             *:*
tcp   LISTEN 0      4096                   *:80              *:*
```