---
id: kali-vm-setup-vmware
title: "Kali VM Workstation Setup Guide (VMware)"
slug: /kali-vm-setup-vmware
authors: [asalucci]
tags: [Kali, Linux, VMWare, Workstation]
published: 2025-02-25
categories: ["Linux", "Kali", "Setup", "Guide", "VMWare"]
---

import Link from '@docusaurus/Link';

# Kali VM Workstation Setup Guide

## 1. Change Keyboard Layout

```bash
setxkbmap ch de
```

### Permanent Change

```bash
sudo nano /etc/default/keyboard
```

```bash
XKBLAYOUT="ch"
XKBVARIANT="de"
```

```bash
sudo dpkg-reconfigure keyboard-configuration
sudo systemctl restart keyboard-setup.service
```

---

## 2. OpenVPN to HackTheBox

```bash
cd HackTheBox
```

```bash
sudo openvpn academy-regular.ovpn
```

---

## 3. 🛡️ Full Kali Linux Update and Cleanup Commands

```bash
sudo apt update && sudo apt upgrade -y && sudo apt full-upgrade -y && sudo apt autoremove -y && sudo apt autoclean && sudo apt clean && sudo apt --fix-broken install
```

> ✅ This fully updates, upgrades, cleans, and fixes your Kali Linux system.

```bash
sudo apt update
```

```bash
sudo apt upgrade -y
```

```bash
sudo apt full-upgrade -y
```

```bash
sudo apt autoremove -y
```

```bash
sudo apt autoclean
```

```bash
sudo apt --fix-broken install
```

:::note
Reboot after a full update (especially after a kernel update):

```bash
sudo reboot
```

:::

## 4. Check if disk space is needed

```bash
df -h
```

---

## 📢 5. xfreerdp `Bleeding Edge` (Remote Desktop on Kali Linux)

```bash
sudo apt update
```

```bash
sudo apt install build-essential git cmake libssl-dev libx11-dev libxext-dev libxinerama-dev libxcursor-dev libxv-dev libxkbfile-dev libxi-dev libxrandr-dev libxrender-dev libxfixes-dev libjpeg-dev libfuse-dev libusb-1.0-0-dev libpulse-dev libvte-2.91-dev libwayland-dev libsystemd-dev libavcodec-dev libavutil-dev libswscale-dev libavformat-dev build-essential cmake git pkg-config libssl-dev libx11-dev libxext-dev libxinerama-dev libxcursor-dev libxv-dev libxkbfile-dev libxi-dev libxrandr-dev libxrender-dev libxfixes-dev libjpeg-dev libfuse-dev libusb-1.0-0-dev libpulse-dev libwayland-dev libsystemd-dev libavcodec-dev libavutil-dev libswscale-dev libavformat-dev libcups2-dev libfuse3-dev -y
```

```bash
git clone https://github.com/FreeRDP/FreeRDP.git
```

```bash
cd FreeRDP
```

```bash
mkdir build
```

```bash
cd build
```

```bash
cmake -DCMAKE_BUILD_TYPE=Release -DWITH_SSE2=ON ..
```

```bash
make -j$(nproc)
```

```bash
sudo make install
```

### Confirm Installation

```bash
xfreerdp /buildconfig
```

### 🎯 Ultimate xfreerdp Connect Command

```bash
xfreerdp /v:<target_ip_or_hostname> /u:<username> /p:<password> /cert:ignore /compression +clipboard +fonts /network:auto /dynamic-resolution /gfx +gfx-progressive /rfx +async-update +async-input +async-transport /size:1366x768 /sound:sys:oss
```