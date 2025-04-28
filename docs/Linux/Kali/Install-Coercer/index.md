---
title: "🧰 Install Coercer"
authors: [asalucci]
tags: [Kali, Linux, VMWare, Workstation]
published: 2025-02-25
categories: ["Linux", "Kali", "Setup", "Guide", "VMWare"]
---

# 🧰 Install Coercer

## Clone Coercer from GitHub and Install in virtual env

```bash
git clone https://github.com/p0dalirius/Coercer.git
cd Coercer
python3 -m venv venv
source venv/bin/activate
pip3 install -r requirements.txt
```

---

## When finished, exit the virtual environment:

```bash
deactivate
```

---

## Use Coercer

### Configure `/etc/resolv.conf` domain DNS

```bash
sudo nano /etc/resolv.conf
```

```bash
nameserver <DC_IP_address>
```