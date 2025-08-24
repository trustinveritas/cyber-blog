---
title: "Shodan.io CHEAT SHEET"
authors: [asalucci]
tags: [HackTheBox, CTF, trustinveritas, alessandro]
published: 2025-08-24
categories: ["SOC", "Analyst", "Write", "Up", "HackTheBox"]
---

# 🔍 SHODAN Cheat Sheet

> A quick reference guide for leveraging **Shodan**, the search engine for Internet-connected devices.  
> Source: Ethical Hackers Academy  

---

## 📌 What is Shodan?
Shodan is a publicly available search engine which scans the entire Internet for a limited number of services and enumerates any discovered services by their banner responses. It indexes that data and makes it searchable.

- **Indexed fields:** data, IP, port, org, host, location.country_code  
- **Pro tip:** Use `"View Raw Data"` to see all banner info from discovered hosts.  
- Always wrap queries in quotes `" "` to avoid confusion and broken queries.

---

## 🌍 Physical Location Searches

| Search Type | Example |
|-------------|---------|
| **Country** | `country:"US"` |
| **City** | `city:"New York"` |
| **State** | `state:"NY"` or `region:"NY"` |
| **Zip Code** | `postal:"92127"` |
| **Geo (GPS)** | `geo:"40.759487,-73.978356"` |
| **Geo (radius)** | `geo:"40.759487,-73.978356,2"` |

---

## 🖥️ IP Addresses & Subnets

| Type | Example |
|------|---------|
| **Single IP Address** | `52.179.197.205` |
| **Hostname** | `hostname:"microsoft.com"` |
| **Subnet** | `net:"52.179.197.0/24"` |
| **Port** | `port:"21"` |
| **Service** | `ftp` |
| **Service on Specific Port** | `"ftp" port:"21"` |
| **ISP** | `isp:"Spectrum"` |
| **ASN** | `ASN:"AS8075"` |

---

## ⚙️ Operating Systems & Products

| Type | Example |
|------|---------|
| **Operating System** | `os:"Windows Server 2008"` , `os:"Linux 2.6.x"` |
| **Organization / Company** | `org:"Microsoft"` |
| **Product** | `product:"Cisco C3550 Router"` |
| **Version** | `product:"nginx" version:"1.8.1"` |
| **Category** | `category:"ics"` , `category:"malware"` |
| **Microsoft SMB** | `smb:"1"` or `smb:"2"` |
| **Microsoft Shared Folders** | `port:"445" "shares"` |

---

## 🌐 Web Applications

| Search Type | Example |
|-------------|---------|
| **Page Title** | `title:"Index of /ftp"` |
| **Page HTML Body** | `html:"XML-RPC server accepts"` |
| **Tech Components** | `http.component:"php"` |
| **SSL/TLS Versions** | `ssl.version:"ssl3"` , `ssl.version:"tlsv1.1"` |
| **Expired Certificates** | `ssl.cert.expired:"true"` |

---

## 📅 Other Useful Queries

| Search Type | Example |
|-------------|---------|
| **After Date** | `after:"01/01/18"` |
| **Before Date** | `before:"12/31/17"` |
| **Has Screenshot** | `has_screenshot:"true"` |
| **Screenshot + Port 3389 (RDP)** | `port:"3389" has_screenshot:"true"` |

⚠️ **Danger:** Exposed RDP often reveals **Windows domains & user accounts**.

---

## 🔒 Limited Access (Pro / Paid)

- **Vulnerability by CVE ID**  
  Example: `vuln:"CVE-2017-0143"`

- **Tags** (Shodan-categorized data)  
  Example: `tag:"ics"` or `tag:"database"`

---

## ✅ Quick Tips

- Always use **quotes** around queries → `"query"`  
- Combine multiple filters for precision → `"ftp" country:"US" port:"21"`  
- Be mindful of **legal boundaries** — Shodan is for security research & awareness.  

---
**✨ Stay curious, stay ethical.**