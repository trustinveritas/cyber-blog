---
title: "2. 🪟➡️🐧 Step-by-Step: Send Windows Event Logs to Elastic Stack"
authors: [asalucci]
tags: [HackTheBox, CTF, trustinveritas, alessandro]
published: 2025-04-15
categories: ["SOC", "Analyst", "Write", "Up", "HackTheBox"]
---

# 🪟➡️🐧 Step-by-Step: Send Windows Event Logs to Elastic Stack

## ✅ 1. Download Winlogbeat on your Windows machine

Go to the official [Winlogbeat download page](https://www.elastic.co/downloads/beats/winlogbeat) and download the `.zip` file.

---

## 📂 2. Extract & Open PowerShell

- Extract it to: `C:\Program Files\Winlogbeat`
- Open **PowerShell as Administrator**
- Navigate to the directory: `cd 'C:\Program Files\Winlogbeat'`

---

## ⚙️ 3. Edit the config (`winlogbeat.yml`)

Open it in Notepad or VS Code:

```powershell
notepad .\winlogbeat.yml
```

Look for this section and replace it like this:

```yaml
###################### Winlogbeat Hardened Configuration ########################

winlogbeat.event_logs:

  # Core Security Events
  - name: Security
    # event_id: 
    #  - 4624  # Successful logon
    #  - 4625  # Failed logon
    #  - 4634  # Logoff
    #  - 4672  # Special privileges assigned to new logon
    #  - 4688  # Process creation
    #  - 4697  # Service installation
    #  - 4719  # Audit policy change
    #  - 4720  # User account created
    #  - 4722  # User account enabled
    #  - 4723  # Password change attempt
    #  - 4724  # Password reset
    #  - 4725  # User account disabled
    #  - 4726  # User account deleted
    #  - 4732  # Added to local group
    #  - 4756  # Added to domain group
    #  - 4768  # Kerberos TGT request
    #  - 4769  # Kerberos service ticket request
    #  - 4771  # Kerberos pre-auth failure
    #  - 4776  # NTLM authentication
    #  - 4798  # User's local group enumeration
    #  - 4799  # User's domain group enumeration
    #  - 4964  # Special logon
    #  - 5140  # SMB share access
    #  - 5142  # Share creation
    #  - 5156  # Allowed inbound network connection
    #  - 5158  # Allowed outbound connection
    #  - 1102  # Audit log cleared

  # Sysmon (must be installed separately with a config like SwiftOnSecurity)
  - name: Microsoft-Windows-Sysmon/Operational
    # event_id:
    #  - 1   # Process creation
    #  - 3   # Network connection
    #  - 7   # Image loaded
    #  - 8   # CreateRemoteThread
    #  - 10  # ProcessAccess
    #  - 11  # File creation
    #  - 12,13,14,15 # Registry events
    #  - 17,18 # Pipe events
    #  - 19,20,21,22 # WMI events
    #  - 23,24,25 # DNS query, image tampering

  # PowerShell Events
  - name: Windows PowerShell
    # event_id: 400, 403, 600, 800

  - name: Microsoft-Windows-PowerShell/Operational
    # event_id: 4100, 4101, 4103, 4104, 4105, 4106

  # System Events
  - name: System

  # Forwarded Events (from other systems)
  - name: ForwardedEvents
    tags: [forwarded]

# ===================== Elasticsearch Output =====================
output.elasticsearch:
  hosts: ["http://192.168.38.129:9200"]
  username: "elastic"
  password: "<YOUR_PASSWORD>"
  ssl.verification_mode: none

# ===================== Kibana =====================
setup.kibana:
  host: "http://192.168.38.129:5601"
  username: "elastic"
  password: "<your_elastic_password>"

# ===================== Dashboard =====================
setup.dashboards.enabled: true

# ===================== Logging =====================
logging.level: warning

# ===================== Processors =====================
processors:
  - add_host_metadata:
      when.not.contains.tags: forwarded
  - add_cloud_metadata: ~
```

## ⚙️ 4. Validate the config (`winlogbeat.yml`)

```powershell
cd "C:\Program Files\Winlogbeat"
```

```powershell
.\winlogbeat.exe test config -c .\winlogbeat.yml -e
```

```powershell
{"log.level":"warn","@timestamp":"2025-04-15T22:35:23.396+0200","log.logger":"tls","log.origin":{"function":"github.com/elastic/elastic-agent-libs/transport/tlscommon.(*TLSConfig).ToConfig","file.name":"tlscommon/tls_config.go","file.line":107},"message":"SSL/TLS verifications disabled.","service.name":"winlogbeat","ecs.version":"1.6.0"}
Config OK
```

## 🚀 5. Install Winlogbeat as a Windows Service

```powershell
.\install-service-winlogbeat.ps1
```

## 📊 6. Setup Dashboards (optional)

```powershell
.\winlogbeat.exe setup --dashboards
```

```powershell
Loading dashboards (Kibana must be running and reachable)
Loaded dashboards
```

## ⚙️ 7. Start `winlogbeat` service

```powershell
Start-Service winlogbeat
```

Check the status of the service.

```powershell
Get-Service winlogbeat
```

```powershell
Status   Name               DisplayName
------   ----               -----------
Running  winlogbeat         winlogbeat
```

