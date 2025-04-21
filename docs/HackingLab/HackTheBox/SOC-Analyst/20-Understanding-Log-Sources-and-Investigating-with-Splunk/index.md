---
title: "20. Understanding Log Sources & Investigating with Splunk - Skills Assessment"
authors: [asalucci]
tags: [HackTheBox, CTF, trustinveritas, alessandro]
published: 2025-04-21
categories: ["SOC", "Analyst", "Write", "Up", "HackTheBox"]
---

import RevealFlag from '@site/src/components/RevealFlag';

# Skills Assessment

## Scenario

This skills assessment section builds upon the progress made in the `Intrusion Detection With Splunk (Real-world Scenario)` section. Our objective is to identify any missing components of the attack chain and trace the malicious process responsible for initiating the infection.

---

## Practical Exercises

### `1. Navigate to http://[Target IP]:8000, open the "Search & Reporting" application, and find through SPL searches against all data the process that created remote threads in rundll32.exe. Answer format: _.exe`

<RevealFlag>{`randomfile.exe`}</RevealFlag>

```sql
index=* EventCode=8 (TargetImage="*\\rundll32.exe" OR TargetImage="rundll32.exe")
| stats count AS remote_thread_creations BY SourceImage
| sort - remote_thread_creations
```

<details>
<summary>Click to view the event</summary>

```txt
11/06/2022 11:24:05 AM
LogName=Microsoft-Windows-Sysmon/Operational
EventCode=8
EventType=4
ComputerName=DESKTOP-EGSS5IS
User=NOT_TRANSLATED
Sid=S-1-5-18
SidType=0
SourceName=Microsoft-Windows-Sysmon
Type=Information
RecordNumber=39763
Keywords=None
TaskCategory=CreateRemoteThread detected (rule: CreateRemoteThread)
OpCode=Info
Message=CreateRemoteThread detected:
RuleName: technique_id=T1055,technique_name=Process Injection
UtcTime: 2022-11-06 19:24:05.905
SourceProcessGuid: {96192a2a-f8f3-6367-9501-000000000900}
SourceProcessId: 1216
SourceImage: C:\Users\waldo\Downloads\randomfile.exe
TargetProcessGuid: {96192a2a-09d5-6368-3b05-000000000900}
TargetProcessId: 2964
TargetImage: C:\Windows\System32\rundll32.exe
NewThreadId: 7468
StartAddress: 0x000002E5397D0000
StartModule: -
StartFunction: -
SourceUser: DESKTOP-EGSS5IS\waldo
TargetUser: DESKTOP-EGSS5IS\waldo
```

</details>

---

### `2. Navigate to http://[Target IP]:8000, open the "Search & Reporting" application, and find through SPL searches against all data the process that started the infection. Answer format: _.exe`

<RevealFlag>{`rundll32.exe`}</RevealFlag>

```sql
index=* EventCode=1 
| eval exe = replace(Image,".*\\\\","")
| stats earliest(_time) AS first_seen BY exe, Image, CommandLine
| sort 0 + first_seen
| table first_seen exe Image CommandLine
```